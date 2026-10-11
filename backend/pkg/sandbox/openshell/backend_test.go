package openshell

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/docker"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeExec struct {
	gotWorkspace string
	gotSandbox   string
	gotCmd       []string
	calls        [][]string
	result       *v1.ExecResult
	err          error
	// script, when set, answers a command instead of result.
	script func(cmd []string) *v1.ExecResult
}

func (f *fakeExec) Run(_ context.Context, workspace, sandbox string, cmd []string, _ ...v1.ExecOptions) (*v1.ExecResult, error) {
	f.gotWorkspace, f.gotSandbox, f.gotCmd = workspace, sandbox, cmd
	f.calls = append(f.calls, cmd)
	if f.err != nil {
		return nil, f.err
	}
	if f.script != nil {
		return f.script(cmd), nil
	}
	return f.result, nil
}

func testBackend(exec execAPI) *Backend {
	cfg := &config.Config{OpenShellWorkspace: "default", OpenShellDefaultImage: "img", OpenShellDefaultPreset: "web_pentest"}
	return newBackend(nil, cfg, nil, exec, nil)
}

func TestBackend_ContainerExec_FramesOutputForNonTTYAndRawForTTY(t *testing.T) {
	exec := &fakeExec{result: &v1.ExecResult{ExitCode: 3, Stdout: []byte("out"), Stderr: []byte("err")}}
	b := testBackend(exec)
	ctx := context.Background()

	t.Run("non-tty is stdcopy-framed", func(t *testing.T) {
		created, err := b.ContainerExecCreate(ctx, "flow-1", client.ExecCreateOptions{Cmd: []string{"id"}})
		require.NoError(t, err)

		resp, err := b.ContainerExecAttach(ctx, created.ID, client.ExecAttachOptions{})
		require.NoError(t, err)
		defer resp.Close()

		var outBuf, errBuf bytes.Buffer
		_, err = stdcopy.StdCopy(&outBuf, &errBuf, resp.Reader)
		require.NoError(t, err)
		assert.Equal(t, "out", outBuf.String())
		assert.Equal(t, "err", errBuf.String())

		inspect, err := b.ContainerExecInspect(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, 3, inspect.ExitCode)
		assert.False(t, inspect.Running, "a run exec is not running")
		assert.Equal(t, []string{"id"}, exec.gotCmd)
	})

	t.Run("tty is raw combined output", func(t *testing.T) {
		created, err := b.ContainerExecCreate(ctx, "flow-1", client.ExecCreateOptions{Cmd: []string{"id"}, TTY: true})
		require.NoError(t, err)

		resp, err := b.ContainerExecAttach(ctx, created.ID, client.ExecAttachOptions{TTY: true})
		require.NoError(t, err)
		defer resp.Close()

		raw, err := io.ReadAll(resp.Reader)
		require.NoError(t, err)
		assert.Equal(t, "outerr", string(raw), "a TTY stream carries no stdcopy headers")
	})
}

func TestBackend_ContainerExecInspect_IsRunningBeforeAttach(t *testing.T) {
	b := testBackend(&fakeExec{result: &v1.ExecResult{}})
	created, err := b.ContainerExecCreate(context.Background(), "flow-1", client.ExecCreateOptions{Cmd: []string{"id"}})
	require.NoError(t, err)

	inspect, err := b.ContainerExecInspect(context.Background(), created.ID)
	require.NoError(t, err)
	assert.True(t, inspect.Running, "an exec that has not been attached has not run yet")
}

func tarOf(t *testing.T, name string, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}))
	_, _ = tw.Write([]byte(body))
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func TestBackend_CopyToContainer_StagesTheTarInChunksAndExtractsItOnce(t *testing.T) {
	exec := &fakeExec{result: &v1.ExecResult{}}
	b := testBackend(exec)
	archive := tarOf(t, "big.bin", strings.Repeat("x", 80*1024))

	err := b.CopyToContainer(context.Background(), "flow-1", "/work", bytes.NewReader(archive), client.CopyToContainerOptions{})
	require.NoError(t, err)

	var staged strings.Builder
	var extracts, removals int
	for _, cmd := range exec.calls {
		switch {
		case cmd[0] == "sh" && strings.Contains(cmd[2], `>> "$2"`):
			assert.LessOrEqual(t, len(cmd[4]), transferChunk, "a staged piece must fit the argument limit")
			staged.WriteString(cmd[4])
		case cmd[0] == "sh" && strings.Contains(cmd[2], "tar -xf"):
			extracts++
			assert.Equal(t, "/work", cmd[5], "the archive is extracted into the destination")
		case cmd[0] == "rm":
			removals++
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(staged.String())
	require.NoError(t, err)
	assert.Equal(t, archive, decoded, "the staged pieces reassemble into the uploaded tar")
	assert.Equal(t, 1, extracts)
	assert.Equal(t, 1, removals, "the staging files are removed")
	assert.Greater(t, len(exec.calls), 4, "an 80 KiB upload needs more than one staged piece")
}

func TestBackend_CopyToContainer_ReportsAFailedExtraction(t *testing.T) {
	exec := &fakeExec{script: func(cmd []string) *v1.ExecResult {
		if cmd[0] == "sh" && strings.Contains(cmd[2], "tar -xf") {
			return &v1.ExecResult{ExitCode: 2, Stderr: []byte("tar: short read")}
		}
		return &v1.ExecResult{}
	}}
	b := testBackend(exec)

	err := b.CopyToContainer(context.Background(), "flow-1", "/work", bytes.NewReader(tarOf(t, "a", "b")), client.CopyToContainerOptions{})
	require.ErrorContains(t, err, "tar: short read")
}

func TestBackend_CopyFromContainer_ReturnsTheTarTheSandboxProduced(t *testing.T) {
	archive := tarOf(t, "work", "")
	exec := &fakeExec{script: func(cmd []string) *v1.ExecResult {
		if cmd[0] == "stat" {
			return &v1.ExecResult{Stdout: []byte("4096|41ed|1700000000|/work/uploads\n")}
		}
		return &v1.ExecResult{Stdout: []byte(base64.StdEncoding.EncodeToString(archive))}
	}}
	b := testBackend(exec)

	reader, stat, err := b.CopyFromContainer(context.Background(), "flow-1", "/work/uploads")
	require.NoError(t, err)
	defer reader.Close()
	assert.True(t, stat.Mode.IsDir(), "a directory keeps its type")

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, archive, got)

	last := exec.calls[len(exec.calls)-1]
	assert.Equal(t, []string{"/work", "uploads"}, last[len(last)-2:], "the archive is made from the parent so the entry keeps its own name")
}

func TestBackend_CopyFromContainer_ReportsAMissingPathAsNotFound(t *testing.T) {
	exec := &fakeExec{result: &v1.ExecResult{ExitCode: 1, Stderr: []byte("stat: cannot statx '/work/ghost': No such file or directory")}}
	b := testBackend(exec)

	_, _, err := b.CopyFromContainer(context.Background(), "flow-1", "/work/ghost")
	require.Error(t, err)
	assert.True(t, docker.IsNotFound(err), "the Files API maps a missing path to 404 through this check")
}

func TestBackend_ContainerExecInspect_ForgetsAFinishedExec(t *testing.T) {
	b := testBackend(&fakeExec{result: &v1.ExecResult{}})
	ctx := context.Background()

	created, err := b.ContainerExecCreate(ctx, "flow-1", client.ExecCreateOptions{Cmd: []string{"id"}})
	require.NoError(t, err)
	resp, err := b.ContainerExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	require.NoError(t, err)
	resp.Close()

	_, err = b.ContainerExecInspect(ctx, created.ID)
	require.NoError(t, err)
	assert.Empty(t, b.execs, "a finished exec must not stay in the map")
}

func TestBackend_ContainerExecAttach_ForgetsAnExecThatFailedToRun(t *testing.T) {
	b := testBackend(&fakeExec{err: errors.New("gateway down")})
	ctx := context.Background()

	created, err := b.ContainerExecCreate(ctx, "flow-1", client.ExecCreateOptions{Cmd: []string{"id"}})
	require.NoError(t, err)
	_, err = b.ContainerExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	require.ErrorContains(t, err, "gateway down")
	assert.Empty(t, b.execs)
}

func TestBackend_ContainerStatPath_ParsesStatOutput(t *testing.T) {
	// size 42, mode 0x41ed (drwxr-xr-x), mtime 1700000000
	exec := &fakeExec{result: &v1.ExecResult{ExitCode: 0, Stdout: []byte("42|41ed|1700000000|/work\n")}}
	b := testBackend(exec)

	stat, err := b.ContainerStatPath(context.Background(), "flow-1", "/work")
	require.NoError(t, err)
	assert.Equal(t, int64(42), stat.Size)
	assert.True(t, stat.Mode.IsDir(), "0x41ed carries the directory bit")
	assert.Equal(t, "work", stat.Name)
}

func TestBackend_RunContainer_FailsClosedOnAnUnknownPreset(t *testing.T) {
	b := testBackend(&fakeExec{result: &v1.ExecResult{}})

	_, err := b.RunContainer(context.Background(), "flow-1", database.ContainerTypePrimary, 1,
		&container.Config{Labels: map[string]string{"openshell.preset": "ghost"}}, nil)
	require.ErrorContains(t, err, "unknown OpenShell preset")
}

type statusRecorder struct {
	database.Querier
	got []database.ContainerStatus
}

func (r *statusRecorder) UpdateContainerStatus(_ context.Context, arg database.UpdateContainerStatusParams) (database.Container, error) {
	r.got = append(r.got, arg.Status)
	return database.Container{}, nil
}

type deleteRecorder struct {
	sandboxAPI
	deleted []string
}

func (d *deleteRecorder) Delete(_ context.Context, _, name string, _ ...v1.DeleteOptions) (*v1.DeletionResult, error) {
	d.deleted = append(d.deleted, name)
	return &v1.DeletionResult{}, nil
}

func TestBackend_StopContainer_DeletesTheSandboxAndRecordsItAsDeleted(t *testing.T) {
	db := &statusRecorder{}
	sandboxes := &deleteRecorder{}
	cfg := &config.Config{OpenShellWorkspace: "default", OpenShellDefaultPreset: "web_pentest"}
	b := newBackend(db, cfg, sandboxes, &fakeExec{result: &v1.ExecResult{}}, nil)

	require.NoError(t, b.StopContainer(context.Background(), "flow-1", 9))
	assert.Equal(t, []string{"flow-1"}, sandboxes.deleted)
	assert.Equal(t, []database.ContainerStatus{database.ContainerStatusDeleted}, db.got,
		"a sandbox that cannot be resumed must not be recorded as merely stopped")
}
