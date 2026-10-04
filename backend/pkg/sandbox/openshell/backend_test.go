package openshell

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"pentagi/pkg/config"
	"pentagi/pkg/database"

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
	result       *v1.ExecResult
	err          error
}

func (f *fakeExec) Run(_ context.Context, workspace, sandbox string, cmd []string, _ ...v1.ExecOptions) (*v1.ExecResult, error) {
	f.gotWorkspace, f.gotSandbox, f.gotCmd = workspace, sandbox, cmd
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type fakeFiles struct {
	uploads   map[string][]byte // remote path -> content
	downloads map[string][]byte // remote path -> content served
}

func (f *fakeFiles) Upload(_ context.Context, _, _, localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	if f.uploads == nil {
		f.uploads = map[string][]byte{}
	}
	f.uploads[remotePath] = data
	return nil
}

func (f *fakeFiles) Download(_ context.Context, _, _, remotePath, localPath string) error {
	data, ok := f.downloads[remotePath]
	if !ok {
		return os.ErrNotExist
	}
	return os.WriteFile(localPath, data, 0o644)
}

func testBackend(exec execAPI, files fileAPI) *Backend {
	cfg := &config.Config{OpenShellWorkspace: "default", OpenShellDefaultImage: "img", OpenShellDefaultPreset: "web_pentest"}
	return newBackend(nil, cfg, nil, exec, files, nil)
}

func TestBackend_ContainerExec_FramesOutputForNonTTYAndRawForTTY(t *testing.T) {
	exec := &fakeExec{result: &v1.ExecResult{ExitCode: 3, Stdout: []byte("out"), Stderr: []byte("err")}}
	b := testBackend(exec, nil)
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
	b := testBackend(&fakeExec{result: &v1.ExecResult{}}, nil)
	created, err := b.ContainerExecCreate(context.Background(), "flow-1", client.ExecCreateOptions{Cmd: []string{"id"}})
	require.NoError(t, err)

	inspect, err := b.ContainerExecInspect(context.Background(), created.ID)
	require.NoError(t, err)
	assert.True(t, inspect.Running, "an exec that has not been attached has not run yet")
}

func TestBackend_CopyToContainer_UploadsEachFileUnderTheDestination(t *testing.T) {
	files := &fakeFiles{}
	b := testBackend(&fakeExec{result: &v1.ExecResult{}}, files)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "notes.txt", Mode: 0o600, Size: 5}))
	_, _ = tw.Write([]byte("hello"))
	require.NoError(t, tw.Close())

	err := b.CopyToContainer(context.Background(), "flow-1", "/work", &buf, client.CopyToContainerOptions{})
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), files.uploads["/work/notes.txt"])
}

func TestBackend_CopyFromContainer_ReturnsASingleEntryTar(t *testing.T) {
	files := &fakeFiles{downloads: map[string][]byte{"/work/out.txt": []byte("result")}}
	b := testBackend(&fakeExec{result: &v1.ExecResult{}}, files)

	reader, stat, err := b.CopyFromContainer(context.Background(), "flow-1", "/work/out.txt")
	require.NoError(t, err)
	defer reader.Close()
	assert.Equal(t, "out.txt", stat.Name)

	tr := tar.NewReader(reader)
	header, err := tr.Next()
	require.NoError(t, err)
	assert.Equal(t, "out.txt", header.Name)
	body, err := io.ReadAll(tr)
	require.NoError(t, err)
	assert.Equal(t, "result", string(body))
}

func TestBackend_ContainerStatPath_ParsesStatOutput(t *testing.T) {
	// size 42, mode 0x41ed (drwxr-xr-x), mtime 1700000000
	exec := &fakeExec{result: &v1.ExecResult{ExitCode: 0, Stdout: []byte("42|41ed|1700000000|/work\n")}}
	b := testBackend(exec, nil)

	stat, err := b.ContainerStatPath(context.Background(), "flow-1", "/work")
	require.NoError(t, err)
	assert.Equal(t, int64(42), stat.Size)
	assert.True(t, stat.Mode.IsDir(), "0x41ed carries the directory bit")
	assert.Equal(t, "work", stat.Name)
}

func TestBackend_RunContainer_FailsClosedOnAnUnknownPreset(t *testing.T) {
	b := testBackend(&fakeExec{result: &v1.ExecResult{}}, nil)

	_, err := b.RunContainer(context.Background(), "flow-1", database.ContainerTypePrimary, 1,
		&container.Config{Labels: map[string]string{"openshell.preset": "ghost"}}, nil)
	require.ErrorContains(t, err, "unknown OpenShell preset")
}
