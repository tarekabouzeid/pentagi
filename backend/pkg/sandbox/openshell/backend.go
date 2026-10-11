// Package openshell adapts an NVIDIA OpenShell gateway to docker.DockerClient so a flow can run its tools in an OpenShell sandbox.
//
// A container name maps 1:1 to a sandbox name in a fixed workspace. Docker's exec create/attach/inspect split is bridged onto OpenShell's single streaming exec with per-exec state kept here.
package openshell

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/docker"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

type sandboxAPI interface {
	Create(ctx context.Context, workspace, name string, spec *v1.SandboxSpec, labels map[string]string, opts ...v1.CreateOptions) (*v1.Sandbox, error)
	Get(ctx context.Context, workspace, name string) (*v1.Sandbox, error)
	Delete(ctx context.Context, workspace, name string, opts ...v1.DeleteOptions) (*v1.DeletionResult, error)
	WaitReady(ctx context.Context, workspace, name string, opts ...v1.WaitOptions) (*v1.Sandbox, error)
}

type execAPI interface {
	Run(ctx context.Context, workspace, sandboxName string, command []string, opts ...v1.ExecOptions) (*v1.ExecResult, error)
}

// transferChunk is the base64 size of one staged upload piece, kept well under the kernel limit on a single argument.
const transferChunk = 64 * 1024

type Backend struct {
	db        database.Querier
	logger    *logrus.Entry
	closer    io.Closer
	sandboxes sandboxAPI
	exec      execAPI

	workspace     string
	defaultImage  string
	defaultPreset string

	mx    sync.Mutex
	execs map[string]*execState
	seq   int64
}

type execState struct {
	sandbox string
	cmd     []string
	workdir string
	env     []string
	tty     bool

	ran      bool
	exitCode int
}

var _ docker.DockerClient = (*Backend)(nil)

// New fails closed: an unreachable gateway or an unknown default preset stops startup instead of falling back to Docker.
func New(ctx context.Context, db database.Querier, cfg *config.Config) (*Backend, error) {
	if _, ok := presets[cfg.OpenShellDefaultPreset]; !ok {
		return nil, fmt.Errorf("OPENSHELL_DEFAULT_PRESET %q is not a known preset (%s)", cfg.OpenShellDefaultPreset, strings.Join(Presets(), ", "))
	}

	sdkCfg := v1.Config{Address: cfg.OpenShellGatewayAddress}
	if cfg.OpenShellToken != "" {
		sdkCfg.Auth = v1.StaticToken(cfg.OpenShellToken)
	} else {
		sdkCfg.Auth = v1.NoAuth()
	}
	if !strings.HasPrefix(cfg.OpenShellGatewayAddress, "http://") {
		sdkCfg.TLS = &v1.TLSConfig{CAFile: cfg.OpenShellTLSCACert, Insecure: cfg.OpenShellTLSInsecure}
	}

	client, err := v1.NewClient(sdkCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the OpenShell gateway at %s: %w", cfg.OpenShellGatewayAddress, err)
	}
	if _, err := client.Health().Check(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("OpenShell gateway at %s is unhealthy: %w", cfg.OpenShellGatewayAddress, err)
	}

	return newBackend(db, cfg, client.Sandboxes(), client.Exec(), client), nil
}

func newBackend(db database.Querier, cfg *config.Config, sandboxes sandboxAPI, exec execAPI, closer io.Closer) *Backend {
	return &Backend{
		db:            db,
		logger:        logrus.WithField("component", "openshell"),
		closer:        closer,
		sandboxes:     sandboxes,
		exec:          exec,
		workspace:     cfg.OpenShellWorkspace,
		defaultImage:  cfg.OpenShellDefaultImage,
		defaultPreset: cfg.OpenShellDefaultPreset,
		execs:         make(map[string]*execState),
	}
}

func (b *Backend) GetDefaultImage() string { return b.defaultImage }

// RunContainer reads the preset from the "openshell.preset" label on container.Config.Labels; an empty or unknown label uses the default preset.
func (b *Backend) RunContainer(
	ctx context.Context,
	containerName string,
	containerType database.ContainerType,
	flowID int64,
	cfg *container.Config,
	_ *container.HostConfig,
) (database.Container, error) {
	if cfg == nil {
		return database.Container{}, fmt.Errorf("no config found for container %s", containerName)
	}

	image := cfg.Image
	if image == "" {
		image = b.defaultImage
	}

	preset := cfg.Labels["openshell.preset"]
	policy, ok := policyFor(preset, b.defaultPreset)
	if !ok {
		return database.Container{}, fmt.Errorf("unknown OpenShell preset %q for flow %d", preset, flowID)
	}

	logger := b.logger.WithContext(ctx).WithFields(logrus.Fields{
		"sandbox": containerName, "image": image, "preset": preset, "flow_id": flowID,
	})
	logger.Info("provisioning OpenShell sandbox")

	dbContainer, err := b.db.CreateContainer(ctx, database.CreateContainerParams{
		Type:    containerType,
		Name:    containerName,
		Image:   image,
		Status:  database.ContainerStatusStarting,
		FlowID:  flowID,
		LocalID: database.StringToNullString(containerName),
	})
	if err != nil {
		return database.Container{}, fmt.Errorf("failed to create container row: %w", err)
	}

	markFailed := func() {
		if _, uerr := b.db.UpdateContainerStatus(ctx, database.UpdateContainerStatusParams{
			Status: database.ContainerStatusFailed, ID: dbContainer.ID,
		}); uerr != nil {
			logger.WithError(uerr).Error("failed to mark the sandbox failed")
		}
	}

	spec := &v1.SandboxSpec{
		Template: &v1.SandboxTemplate{Image: image},
		Policy:   policy,
	}
	if _, err := b.sandboxes.Create(ctx, b.workspace, containerName, spec, nil); err != nil {
		markFailed()
		return database.Container{}, fmt.Errorf("failed to create OpenShell sandbox: %w", err)
	}
	if _, err := b.sandboxes.WaitReady(ctx, b.workspace, containerName); err != nil {
		markFailed()
		return database.Container{}, fmt.Errorf("OpenShell sandbox %q never became ready: %w", containerName, err)
	}

	updated, err := b.db.UpdateContainerStatusLocalID(ctx, database.UpdateContainerStatusLocalIDParams{
		Status:  database.ContainerStatusRunning,
		LocalID: database.StringToNullString(containerName),
		ID:      dbContainer.ID,
	})
	if err != nil {
		return database.Container{}, fmt.Errorf("failed to record the ready sandbox: %w", err)
	}

	logger.Info("OpenShell sandbox ready")

	return updated, nil
}

// StopContainer deletes the sandbox: OpenShell cannot suspend one, so the row is recorded as deleted rather than stopped to keep a later start from resuming a sandbox that is gone.
func (b *Backend) StopContainer(ctx context.Context, containerID string, dbID int64) error {
	return b.RemoveContainer(ctx, containerID, dbID)
}

func (b *Backend) RemoveContainer(ctx context.Context, containerID string, dbID int64) error {
	if _, err := b.sandboxes.Delete(ctx, b.workspace, containerID); err != nil && !isNotFound(err) {
		return fmt.Errorf("failed to remove OpenShell sandbox %q: %w", containerID, err)
	}
	if _, err := b.db.UpdateContainerStatus(ctx, database.UpdateContainerStatusParams{
		Status: database.ContainerStatusDeleted, ID: dbID,
	}); err != nil {
		return fmt.Errorf("failed to record the removed sandbox: %w", err)
	}
	return nil
}

func (b *Backend) IsContainerRunning(ctx context.Context, containerID string) (bool, error) {
	sandbox, err := b.sandboxes.Get(ctx, b.workspace, containerID)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to inspect OpenShell sandbox %q: %w", containerID, err)
	}
	return sandbox.Status.Phase == v1.SandboxReady, nil
}

// KillFlowCommands is a no-op: each exec is its own gateway call, so there is no background process to sweep.
func (b *Backend) KillFlowCommands(ctx context.Context, containerID string) error {
	return nil
}

func (b *Backend) ContainerExecCreate(ctx context.Context, containerName string, cfg client.ExecCreateOptions) (client.ExecCreateResult, error) {
	b.mx.Lock()
	defer b.mx.Unlock()

	b.seq++
	id := "osh-exec-" + strconv.FormatInt(b.seq, 10)
	b.execs[id] = &execState{
		sandbox: containerName,
		cmd:     cfg.Cmd,
		workdir: cfg.WorkingDir,
		env:     cfg.Env,
		tty:     cfg.TTY,
	}
	return client.ExecCreateResult{ID: id}, nil
}

// ContainerExecAttach returns output raw for a TTY exec and stdcopy-framed otherwise, as a real daemon streams it.
func (b *Backend) ContainerExecAttach(ctx context.Context, execID string, _ client.ExecAttachOptions) (client.HijackedResponse, error) {
	b.mx.Lock()
	state, ok := b.execs[execID]
	b.mx.Unlock()
	if !ok {
		return client.HijackedResponse{}, fmt.Errorf("unknown exec id %q", execID)
	}

	opts := v1.ExecOptions{WorkDir: state.workdir, NoLoginShell: true}
	if len(state.env) > 0 {
		opts.Env = make(map[string]string, len(state.env))
		for _, kv := range state.env {
			if k, v, found := strings.Cut(kv, "="); found {
				opts.Env[k] = v
			}
		}
	}

	result, err := b.exec.Run(ctx, b.workspace, state.sandbox, state.cmd, opts)
	if err != nil {
		b.mx.Lock()
		delete(b.execs, execID)
		b.mx.Unlock()
		return client.HijackedResponse{}, fmt.Errorf("OpenShell exec failed: %w", err)
	}

	b.mx.Lock()
	state.ran = true
	state.exitCode = result.ExitCode
	b.mx.Unlock()

	var buf bytes.Buffer
	if state.tty {
		buf.Write(result.Stdout)
		buf.Write(result.Stderr)
	} else {
		writeStdFrame(&buf, 1, result.Stdout)
		writeStdFrame(&buf, 2, result.Stderr)
	}

	return client.HijackedResponse{Conn: nopConn{}, Reader: bufio.NewReader(&buf)}, nil
}

// ContainerExecInspect forgets a finished exec: callers inspect each exec once, after reading its output.
func (b *Backend) ContainerExecInspect(ctx context.Context, execID string) (client.ExecInspectResult, error) {
	b.mx.Lock()
	defer b.mx.Unlock()

	state, ok := b.execs[execID]
	if !ok {
		return client.ExecInspectResult{}, fmt.Errorf("unknown exec id %q", execID)
	}
	if state.ran {
		delete(b.execs, execID)
	}
	return client.ExecInspectResult{ID: execID, ContainerID: state.sandbox, Running: !state.ran, ExitCode: state.exitCode}, nil
}

func (b *Backend) ContainerStatPath(ctx context.Context, containerID string, p string) (container.PathStat, error) {
	// %X-style escapes are portable across GNU and busybox coreutils.
	out, code, err := b.runGather(ctx, containerID, []string{"stat", "-c", "%s|%f|%Y|%n", p})
	if err != nil {
		return container.PathStat{}, err
	}
	if code != 0 {
		if strings.Contains(out, "No such file") {
			return container.PathStat{}, fmt.Errorf("stat %q in sandbox %q: %w", p, containerID, cerrdefs.ErrNotFound)
		}
		return container.PathStat{}, fmt.Errorf("stat %q failed in sandbox %q: %s", p, containerID, strings.TrimSpace(out))
	}
	return parseStat(strings.TrimSpace(out), p)
}

func (b *Backend) ListContainerDir(ctx context.Context, containerID string, dirPath string) (docker.ContainerDirListing, error) {
	if strings.TrimSpace(dirPath) == "" {
		dirPath = docker.WorkFolderPathInContainer
	}

	dirStat, err := b.ContainerStatPath(ctx, containerID, dirPath)
	if err != nil {
		return docker.ContainerDirListing{}, fmt.Errorf("failed to stat sandbox path %q: %w", dirPath, err)
	}
	if !dirStat.Mode.IsDir() {
		return docker.ContainerDirListing{}, fmt.Errorf("sandbox path %q is not a directory", dirPath)
	}

	out, code, err := b.runGather(ctx, containerID, []string{"find", dirPath, "-maxdepth", "1", "-mindepth", "1", "!", "-name", ".*"})
	if err != nil {
		return docker.ContainerDirListing{}, err
	}
	if code != 0 {
		return docker.ContainerDirListing{}, fmt.Errorf("listing %q failed in sandbox %q: %s", dirPath, containerID, strings.TrimSpace(out))
	}

	var listing docker.ContainerDirListing
	for _, entry := range strings.Split(out, "\n") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		stat, statErr := b.ContainerStatPath(ctx, containerID, entry)
		if statErr != nil {
			listing.Failures = append(listing.Failures, docker.ContainerEntryError{Name: path.Base(entry), Path: entry, Err: statErr})
			continue
		}
		listing.Files = append(listing.Files, stat)
	}
	return listing, nil
}

// File transfer runs tar over exec, base64-framed so binary content survives the gateway: the SDK's file client has no transport in this release, and tar also moves directories the way Docker's copy API does.
func (b *Backend) CopyToContainer(ctx context.Context, containerID, dstPath string, content io.Reader, _ client.CopyToContainerOptions) error {
	data, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("failed to read the upload tar: %w", err)
	}

	b.mx.Lock()
	b.seq++
	stage := "/tmp/.pentagi-upload-" + strconv.FormatInt(b.seq, 10)
	b.mx.Unlock()

	encoded := base64.StdEncoding.EncodeToString(data)
	defer func() {
		_, _, _ = b.runGather(context.WithoutCancel(ctx), containerID, []string{"rm", "-f", stage, stage + ".tar"})
	}()

	if out, code, err := b.runGather(ctx, containerID, []string{"mkdir", "-p", dstPath}); err != nil || code != 0 {
		return transferError("create "+dstPath, containerID, out, code, err)
	}
	for start := 0; start < len(encoded); start += transferChunk {
		chunk := encoded[start:min(start+transferChunk, len(encoded))]
		if out, code, err := b.runGather(ctx, containerID, []string{"sh", "-c", `printf %s "$1" >> "$2"`, "sh", chunk, stage}); err != nil || code != 0 {
			return transferError("stage the upload", containerID, out, code, err)
		}
	}
	script := `touch "$1" && base64 -d "$1" > "$1.tar" && tar -xf "$1.tar" -C "$2"`
	if out, code, err := b.runGather(ctx, containerID, []string{"sh", "-c", script, "sh", stage, dstPath}); err != nil || code != 0 {
		return transferError("extract the upload into "+dstPath, containerID, out, code, err)
	}
	return nil
}

func (b *Backend) CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error) {
	stat, err := b.ContainerStatPath(ctx, containerID, srcPath)
	if err != nil {
		return nil, container.PathStat{}, err
	}

	script := `tmp=$(mktemp) && tar -cf "$tmp" -C "$1" "$2" && base64 "$tmp" | tr -d '\n'; s=$?; rm -f "$tmp"; exit $s`
	result, err := b.exec.Run(ctx, b.workspace, containerID,
		[]string{"sh", "-c", script, "sh", path.Dir(srcPath), path.Base(srcPath)}, v1.ExecOptions{NoLoginShell: true})
	if err != nil {
		return nil, container.PathStat{}, fmt.Errorf("OpenShell exec failed in sandbox %q: %w", containerID, err)
	}
	if result.ExitCode != 0 {
		return nil, container.PathStat{}, transferError("archive "+srcPath, containerID, string(result.Stderr), result.ExitCode, nil)
	}

	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(result.Stdout)))
	if err != nil {
		return nil, container.PathStat{}, fmt.Errorf("failed to decode the archive of %q from sandbox %q: %w", srcPath, containerID, err)
	}
	return io.NopCloser(bytes.NewReader(data)), stat, nil
}

func transferError(what, sandbox, output string, code int, err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("failed to %s in sandbox %q (exit %d): %s", what, sandbox, code, strings.TrimSpace(output))
}

// Cleanup is a no-op: sandboxes are per-flow and deleted when the flow finishes.
func (b *Backend) Cleanup(ctx context.Context) error {
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}

func (b *Backend) runGather(ctx context.Context, sandbox string, cmd []string) (string, int, error) {
	result, err := b.exec.Run(ctx, b.workspace, sandbox, cmd, v1.ExecOptions{NoLoginShell: true})
	if err != nil {
		return "", 0, fmt.Errorf("OpenShell exec failed in sandbox %q: %w", sandbox, err)
	}
	var out strings.Builder
	out.Write(result.Stdout)
	out.Write(result.Stderr)
	return out.String(), result.ExitCode, nil
}

func parseStat(line, requestedPath string) (container.PathStat, error) {
	fields := strings.SplitN(line, "|", 4)
	if len(fields) < 3 {
		return container.PathStat{}, fmt.Errorf("unexpected stat output %q", line)
	}
	size, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return container.PathStat{}, fmt.Errorf("stat size %q: %w", fields[0], err)
	}
	raw, err := strconv.ParseUint(fields[1], 16, 32)
	if err != nil {
		return container.PathStat{}, fmt.Errorf("stat mode %q: %w", fields[1], err)
	}
	mtime, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return container.PathStat{}, fmt.Errorf("stat mtime %q: %w", fields[2], err)
	}
	name := path.Base(requestedPath)
	if len(fields) == 4 && fields[3] != "" {
		name = path.Base(fields[3])
	}
	return container.PathStat{Name: name, Size: size, Mode: statModeToFileMode(uint32(raw)), Mtime: time.Unix(mtime, 0)}, nil
}

func isNotFound(err error) bool {
	return v1.IsNotFound(err)
}

// writeStdFrame writes a Docker stdcopy frame: stream byte, 3 zero bytes, big-endian uint32 length, payload.
func writeStdFrame(buf *bytes.Buffer, stream byte, payload []byte) {
	if len(payload) == 0 {
		return
	}
	var header [8]byte
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	buf.Write(header[:])
	buf.Write(payload)
}

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(b []byte) (int, error)      { return len(b), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nopAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return nopAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

type nopAddr struct{}

func (nopAddr) Network() string { return "openshell" }
func (nopAddr) String() string  { return "openshell" }

// statModeToFileMode keeps the directory bit the Files tab uses to tell folders from files.
func statModeToFileMode(raw uint32) os.FileMode {
	mode := os.FileMode(raw & 0o777)
	switch raw & 0xf000 {
	case 0x4000: // S_IFDIR
		mode |= os.ModeDir
	case 0xa000: // S_IFLNK
		mode |= os.ModeSymlink
	case 0x1000: // S_IFIFO
		mode |= os.ModeNamedPipe
	case 0x2000: // S_IFCHR
		mode |= os.ModeCharDevice | os.ModeDevice
	case 0x6000: // S_IFBLK
		mode |= os.ModeDevice
	case 0xc000: // S_IFSOCK
		mode |= os.ModeSocket
	}
	return mode
}
