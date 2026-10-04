// Package openshell adapts an NVIDIA OpenShell gateway to the
// docker.DockerClient surface PentAGI's tools are written against, so a flow
// can run its tools in an OpenShell sandbox instead of a Docker container with
// no change to the terminal, file or flow-file code.
//
// OpenShell addresses a sandbox by (workspace, name) over gRPC; this adapter
// maps PentAGI's container name 1:1 to a sandbox name in a fixed workspace, and
// bridges Docker's exec create/attach/inspect split onto OpenShell's single
// streaming exec by keeping per-exec state here.
package openshell

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
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
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"
)

// sandboxAPI, execAPI and fileAPI are the slices of the OpenShell SDK this
// backend uses. They are interfaces so a test can supply fakes; the SDK's
// concrete clients satisfy them.
type sandboxAPI interface {
	Create(ctx context.Context, workspace, name string, spec *v1.SandboxSpec, labels map[string]string, opts ...v1.CreateOptions) (*v1.Sandbox, error)
	Get(ctx context.Context, workspace, name string) (*v1.Sandbox, error)
	Delete(ctx context.Context, workspace, name string, opts ...v1.DeleteOptions) (*v1.DeletionResult, error)
	WaitReady(ctx context.Context, workspace, name string, opts ...v1.WaitOptions) (*v1.Sandbox, error)
}

type execAPI interface {
	Run(ctx context.Context, workspace, sandboxName string, command []string, opts ...v1.ExecOptions) (*v1.ExecResult, error)
}

type fileAPI interface {
	Upload(ctx context.Context, workspace, sandboxName, localPath, remotePath string) error
	Download(ctx context.Context, workspace, sandboxName, remotePath, localPath string) error
}

// Backend is an OpenShell-backed docker.DockerClient.
type Backend struct {
	db        database.Querier
	logger    *logrus.Entry
	closer    io.Closer
	sandboxes sandboxAPI
	exec      execAPI
	files     fileAPI

	workspace     string
	defaultImage  string
	defaultPreset string

	mx    sync.Mutex
	execs map[string]*execState
	seq   int64
}

// execState holds a created-but-not-run exec until it is attached, then its
// exit code until it is inspected.
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

// New dials the gateway in cfg and returns a Backend. It fails closed: a
// gateway that cannot be reached, or a default preset that is not built in,
// stops startup rather than silently falling back to Docker.
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

	return newBackend(db, cfg, client.Sandboxes(), client.Exec(), client.Files(), client), nil
}

// newBackend builds a Backend from already-resolved SDK slices. The exported
// New wires the real client; tests wire fakes.
func newBackend(db database.Querier, cfg *config.Config, sandboxes sandboxAPI, exec execAPI, files fileAPI, closer io.Closer) *Backend {
	return &Backend{
		db:            db,
		logger:        logrus.WithField("component", "openshell"),
		closer:        closer,
		sandboxes:     sandboxes,
		exec:          exec,
		files:         files,
		workspace:     cfg.OpenShellWorkspace,
		defaultImage:  cfg.OpenShellDefaultImage,
		defaultPreset: cfg.OpenShellDefaultPreset,
		execs:         make(map[string]*execState),
	}
}

func (b *Backend) GetDefaultImage() string { return b.defaultImage }

// RunContainer provisions a sandbox for the flow. The preset comes from the
// flow's sandbox profile, carried here on container.Config.Labels under
// "openshell.preset"; an empty or unknown label falls back to the configured
// default preset.
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

func (b *Backend) StopContainer(ctx context.Context, containerID string, dbID int64) error {
	if _, err := b.sandboxes.Delete(ctx, b.workspace, containerID); err != nil && !isNotFound(err) {
		return fmt.Errorf("failed to stop OpenShell sandbox %q: %w", containerID, err)
	}
	if _, err := b.db.UpdateContainerStatus(ctx, database.UpdateContainerStatusParams{
		Status: database.ContainerStatusStopped, ID: dbID,
	}); err != nil {
		return fmt.Errorf("failed to record the stopped sandbox: %w", err)
	}
	return nil
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

// KillFlowCommands has no OpenShell equivalent: each exec is its own gateway
// call with no shared background process to sweep, so a finished Run leaves
// nothing to kill. It is a no-op rather than an error so flow teardown and the
// terminal's stop path behave the same as on Docker.
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

// ContainerExecAttach runs the created command to completion and returns its
// output as a stream shaped like Docker's: raw when the exec requested a TTY,
// stdcopy-framed otherwise, so the existing demux and plain-read callers both
// behave as they do against a real daemon.
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

func (b *Backend) ContainerExecInspect(ctx context.Context, execID string) (client.ExecInspectResult, error) {
	b.mx.Lock()
	defer b.mx.Unlock()

	state, ok := b.execs[execID]
	if !ok {
		return client.ExecInspectResult{}, fmt.Errorf("unknown exec id %q", execID)
	}
	return client.ExecInspectResult{ID: execID, ContainerID: state.sandbox, Running: !state.ran, ExitCode: state.exitCode}, nil
}

func (b *Backend) ContainerStatPath(ctx context.Context, containerID string, p string) (container.PathStat, error) {
	// `stat -c <fmt>` prints size, octal mode and mtime; %X-style escapes are
	// portable across GNU and busybox coreutils.
	out, code, err := b.runGather(ctx, containerID, []string{"stat", "-c", "%s|%f|%Y|%n", p})
	if err != nil {
		return container.PathStat{}, err
	}
	if code != 0 {
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

// CopyToContainer untars content and uploads each regular file under dstPath,
// so a terminal WriteFile (a one-file tar) and a flow-file sync (many files)
// both land where Docker would put them.
func (b *Backend) CopyToContainer(ctx context.Context, containerID, dstPath string, content io.Reader, _ client.CopyToContainerOptions) error {
	tr := tar.NewReader(content)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read the upload tar: %w", err)
		}
		if header.FileInfo().IsDir() {
			continue
		}

		tmp, err := os.CreateTemp("", "osh-upload-*")
		if err != nil {
			return fmt.Errorf("failed to stage an upload: %w", err)
		}
		_, copyErr := io.Copy(tmp, tr)
		closeErr := tmp.Close()
		if copyErr != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("failed to stage an upload: %w", copyErr)
		}
		if closeErr != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("failed to stage an upload: %w", closeErr)
		}

		remote := path.Join(dstPath, header.Name)
		uploadErr := b.files.Upload(ctx, b.workspace, containerID, tmp.Name(), remote)
		os.Remove(tmp.Name())
		if uploadErr != nil {
			return fmt.Errorf("failed to upload %q to sandbox %q: %w", remote, containerID, uploadErr)
		}
	}
}

// CopyFromContainer downloads srcPath and returns it as a single-entry tar,
// the shape the terminal's reader expects from Docker.
func (b *Backend) CopyFromContainer(ctx context.Context, containerID, srcPath string) (io.ReadCloser, container.PathStat, error) {
	tmp, err := os.CreateTemp("", "osh-download-*")
	if err != nil {
		return nil, container.PathStat{}, fmt.Errorf("failed to stage a download: %w", err)
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)

	if err := b.files.Download(ctx, b.workspace, containerID, srcPath, tmpName); err != nil {
		return nil, container.PathStat{}, fmt.Errorf("failed to download %q from sandbox %q: %w", srcPath, containerID, err)
	}

	data, err := os.ReadFile(tmpName)
	if err != nil {
		return nil, container.PathStat{}, fmt.Errorf("failed to read the downloaded file: %w", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	name := path.Base(srcPath)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		return nil, container.PathStat{}, fmt.Errorf("failed to tar the downloaded file: %w", err)
	}
	if _, err := tw.Write(data); err != nil {
		return nil, container.PathStat{}, fmt.Errorf("failed to tar the downloaded file: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, container.PathStat{}, fmt.Errorf("failed to close the download tar: %w", err)
	}

	stat := container.PathStat{Name: name, Size: int64(len(data)), Mode: 0o644, Mtime: time.Now()}
	return io.NopCloser(&buf), stat, nil
}

// Cleanup is a no-op: OpenShell sandboxes are per-flow and are deleted when the
// flow finishes, so there is no process-wide pool to sweep on shutdown.
func (b *Backend) Cleanup(ctx context.Context) error {
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}

// runGather runs a command and returns its combined output and exit code. It is
// used by stat and list, which need the text rather than a stream.
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

// parseStat parses "size|hexmode|mtime|name" from `stat -c`.
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

// writeStdFrame writes one Docker stdcopy frame: stream byte, three zero bytes,
// a big-endian uint32 length, then the payload. demuxExecStdout reads these.
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

// nopConn is a net.Conn that backs a HijackedResponse whose data already lives
// in its Reader; only Close is ever called, by HijackedResponse.Close.
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

var _ = types.SandboxPolicy{}

// statModeToFileMode maps the low 16 bits of a stat() st_mode (as `stat -c %f`
// prints in hex) to Go's os.FileMode, carrying the directory bit the Files tab
// relies on to tell a folder from a file.
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
