package executor

import (
	"context"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

// Backend defines the minimal interface for running commands and managing files
// inside an isolated execution environment (container, sandbox, or remote shell).
//
// Implementations:
//   - DockerBackend (default): wraps docker.DockerClient, delegates to Docker Engine API
//   - OpenShellBackend (planned): NVIDIA OpenShell policy-governed sandbox
//   - K8sSandboxBackend (planned): kubernetes-sigs/agent-sandbox CRD
//
// The interface mirrors the Docker exec/copy API surface used by terminal.go so that
// the existing tool logic (timeout, detach, tar, logging) remains untouched.
type Backend interface {
	// ContainerExecCreate creates a new exec configuration in the environment.
	ContainerExecCreate(ctx context.Context, name string, config container.ExecOptions) (container.ExecCreateResponse, error)

	// ContainerExecAttach connects to an exec process to stream stdin/stdout/stderr.
	ContainerExecAttach(ctx context.Context, execID string, config container.ExecAttachOptions) (types.HijackedResponse, error)

	// ContainerExecInspect returns the exit status of an exec process.
	ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error)

	// CopyToContainer writes a tar archive into the environment at dstPath.
	CopyToContainer(ctx context.Context, containerID string, dstPath string, content io.Reader, options container.CopyToContainerOptions) error

	// CopyFromContainer reads a tar archive of srcPath from the environment.
	CopyFromContainer(ctx context.Context, containerID string, srcPath string) (io.ReadCloser, container.PathStat, error)

	// IsContainerRunning reports whether the execution environment is operational.
	IsContainerRunning(ctx context.Context, containerID string) (bool, error)

	// GetDefaultImage returns the default container/sandbox image for provisioning.
	GetDefaultImage() string
}

// LifecycleManager handles provisioning and teardown of execution environments.
// Separated from Backend because the terminal tool only needs Backend,
// while the flow-level orchestrator manages the lifecycle.
type LifecycleManager interface {
	// RunContainer creates and starts a new execution environment.
	RunContainer(ctx context.Context, containerName string, containerType interface{},
		flowID int64, config *container.Config, hostConfig *container.HostConfig) (EnvironmentInfo, error)

	// StopContainer halts the execution environment.
	StopContainer(ctx context.Context, containerID string, dbID int64) error

	// RemoveContainer destroys the execution environment and cleans up resources.
	RemoveContainer(ctx context.Context, containerID string, dbID int64) error

	// Cleanup removes all environments managed by this lifecycle manager.
	Cleanup(ctx context.Context) error
}

// EnvironmentInfo is returned by RunContainer with identifiers for the new environment.
type EnvironmentInfo struct {
	ID      int64  // database row ID
	LocalID string // runtime identifier (container ID, sandbox name, etc.)
}
