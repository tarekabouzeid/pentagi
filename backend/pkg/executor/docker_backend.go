package executor

import (
	"context"
	"io"

	"pentagi/pkg/docker"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

// DockerBackend adapts docker.DockerClient to the executor.Backend interface.
// This is a thin pass-through; all logic remains in terminal.go.
type DockerBackend struct {
	client docker.DockerClient
}

// NewDockerBackend creates a Backend that delegates to the given DockerClient.
func NewDockerBackend(client docker.DockerClient) Backend {
	return &DockerBackend{client: client}
}

func (d *DockerBackend) ContainerExecCreate(ctx context.Context, name string, config container.ExecOptions) (container.ExecCreateResponse, error) {
	return d.client.ContainerExecCreate(ctx, name, config)
}

func (d *DockerBackend) ContainerExecAttach(ctx context.Context, execID string, config container.ExecAttachOptions) (types.HijackedResponse, error) {
	return d.client.ContainerExecAttach(ctx, execID, config)
}

func (d *DockerBackend) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	return d.client.ContainerExecInspect(ctx, execID)
}

func (d *DockerBackend) CopyToContainer(ctx context.Context, containerID string, dstPath string, content io.Reader, options container.CopyToContainerOptions) error {
	return d.client.CopyToContainer(ctx, containerID, dstPath, content, options)
}

func (d *DockerBackend) CopyFromContainer(ctx context.Context, containerID string, srcPath string) (io.ReadCloser, container.PathStat, error) {
	return d.client.CopyFromContainer(ctx, containerID, srcPath)
}

func (d *DockerBackend) IsContainerRunning(ctx context.Context, containerID string) (bool, error) {
	return d.client.IsContainerRunning(ctx, containerID)
}

func (d *DockerBackend) GetDefaultImage() string {
	return d.client.GetDefaultImage()
}

