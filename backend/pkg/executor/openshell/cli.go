package openshell

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CLI wraps the openshell command-line tool for sandbox lifecycle management.
type CLI struct {
	binPath string
	host    string
}

// NewCLI creates a CLI wrapper for the openshell binary.
func NewCLI(binPath, host string) *CLI {
	return &CLI{
		binPath: binPath,
		host:    host,
	}
}

// SandboxInfo represents the parsed output of a sandbox list/inspect operation.
type SandboxInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

// CreateSandbox creates a new sandbox with the given name and preset policy.
func (c *CLI) CreateSandbox(ctx context.Context, name, preset string) (*SandboxInfo, error) {
	args := []string{"sandbox", "create", "--name", name}
	if preset != "" {
		args = append(args, "--preset", preset)
	}
	if c.host != "" {
		args = append(args, "--host", c.host)
	}
	args = append(args, "--output", "json")

	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox %q: %w", name, err)
	}

	var info SandboxInfo
	if err := json.Unmarshal(out, &info); err != nil {
		// If JSON parsing fails, the CLI may not support --output json for create.
		// Try to parse the output as a simple success message.
		info.Name = name
		info.Status = "running"
	}

	return &info, nil
}

// DeleteSandbox destroys the sandbox with the given name.
func (c *CLI) DeleteSandbox(ctx context.Context, name string) error {
	args := []string{"sandbox", "delete", "--name", name}
	if c.host != "" {
		args = append(args, "--host", c.host)
	}

	_, err := c.run(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to delete sandbox %q: %w", name, err)
	}

	return nil
}

// ListSandboxes returns all sandboxes on the host.
func (c *CLI) ListSandboxes(ctx context.Context) ([]SandboxInfo, error) {
	args := []string{"sandbox", "list", "--output", "json"}
	if c.host != "" {
		args = append(args, "--host", c.host)
	}

	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list sandboxes: %w", err)
	}

	var sandboxes []SandboxInfo
	if err := json.Unmarshal(out, &sandboxes); err != nil {
		return nil, fmt.Errorf("failed to parse sandbox list: %w", err)
	}

	return sandboxes, nil
}

// InspectSandbox returns info about a specific sandbox.
func (c *CLI) InspectSandbox(ctx context.Context, name string) (*SandboxInfo, error) {
	sandboxes, err := c.ListSandboxes(ctx)
	if err != nil {
		return nil, err
	}

	for i := range sandboxes {
		if sandboxes[i].Name == name {
			return &sandboxes[i], nil
		}
	}

	return nil, fmt.Errorf("sandbox %q not found", name)
}

// SetPolicy applies a policy YAML file to the sandbox.
func (c *CLI) SetPolicy(ctx context.Context, name, policyPath string) error {
	args := []string{"policy", "set", "--sandbox", name, "--file", policyPath}
	if c.host != "" {
		args = append(args, "--host", c.host)
	}

	_, err := c.run(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to set policy on sandbox %q: %w", name, err)
	}

	return nil
}

func (c *CLI) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.binPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return nil, fmt.Errorf("%s: %s", strings.Join(append([]string{c.binPath}, args...), " "), errMsg)
	}

	return stdout.Bytes(), nil
}
