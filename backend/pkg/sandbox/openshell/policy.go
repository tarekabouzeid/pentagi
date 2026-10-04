package openshell

import (
	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// Preset is a named sandbox security policy an operator can pick per flow.
// The presets intentionally mirror common pentest postures; the names are what
// a flow stores in its sandbox profile.
type Preset struct {
	Name        string
	Description string
	Policy      *types.SandboxPolicy
}

// presets are the built-in policies. web_pentest is the default: full network
// egress and writable scratch space for an authorized engagement. recon_only
// withholds mail ports. binary_analysis cuts off the network entirely for
// malware work.
var presets = map[string]Preset{
	"web_pentest": {
		Name:        "web_pentest",
		Description: "Full web pentest: outbound network, writable scratch in /tmp, /home and /work",
		Policy: &types.SandboxPolicy{
			Filesystem: &types.FilesystemPolicy{
				IncludeWorkdir: true,
				ReadOnly:       []string{"/"},
				ReadWrite:      []string{"/tmp", "/home", "/var/tmp", "/work"},
			},
			NetworkPolicies: map[string]types.NetworkPolicyRule{
				"egress": {
					Name: "egress",
					Endpoints: []types.PolicyNetworkEndpoint{
						{Host: "*", Access: types.NetworkAccessPresetFull},
					},
				},
			},
		},
	},
	"recon_only": {
		Name:        "recon_only",
		Description: "Reconnaissance only: outbound network except mail ports, limited writable scratch",
		Policy: &types.SandboxPolicy{
			Filesystem: &types.FilesystemPolicy{
				IncludeWorkdir: true,
				ReadOnly:       []string{"/"},
				ReadWrite:      []string{"/tmp", "/work"},
			},
			NetworkPolicies: map[string]types.NetworkPolicyRule{
				"egress": {
					Name: "egress",
					Endpoints: []types.PolicyNetworkEndpoint{
						{Host: "*", Access: types.NetworkAccessPresetReadOnly},
					},
				},
			},
		},
	},
	"binary_analysis": {
		Name:        "binary_analysis",
		Description: "Binary and malware analysis: no network, isolated writable scratch",
		Policy: &types.SandboxPolicy{
			Filesystem: &types.FilesystemPolicy{
				IncludeWorkdir: true,
				ReadOnly:       []string{"/"},
				ReadWrite:      []string{"/tmp", "/work"},
			},
			// No NetworkPolicies: nothing is admitted, so egress is denied.
		},
	},
}

// Presets lists the built-in preset names.
func Presets() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	return names
}

// policyFor returns the policy of a preset, falling back to the given default
// preset when name is empty, and reporting whether the name was known.
func policyFor(name, fallback string) (*types.SandboxPolicy, bool) {
	if name == "" {
		name = fallback
	}
	preset, ok := presets[name]
	if !ok {
		return nil, false
	}
	return preset.Policy, true
}

var _ = v1.SandboxReady
