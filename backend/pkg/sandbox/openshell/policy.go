package openshell

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

type Preset struct {
	Name        string
	Description string
	Policy      *types.SandboxPolicy
}

// web_pentest is the default; recon_only withholds mail ports; binary_analysis has no network.
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
		},
	},
}

func Presets() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	return names
}

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
