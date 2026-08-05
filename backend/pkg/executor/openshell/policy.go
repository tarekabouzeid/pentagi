package openshell

// PolicyPreset defines a named security policy for an OpenShell sandbox.
type PolicyPreset struct {
	Name        string
	Description string
	YAML        string
}

// Presets contains the built-in policy presets for common pentesting scenarios.
var Presets = map[string]PolicyPreset{
	"web_pentest": {
		Name:        "web_pentest",
		Description: "Full web penetration testing with network access, common pentest tools, and filesystem write in /tmp and /home",
		YAML: `version: "1"
name: web_pentest
description: Web penetration testing sandbox policy

filesystem:
  allow_read:
    - /
  allow_write:
    - /tmp
    - /home
    - /var/tmp
    - /opt
  deny:
    - /etc/shadow
    - /etc/gshadow
    - /proc/kcore

network:
  allow_outbound: true
  allow_inbound: false
  blocked_ports: []

processes:
  allow_all: true
  max_processes: 256

resources:
  max_memory_mb: 4096
  max_cpu_percent: 80
  max_disk_mb: 10240
`,
	},
	"recon_only": {
		Name:        "recon_only",
		Description: "Reconnaissance only: network scanning and information gathering, limited write access",
		YAML: `version: "1"
name: recon_only
description: Reconnaissance-only sandbox policy

filesystem:
  allow_read:
    - /
  allow_write:
    - /tmp
    - /home/agent
  deny:
    - /etc/shadow
    - /etc/gshadow
    - /proc/kcore

network:
  allow_outbound: true
  allow_inbound: false
  blocked_ports:
    - 25
    - 587

processes:
  allow_all: true
  max_processes: 128

resources:
  max_memory_mb: 2048
  max_cpu_percent: 50
  max_disk_mb: 2048
`,
	},
	"binary_analysis": {
		Name:        "binary_analysis",
		Description: "Binary and malware analysis: no network access, isolated filesystem",
		YAML: `version: "1"
name: binary_analysis
description: Binary analysis sandbox policy - network isolated

filesystem:
  allow_read:
    - /
  allow_write:
    - /tmp
    - /home/agent
    - /opt/analysis
  deny:
    - /etc/shadow
    - /etc/gshadow
    - /proc/kcore

network:
  allow_outbound: false
  allow_inbound: false
  blocked_ports: []

processes:
  allow_all: true
  max_processes: 64

resources:
  max_memory_mb: 8192
  max_cpu_percent: 90
  max_disk_mb: 20480
`,
	},
}
