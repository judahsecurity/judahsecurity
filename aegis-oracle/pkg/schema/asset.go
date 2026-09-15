package schema

import (
	"strconv"
	"strings"
)

type Exposure string

const (
	ExposureInternet Exposure = "internet"
	ExposureInternal Exposure = "internal"
	ExposureIsolated Exposure = "isolated"
	ExposureUnknown  Exposure = "unknown"
)

type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
	CriticalityUnknown  Criticality = "unknown"
)

// Asset is the bot's view of a single asset from the host ASM platform.
// The ASM is the source of truth; adapters populate this from inventory.
type Asset struct {
	ID          string       `json:"asset_id"`
	TenantID    string       `json:"tenant_id,omitempty"`
	Hostname    string       `json:"hostname,omitempty"`
	IP          string       `json:"ip,omitempty"`
	OpenPorts   []int        `json:"open_ports,omitempty"`
	Signals     AssetSignals `json:"signals"`
	Criticality Criticality  `json:"criticality"`
	Exposure    Exposure     `json:"exposure"`
	Source      string       `json:"source"`
	UpdatedAt   FlexTime     `json:"updated_at"`
}

// AssetSignals is intentionally a flat bag with optional fields organized
// in tiers (Network/HTTP/TLS basic → tech stack → behavioral → deep).
// Phase B preconditions reference signal paths via dotted keys; missing =
// PreconditionUnknown. New tiers add new optional fields without breaking
// older signals.
type AssetSignals struct {
	Network *NetworkSignals `json:"network,omitempty"`
	HTTP    *HTTPSignals    `json:"http,omitempty"`
	TLS     *TLSSignals     `json:"tls,omitempty"`

	TechStack []TechComponent `json:"tech_stack,omitempty"`

	Auth *AuthSignals `json:"auth,omitempty"`
	// NetworkPosition captures the asset's role in the network topology —
	// specifically whether it is a high-value pivot target or credential store.
	// OPES criticality uses this to boost blast-radius scoring beyond the
	// flat Criticality enum when lateral movement risk is elevated.
	NetworkPosition *NetworkPositionSignals `json:"network_position,omitempty"`

	RuntimeFlags   map[string]string                `json:"runtime_flags,omitempty"`
	Container      *ContainerSignals                `json:"container,omitempty"`
	Tenant         *TenantSignals                   `json:"tenant,omitempty"`
	FS             *FSSignals                       `json:"fs,omitempty"`
	Components     []ComponentObservation           `json:"components,omitempty"`
	SignalEvidence map[string][]EvidenceObservation `json:"signal_evidence,omitempty"`

	Extra map[string]string `json:"extra,omitempty"`
}

type NetworkSignals struct {
	InternetFacing *bool  `json:"internet_facing,omitempty"`
	OpenPorts      []int  `json:"open_ports,omitempty"`
	WAF            string `json:"waf,omitempty"`
}

type HTTPSignals struct {
	Headers      map[string]string `json:"headers,omitempty"`
	ServerBanner string            `json:"server_banner,omitempty"`
}

type TLSSignals struct {
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
}

type TechComponent struct {
	Name       string  `json:"name"`
	Version    string  `json:"version,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type AuthSignals struct {
	Required *bool  `json:"required,omitempty"`
	Method   string `json:"method,omitempty"`
}

type ContainerSignals struct {
	StartupArgs []string `json:"startup_args,omitempty"`
	Image       string   `json:"image,omitempty"`
}

type TenantSignals struct {
	RunsUserCode *bool  `json:"runs_user_code,omitempty"`
	SandboxKind  string `json:"sandbox_kind,omitempty"`
}

type FSSignals struct {
	WritablePaths []string `json:"writable_paths,omitempty"`
}

// NetworkPositionSignals describes where an asset sits in the network topology
// and what lateral movement value it represents to an attacker. Populated by
// the ASM adapter from inventory/CMDB data.
type NetworkPositionSignals struct {
	// IsCredentialStore indicates this asset holds credentials, secrets, or
	// authentication material for other services — e.g. Active Directory,
	// LDAP, Vault, AWS IAM, a secrets manager, or an SSO provider. Compromising
	// it gives an attacker credentials usable across the environment.
	IsCredentialStore *bool `json:"is_credential_store,omitempty"`

	// IsPivotPoint indicates this asset has network access to multiple segments
	// or is multi-homed (e.g. a bastion, jump host, VPN concentrator, or
	// internal gateway). Compromising it gives an attacker a foothold from
	// which to reach otherwise-isolated subnets.
	IsPivotPoint *bool `json:"is_pivot_point,omitempty"`

	// AdjacentSegments lists the network segments or VLANs reachable directly
	// from this asset — populated from CMDB, firewall rules, or ASM network
	// graph. Used by the contextual evaluator to assess lateral movement radius.
	AdjacentSegments []string `json:"adjacent_segments,omitempty"`

	// IsEdgeNode indicates this asset is on the internet-facing perimeter
	// (e.g. a load balancer, API gateway, or edge proxy). Compromising it
	// often provides a foothold for internal reconnaissance.
	IsEdgeNode *bool `json:"is_edge_node,omitempty"`
}

// Lookup resolves a dotted signal path against the asset signals.
// Returns (value, true) when present, ("", false) when missing.
//
// Supported paths:
//
//	network.internet_facing | network.waf
//	auth.required | auth.method
//	tech_stack.<name> | tech_stack.<name>.version
//	runtime_flags.<key>
//	container.startup_args | container.image
//	tenant.runs_user_code | tenant.sandbox_kind
//	fs.writable_paths
//	extra.<key>
//
// New signals: extend the switch below alongside the corresponding struct
// field. Keep the canonical path list in sync with prompts/v1.go.
func (s AssetSignals) Lookup(path string) (string, bool) {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) < 2 {
		return "", false
	}
	head, tail := parts[0], parts[1]

	switch head {
	case "runtime_flags":
		if v, ok := s.RuntimeFlags[tail]; ok {
			return v, true
		}
	case "tenant":
		if s.Tenant == nil {
			return "", false
		}
		switch tail {
		case "runs_user_code":
			if s.Tenant.RunsUserCode != nil {
				return strconv.FormatBool(*s.Tenant.RunsUserCode), true
			}
		case "sandbox_kind":
			if s.Tenant.SandboxKind != "" {
				return s.Tenant.SandboxKind, true
			}
		}
	case "auth":
		if s.Auth == nil {
			return "", false
		}
		switch tail {
		case "required":
			if s.Auth.Required != nil {
				return strconv.FormatBool(*s.Auth.Required), true
			}
		case "method":
			if s.Auth.Method != "" {
				return s.Auth.Method, true
			}
		}
	case "network":
		if s.Network == nil {
			return "", false
		}
		switch tail {
		case "internet_facing":
			if s.Network.InternetFacing != nil {
				return strconv.FormatBool(*s.Network.InternetFacing), true
			}
		case "open_ports":
			if len(s.Network.OpenPorts) > 0 {
				parts := make([]string, 0, len(s.Network.OpenPorts))
				for _, p := range s.Network.OpenPorts {
					parts = append(parts, strconv.Itoa(p))
				}
				return strings.Join(parts, ","), true
			}
		case "waf":
			if s.Network.WAF != "" {
				return s.Network.WAF, true
			}
		}
	case "container":
		if s.Container == nil {
			return "", false
		}
		switch tail {
		case "startup_args":
			if len(s.Container.StartupArgs) > 0 {
				return strings.Join(s.Container.StartupArgs, " "), true
			}
		case "image":
			if s.Container.Image != "" {
				return s.Container.Image, true
			}
		}
	case "fs":
		if s.FS == nil {
			return "", false
		}
		if tail == "writable_paths" && len(s.FS.WritablePaths) > 0 {
			return strings.Join(s.FS.WritablePaths, ","), true
		}
	case "tech_stack":
		// Two valid forms: "tech_stack.<name>" → version, or
		// "tech_stack.<name>.version".
		name, sub, _ := strings.Cut(tail, ".")
		for _, t := range s.TechStack {
			if !strings.EqualFold(t.Name, name) {
				continue
			}
			if sub == "" || sub == "version" {
				if t.Version != "" {
					return t.Version, true
				}
			}
		}
	case "components":
		name, state, ok := strings.Cut(tail, ".")
		if !ok {
			return "", false
		}
		for _, component := range s.Components {
			if !strings.EqualFold(component.Name, name) {
				continue
			}
			var value *bool
			switch state {
			case "installed":
				value = component.Installed
			case "enabled":
				value = component.Enabled
			case "used":
				value = component.Used
			case "idle_on_demand":
				value = component.IdleOnDemand
			case "executing":
				value = component.Executing
			case "attacker_reachable":
				value = component.AttackerReachable
			}
			if value != nil {
				return strconv.FormatBool(*value), true
			}
		}
	case "network_position":
		if s.NetworkPosition == nil {
			return "", false
		}
		switch tail {
		case "is_credential_store":
			if s.NetworkPosition.IsCredentialStore != nil {
				return strconv.FormatBool(*s.NetworkPosition.IsCredentialStore), true
			}
		case "is_pivot_point":
			if s.NetworkPosition.IsPivotPoint != nil {
				return strconv.FormatBool(*s.NetworkPosition.IsPivotPoint), true
			}
		case "is_edge_node":
			if s.NetworkPosition.IsEdgeNode != nil {
				return strconv.FormatBool(*s.NetworkPosition.IsEdgeNode), true
			}
		case "adjacent_segments":
			if len(s.NetworkPosition.AdjacentSegments) > 0 {
				return strings.Join(s.NetworkPosition.AdjacentSegments, ","), true
			}
		}
	case "extra":
		if v, ok := s.Extra[tail]; ok {
			return v, true
		}
	}
	return "", false
}

// LookupWithEvidence returns the signal value together with observations that
// establish its provenance and freshness.
func (s AssetSignals) LookupWithEvidence(path string) (string, []EvidenceObservation, bool) {
	value, ok := s.Lookup(path)
	if !ok {
		return "", s.SignalEvidence[path], false
	}
	evidence := append([]EvidenceObservation(nil), s.SignalEvidence[path]...)
	if strings.HasPrefix(path, "components.") {
		parts := strings.Split(path, ".")
		if len(parts) >= 3 {
			for _, component := range s.Components {
				if strings.EqualFold(component.Name, parts[1]) {
					for _, observation := range component.Evidence {
						if observation.SignalPath == path {
							evidence = append(evidence, observation)
						}
					}
				}
			}
		}
	}
	return value, evidence, true
}
