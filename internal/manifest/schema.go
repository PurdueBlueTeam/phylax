package manifest

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Schemas returns the JSON Schema (draft 2020-12) of every manifest file,
// generated from the Go types so the two cannot drift. Keys are file names.
// Structs are closed (additionalProperties: false), matching the loader's
// strict decoding.
func Schemas() map[string]map[string]any {
	wrap := func(title, key string, elem reflect.Type) map[string]any {
		return rootSchema(title, map[string]any{
			"type": "object", "additionalProperties": false,
			"properties": map[string]any{key: typeSchema(elem)},
			"required":   []string{key},
		})
	}
	mapOf := func(t reflect.Type) reflect.Type { return reflect.MapOf(reflect.TypeOf(""), t) }
	return map[string]map[string]any{
		FileTopology:     rootSchema("Phylax topology.yml", typeSchema(reflect.TypeOf(Topology{}))),
		FileHosts:        wrap("Phylax hosts.yml", "hosts", mapOf(reflect.TypeOf(Host{}))),
		FileServices:     wrap("Phylax services.yml", "services", mapOf(reflect.TypeOf(Service{}))),
		FileAccounts:     wrap("Phylax accounts.yml", "accounts", mapOf(reflect.TypeOf(Account{}))),
		FileScorer:       wrap("Phylax scorer.yml", "scorer", reflect.TypeOf(Scorer{})),
		FileDevices:      wrap("Phylax devices.yml", "devices", mapOf(reflect.TypeOf(Device{}))),
		FileDecoys:       wrap("Phylax decoys.yml", "decoys", mapOf(reflect.TypeOf(HostDecoys{}))),
		FileIntegrations: wrap("Phylax integrations.yml", "integrations", mapOf(reflect.TypeOf(Integration{}))),
		FilePolicy:       wrap("Phylax policy.yml", "policy", reflect.TypeOf(Policy{})),
		FileOverrides:    wrap("Phylax overrides.yml", "overrides", reflect.TypeOf(Overrides{})),
	}
}

// MarshalSchema renders a schema as indented JSON with a trailing newline.
func MarshalSchema(s map[string]any) ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func rootSchema(title string, body map[string]any) map[string]any {
	out := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title":   title,
	}
	for k, v := range body {
		out[k] = v
	}
	return out
}

// enums maps "Type.yamlField" to the allowed values.
var enums = map[string][]string{
	"OS.family":            {"debian", "rhel", "suse", "arch", "alpine", "windows"},
	"Host.class":           {"server", "workstation"},
	"Host.roles":           validRoles, // applied to items
	"Service.kind":         validKinds,
	"Service.state":        {"running", "stopped", "disabled"},
	"Listener.proto":       {"tcp", "udp"},
	"Dependency.proto":     {"tcp", "udp"},
	"EgressAllow.proto":    {"tcp", "udp"},
	"Transport.starttls":   {"never", "optional", "required"},
	"Transport.auth":       {"password", "ntlm", "key", "none"},
	"Transport.encryption": {"none", "optional", "required"},
	"Account.scope":        {"local", "domain", "service", "device"},
	"Account.rotation":     {"pcr_transaction", "free", "manual"},
	"Account.ssh_auth":     {"password", "both", "key_only"},
	"Scorer.engine":        {"quotient"},
	"Scorer.poll_portal":   {"off", "ask_organizers", "operator_paste", "cookie_poll"},
	"Device.vendor":        {"panos", "vyos", "ftd"},
	"NAT.mode":             {"static_1to1_same_octet"},
	"ControllerPath.via":   {"static_nat"},
	"HostDecoys.exposure":  {"lan", "public", "both"},
	"Honeytoken.kind":      {"ssh_key", "db_cred", "shell_history", "passwords_file", "browser_cred", "aws_key", "honey_file", "ad_spn", "ad_asrep", "ad_admin"},
	"DecoyListener.kind":   {"ssh", "mysql", "redis", "telnet", "winrm", "rdp", "http_admin", "smb"},
	"Hardening.ntlm":       {"allow", "deny"},
	"Hardening.icmp_echo":  {"allow", "drop"},
	"FirewallPolicy.icmp":  {"allow", "drop"},
	"FirewallPolicy.dhcp":  {"allow", "drop"},
	"FirewallPolicy.ipv6":  {"allow", "drop"},
}

// patterns maps "Type.yamlField" to a regular expression (applied to items
// for arrays).
var patterns = map[string]string{
	"Listener.port_range":     portRangePattern,
	"Dependency.port_ranges":  portRangePattern,
	"EgressAllow.port_ranges": portRangePattern,
	"Host.rpc_range":          portRangePattern,
	"Host.domain_member":      `^.+$`,
}

const portRangePattern = `^[0-9]{1,5}(-[0-9]{1,5})?$`

var (
	scoredType     = reflect.TypeOf(Scored(""))
	durationType   = reflect.TypeOf(Duration{})
	stringListType = reflect.TypeOf(StringList(nil))
)

func typeSchema(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t {
	case scoredType:
		return map[string]any{"enum": []any{true, false, "unknown"}}
	case durationType:
		return map[string]any{"type": "string", "pattern": `^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`}
	case stringListType:
		return map[string]any{"oneOf": []any{
			map[string]any{"type": "string"},
			map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}}
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Uint16:
		return map[string]any{"type": "integer", "minimum": 0, "maximum": 65535}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": typeSchema(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": typeSchema(t.Elem())}
	case reflect.Struct:
		props := map[string]any{}
		var required []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "" || name == "-" {
				continue
			}
			s := typeSchema(f.Type)
			if vals, ok := enums[t.Name()+"."+name]; ok {
				if s["type"] == "array" {
					s["items"] = map[string]any{"type": "string", "enum": vals}
				} else {
					s["enum"] = vals
				}
			}
			if pat, ok := patterns[t.Name()+"."+name]; ok {
				if s["type"] == "array" {
					s["items"] = map[string]any{"type": "string", "pattern": pat}
				} else {
					s["pattern"] = pat
				}
			}
			props[name] = s
			if !strings.Contains(opts, "omitempty") {
				required = append(required, name)
			}
		}
		out := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
		if len(required) > 0 {
			out["required"] = required
		}
		return out
	}
	panic(fmt.Sprintf("manifest schema: unsupported type %s", t))
}
