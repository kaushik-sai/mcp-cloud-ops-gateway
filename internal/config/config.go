// Package config loads the gateway's configuration file.
//
// The file holds no secrets: callers and approvers are listed by the SHA-256 of their token, and
// cloud credentials come from OIDC token files at run time. Unknown fields are rejected, so a
// typo fails at start-up instead of silently disabling a control.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole file.
type Config struct {
	Server      Server                `yaml:"server"`
	PolicyFile  string                `yaml:"policy_file"`
	Audit       Audit                 `yaml:"audit"`
	Approvals   Approvals             `yaml:"approvals"`
	Principals  []Principal           `yaml:"principals"`
	Approvers   []Approver            `yaml:"approvers"`
	Credentials map[string]Credential `yaml:"credentials"`
	Kubernetes  *Kubernetes           `yaml:"kubernetes,omitempty"`
	AWS         *AWS                  `yaml:"aws,omitempty"`
	Azure       *Azure                `yaml:"azure,omitempty"`
	Terraform   *Terraform            `yaml:"terraform,omitempty"`
	Limits      Limits                `yaml:"limits"`

	dir string
}

type Server struct {
	Name string `yaml:"name"`
	// HTTPListen is the MCP endpoint (streamable HTTP) for remote agents. Empty disables it.
	HTTPListen string `yaml:"http_listen"`
	// AdminListen serves the approval API. It must differ from HTTPListen.
	AdminListen string `yaml:"admin_listen"`
	// StdioPrincipal is the principal a stdio client acts as (the process that launched us).
	StdioPrincipal string `yaml:"stdio_principal"`
}

type Audit struct {
	File         string `yaml:"file"`
	MirrorStderr bool   `yaml:"mirror_stderr"`
}

type Approvals struct {
	PendingTTL time.Duration `yaml:"pending_ttl"`
	UseWindow  time.Duration `yaml:"use_window"`
	MaxPending int           `yaml:"max_pending_per_principal"`
}

// Principal is an agent identity: a policy profile and, for HTTP, a token hash.
type Principal struct {
	Name        string `yaml:"name"`
	Profile     string `yaml:"profile"`
	TokenSHA256 string `yaml:"token_sha256,omitempty"`
}

// Approver is a human who may decide approvals through the admin API.
type Approver struct {
	Name        string `yaml:"name"`
	TokenSHA256 string `yaml:"token_sha256"`
}

// Credential configures one provider. Type selects which fields apply.
type Credential struct {
	Type string `yaml:"type"` // none | kubeconfig | in_cluster | aws_web_identity | azure_federated

	// kubeconfig
	Path    string `yaml:"path,omitempty"`
	Context string `yaml:"context,omitempty"`

	// aws_web_identity and azure_federated
	TokenFile string `yaml:"token_file,omitempty"`

	// aws_web_identity
	RoleARN       string        `yaml:"role_arn,omitempty"`
	Region        string        `yaml:"region,omitempty"`
	Duration      time.Duration `yaml:"duration,omitempty"`
	SessionPolicy string        `yaml:"session_policy,omitempty"`
	STSEndpoint   string        `yaml:"sts_endpoint,omitempty"`

	// azure_federated
	TenantID  string `yaml:"tenant_id,omitempty"`
	ClientID  string `yaml:"client_id,omitempty"`
	Authority string `yaml:"authority,omitempty"`
}

// Group settings: which credential read tools and mutating tools use.
type Kubernetes struct {
	ReadCredential  string `yaml:"read_credential"`
	WriteCredential string `yaml:"write_credential"`
	Kubectl         string `yaml:"kubectl,omitempty"`
	MaxLogLines     int    `yaml:"max_log_lines,omitempty"`
}

type AWS struct {
	ReadCredential  string `yaml:"read_credential"`
	WriteCredential string `yaml:"write_credential"`
	CLI             string `yaml:"cli,omitempty"`
}

type Azure struct {
	ReadCredential  string            `yaml:"read_credential"`
	WriteCredential string            `yaml:"write_credential"`
	Subscriptions   map[string]string `yaml:"subscriptions"`
	ARMEndpoint     string            `yaml:"arm_endpoint,omitempty"`
}

type Terraform struct {
	Credential string            `yaml:"credential"`
	Binary     string            `yaml:"binary,omitempty"`
	Workspaces map[string]string `yaml:"workspaces"`
}

type Limits struct {
	CommandTimeout time.Duration `yaml:"command_timeout"`
	MaxOutputBytes int           `yaml:"max_output_bytes"`
}

// Load reads, defaults and validates a config file. Relative paths in it resolve against the
// file's directory.
func Load(file string) (*Config, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded, err := expandEnv(string(data))
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	c.dir = filepath.Dir(abs)
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// expandEnv replaces ${NAME} with the environment variable NAME, so one file serves every
// environment (dev, staging, prod) with only variables changing. An unset variable is an error,
// never an empty string; "$" not followed by "{" is left alone, and "$${" escapes a literal "${".
func expandEnv(s string) (string, error) {
	var missing []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("${")
			i += 2
			continue
		}
		if !strings.HasPrefix(s[i:], "${") {
			b.WriteByte(s[i])
			continue
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", errors.New("config: unclosed ${ in config file")
		}
		name := s[i+2 : i+end]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
		}
		b.WriteString(v)
		i += end
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("config: environment variables not set: %s", strings.Join(missing, ", "))
	}
	return b.String(), nil
}

// Path resolves p against the config file's directory, after expanding a leading "~/".
func (c *Config) Path(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

func (c *Config) defaults() {
	if c.Server.Name == "" {
		c.Server.Name = "mcp-cloud-ops-gateway"
	}
	if c.Server.AdminListen == "" {
		c.Server.AdminListen = "127.0.0.1:8081"
	}
	if c.Audit.File == "" {
		c.Audit.File = "audit.jsonl"
	}
	if c.Limits.CommandTimeout == 0 {
		c.Limits.CommandTimeout = 60 * time.Second
	}
	if c.Limits.MaxOutputBytes == 0 {
		c.Limits.MaxOutputBytes = 64 * 1024
	}
}

func (c *Config) validate() error {
	var errs []error
	if c.PolicyFile == "" {
		errs = append(errs, errors.New("policy_file is required"))
	}
	if c.Server.HTTPListen != "" && c.Server.HTTPListen == c.Server.AdminListen {
		errs = append(errs, errors.New("server.http_listen and server.admin_listen must differ"))
	}
	hashes := map[string]string{}
	names := map[string]bool{}
	addHash := func(owner, h string) {
		if h == "" {
			return
		}
		if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
			errs = append(errs, fmt.Errorf("%s: token_sha256 must be 64 hex characters", owner))
			return
		}
		h = strings.ToLower(h)
		if other, dup := hashes[h]; dup {
			errs = append(errs, fmt.Errorf("%s and %s share a token; every caller needs its own", owner, other))
		}
		hashes[h] = owner
	}
	for _, p := range c.Principals {
		owner := "principal " + p.Name
		if p.Name == "" || p.Profile == "" {
			errs = append(errs, fmt.Errorf("principals: name and profile are required (%q)", p.Name))
		}
		if names[p.Name] {
			errs = append(errs, fmt.Errorf("%s is listed twice", owner))
		}
		names[p.Name] = true
		addHash(owner, p.TokenSHA256)
	}
	for _, a := range c.Approvers {
		owner := "approver " + a.Name
		if a.Name == "" || a.TokenSHA256 == "" {
			errs = append(errs, fmt.Errorf("approvers: name and token_sha256 are required (%q)", a.Name))
		}
		if names[a.Name] {
			errs = append(errs, fmt.Errorf("%s has the same name as another principal or approver", owner))
		}
		names[a.Name] = true
		addHash(owner, a.TokenSHA256)
	}
	if c.Server.StdioPrincipal != "" && !c.hasPrincipal(c.Server.StdioPrincipal) {
		errs = append(errs, fmt.Errorf("server.stdio_principal %q is not in principals", c.Server.StdioPrincipal))
	}
	for name, cr := range c.Credentials {
		if err := cr.validate(); err != nil {
			errs = append(errs, fmt.Errorf("credential %s: %w", name, err))
		}
	}
	ref := func(where, name string) {
		if name == "" {
			errs = append(errs, fmt.Errorf("%s is required", where))
			return
		}
		if _, ok := c.Credentials[name]; !ok {
			errs = append(errs, fmt.Errorf("%s: unknown credential %q", where, name))
		}
	}
	if k := c.Kubernetes; k != nil {
		ref("kubernetes.read_credential", k.ReadCredential)
		ref("kubernetes.write_credential", k.WriteCredential)
	}
	if a := c.AWS; a != nil {
		ref("aws.read_credential", a.ReadCredential)
		ref("aws.write_credential", a.WriteCredential)
	}
	if z := c.Azure; z != nil {
		ref("azure.read_credential", z.ReadCredential)
		ref("azure.write_credential", z.WriteCredential)
		if len(z.Subscriptions) == 0 {
			errs = append(errs, errors.New("azure.subscriptions: at least one alias is required"))
		}
	}
	if t := c.Terraform; t != nil {
		ref("terraform.credential", t.Credential)
		if len(t.Workspaces) == 0 {
			errs = append(errs, errors.New("terraform.workspaces: at least one workspace is required"))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config: %w", errors.Join(errs...))
	}
	return nil
}

func (c *Config) hasPrincipal(name string) bool {
	for _, p := range c.Principals {
		if p.Name == name {
			return true
		}
	}
	return false
}

func (cr Credential) validate() error {
	switch cr.Type {
	case "none", "in_cluster":
	case "kubeconfig":
		if cr.Path == "" && cr.Context == "" {
			return errors.New("kubeconfig needs path or context")
		}
	case "aws_web_identity":
		if cr.RoleARN == "" || cr.TokenFile == "" || (cr.Region == "" && cr.STSEndpoint == "") {
			return errors.New("aws_web_identity needs role_arn, token_file and region (or sts_endpoint)")
		}
		if cr.Duration != 0 && (cr.Duration < 15*time.Minute || cr.Duration > 12*time.Hour) {
			return errors.New("aws_web_identity duration must be between 15m and 12h")
		}
	case "azure_federated":
		if cr.TenantID == "" || cr.ClientID == "" || cr.TokenFile == "" {
			return errors.New("azure_federated needs tenant_id, client_id and token_file")
		}
	default:
		return fmt.Errorf("unknown type %q", cr.Type)
	}
	return nil
}
