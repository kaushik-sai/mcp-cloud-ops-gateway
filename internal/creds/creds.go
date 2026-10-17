// Package creds gives each tool call short-lived, narrowly scoped cloud credentials.
//
// The gateway holds no long-lived cloud keys. It holds an OIDC token from its platform (a
// Kubernetes projected service-account token, or the GitHub Actions OIDC token) and exchanges it
// for credentials that last minutes: AWS STS AssumeRoleWithWebIdentity, or an Entra ID access
// token through workload identity federation. Each tool names the provider it uses, so read tools
// can run under a reader role and mutating tools under a separate operator role. Credentials go to
// the CLI through its environment or to the HTTP client as a header; the agent never sees them.
package creds

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Lease is what a tool needs to act under a provider's identity.
type Lease struct {
	// Env is added to the CLI's environment.
	Env map[string]string
	// KubeContext, when set, is passed to kubectl as --context.
	KubeContext string
	// Bearer, when set, is sent as the Authorization header of REST calls (Azure Resource Manager).
	Bearer string
	// Expires is when the credentials stop working; zero for credentials that do not expire.
	Expires time.Time
}

// Provider issues leases.
type Provider interface {
	Lease(ctx context.Context) (Lease, error)
}

// HTTPDoer is the subset of *http.Client the token exchanges use, so tests can fake it.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// refreshBefore is how long before expiry a cached credential is replaced.
const refreshBefore = 2 * time.Minute

// None gives an empty lease, for tools that need no credentials.
type None struct{}

func (None) Lease(context.Context) (Lease, error) { return Lease{}, nil }

// Kubeconfig points kubectl at a kubeconfig file and context. Use it for local clusters (kind)
// and for development. In production prefer InCluster.
type Kubeconfig struct {
	Path    string
	Context string
}

func (k Kubeconfig) Lease(context.Context) (Lease, error) {
	env := map[string]string{}
	if k.Path != "" {
		env["KUBECONFIG"] = k.Path
	}
	return Lease{Env: env, KubeContext: k.Context}, nil
}

// InCluster lets kubectl use the pod's service account. kubectl finds it through the
// KUBERNETES_SERVICE_HOST and _PORT variables, which the runner does not pass by default, so this
// provider forwards them.
type InCluster struct {
	Getenv func(string) string
}

func (k InCluster) Lease(context.Context) (Lease, error) {
	get := k.Getenv
	if get == nil {
		get = os.Getenv
	}
	host, port := get("KUBERNETES_SERVICE_HOST"), get("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Lease{}, errors.New("in_cluster: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set; is the gateway running in a pod?")
	}
	return Lease{Env: map[string]string{"KUBERNETES_SERVICE_HOST": host, "KUBERNETES_SERVICE_PORT": port}}, nil
}

// cache holds one lease until shortly before it expires.
type cache struct {
	mu    sync.Mutex
	lease Lease
	now   func() time.Time
}

func (c *cache) get(ctx context.Context, fetch func(context.Context) (Lease, error)) (Lease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if !c.lease.Expires.IsZero() && now().Add(refreshBefore).Before(c.lease.Expires) {
		return c.lease, nil
	}
	l, err := fetch(ctx)
	if err != nil {
		return Lease{}, err
	}
	c.lease = l
	return l, nil
}

func readToken(file string) (string, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied path to the platform's OIDC token
	if err != nil {
		return "", fmt.Errorf("read OIDC token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("OIDC token file %s is empty", file)
	}
	return tok, nil
}

// AWSWebIdentity exchanges the platform's OIDC token for temporary AWS credentials with
// sts:AssumeRoleWithWebIdentity. The call is unsigned by design: the OIDC token is the proof.
type AWSWebIdentity struct {
	RoleARN     string
	TokenFile   string
	Region      string
	SessionName string
	// Duration of the credentials; STS allows 15 minutes to the role's maximum. Default 15 minutes.
	Duration time.Duration
	// SessionPolicy, when set, is an inline IAM policy that narrows the role further for this
	// gateway (the effective permissions are the intersection).
	SessionPolicy string
	// Endpoint overrides the STS endpoint (LocalStack, tests). Default https://sts.<region>.amazonaws.com/.
	Endpoint string
	HTTP     HTTPDoer

	c cache
}

type stsResponse struct {
	Result struct {
		Credentials struct {
			AccessKeyID     string    `xml:"AccessKeyId"`
			SecretAccessKey string    `xml:"SecretAccessKey"`
			SessionToken    string    `xml:"SessionToken"`
			Expiration      time.Time `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

type stsError struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

func (a *AWSWebIdentity) Lease(ctx context.Context) (Lease, error) {
	return a.c.get(ctx, a.fetch)
}

func (a *AWSWebIdentity) fetch(ctx context.Context) (Lease, error) {
	tok, err := readToken(a.TokenFile)
	if err != nil {
		return Lease{}, err
	}
	dur := a.Duration
	if dur <= 0 {
		dur = 15 * time.Minute
	}
	session := a.SessionName
	if session == "" {
		session = "mcp-cloud-ops-gateway"
	}
	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {a.RoleARN},
		"RoleSessionName":  {session},
		"WebIdentityToken": {tok},
		"DurationSeconds":  {strconv.Itoa(int(dur.Seconds()))},
	}
	if a.SessionPolicy != "" {
		form.Set("Policy", a.SessionPolicy)
	}
	endpoint := a.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://sts.%s.amazonaws.com/", a.Region)
	}
	body, status, err := post(ctx, a.HTTP, endpoint, form)
	if err != nil {
		return Lease{}, fmt.Errorf("aws sts: %w", err)
	}
	if status != http.StatusOK {
		var e stsError
		_ = xml.Unmarshal(body, &e)
		return Lease{}, fmt.Errorf("aws sts: HTTP %d %s: %s", status, e.Error.Code, e.Error.Message)
	}
	var r stsResponse
	if err := xml.Unmarshal(body, &r); err != nil {
		return Lease{}, fmt.Errorf("aws sts: decode response: %w", err)
	}
	c := r.Result.Credentials
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return Lease{}, errors.New("aws sts: response has no credentials")
	}
	env := map[string]string{
		"AWS_ACCESS_KEY_ID":     c.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": c.SecretAccessKey,
		"AWS_SESSION_TOKEN":     c.SessionToken,
		// The CLI must not fall back to a profile or instance metadata if these fail.
		"AWS_EC2_METADATA_DISABLED":   "true",
		"AWS_CONFIG_FILE":             os.DevNull,
		"AWS_SHARED_CREDENTIALS_FILE": os.DevNull,
	}
	if a.Region != "" {
		env["AWS_REGION"] = a.Region
	}
	return Lease{Env: env, Expires: c.Expiration}, nil
}

// AzureFederated exchanges the platform's OIDC token for an Entra ID access token (workload
// identity federation: client credentials with a JWT client assertion, no client secret).
type AzureFederated struct {
	TenantID  string
	ClientID  string
	TokenFile string
	// Scope of the token. Default Azure Resource Manager.
	Scope string
	// Authority overrides https://login.microsoftonline.com (sovereign clouds, tests).
	Authority string
	HTTP      HTTPDoer

	c cache
}

func (z *AzureFederated) Lease(ctx context.Context) (Lease, error) {
	return z.c.get(ctx, z.fetch)
}

func (z *AzureFederated) fetch(ctx context.Context) (Lease, error) {
	tok, err := readToken(z.TokenFile)
	if err != nil {
		return Lease{}, err
	}
	scope := z.Scope
	if scope == "" {
		scope = "https://management.azure.com/.default"
	}
	authority := strings.TrimRight(z.Authority, "/")
	if authority == "" {
		authority = "https://login.microsoftonline.com"
	}
	form := url.Values{
		"client_id":             {z.ClientID},
		"scope":                 {scope},
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {tok},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", authority, url.PathEscape(z.TenantID))
	body, status, err := post(ctx, z.HTTP, endpoint, form)
	if err != nil {
		return Lease{}, fmt.Errorf("entra token: %w", err)
	}
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return Lease{}, fmt.Errorf("entra token: HTTP %d, undecodable response", status)
	}
	if status != http.StatusOK || r.AccessToken == "" {
		// The description can quote the request; keep only its first line.
		desc, _, _ := strings.Cut(r.Description, "\n")
		return Lease{}, fmt.Errorf("entra token: HTTP %d %s: %s", status, r.Error, desc)
	}
	return Lease{Bearer: r.AccessToken, Expires: time.Now().Add(time.Duration(r.ExpiresIn) * time.Second)}, nil
}

func post(ctx context.Context, doer HTTPDoer, endpoint string, form url.Values) ([]byte, int, error) {
	if doer == nil {
		doer = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json, text/xml")
	resp, err := doer.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
