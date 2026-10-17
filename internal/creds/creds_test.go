package creds

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tokenFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const stsOK = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLEEXAMPLE00</AccessKeyId>
      <SecretAccessKey>fake-secret</SecretAccessKey>
      <SessionToken>fake-session</SessionToken>
      <Expiration>%s</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`

func TestAWSWebIdentityExchangesAndCaches(t *testing.T) {
	var hits atomic.Int32
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(body))
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		_, _ = w.Write([]byte(strings.Replace(stsOK, "%s", exp, 1)))
	}))
	defer srv.Close()

	p := &AWSWebIdentity{RoleARN: "arn:aws:iam::123456789012:role/reader", TokenFile: tokenFile(t, "oidc-jwt\n"),
		Region: "eu-west-1", Endpoint: srv.URL, SessionPolicy: `{"Version":"2012-10-17"}`}
	l, err := p.Lease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.Env["AWS_ACCESS_KEY_ID"] != "ASIAEXAMPLEEXAMPLE00" || l.Env["AWS_SESSION_TOKEN"] != "fake-session" ||
		l.Env["AWS_REGION"] != "eu-west-1" || l.Env["AWS_EC2_METADATA_DISABLED"] != "true" {
		t.Fatalf("env %v", l.Env)
	}
	if got.Get("Action") != "AssumeRoleWithWebIdentity" || got.Get("WebIdentityToken") != "oidc-jwt" ||
		got.Get("DurationSeconds") != "900" || got.Get("Policy") == "" {
		t.Fatalf("request %v", got)
	}
	if _, err := p.Lease(context.Background()); err != nil || hits.Load() != 1 {
		t.Fatalf("second lease should come from cache (hits=%d, err=%v)", hits.Load(), err)
	}
}

func TestAWSWebIdentityRefreshesNearExpiry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		exp := time.Now().Add(time.Minute).UTC().Format(time.RFC3339) // inside the refresh margin
		_, _ = w.Write([]byte(strings.Replace(stsOK, "%s", exp, 1)))
	}))
	defer srv.Close()
	p := &AWSWebIdentity{RoleARN: "r", TokenFile: tokenFile(t, "t"), Endpoint: srv.URL}
	_, _ = p.Lease(context.Background())
	_, _ = p.Lease(context.Background())
	if hits.Load() != 2 {
		t.Fatalf("hits=%d, want 2", hits.Load())
	}
}

func TestAWSWebIdentityErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>AccessDenied</Code><Message>Not authorized</Message></Error></ErrorResponse>`))
	}))
	defer srv.Close()
	p := &AWSWebIdentity{RoleARN: "r", TokenFile: tokenFile(t, "t"), Endpoint: srv.URL}
	if _, err := p.Lease(context.Background()); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("got %v", err)
	}
	p = &AWSWebIdentity{RoleARN: "r", TokenFile: tokenFile(t, "  "), Endpoint: srv.URL}
	if _, err := p.Lease(context.Background()); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("got %v", err)
	}
}

func TestAzureFederated(t *testing.T) {
	var got url.Values
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(body))
		if got.Get("client_assertion") != "oidc-jwt" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS700016: bad\nTrace ID: x"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"arm-token","expires_in":3600}`))
	}))
	defer srv.Close()

	p := &AzureFederated{TenantID: "tenant-1", ClientID: "client-1", TokenFile: tokenFile(t, "oidc-jwt"), Authority: srv.URL}
	l, err := p.Lease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.Bearer != "arm-token" || path != "/tenant-1/oauth2/v2.0/token" || got.Get("grant_type") != "client_credentials" ||
		got.Get("scope") != "https://management.azure.com/.default" || got.Get("client_secret") != "" {
		t.Fatalf("lease %+v path %s form %v", l, path, got)
	}

	bad := &AzureFederated{TenantID: "t", ClientID: "c", TokenFile: tokenFile(t, "wrong"), Authority: srv.URL}
	_, err = bad.Lease(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid_client") || strings.Contains(err.Error(), "Trace ID") {
		t.Fatalf("got %v", err)
	}
}

func TestStaticProviders(t *testing.T) {
	l, _ := Kubeconfig{Path: "/k", Context: "kind"}.Lease(context.Background())
	if l.Env["KUBECONFIG"] != "/k" || l.KubeContext != "kind" {
		t.Fatalf("got %+v", l)
	}
	env := map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1", "KUBERNETES_SERVICE_PORT": "443"}
	l, err := InCluster{Getenv: func(k string) string { return env[k] }}.Lease(context.Background())
	if err != nil || l.Env["KUBERNETES_SERVICE_HOST"] != "10.0.0.1" {
		t.Fatalf("got %+v %v", l, err)
	}
	if _, err := (InCluster{Getenv: func(string) string { return "" }}).Lease(context.Background()); err == nil {
		t.Fatal("in_cluster outside a pod must fail")
	}
	if l, _ := (None{}).Lease(context.Background()); len(l.Env) != 0 {
		t.Fatal("none must be empty")
	}
}
