// Command mcp-cloud-ops-gateway is a governed MCP server for cloud and Kubernetes operations.
//
//	mcp-cloud-ops-gateway serve     --config gateway.yaml [--stdio]
//	mcp-cloud-ops-gateway validate  --config gateway.yaml
//	mcp-cloud-ops-gateway approvals list|show|approve|deny [id] [--note text]
//	mcp-cloud-ops-gateway audit verify --file audit.jsonl
//	mcp-cloud-ops-gateway hash-token        (reads a token on stdin)
//	mcp-cloud-ops-gateway version
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/approval"
	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/audit"
	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/config"
	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/gateway"
	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/policy"
	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/runner"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

const usage = `usage: mcp-cloud-ops-gateway <command> [flags]

commands:
  serve       run the gateway (HTTP and admin listeners; --stdio for a local MCP client)
  validate    check the config and policy files and list the tools that would be served
  approvals   list, show, approve or deny pending approvals through the admin API
  audit       verify the hash chain of an audit log
  hash-token  print the SHA-256 of a token read from stdin, for the config file
  version     print the version`

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return errors.New("no command")
	}
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stdin, stdout, stderr)
	case "validate":
		return validate(args[1:], stdout)
	case "approvals":
		return approvals(ctx, args[1:], stdout)
	case "audit":
		return auditCmd(args[1:], stdout)
	case "hash-token":
		return hashToken(stdin, stdout)
	case "version":
		fmt.Fprintln(stdout, gateway.Version)
		return nil
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage)
		return nil
	default:
		fmt.Fprintln(stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func load(path string) (*config.Config, *policy.Policy, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	pol, err := policy.Load(cfg.Path(cfg.PolicyFile), gateway.AllTools())
	if err != nil {
		return nil, nil, err
	}
	return cfg, pol, nil
}

func validate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	cfgPath := fs.String("config", "gateway.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, pol, err := load(*cfgPath)
	if err != nil {
		return err
	}
	g, err := gateway.New(cfg, gateway.Deps{Policy: pol})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "config and policy are valid\ntools: %s\n", strings.Join(g.ToolNames(), ", "))
	for _, p := range cfg.Principals {
		fmt.Fprintf(stdout, "\nprincipal %s (profile %s)\n", p.Name, p.Profile)
		effects := pol.Explain(p.Profile, g.ToolNames())
		for _, tool := range g.ToolNames() {
			if tool != gateway.PolicyToolName {
				fmt.Fprintf(stdout, "  %-28s %s\n", tool, effects[tool])
			}
		}
	}
	return nil
}

func serve(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "gateway.yaml", "config file")
	stdio := fs.Bool("stdio", false, "also serve MCP on stdin/stdout, as server.stdio_principal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// stdout belongs to the MCP protocol in stdio mode, so logs always go to stderr.
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, pol, err := load(*cfgPath)
	if err != nil {
		return err
	}
	var mirror io.Writer
	if cfg.Audit.MirrorStderr {
		mirror = stderr
	}
	auditLog, err := audit.Open(cfg.Path(cfg.Audit.File), mirror)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	httpClient := &http.Client{Timeout: 30 * time.Second}
	g, err := gateway.New(cfg, gateway.Deps{
		Policy: pol,
		Approvals: approval.NewBroker(approval.Options{
			PendingTTL: cfg.Approvals.PendingTTL, UseWindow: cfg.Approvals.UseWindow, MaxPendingPerPrincipal: cfg.Approvals.MaxPending,
		}),
		Audit:     auditLog,
		Runner:    runner.Exec{Timeout: cfg.Limits.CommandTimeout},
		HTTP:      httpClient,
		Providers: gateway.Providers(cfg, httpClient),
		Logger:    logger,
	})
	if err != nil {
		return err
	}
	if _, err := auditLog.Write(audit.Record{Event: "startup", Outcome: gateway.Version}); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 3)
	var servers []*http.Server

	listen := func(name, addr string, h http.Handler) error {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s listener: %w", name, err)
		}
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		logger.Info("listening", "listener", name, "addr", ln.Addr().String())
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", name, err)
			}
		}()
		return nil
	}
	if err := listen("admin", cfg.Server.AdminListen, g.AdminHandler()); err != nil {
		return err
	}
	if cfg.Server.HTTPListen != "" {
		if err := listen("mcp", cfg.Server.HTTPListen, g.MCPHandler()); err != nil {
			return err
		}
	}
	if *stdio {
		if cfg.Server.StdioPrincipal == "" {
			return errors.New("--stdio needs server.stdio_principal in the config")
		}
		go func() {
			t := &mcp.IOTransport{Reader: io.NopCloser(stdin), Writer: nopWriteCloser{stdout}}
			errc <- g.NewServer(cfg.Server.StdioPrincipal).Run(ctx, t)
		}()
	} else if cfg.Server.HTTPListen == "" {
		return errors.New("nothing to serve: set server.http_listen or pass --stdio")
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	_, _ = auditLog.Write(audit.Record{Event: "shutdown"})
	// A stdio client closing its end is a normal way to stop.
	if runErr != nil && (errors.Is(runErr, io.EOF) || errors.Is(runErr, context.Canceled) || strings.Contains(runErr.Error(), "closed")) {
		return nil
	}
	return runErr
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func approvals(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: approvals list|show|approve|deny [id] [--admin-url URL] [--note text]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
	adminURL := fs.String("admin-url", envOr("MCPGW_ADMIN_URL", "http://127.0.0.1:8081"), "admin API base URL (env MCPGW_ADMIN_URL)")
	note := fs.String("note", "", "note recorded with the decision")
	status := fs.String("status", "pending", "list: status filter (pending, approved, denied, used, expired, or empty for all)")
	rest := args[1:]
	var id string
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		id, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	token := os.Getenv("MCPGW_ADMIN_TOKEN")
	if token == "" {
		return errors.New("set MCPGW_ADMIN_TOKEN to your approver token")
	}
	base := strings.TrimRight(*adminURL, "/")

	var method, url string
	var body []byte
	switch sub {
	case "list":
		method, url = http.MethodGet, base+"/v1/approvals?status="+*status
	case "show", "approve", "deny":
		if id == "" {
			return fmt.Errorf("approvals %s needs an approval id", sub)
		}
		method, url = http.MethodGet, base+"/v1/approvals/"+id
		if sub != "show" {
			method, url = http.MethodPost, base+"/v1/approvals/"+id+"/"+sub
			body, _ = json.Marshal(map[string]string{"note": *note})
		}
	default:
		return fmt.Errorf("unknown approvals command %q", sub)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, _ = stdout.Write(out)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("admin API returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func auditCmd(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: audit verify --file audit.jsonl")
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	file := fs.String("file", "audit.jsonl", "audit log to verify")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	res, err := audit.VerifyFile(*file)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	if res.Broken {
		return fmt.Errorf("audit chain broken at line %d: %s", res.Line, res.Problem)
	}
	return nil
}

func hashToken(stdin io.Reader, stdout io.Writer) error {
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	token := strings.TrimSpace(line)
	if len(token) < 32 {
		return errors.New("token must be at least 32 characters; generate one with: openssl rand -hex 32")
	}
	fmt.Fprintln(stdout, gateway.HashToken(token))
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
