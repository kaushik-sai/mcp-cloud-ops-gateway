package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/approval"
	"github.com/kaushik-sai/mcp-cloud-ops-gateway/internal/audit"
)

// AdminHandler serves the approval API for humans. It listens on its own address and accepts
// only approver tokens, so an agent's token cannot approve anything even if the agent finds the
// address.
//
//	GET  /v1/approvals?status=pending
//	GET  /v1/approvals/{id}
//	POST /v1/approvals/{id}/approve   {"note": "..."}
//	POST /v1/approvals/{id}/deny      {"note": "..."}
func (g *Gateway) AdminHandler() http.Handler {
	entries := map[string]string{}
	for _, a := range g.cfg.Approvers {
		entries[strings.ToLower(a.TokenSHA256)] = a.Name
	}
	api := http.NewServeMux()
	api.HandleFunc("GET /v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, g.deps.Approvals.List(approval.Status(r.URL.Query().Get("status"))))
	})
	api.HandleFunc("GET /v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		req, err := g.deps.Approvals.Get(r.PathValue("id"))
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, req)
	})
	decide := func(approve bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			approver := auth.TokenInfoFromContext(r.Context()).UserID
			var body struct {
				Note string `json:"note"`
			}
			if r.ContentLength != 0 {
				if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON like {\"note\": \"...\"}"})
					return
				}
			}
			req, err := g.deps.Approvals.Decide(r.PathValue("id"), approver, approve, body.Note)
			if err != nil {
				writeError(w, err)
				return
			}
			outcome := "denied"
			if approve {
				outcome = "approved"
			}
			g.record(audit.Record{Event: "approval_decided", Principal: req.Principal, Tool: req.Tool, Args: req.Args,
				ApprovalID: req.ID, Approver: approver, Outcome: outcome})
			writeJSON(w, http.StatusOK, req)
		}
	}
	api.HandleFunc("POST /v1/approvals/{id}/approve", decide(true))
	api.HandleFunc("POST /v1/approvals/{id}/deny", decide(false))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	if len(entries) == 0 {
		mux.HandleFunc("/v1/", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrNoApprover.Error()})
		})
		return mux
	}
	mux.Handle("/v1/", auth.RequireBearerToken(TokenVerifier(entries), nil)(api))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusConflict
	switch {
	case errors.Is(err, approval.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, approval.ErrSelfApproval):
		status = http.StatusForbidden
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
