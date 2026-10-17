// Package redact removes credentials from text before it reaches an agent or the audit log.
//
// It is a safety net, not the main control: tools never ask for secrets (Kubernetes Secrets are
// not readable through the gateway) and credentials are passed to CLIs through the environment,
// never through arguments. Redaction catches what slips through anyway, such as a token printed
// in a pod log or an access key in a Terraform plan.
package redact

import "regexp"

// Placeholder replaces every match.
const Placeholder = "[REDACTED]"

type rule struct {
	name string
	re   *regexp.Regexp
	// keep keeps the first capture group (the key in key=value rules), so the reader can still
	// see which field was hidden.
	keep bool
}

var rules = []rule{
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{name: "aws-access-key-id", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "github-token", re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b`)},
	{name: "slack-token", re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{name: "bearer", re: regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{16,}`), keep: true},
	{name: "azure-connection-string", re: regexp.MustCompile(`(?i)((?:AccountKey|SharedAccessKey|SharedAccessSignature)=)[^;"'\s]+`), keep: true},
	{name: "key-value", re: regexp.MustCompile(`(?i)((?:password|passwd|secret|client_secret|api[_-]?key|access[_-]?key|secret[_-]?access[_-]?key|session[_-]?token|token)["']?\s*[:=]\s*["']?)[^"'\s,;}]{6,}`), keep: true},
}

// String returns s with every known credential pattern replaced by Placeholder, and the number of
// replacements made.
func String(s string) (string, int) {
	count := 0
	for _, r := range rules {
		s = r.re.ReplaceAllStringFunc(s, func(m string) string {
			count++
			if r.keep {
				sub := r.re.FindStringSubmatch(m)
				return sub[1] + Placeholder
			}
			return Placeholder
		})
	}
	return s, count
}

// Value redacts every string inside a decoded JSON value (maps, slices and strings), in place
// for maps and slices, and returns the result.
func Value(v any) any {
	switch t := v.(type) {
	case string:
		out, _ := String(t)
		return out
	case map[string]any:
		for k, item := range t {
			t[k] = Value(item)
		}
		return t
	case []any:
		for i, item := range t {
			t[i] = Value(item)
		}
		return t
	default:
		return v
	}
}
