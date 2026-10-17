package redact

import (
	"strings"
	"testing"
)

// Fake credentials, built from parts so secret scanners do not flag this file.
var (
	fakeAWSKey = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeGH     = "ghp_" + strings.Repeat("a1B2", 9)
	fakeJWT    = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".c2lnbmF0dXJlLXZhbHVlLWhlcmU"
)

func TestString(t *testing.T) {
	cases := []struct {
		name, in, mustNotContain, mustContain string
	}{
		{"aws key", "id=" + fakeAWSKey + " ok", fakeAWSKey, Placeholder},
		{"github token", "token " + fakeGH, fakeGH, Placeholder},
		{"jwt", "auth " + fakeJWT, fakeJWT, Placeholder},
		{"bearer keeps prefix", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345", "abcdefghijklmnop", "Bearer " + Placeholder},
		{"password keeps key", `{"password": "hunter2hunter2"}`, "hunter2", `"password": "` + Placeholder},
		{"azure conn string", "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=c2VjcmV0a2V5;EndpointSuffix=core", "c2VjcmV0a2V5", "AccountKey=" + Placeholder},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow", Placeholder},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, n := String(tc.in)
			if strings.Contains(out, tc.mustNotContain) || !strings.Contains(out, tc.mustContain) || n == 0 {
				t.Fatalf("got %q (n=%d)", out, n)
			}
		})
	}
}

func TestLeavesOrdinaryTextAlone(t *testing.T) {
	in := "pod api-7d9f ready 3/3, replicas=3, image nginx:1.27, token_count is a word"
	out, n := String(in)
	if out != in || n != 0 {
		t.Fatalf("changed ordinary text: %q (n=%d)", out, n)
	}
}

func TestValue(t *testing.T) {
	v := map[string]any{"a": []any{"x " + fakeAWSKey}, "b": map[string]any{"c": "password=supersecret1"}, "n": 3.0}
	Value(v)
	if strings.Contains(v["a"].([]any)[0].(string), fakeAWSKey) || strings.Contains(v["b"].(map[string]any)["c"].(string), "supersecret1") || v["n"] != 3.0 {
		t.Fatalf("got %v", v)
	}
}
