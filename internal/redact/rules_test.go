package redact

import (
	"strings"
	"testing"
)

// The rules.yaml shipped with the project must always load.
func TestLoadProvidedRules(t *testing.T) {
	r, err := LoadRules("../../rules.yaml")
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(r.KeyRules) != 5 || len(r.ValueRules) != 5 {
		t.Fatalf("got %d key rules and %d value rules, want 5 and 5",
			len(r.KeyRules), len(r.ValueRules))
	}
}

func TestKeyRuleMatching(t *testing.T) {
	r, err := LoadRules("../../rules.yaml")
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	tests := []struct {
		rule      string
		key       string
		inHeaders bool
		want      bool
	}{
		// exact names, case-insensitive
		{"auth-headers", "Authorization", true, true},
		{"auth-headers", "authorization", true, true},
		{"auth-headers", "AUTHORIZATION", true, true},
		{"auth-headers", "Content-Type", true, false},
		// scope: headers only
		{"auth-headers", "Authorization", false, false},
		// scope: any
		{"api-key-names", "X-Api-Key", true, true},
		{"api-key-names", "api_key", false, true},
		{"api-key-names", "ApiKey", false, true},
		// scope: body only
		{"secret-fields", "password", false, true},
		{"secret-fields", "Password", false, true},
		{"secret-fields", "password", true, false},
		// the regex is anchored with ^...$, so these must NOT match
		{"secret-fields", "password_hint", false, false},
		{"secret-fields", "passwordless", false, false},
		{"secret-fields", "tokenizer", false, false},
	}

	for _, tc := range tests {
		kr := findKeyRule(t, r, tc.rule)
		got := kr.matchesKey(tc.key, tc.inHeaders)
		if got != tc.want {
			t.Errorf("rule %s, key %q (inHeaders=%v): got %v, want %v",
				tc.rule, tc.key, tc.inHeaders, got, tc.want)
		}
	}
}

// findKeyRule returns the key rule with the given name, or fails the test.
func findKeyRule(t *testing.T, r *Rules, name string) *KeyRule {
	t.Helper()
	for i := range r.KeyRules {
		if r.KeyRules[i].Name == name {
			return &r.KeyRules[i]
		}
	}
	t.Fatalf("no key rule named %q", name)
	return nil
}

// Bad rules files must be rejected with a helpful message, never loaded.
func TestParseRulesRejectsBadConfig(t *testing.T) {
	const settings = `
version: 1
settings:
  mask: { replacement: "****" }
  partial: { keep_last: 4, fill: "*" }
  hash: { algorithm: sha256 }
`
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"empty file", ``, "empty"},
		{"not yaml", `{{{`, "parsing rules"},
		{"no rules", settings, "no rules defined"},
		{"typo in field name", settings + `
value_rules:
  - { name: a, pattren: "x", action: mask }
`, "pattren"},
		{"wrong version", strings.Replace(settings, "version: 1", "version: 2", 1) + `
value_rules:
  - { name: a, pattern: "x", action: mask }
`, "unsupported version 2"},
		{"unknown action", settings + `
value_rules:
  - { name: a, pattern: "x", action: scramble }
`, `unknown action "scramble"`},
		{"unknown scope", settings + `
key_rules:
  - { name: a, scope: query, match: { exact: [x] }, action: mask }
`, `unknown scope "query"`},
		{"both exact and regex", settings + `
key_rules:
  - { name: a, scope: any, match: { exact: [x], regex: "y" }, action: mask }
`, "exactly one of exact or regex"},
		{"neither exact nor regex", settings + `
key_rules:
  - { name: a, scope: any, match: {}, action: mask }
`, "exactly one of exact or regex"},
		{"bad regex", settings + `
key_rules:
  - { name: a, scope: any, match: { regex: "(" }, action: mask }
`, "bad regex"},
		{"unknown validator", settings + `
value_rules:
  - { name: a, pattern: "x", validator: mod97, action: mask }
`, `unknown validator "mod97"`},
		{"pattern matches empty text", settings + `
value_rules:
  - { name: a, pattern: "x*", action: mask }
`, "must not match empty text"},
		{"duplicate names", settings + `
value_rules:
  - { name: a, pattern: "x", action: mask }
  - { name: a, pattern: "y", action: mask }
`, `duplicate rule name "a"`},
		{"unsupported hash", strings.Replace(settings, "sha256", "md5", 1) + `
value_rules:
  - { name: a, pattern: "x", action: hash }
`, `"md5" is not supported`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseRules([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected an error, got rules: %+v", r)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}
