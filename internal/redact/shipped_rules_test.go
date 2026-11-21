package redact

import "testing"

// These tests run the rules.yaml that ships with the project, so they check
// the configuration itself, not just the engine.

// Tokens from the sample data. tokenA has '_' in its signature; tokenB has
// '_' in its payload and '-' and '_' in its signature.
const (
	tokenA = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	tokenB = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiPz8_In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func TestShippedJWTRule(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"'_' in the signature (sample line 15)",
			`{"body":{"id_token":"` + tokenA + `"}}`,
			`{"body":{"id_token":"****"}}`},
		{"'_' in the payload, inside text (sample line 16)",
			`{"body":{"msg":"session ` + tokenB + ` expired, retry"}}`,
			`{"body":{"msg":"session **** expired, retry"}}`},
		{"inside JSON stored in a response body (sample line 11)",
			`{"response":{"body":"{\"access_token\":\"` + tokenB + `\",\"expires_in\":3600}"}}`,
			`{"response":{"body":"{\"access_token\":\"****\",\"expires_in\":3600}"}}`},
		{"unsigned token with an empty signature",
			`{"body":{"t":"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."}}`,
			`{"body":{"t":"****"}}`},
		{"three dotted words are not a JWT",
			`{"body":{"t":"Bearer abc.def.ghi"}}`,
			`{"body":{"t":"Bearer abc.def.ghi"}}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := LoadRules("../../rules.yaml")
			if err != nil {
				t.Fatalf("LoadRules: %v", err)
			}
			rd := NewRedactor(rules)

			got, err := rd.RedactLine([]byte(tc.input))
			if err != nil {
				t.Fatalf("RedactLine: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}
