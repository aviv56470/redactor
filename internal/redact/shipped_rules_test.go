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

func TestShippedCardRule(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no gaps",
			`{"body":{"n":"4111111111111111"}}`,
			`{"body":{"n":"************1111"}}`},
		{"groups of 4 with spaces (sample line 1)",
			`{"body":{"note":"card 4111 1111 1111 1111 on file"}}`,
			`{"body":{"note":"card ***************1111 on file"}}`},
		{"groups of 4 with dashes (sample line 6)",
			`{"body":{"message":"please charge 5555-5555-5555-4444 and send the receipt"}}`,
			`{"body":{"message":"please charge ***************4444 and send the receipt"}}`},
		{"American Express 4-6-5 and Diners 4-6-4 (sample line 36)",
			`{"body":{"note":"amex 3782 822463 10005, diners 3056 930902 5904"}}`,
			`{"body":{"note":"amex *************0005, diners ************5904"}}`},
		{"in an array (sample line 44)",
			`{"body":["5555 5555 5555 4444"]}`,
			`{"body":["***************4444"]}`},
		{"grouped number failing Luhn is kept",
			`{"body":{"n":"4111 1111 1111 1112"}}`,
			`{"body":{"n":"4111 1111 1111 1112"}}`},
		{"card followed by another number",
			`{"body":{"n":"4111 1111 1111 1111 12 items"}}`,
			`{"body":{"n":"***************1111 12 items"}}`},
		{"dates and phone numbers are not cards",
			`{"body":{"n":"2025-01-15 +1 (415) 555-0132"}}`,
			`{"body":{"n":"2025-01-15 +1 (415) 555-0132"}}`},
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

func TestShippedSecretAssignmentRule(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"password inside a debug message (sample line 41)",
			`{"body":{"debug":"login attempt password=hunter2 for user=zed"}}`,
			`{"body":{"debug":"login attempt **** for user=zed"}}`},
		{"any case, other credential names",
			`{"body":{"msg":"retry with TOKEN=abc123 and api_key=k-9"}}`,
			`{"body":{"msg":"retry with **** and ****"}}`},
		{"stops at the next & in a URL inside text",
			`{"body":{"msg":"redirect to /cb?access_token=xyz&state=1 now"}}`,
			`{"body":{"msg":"redirect to /cb?****&state=1 now"}}`},
		{"in a header value",
			`{"headers":{"X-Debug":"password=hunter2"}}`,
			`{"headers":{"X-Debug":"****"}}`},
		{"longer names are not credentials",
			`{"body":{"msg":"password_hint=pet tokenizer=bpe"}}`,
			`{"body":{"msg":"password_hint=pet tokenizer=bpe"}}`},
		{"form data keeps the name (handled by the key rules)",
			`{"body":"user=zed&password=hunter2"}`,
			`{"body":"user=zed&password=****"}`},
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
