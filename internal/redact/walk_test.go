package redact

import (
	"maps"
	"strings"
	"testing"
)

// testKeyRules are key rules written for these tests.
const testKeyRules = `
key_rules:
  - { name: auth,   scope: headers, match: { exact: [Authorization, Set-Cookie] }, action: mask }
  - { name: apikey, scope: any,     match: { regex: '(?i)^(x-)?api[_-]?key$' },     action: mask }
  - { name: secret, scope: body,    match: { regex: '(?i)^(password|token)$' },     action: mask }
  - { name: pan,    scope: body,    match: { regex: '(?i)^card_?number$' },         action: partial }
  - { name: cvv,    scope: body,    match: { regex: '(?i)^cvv$' },                  action: remove }
`

func TestRedactLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Keeping the output faithful to the input
		{"key order and number formats are kept",
			`{"b":1,"a":10.50,"c":1e3,"d":12345678901234567890}`,
			`{"b":1,"a":10.50,"c":1e3,"d":12345678901234567890}`},
		{"spaces between tokens are dropped",
			`{ "a" : [ 1 , 2 ] }`,
			`{"a":[1,2]}`},
		{"HTML characters are not escaped",
			`{"body":{"note":"Tom & Jerry <tom@example.com>"}}`,
			`{"body":{"note":"Tom & Jerry <****>"}}`},
		{"escaped characters are decoded before matching",
			`{"body":{"contact":"alice\u0040example.com"}}`,
			`{"body":{"contact":"****"}}`},
		{"duplicate keys are both kept and both redacted",
			`{"body":{"email":"a@b.com","email":"c@d.org"}}`,
			`{"body":{"email":"****","email":"****"}}`},

		// Where key rules apply
		{"header rules apply in headers, any case",
			`{"headers":{"authorization":"Bearer x","AUTHORIZATION":"Basic y"}}`,
			`{"headers":{"authorization":"****","AUTHORIZATION":"****"}}`},
		{"header rules don't apply in a body",
			`{"body":{"Authorization":"plain"}}`,
			`{"body":{"Authorization":"plain"}}`},
		{"body rules don't apply in headers",
			`{"headers":{"password":"x"},"body":{"password":"x"}}`,
			`{"headers":{"password":"x"},"body":{"password":"****"}}`},
		{"scope any applies in both",
			`{"headers":{"X-Api-Key":"k1"},"body":{"api_key":"k2"}}`,
			`{"headers":{"X-Api-Key":"****"},"body":{"api_key":"****"}}`},
		{"response headers and body",
			`{"response":{"headers":{"Set-Cookie":"a=b"},"body":{"token":"t"}}}`,
			`{"response":{"headers":{"Set-Cookie":"****"},"body":{"token":"****"}}}`},
		{"a field called headers inside a body is body data",
			`{"body":{"headers":{"Authorization":"x"}}}`,
			`{"body":{"headers":{"Authorization":"x"}}}`},
		{"unexpected top-level fields get body rules",
			`{"extra":{"password":"x"}}`,
			`{"extra":{"password":"****"}}`},

		// Recursion
		{"nested objects and arrays",
			`{"body":{"orders":[{"items":[{"buyer":{"email":"a@b.com"}}]},{"items":[]},{"items":[[{"deep":["c@d.org"]}]]}]}}`,
			`{"body":{"orders":[{"items":[{"buyer":{"email":"****"}}]},{"items":[]},{"items":[[{"deep":["****"]}]]}]}}`},
		{"top-level array",
			`["a@b.com","4111111111111111"]`,
			`["****","************1111"]`},
		{"top-level number", `42`, `42`},

		// The remove action
		{"remove drops the key",
			`{"body":{"card":{"number":"4111111111111111","cvv":"123"}}}`,
			`{"body":{"card":{"number":"************1111"}}}`},
		{"remove the first key", `{"body":{"cvv":"1","a":2}}`, `{"body":{"a":2}}`},
		{"remove the only key", `{"body":{"cvv":"1"}}`, `{"body":{}}`},
		{"remove a key whose value is an object",
			`{"body":{"cvv":{"x":[1,2]},"a":1}}`,
			`{"body":{"a":1}}`},

		// Key rules on values that aren't strings
		{"null, false and numbers under sensitive keys",
			`{"body":{"password":null,"token":false,"card_number":4111111111111111}}`,
			`{"body":{"password":null,"token":false,"card_number":"************1111"}}`},
		{"empty values under sensitive keys stay empty",
			`{"body":{"password":"","token":[]}}`,
			`{"body":{"password":"","token":[]}}`},
		{"every string under a sensitive key is redacted",
			`{"headers":{"Set-Cookie":["session=abc; HttpOnly","csrf=zzz"]}}`,
			`{"headers":{"Set-Cookie":["****","****"]}}`},
		{"objects under a sensitive key",
			`{"body":{"password":{"old":"a","new":"b"}}}`,
			`{"body":{"password":{"old":"****","new":"****"}}}`},

		// Value rules on numbers and keys
		{"card numbers stored as numbers",
			`{"body":{"n":4111111111111111,"m":4111111111111112}}`,
			`{"body":{"n":"************1111","m":4111111111111112}}`},
		{"emails used as keys",
			`{"body":{"a@b.com":true}}`,
			`{"body":{"****":true}}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rd := newTestRedactor(t, testKeyRules+testValueRules)

			got, err := rd.RedactLine([]byte(tc.input))
			if err != nil {
				t.Fatalf("RedactLine(%s): unexpected error: %v", tc.input, err)
			}
			if string(got) != tc.want {
				t.Errorf("RedactLine(%s)\n got: %s\nwant: %s", tc.input, got, tc.want)
			}

			// Idempotency: redacting the output again must change nothing.
			again, err := rd.RedactLine(got)
			if err != nil {
				t.Fatalf("second pass: unexpected error: %v", err)
			}
			if string(again) != string(got) {
				t.Errorf("not idempotent:\n first: %s\nsecond: %s", got, again)
			}
		})
	}
}

func TestRedactLineRejectsBrokenInput(t *testing.T) {
	deep := strings.Repeat("[", maxDepth+5) + strings.Repeat("]", maxDepth+5)

	tests := []struct {
		name  string
		input string
	}{
		{"empty", ``},
		{"truncated", `{"body":{"email":"trunc@exam`},
		{"missing colon", `{"a" 1}`},
		{"two values on one line", `{"a":1} {"b":2}`},
		{"garbage after the value", `{"a":1}x`},
		{"plain text log line", `2025-01-15 10:00:20 WARN upstream timeout user=erin@example.com retry=3`},
		{"nested too deeply", deep},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rd := newTestRedactor(t, testKeyRules+testValueRules)

			out, err := rd.RedactLine([]byte(tc.input))
			if err == nil {
				t.Fatalf("expected an error, got output: %s", out)
			}
			if out != nil {
				t.Errorf("on error the output must be empty, got: %s", out)
			}
		})
	}
}

func TestRedactLineCounts(t *testing.T) {
	rd := newTestRedactor(t, testKeyRules+testValueRules)

	_, err := rd.RedactLine([]byte(
		`{"headers":{"Authorization":"x"},"body":{"email":"a@b.com","cvv":"1","password":"p"}}`))
	if err != nil {
		t.Fatalf("RedactLine: %v", err)
	}

	want := map[string]int{"auth": 1, "email": 1, "cvv": 1, "secret": 1}
	if got := rd.Counts(); !maps.Equal(got, want) {
		t.Errorf("Counts() = %v, want %v", got, want)
	}
}

// A value that a key rule redacts is counted once, for the key rule only,
// even if a value rule would also have matched it.
func TestKeyRuleValueIsCountedOnce(t *testing.T) {
	rd := newTestRedactor(t, testKeyRules+testValueRules)

	for _, line := range []string{
		`{"body":{"card_number":4111111111111111}}`,
		`{"body":{"card_number":"4111111111111111"}}`,
	} {
		if _, err := rd.RedactLine([]byte(line)); err != nil {
			t.Fatalf("RedactLine(%s): %v", line, err)
		}
	}

	want := map[string]int{"pan": 2}
	if got := rd.Counts(); !maps.Equal(got, want) {
		t.Errorf("Counts() = %v, want %v", got, want)
	}
}
