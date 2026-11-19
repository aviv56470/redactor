package redact

import (
	"maps"
	"testing"
)

// testSettings is the settings block used by the test rules below.
const testSettings = `
version: 1
settings:
  mask: { replacement: "****" }
  partial: { keep_last: 4, fill: "*" }
  hash: { algorithm: sha256 }
`

// testValueRules are small rules written for these tests, so the tests
// check the engine itself and don't depend on the shipped rules.yaml.
const testValueRules = `
value_rules:
  - { name: email, pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', action: mask }
  - { name: card,  pattern: '\b\d{13,19}\b', validator: luhn, action: partial }
  - { name: key,   pattern: '\bsk_live_[A-Za-z0-9]+\b', action: mask }
  - { name: ssn,   pattern: '\b\d{3}-\d{2}-\d{4}\b', action: remove }
`

// newTestRedactor builds a Redactor from testSettings plus the given rules.
func newTestRedactor(t *testing.T, rulesYAML string) *Redactor {
	t.Helper()
	rules, err := ParseRules([]byte(testSettings + rulesYAML))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	return NewRedactor(rules)
}

func TestRewrite(t *testing.T) {
	rd := newTestRedactor(t, testValueRules)

	tests := []struct {
		name   string
		action string
		input  string
		want   string
	}{
		{"mask", ActionMask, "hunter2", "****"},
		{"mask leaves empty value alone", ActionMask, "", ""},
		{"partial card", ActionPartial, "4111111111111111", "************1111"},
		{"partial one more than kept", ActionPartial, "12345", "*2345"},
		{"partial too short is fully hidden", ActionPartial, "1234", "****"},
		{"partial counts characters not bytes", ActionPartial, "כרטיס1234", "*****1234"},
		{"partial is idempotent", ActionPartial, "************1111", "************1111"},
		{"hash", ActionHash, "abc",
			"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"hash is idempotent", ActionHash,
			"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"remove", ActionRemove, "123", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rd.rewrite(tc.action, tc.input)
			if got != tc.want {
				t.Errorf("rewrite(%s, %q) = %q, want %q", tc.action, tc.input, got, tc.want)
			}
		})
	}
}

func TestRedactString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"nothing sensitive", "hello world", "hello world"},
		{"email in text", "contact a@b.com today", "contact **** today"},
		{"two emails", "a@b.com,c@d.org", "****,****"},
		{"valid card", "card 4111111111111111 on file", "card ************1111 on file"},
		{"card failing luhn is kept", "order ref 4111111111111112 was shipped",
			"order ref 4111111111111112 was shipped"},
		{"valid and invalid cards", "first 4111111111111111 then 4111111111111112",
			"first ************1111 then 4111111111111112"},
		{"remove action", "ssn 123-45-6789 ok", "ssn  ok"},
		{"api key", "Temporary key: sk_live_9fA2kLmQ7x. Thanks!", "Temporary key: ****. Thanks!"},
		{"hebrew text", "מספר כרטיס: 4111111111111111 אימייל: user@example.com",
			"מספר כרטיס: ************1111 אימייל: ****"},
		{"emoji around values", "💳4111111111111111💳 and 😀zed@example.com😀",
			"💳************1111💳 and 😀****😀"},
		{"already redacted", "************1111 and ****", "************1111 and ****"},
		{"card at end of sentence", "pay with 5555555555554444.", "pay with ************4444."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rd := newTestRedactor(t, testValueRules)

			got := rd.redactString(tc.input)
			if got != tc.want {
				t.Errorf("redactString(%q)\n got: %q\nwant: %q", tc.input, got, tc.want)
			}

			// Idempotency: redacting the output again must change nothing.
			if again := rd.redactString(got); again != got {
				t.Errorf("not idempotent:\n first: %q\nsecond: %q", got, again)
			}
		})
	}
}

func TestHashedEmailIsIdempotent(t *testing.T) {
	rd := newTestRedactor(t, `
value_rules:
  - { name: email, pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', action: hash }
`)
	once := rd.redactString("mail a@b.com")
	twice := rd.redactString(once)
	if once == "mail a@b.com" {
		t.Fatalf("email was not hashed: %q", once)
	}
	if twice != once {
		t.Errorf("hashing twice changed the value:\n first: %q\nsecond: %q", once, twice)
	}
}

func TestCounts(t *testing.T) {
	rd := newTestRedactor(t, testValueRules)

	out := rd.redactString("a@b.com, c@d.org, 4111111111111111, 4111111111111112")
	rd.redactString(out) // already redacted: must not be counted again

	want := map[string]int{"email": 2, "card": 1}
	if got := rd.Counts(); !maps.Equal(got, want) {
		t.Errorf("Counts() = %v, want %v", got, want)
	}
}
