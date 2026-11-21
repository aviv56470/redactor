package redact

import (
	"bytes"
	"strings"
	"testing"
)

// processString runs Process on input and returns what it wrote and reported.
func processString(t *testing.T, rd *Redactor, input string) (string, []string, Stats) {
	t.Helper()
	var out bytes.Buffer
	var reports []string
	report := func(line int, reason string) {
		reports = append(reports, reason)
	}
	stats, err := rd.Process(strings.NewReader(input), &out, report)
	if err != nil {
		t.Fatalf("Process: unexpected error: %v", err)
	}
	return out.String(), reports, stats
}

func TestProcess(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		stats Stats
	}{
		{"one line per line",
			"{\"a\":\"a@b.com\"}\n{\"b\":1}\n",
			"{\"a\":\"****\"}\n{\"b\":1}\n",
			Stats{Lines: 2}},
		{"last line without a newline",
			"{\"a\":1}\n{\"b\":2}",
			"{\"a\":1}\n{\"b\":2}\n",
			Stats{Lines: 2}},
		{"Windows line endings",
			"{\"a\":1}\r\n{\"b\":2}\r\n",
			"{\"a\":1}\n{\"b\":2}\n",
			Stats{Lines: 2}},
		{"blank and whitespace-only lines are dropped",
			"{\"a\":1}\n\n   \n\t\n{\"b\":2}\n",
			"{\"a\":1}\n{\"b\":2}\n",
			Stats{Lines: 2, Blank: 3}},
		{"broken lines are replaced by an error record",
			"{\"a\":1}\n{\"email\":\"trunc@exam\n{\"b\":2}\n",
			"{\"a\":1}\n{\"redactor_error\":\"truncated JSON\",\"line\":2}\n{\"b\":2}\n",
			Stats{Lines: 3, Rejected: 1}},
		{"a plain text line is rejected",
			"2025-01-15 WARN user=erin@example.com\n",
			"{\"redactor_error\":\"unexpected data after JSON value\",\"line\":1}\n",
			Stats{Lines: 1, Rejected: 1}},
		{"empty input", "", "", Stats{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rd := newTestRedactor(t, testKeyRules+testValueRules)
			got, _, stats := processString(t, rd, tc.input)
			if got != tc.want {
				t.Errorf("output\n got: %q\nwant: %q", got, tc.want)
			}
			if stats != tc.stats {
				t.Errorf("stats = %+v, want %+v", stats, tc.stats)
			}
		})
	}
}

// The content of a rejected line must never appear in the output or in a
// report, because a broken line may still contain secrets.
func TestRejectedLinesNeverLeak(t *testing.T) {
	rd := newTestRedactor(t, testKeyRules+testValueRules)
	input := "{\"headers\":{\"Authorization\":\"Bearer secret-token\n" +
		"not json at all: erin@example.com password=hunter2\n" +
		"{\"a\":1} {\"password\":\"hunter2\"}\n"

	out, reports, stats := processString(t, rd, input)
	if stats.Rejected != 3 {
		t.Fatalf("Rejected = %d, want 3", stats.Rejected)
	}
	everything := out + strings.Join(reports, "\n")
	for _, secret := range []string{"secret-token", "erin@example.com", "hunter2"} {
		if strings.Contains(everything, secret) {
			t.Errorf("%q leaked into the output or a report:\n%s", secret, everything)
		}
	}
}

func TestLineTooLong(t *testing.T) {
	rd := newTestRedactor(t, testKeyRules+testValueRules)
	rd.maxLineBytes = 20

	input := "{\"a\":1}\n" +
		"{\"note\":\"" + strings.Repeat("x", 100) + "\"}\n" +
		"{\"b\":2}\n"
	want := "{\"a\":1}\n" +
		"{\"redactor_error\":\"line too long\",\"line\":2}\n" +
		"{\"b\":2}\n"

	got, reports, _ := processString(t, rd, input)
	if got != want {
		t.Errorf("output\n got: %q\nwant: %q", got, want)
	}
	if len(reports) != 1 || reports[0] != "line too long" {
		t.Errorf("reports = %q, want one \"line too long\"", reports)
	}
}

// Running the tool on its own output must change nothing, including the
// error records it wrote for broken lines.
func TestProcessIsIdempotent(t *testing.T) {
	input := "{\"body\":{\"email\":\"a@b.com\",\"password\":\"x\"}}\n" +
		"\n" +
		"{\"broken\":\n" +
		"[\"4111111111111111\"]\n"

	first, _, _ := processString(t, newTestRedactor(t, testKeyRules+testValueRules), input)
	second, _, _ := processString(t, newTestRedactor(t, testKeyRules+testValueRules), first)
	if second != first {
		t.Errorf("not idempotent:\n first: %q\nsecond: %q", first, second)
	}
}
