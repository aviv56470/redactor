package main

import (
	"bytes"
	"strings"
	"testing"
)

// runRedactor runs the program like a user would and returns its exit code,
// stdout and stderr. go test runs in the project root, so the default
// rules.yaml and testdata/ are found there.
func runRedactor(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestReadsStdinWhenNoFileIsGiven(t *testing.T) {
	code, stdout, stderr := runRedactor(t, `{"body":{"password":"hunter2"}}`+"\n")
	if code != exitOK {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr)
	}
	if want := `{"body":{"password":"****"}}` + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if !strings.Contains(stderr, "secret-fields        1") {
		t.Errorf("summary is missing the secret-fields count:\n%s", stderr)
	}
}

// If the rules can't be loaded, nothing may be written to stdout.
func TestBadRulesWriteNothing(t *testing.T) {
	code, stdout, stderr := runRedactor(t, `{"body":{"password":"hunter2"}}`+"\n",
		"--rules", "does-not-exist.yaml")
	if code != exitError {
		t.Errorf("exit code %d, want %d", code, exitError)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty, got %q", stdout)
	}
	if !strings.Contains(stderr, "does-not-exist.yaml") {
		t.Errorf("stderr should name the missing file:\n%s", stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _, _ := runRedactor(t, "", "a.ndjson", "b.ndjson"); code != exitUsage {
		t.Errorf("two input files: exit code %d, want %d", code, exitUsage)
	}
	if code, _, _ := runRedactor(t, "", "--no-such-flag"); code != exitUsage {
		t.Errorf("unknown flag: exit code %d, want %d", code, exitUsage)
	}
	if code, _, _ := runRedactor(t, "", "missing.ndjson"); code != exitError {
		t.Errorf("missing input file: exit code %d, want %d", code, exitError)
	}
}

// The provided sample, end to end: every line produces one output line,
// broken lines are reported without their content, and running the tool on
// its own output changes nothing.
func TestSampleFile(t *testing.T) {
	code, first, stderr := runRedactor(t, "", "testdata/input.ndjson")
	if code != exitOK {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr)
	}

	if !strings.Contains(stderr, "48 lines, 3 rejected, 2 blank lines skipped") {
		t.Errorf("unexpected line counts in summary:\n%s", stderr)
	}
	// The sample has four JWTs outside the Authorization headers (lines 11,
	// 15 twice, and 16). The original rules.yaml only matched two of them.
	if !strings.Contains(stderr, "jwt                  4") {
		t.Errorf("expected 4 JWT redactions in summary:\n%s", stderr)
	}
	// Lines 20, 21 and 50 are broken. Their content must not be printed.
	for _, secret := range []string{"erin@example.com", "trunc@exam", "eyJzdWIi"} {
		if strings.Contains(stderr, secret) || strings.Contains(first, secret) {
			t.Errorf("%q from a rejected line was printed", secret)
		}
	}

	code, second, _ := runRedactor(t, first)
	if code != exitOK {
		t.Fatalf("second pass: exit code %d", code)
	}
	if second != first {
		t.Errorf("running on its own output changed it")
	}
}
