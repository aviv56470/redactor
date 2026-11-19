package redact

import "testing"

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"visa test card", "4111111111111111", true},
		{"one digit changed", "4111111111111112", false},
		{"mastercard", "5555555555554444", true},
		{"amex, 15 digits", "378282246310005", true},
		{"diners, 14 digits", "30569309025904", true},
		{"discover", "6011111111111117", true},
		{"with spaces", "4111 1111 1111 1111", true},
		{"with dashes", "5555-5555-5555-4444", true},
		{"amex grouping", "3782 822463 10005", true},
		{"timestamp from sample data", "1705312800123456", false},
		{"empty string", "", false},
		{"only separators", " - ", false},
		{"contains a letter", "4111a11111111111", false},
		{"non-ASCII digit", "４111111111111111", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := luhnValid(tc.input)
			if got != tc.want {
				t.Errorf("luhnValid(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
