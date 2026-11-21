package redact

import "testing"

func TestRedactStructuredStrings(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Form data in a body
		{"form body",
			`{"body":"email=bob%40example.com&password=hunter2&card=4111111111111111&remember=on"}`,
			`{"body":"email=****&password=****&card=************1111&remember=on"}`},
		{"form pair removed",
			`{"body":"a=1&cvv=123&b=2"}`,
			`{"body":"a=1&b=2"}`},
		{"form first pair removed",
			`{"body":"cvv=123&a=1"}`,
			`{"body":"a=1"}`},
		{"unchanged pairs keep their encoding",
			`{"body":"q=hello+world&x=%7E"}`,
			`{"body":"q=hello+world&x=%7E"}`},
		{"broken encoding falls back to plain text for that pair",
			`{"body":"a=%zz&password=x"}`,
			`{"body":"a=%zz&password=****"}`},
		{"a sentence with = is not form data",
			`{"body":"a = b & c = d"}`,
			`{"body":"a = b & c = d"}`},
		{"base64 padding is not form data",
			`{"body":"UEsDBBQAAAAIAA=="}`,
			`{"body":"UEsDBBQAAAAIAA=="}`},

		// JSON stored inside a string
		{"JSON object in a body string",
			`{"body":"{\"email\":\"carol@example.com\",\"password\":\"p@ssw0rd!\",\"profile\":{\"card\":\"5555555555554444\"}}"}`,
			`{"body":"{\"email\":\"****\",\"password\":\"****\",\"profile\":{\"card\":\"************4444\"}}"}`},
		{"JSON array in a body string",
			`{"body":"[\"a@b.com\",1]"}`,
			`{"body":"[\"****\",1]"}`},
		{"JSON string deeper inside a response body",
			`{"response":{"body":{"raw":"{\"token\":\"t\"}"}}}`,
			`{"response":{"body":{"raw":"{\"token\":\"****\"}"}}}`},
		{"JSON inside JSON inside JSON",
			`{"body":"{\"inner\":\"{\\\"password\\\":\\\"x\\\"}\"}"}`,
			`{"body":"{\"inner\":\"{\\\"password\\\":\\\"****\\\"}\"}"}`},
		{"text that only starts like JSON",
			`{"body":"[note] call a@b.com"}`,
			`{"body":"[note] call ****"}`},

		// Plain text
		{"plain text body",
			`{"body":"Hi team, reset a@b.com. Key: sk_live_abc123"}`,
			`{"body":"Hi team, reset ****. Key: ****"}`},

		// The request path and its query string
		{"query string",
			`{"path":"/v1/reset?token=abc123def456&email=gina%40example.com"}`,
			`{"path":"/v1/reset?token=****&email=****"}`},
		{"value inside the path itself",
			`{"path":"/users/a@b.com/profile"}`,
			`{"path":"/users/****/profile"}`},
		{"query that isn't clean pairs still gets value rules",
			`{"path":"/search?q=a@b.com&debug"}`,
			`{"path":"/search?q=****&debug"}`},
		{"a field called path inside a body is body data",
			`{"body":{"path":"a=1&password=x"}}`,
			`{"body":{"path":"a=1&password=****"}}`},
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

func TestEscapeFormValue(t *testing.T) {
	tests := []struct{ input, want string }{
		{"****", "****"},
		{"************1111", "************1111"},
		{"sha256:ab12", "sha256:ab12"},
		{"a b&c=d", "a+b%26c%3Dd"},
	}
	for _, tc := range tests {
		if got := escapeFormValue(tc.input); got != tc.want {
			t.Errorf("escapeFormValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
