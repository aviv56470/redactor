package redact

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// formData matches text made only of form-encoded pairs, like "a=1&b=2"
// (the format browsers use to submit HTML forms). Spaces and a bare "=" inside
// a value are not allowed, so an ordinary sentence ("a = b") or base64 padding
// ("QUJD==") isn't mistaken for form data.
var formData = regexp.MustCompile(`^[^=&\s]+=[^=&\s]*(?:&[^=&\s]+=[^=&\s]*)*$`)

// redactText redacts one string, choosing how by where the string is.
func (rd *Redactor) redactText(s string, loc location, forced *KeyRule, depth int) (string, error) {
	switch {
	case forced != nil:
		return rd.applyKeyRule(forced, s), nil
	case loc == inBody:
		return rd.redactBodyString(s, depth)
	case loc == inPath:
		return rd.redactPath(s), nil
	default:
		return rd.redactString(s), nil
	}
}

// redactBodyString redacts a string inside a body. A body string often has
// a structure of its own, so this tries, in order:
//  1. JSON stored inside the string:  "{\"password\":\"x\"}"
//  2. form data:                      "email=a%40b.com&password=x"
//  3. plain text, where only the value rules apply.
func (rd *Redactor) redactBodyString(s string, depth int) (string, error) {
	switch {
	case isJSONContainer(s):
		return rd.redactJSONText(s, depth)
	case formData.MatchString(s):
		return rd.redactForm(s), nil
	default:
		return rd.redactString(s), nil
	}
}

// isJSONContainer reports whether s is a complete, valid JSON object or array.
func isJSONContainer(s string) bool {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return false
	}
	return json.Valid([]byte(t))
}

// redactJSONText redacts JSON that was stored inside a string, with body
// rules, and returns it as compact JSON text. depth carries on from the
// outer line, so JSON hidden inside JSON inside JSON still counts towards
// maxDepth.
func (rd *Redactor) redactJSONText(s string, depth int) (string, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	w := newJSONWriter()
	if err := rd.walk(dec, w, inBody, nil, depth+1); err != nil {
		return "", err
	}
	return w.buf.String(), nil
}

// redactForm redacts form data such as "email=a%40b.com&password=x".
// Each pair is decoded first ("a%40b.com" becomes "a@b.com"), then the key
// rules (as body keys) and value rules are applied. Pairs that don't change
// are kept exactly as they were written.
func (rd *Redactor) redactForm(s string) string {
	pairs := strings.Split(s, "&")
	kept := make([]string, 0, len(pairs))

	for _, pair := range pairs {
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, keyErr := url.QueryUnescape(rawKey)
		value, valueErr := url.QueryUnescape(rawValue)
		if keyErr != nil || valueErr != nil {
			// Broken encoding such as "%zz": treat this pair as plain text.
			kept = append(kept, rd.redactString(pair))
			continue
		}

		rule := rd.matchKeyRule(key, inBody)
		if rule != nil && rule.Action == ActionRemove {
			rd.counts[rule.Name]++
			continue // drop the whole pair
		}

		var out string
		if rule != nil {
			out = rd.applyKeyRule(rule, value)
		} else {
			out = rd.redactString(value)
		}

		if out == value {
			kept = append(kept, pair) // unchanged: keep the original text
		} else {
			kept = append(kept, rawKey+"="+escapeFormValue(out))
		}
	}
	return strings.Join(kept, "&")
}

// escapeFormValue encodes a redacted value for form data. url.QueryEscape
// would turn "*" into "%2A" and ":" into "%3A"; both are allowed in form
// values, so they're kept readable ("****", "sha256:...").
func escapeFormValue(s string) string {
	escaped := url.QueryEscape(s)
	return strings.NewReplacer("%2A", "*", "%3A", ":").Replace(escaped)
}

// redactPath redacts a request path such as "/v1/reset?token=x&email=a%40b.com".
// The part before "?" gets the value rules. The query string after it is
// redacted like form data, so a parameter called "token" gets the same key
// rule as a body field called "token". (Browsers never send the "#..." part
// of a URL to the server, so a logged path has no fragment to worry about.)
func (rd *Redactor) redactPath(s string) string {
	path, query, hasQuery := strings.Cut(s, "?")
	path = rd.redactString(path)
	if !hasQuery {
		return path
	}

	if formData.MatchString(query) {
		query = rd.redactForm(query)
	} else {
		query = rd.redactString(query) // e.g. "q=x&debug": not clean pairs, so plain text
	}
	return path + "?" + query
}
