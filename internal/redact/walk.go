package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxDepth limits how deeply objects and arrays may nest in one line, so a
// hostile line like [[[[[[... can't make the walker recurse forever.
const maxDepth = 1000

// Errors from RedactLine. Their messages contain none of the line's content,
// so they are safe to print.
var (
	errTooDeep      = errors.New("JSON nested too deeply")
	errTrailingData = errors.New("unexpected data after JSON value")
)

// location says which part of a transaction the walker is in.
type location int

const (
	inEnvelope location = iota // the transaction itself: ts, method, response, ...
	inHeaders                  // an HTTP headers object
	inBody                     // a request or response body
	inPath                     // the request path, including its query string
)

// RedactLine redacts one NDJSON line (without its trailing newline) and
// returns the redacted JSON. If the line isn't valid JSON it returns an error
// and no output, so a half-redacted line can never be written anywhere.
func (rd *Redactor) RedactLine(line []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber() // keep numbers exactly as written, e.g. 10.50 or 12345678901234567890

	w := newJSONWriter()
	if err := rd.walk(dec, w, inEnvelope, nil, 0); err != nil {
		return nil, err
	}

	// The line must contain exactly one JSON value. Anything after it
	// (other than spaces) means the line is broken.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errTrailingData
	}
	return w.buf.Bytes(), nil
}

// walk reads one JSON value from dec and writes its redacted form to w.
//
// loc says where the value is (envelope, headers or body). forced is the
// key rule that matched the key this value sits under, or nil. When it is
// set, every string and number inside the value gets that rule's action.
func (rd *Redactor) walk(dec *json.Decoder, w *jsonWriter, loc location, forced *KeyRule, depth int) error {
	if depth > maxDepth {
		return errTooDeep
	}

	tok, err := dec.Token()
	if err != nil {
		return err
	}

	switch t := tok.(type) {
	case json.Delim: // { or [
		switch t {
		case '{':
			return rd.walkObject(dec, w, loc, forced, depth)
		case '[':
			return rd.walkArray(dec, w, loc, forced, depth)
		}
		return fmt.Errorf("unexpected %q", t)

	case string:
		out, err := rd.redactText(t, loc, forced, depth)
		if err != nil {
			return err
		}
		w.writeString(out)

	case json.Number:
		s := string(t)
		if forced != nil {
			w.writeString(rd.applyKeyRule(forced, s))
		} else if out := rd.redactString(s); out != s {
			w.writeString(out) // e.g. a card number stored as a number: now it's text
		} else {
			w.buf.WriteString(s) // unchanged: copy the number exactly as written
		}

	case bool:
		// true and false can't hold a secret, so they're copied as they are.
		if t {
			w.buf.WriteString("true")
		} else {
			w.buf.WriteString("false")
		}

	case nil:
		w.buf.WriteString("null")

	default:
		return fmt.Errorf("unexpected JSON token of type %T", t)
	}
	return nil
}

// walkObject handles everything after an opening '{'.
func (rd *Redactor) walkObject(dec *json.Decoder, w *jsonWriter, loc location, forced *KeyRule, depth int) error {
	w.buf.WriteByte('{')
	first := true

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("object key is not a string")
		}

		rule := forced
		if rule == nil {
			rule = rd.matchKeyRule(key, loc)
		}

		if rule != nil && rule.Action == ActionRemove {
			// Drop the key and its whole value.
			if err := skipValue(dec); err != nil {
				return err
			}
			rd.counts[rule.Name]++
			continue
		}

		if !first {
			w.buf.WriteByte(',')
		}
		first = false

		w.writeString(rd.redactString(key)) // a key can contain an email too
		w.buf.WriteByte(':')
		if err := rd.walk(dec, w, childLocation(loc, key), rule, depth+1); err != nil {
			return err
		}
	}

	if _, err := dec.Token(); err != nil { // the closing '}'
		return err
	}
	w.buf.WriteByte('}')
	return nil
}

// walkArray handles everything after an opening '['.
func (rd *Redactor) walkArray(dec *json.Decoder, w *jsonWriter, loc location, forced *KeyRule, depth int) error {
	w.buf.WriteByte('[')

	for i := 0; dec.More(); i++ {
		if i > 0 {
			w.buf.WriteByte(',')
		}
		if err := rd.walk(dec, w, loc, forced, depth+1); err != nil {
			return err
		}
	}

	if _, err := dec.Token(); err != nil { // the closing ']'
		return err
	}
	w.buf.WriteByte(']')
	return nil
}

// childLocation decides where the value under key is. Only at the top of a
// transaction do "headers", "body" and "path" switch the location, so a
// field called "headers" inside a body is still just body data.
func childLocation(loc location, key string) location {
	if loc != inEnvelope {
		return loc
	}
	switch key {
	case "headers":
		return inHeaders
	case "body":
		return inBody
	case "path":
		return inPath
	}
	return inEnvelope
}

// matchKeyRule returns the first key rule that matches key, or nil.
// Everything outside a headers object counts as body for key rules, so an
// unexpected field next to "body" can't hide a password from the rules.
func (rd *Redactor) matchKeyRule(key string, loc location) *KeyRule {
	for i := range rd.rules.KeyRules {
		kr := &rd.rules.KeyRules[i]
		if kr.matchesKey(key, loc == inHeaders) {
			return kr
		}
	}
	return nil
}

// applyKeyRule applies a key rule's action to one value and counts it.
func (rd *Redactor) applyKeyRule(kr *KeyRule, value string) string {
	out := rd.rewrite(kr.Action, value)
	if out != value {
		rd.counts[kr.Name]++
	}
	return out
}

// skipValue reads one complete JSON value from dec and throws it away.
func skipValue(dec *json.Decoder) error {
	var discard json.RawMessage
	return dec.Decode(&discard)
}

// jsonWriter collects the output for one line.
type jsonWriter struct {
	buf bytes.Buffer
	enc *json.Encoder
}

func newJSONWriter() *jsonWriter {
	w := &jsonWriter{}
	w.enc = json.NewEncoder(&w.buf)
	// By default Go writes < > & as escape codes (\u003c, \u003e, \u0026)
	// so the JSON is safe to paste into HTML. Logs aren't HTML, so keep
	// "Tom & Jerry" exactly as it was written.
	w.enc.SetEscapeHTML(false)
	return w
}

// writeString writes s as a quoted, escaped JSON string.
func (w *jsonWriter) writeString(s string) {
	_ = w.enc.Encode(s)             // encoding a string can't fail
	w.buf.Truncate(w.buf.Len() - 1) // Encode adds a newline at the end; remove it
}
