package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"regexp"
	"strings"
)

// hashPrefix marks values produced by the hash action, e.g. "sha256:ba78...".
const hashPrefix = "sha256:"

// hashedValue matches the output of the hash action. Values that already
// look like this are not hashed again, which keeps redaction idempotent.
var hashedValue = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Redactor applies a set of rules and counts what it changed.
// A Redactor is not safe for use by several goroutines at once.
type Redactor struct {
	rules        *Rules
	counts       map[string]int // rule name -> number of values changed
	maxLineBytes int            // longest line Process will hold in memory
}

// NewRedactor returns a Redactor that applies the given rules.
func NewRedactor(rules *Rules) *Redactor {
	return &Redactor{
		rules:        rules,
		counts:       make(map[string]int),
		maxLineBytes: DefaultMaxLineBytes,
	}
}

// Counts returns how many values each rule has changed so far.
// It returns a copy, so callers can't modify the Redactor's own counts.
func (rd *Redactor) Counts() map[string]int {
	return maps.Clone(rd.counts)
}

// redactString applies every value rule to s, in the order they appear in
// the rules file. Each rule sees the result of the rules before it.
func (rd *Redactor) redactString(s string) string {
	for i := range rd.rules.ValueRules {
		vr := &rd.rules.ValueRules[i]
		s = vr.re.ReplaceAllStringFunc(s, func(match string) string {
			if vr.Validator == "luhn" && !luhnValid(match) {
				return match // looks like a card number, but isn't one
			}
			out := rd.rewrite(vr.Action, match)
			if out != match {
				rd.counts[vr.Name]++
			}
			return out
		})
	}
	return s
}

// rewrite applies one action to a sensitive value and returns the result.
func (rd *Redactor) rewrite(action, value string) string {
	if value == "" {
		return value // nothing to hide
	}

	switch action {
	case ActionMask:
		return rd.rules.Settings.Mask.Replacement
	case ActionPartial:
		return partial(value, rd.rules.Settings.Partial)
	case ActionHash:
		if hashedValue.MatchString(value) {
			return value // already hashed; hashing again would change it
		}
		sum := sha256.Sum256([]byte(value))
		return hashPrefix + hex.EncodeToString(sum[:])
	case ActionRemove:
		return ""
	}

	// Unreachable, because actions are checked when the rules are loaded.
	// If it ever happens, hide the value rather than leak it.
	return rd.rules.Settings.Mask.Replacement
}

// partial keeps the last p.KeepLast characters of value and replaces the
// rest with p.Fill. A value too short to hide anything is replaced entirely.
func partial(value string, p PartialSettings) string {
	runes := []rune(value) // characters, not bytes, so "כרטיס" isn't cut mid-letter
	keep := p.KeepLast
	if len(runes) <= keep {
		keep = 0
	}
	hidden := len(runes) - keep
	return strings.Repeat(p.Fill, hidden) + string(runes[hidden:])
}
