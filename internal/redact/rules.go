package redact

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// The actions a rule can take on a sensitive value.
const (
	ActionMask    = "mask"
	ActionPartial = "partial"
	ActionHash    = "hash"
	ActionRemove  = "remove"
)

// Where a key rule applies.
const (
	ScopeHeaders = "headers"
	ScopeBody    = "body"
	ScopeAny     = "any"
)

// Rules is the parsed and validated content of a rules file.
type Rules struct {
	Version    int         `yaml:"version"`
	Settings   Settings    `yaml:"settings"`
	KeyRules   []KeyRule   `yaml:"key_rules"`
	ValueRules []ValueRule `yaml:"value_rules"`
}

// Settings configures how each action rewrites a value.
type Settings struct {
	Mask    MaskSettings    `yaml:"mask"`
	Partial PartialSettings `yaml:"partial"`
	Hash    HashSettings    `yaml:"hash"`
}

type MaskSettings struct {
	Replacement string `yaml:"replacement"`
}

type PartialSettings struct {
	KeepLast int    `yaml:"keep_last"`
	Fill     string `yaml:"fill"`
}

type HashSettings struct {
	Algorithm string `yaml:"algorithm"`
}

// KeyRule matches on the name of a JSON key or HTTP header.
type KeyRule struct {
	Name   string   `yaml:"name"`
	Scope  string   `yaml:"scope"`
	Match  KeyMatch `yaml:"match"`
	Action string   `yaml:"action"`

	// Filled in by compile(), not read from YAML.
	exact map[string]bool // lower-cased names from Match.Exact
	re    *regexp.Regexp  // compiled Match.Regex
}

// KeyMatch holds exactly one of Exact or Regex.
type KeyMatch struct {
	Exact []string `yaml:"exact"`
	Regex string   `yaml:"regex"`
}

// ValueRule matches on the content of a string, whatever its key is called.
type ValueRule struct {
	Name      string `yaml:"name"`
	Pattern   string `yaml:"pattern"`
	Validator string `yaml:"validator"`
	Action    string `yaml:"action"`

	re *regexp.Regexp // compiled Pattern, filled in by compile()
}

// LoadRules reads, parses and validates a rules file.
func LoadRules(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file: %w", err)
	}
	return ParseRules(data)
}

// ParseRules parses and validates rules from YAML. Unknown fields are
// rejected, so a typo such as "pattren" is an error instead of a rule
// that silently does nothing.
func ParseRules(data []byte) (*Rules, error) {
	var r Rules
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("rules file is empty")
		}
		return nil, fmt.Errorf("parsing rules: %w", err)
	}
	if err := r.validate(); err != nil {
		return nil, fmt.Errorf("invalid rules: %w", err)
	}
	return &r, nil
}

// validate checks the whole file and compiles every rule.
func (r *Rules) validate() error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported version %d (want 1)", r.Version)
	}
	if err := r.Settings.validate(); err != nil {
		return err
	}
	if len(r.KeyRules) == 0 && len(r.ValueRules) == 0 {
		return errors.New("no rules defined")
	}

	seen := map[string]bool{} // rule names must be unique: the summary counts by name
	for i := range r.KeyRules {
		kr := &r.KeyRules[i]
		if err := checkName(kr.Name, seen); err != nil {
			return fmt.Errorf("key rule #%d: %w", i+1, err)
		}
		if err := kr.compile(); err != nil {
			return fmt.Errorf("key rule %q: %w", kr.Name, err)
		}
	}
	for i := range r.ValueRules {
		vr := &r.ValueRules[i]
		if err := checkName(vr.Name, seen); err != nil {
			return fmt.Errorf("value rule #%d: %w", i+1, err)
		}
		if err := vr.compile(); err != nil {
			return fmt.Errorf("value rule %q: %w", vr.Name, err)
		}
	}
	return nil
}

func (s *Settings) validate() error {
	if s.Mask.Replacement == "" {
		return errors.New("settings.mask.replacement must not be empty")
	}
	if s.Partial.KeepLast < 0 {
		return errors.New("settings.partial.keep_last must not be negative")
	}
	if utf8.RuneCountInString(s.Partial.Fill) != 1 {
		return errors.New("settings.partial.fill must be exactly one character")
	}
	if s.Hash.Algorithm != "sha256" {
		return fmt.Errorf("settings.hash.algorithm %q is not supported (want sha256)", s.Hash.Algorithm)
	}
	return nil
}

// compile validates a key rule and prepares it for fast matching.
func (kr *KeyRule) compile() error {
	switch kr.Scope {
	case ScopeHeaders, ScopeBody, ScopeAny:
		// ok
	default:
		return fmt.Errorf("unknown scope %q (want headers, body or any)", kr.Scope)
	}
	if err := checkAction(kr.Action); err != nil {
		return err
	}

	hasExact := len(kr.Match.Exact) > 0
	hasRegex := kr.Match.Regex != ""
	if hasExact == hasRegex {
		return errors.New("match needs exactly one of exact or regex")
	}

	if hasExact {
		kr.exact = make(map[string]bool, len(kr.Match.Exact))
		for _, name := range kr.Match.Exact {
			kr.exact[strings.ToLower(name)] = true
		}
		return nil
	}

	re, err := regexp.Compile(kr.Match.Regex)
	if err != nil {
		return fmt.Errorf("bad regex: %w", err)
	}
	kr.re = re
	return nil
}

// matchesKey reports whether this rule applies to a key called name.
// inHeaders is true for HTTP header names and false for keys in a body.
// Exact names are compared case-insensitively, because HTTP header names
// are case-insensitive ("authorization" is the same header as "Authorization").
func (kr *KeyRule) matchesKey(name string, inHeaders bool) bool {
	switch kr.Scope {
	case ScopeHeaders:
		if !inHeaders {
			return false
		}
	case ScopeBody:
		if inHeaders {
			return false
		}
	}

	if kr.exact != nil {
		return kr.exact[strings.ToLower(name)]
	}
	return kr.re.MatchString(name)
}

// compile validates a value rule and compiles its pattern.
func (vr *ValueRule) compile() error {
	if err := checkAction(vr.Action); err != nil {
		return err
	}
	switch vr.Validator {
	case "", "luhn":
		// ok: no validator, or one we support
	default:
		return fmt.Errorf("unknown validator %q (supported: luhn)", vr.Validator)
	}
	if vr.Pattern == "" {
		return errors.New("pattern must not be empty")
	}

	re, err := regexp.Compile(vr.Pattern)
	if err != nil {
		return fmt.Errorf("bad pattern: %w", err)
	}
	if re.MatchString("") {
		// A pattern that matches empty text would "redact" the gaps
		// between every character.
		return errors.New("pattern must not match empty text")
	}
	vr.re = re
	return nil
}

func checkAction(action string) error {
	switch action {
	case ActionMask, ActionPartial, ActionHash, ActionRemove:
		return nil
	}
	return fmt.Errorf("unknown action %q (want mask, partial, hash or remove)", action)
}

func checkName(name string, seen map[string]bool) error {
	if name == "" {
		return errors.New("missing name")
	}
	if seen[name] {
		return fmt.Errorf("duplicate rule name %q", name)
	}
	seen[name] = true
	return nil
}
