// Command redactor removes sensitive data from NDJSON API traffic logs.
//
// Usage:
//
//	redactor [--rules rules.yaml] [input-file]
//
// It reads standard input when no file is given, writes the redacted lines
// to standard output, and prints a summary to standard error.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/aviv56470/redactor/internal/redact"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1 // the rules or the input couldn't be read, or writing failed
	exitUsage = 2 // the command line was wrong
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the whole program. It takes its arguments and streams as
// parameters instead of using os.Args and os.Stdin directly, so tests can
// call it with their own input and check what it printed.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("redactor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: redactor [--rules rules.yaml] [input-file]")
		flags.PrintDefaults()
	}
	rulesPath := flags.String("rules", "rules.yaml", "path to the rules file")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	// Load the rules before reading any input. If they can't be loaded,
	// stop here: nothing is written to stdout, so nothing passes through
	// unredacted.
	rules, err := redact.LoadRules(*rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "redactor: %v\n", err)
		return exitError
	}

	input := stdin
	switch flags.NArg() {
	case 0:
		// no file given: read standard input
	case 1:
		f, err := os.Open(flags.Arg(0))
		if err != nil {
			fmt.Fprintf(stderr, "redactor: %v\n", err)
			return exitError
		}
		defer f.Close()
		input = f
	default:
		flags.Usage()
		return exitUsage
	}

	rd := redact.NewRedactor(rules)
	report := func(line int, reason string) {
		fmt.Fprintf(stderr, "redactor: line %d rejected: %s\n", line, reason)
	}
	stats, err := rd.Process(input, stdout, report)
	printSummary(stderr, rules, stats, rd.Counts())
	if err != nil {
		fmt.Fprintf(stderr, "redactor: %v\n", err)
		return exitError
	}
	return exitOK
}

// printSummary writes the line counts and the number of redactions made by
// each rule, in the order the rules appear in the rules file. Rules that
// never matched are listed too: a 0 can be a sign that a rule is broken.
func printSummary(w io.Writer, rules *redact.Rules, stats redact.Stats, counts map[string]int) {
	fmt.Fprintf(w, "redactor: %d lines, %d rejected, %d blank lines skipped\n",
		stats.Lines, stats.Rejected, stats.Blank)
	fmt.Fprintln(w, "redactor: redactions per rule:")
	for _, kr := range rules.KeyRules {
		fmt.Fprintf(w, "  %-20s %d\n", kr.Name, counts[kr.Name])
	}
	for _, vr := range rules.ValueRules {
		fmt.Fprintf(w, "  %-20s %d\n", vr.Name, counts[vr.Name])
	}
}
