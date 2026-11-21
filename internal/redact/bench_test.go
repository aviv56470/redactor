package redact

import (
	"bufio"
	"os"
	"testing"
)

// BenchmarkRedactLine measures how long the engine takes per line, using the
// lines of the provided sample. Run it with:
//
//	go test -bench . -benchmem ./internal/redact/
//
// To see where the time goes, add -cpuprofile cpu.out and then run
// go tool pprof -top -cum cpu.out
func BenchmarkRedactLine(b *testing.B) {
	rules, err := LoadRules("../../rules.yaml")
	if err != nil {
		b.Fatal(err)
	}

	f, err := os.Open("../../testdata/input.ndjson")
	if err != nil {
		b.Fatal(err)
	}
	var lines [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, append([]byte(nil), scanner.Bytes()...))
	}
	f.Close()
	// Scan stops at the first read error (or a line over 64 KB) without
	// saying so; Err tells us whether that happened.
	if err := scanner.Err(); err != nil {
		b.Fatal(err)
	}

	rd := NewRedactor(rules)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			_, _ = rd.RedactLine(line)
		}
	}

	// The default ns/op is for all the sample lines together; this is per line.
	perLine := float64(b.Elapsed().Microseconds()) / float64(b.N*len(lines))
	b.ReportMetric(perLine, "us/line")
}
