package redact

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DefaultMaxLineBytes is the longest line Process will hold in memory.
// A longer line is skipped and reported instead of being read whole.
const DefaultMaxLineBytes = 16 << 20 // 16 MiB

// errTooLong is returned by readLine for a line over the size limit.
var errTooLong = errors.New("line too long")

// Stats counts what Process did with the input lines.
type Stats struct {
	Lines    int // non-blank lines read
	Rejected int // lines that couldn't be redacted and were replaced by an error record
	Blank    int // empty or whitespace-only lines, which are dropped
}

// Process reads NDJSON from in and writes redacted NDJSON to out.
//
// It handles one line at a time, so memory use depends on the longest line
// (at most rd.maxLineBytes), not on the size of the input. A line that can't
// be redacted is replaced by a small error record, for example
// {"redactor_error":"truncated JSON","line":20}, and report is called with
// the line number and the same reason. Neither ever contains the line itself.
func (rd *Redactor) Process(in io.Reader, out io.Writer, report func(line int, reason string)) (Stats, error) {
	var stats Stats
	br := bufio.NewReader(in)
	bw := bufio.NewWriter(out)

	for lineNo := 1; ; lineNo++ {
		line, readErr := readLine(br, rd.maxLineBytes)
		if readErr == io.EOF {
			break // no more input
		}
		if readErr != nil && readErr != errTooLong {
			return stats, fmt.Errorf("reading input: %w", readErr)
		}

		if readErr == nil && len(bytes.TrimSpace(line)) == 0 {
			stats.Blank++
			continue // a blank line has no data to keep
		}
		stats.Lines++

		var output []byte
		lineErr := readErr // errTooLong, or nil
		if lineErr == nil {
			output, lineErr = rd.RedactLine(line)
		}
		if lineErr != nil {
			stats.Rejected++
			reason := safeReason(lineErr)
			if report != nil {
				report(lineNo, reason)
			}
			output = errorRecord(lineNo, reason)
		}

		if _, err := bw.Write(output); err != nil {
			return stats, fmt.Errorf("writing output: %w", err)
		}
		if err := bw.WriteByte('\n'); err != nil {
			return stats, fmt.Errorf("writing output: %w", err)
		}
	}

	if err := bw.Flush(); err != nil {
		return stats, fmt.Errorf("writing output: %w", err)
	}
	return stats, nil
}

// readLine returns the next line from br without its line ending ("\n" or
// "\r\n"), or io.EOF when there are no more lines. A line longer than max
// bytes is read to its end but not kept, and readLine returns errTooLong.
// So memory never holds more than about max bytes of one line.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	tooLong := false

	for {
		chunk, err := br.ReadSlice('\n')
		switch {
		case tooLong:
			// Already over the limit: keep reading to the end of the line,
			// but don't store any of it.
		case len(line)+len(chunk) > max+2: // +2 leaves room for "\r\n"
			tooLong, line = true, nil
		default:
			line = append(line, chunk...)
		}

		if err == bufio.ErrBufferFull {
			continue // the line is longer than br's buffer: read the next piece
		}
		if err == io.EOF && len(line) == 0 && !tooLong {
			return nil, io.EOF
		}
		if err != nil && err != io.EOF {
			return nil, err
		}

		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if tooLong || len(line) > max {
			return nil, errTooLong
		}
		return line, nil
	}
}

// safeReason turns a line's error into a short reason that is safe to print.
// Errors from the JSON decoder can quote a character from the input, so only
// reasons from this fixed list are ever shown.
func safeReason(err error) string {
	var syntaxErr *json.SyntaxError
	switch {
	case errors.Is(err, errTooLong):
		return "line too long"
	case errors.Is(err, errTooDeep):
		return "JSON nested too deeply"
	case errors.Is(err, errTrailingData):
		return "unexpected data after JSON value"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "truncated JSON"
	case errors.As(err, &syntaxErr):
		return fmt.Sprintf("invalid JSON at byte %d", syntaxErr.Offset)
	default:
		return "invalid JSON"
	}
}

// errorRecord is written in place of a line that couldn't be redacted. The
// output stays valid NDJSON, and the gap stays visible to whoever reads it.
func errorRecord(line int, reason string) []byte {
	record := struct {
		Error string `json:"redactor_error"`
		Line  int    `json:"line"`
	}{reason, line}

	b, _ := json.Marshal(record) // a struct of a string and an int can't fail
	return b
}
