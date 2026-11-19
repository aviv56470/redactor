package redact

// luhnValid reports whether s passes the Luhn checksum used by credit card
// numbers. Spaces and dashes are ignored, so "4111 1111 1111 1111" and
// "4111-1111-1111-1111" are checked as "4111111111111111".
// Any other non-digit character makes it invalid.
func luhnValid(s string) bool {
	sum := 0
	digits := 0
	double := false // the rightmost digit is never doubled

	// Walk the string from the last character to the first.
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}

		d := int(c - '0') // turn the character '7' into the number 7
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		digits++
		double = !double
	}

	return digits > 0 && sum%10 == 0
}
