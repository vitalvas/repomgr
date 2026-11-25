package rpmrepo

import "strings"

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// charAt returns 0 past the end, like the terminating NUL of a C string.
func charAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}

	return 0
}

// skipSeparators returns the index of the first alphanumeric, "~", or "^"
// byte of s at or after i.
func skipSeparators(s string, i int) int {
	for i < len(s) && !isDigit(s[i]) && !isAlpha(s[i]) && s[i] != '~' && s[i] != '^' {
		i++
	}

	return i
}

// compareSeparator handles "~" and "^" at the current bytes, 0 meaning the
// end. sep is false when neither byte is one; otherwise a non-zero rc ends the
// comparison and a zero rc steps past both separators.
func compareSeparator(ca, cb byte) (rc int, sep bool) {
	switch {
	// A tilde sorts before everything else.
	case ca == '~' && cb == '~':
		return 0, true
	case ca == '~':
		return -1, true
	case cb == '~':
		return 1, true
	case ca != '^' && cb != '^':
		return 0, false
	// A caret sorts like a tilde, except that a version ending here is lower.
	case ca == 0:
		return -1, true
	case cb == 0:
		return 1, true
	case ca != '^':
		return 1, true
	case cb != '^':
		return -1, true
	}

	return 0, true
}

// compareSegment compares two non-empty segments of the same class. A longer
// number without leading zeros is higher; otherwise bytes decide.
func compareSegment(one, two string, numeric bool) int {
	if numeric {
		one = strings.TrimLeft(one, "0")
		two = strings.TrimLeft(two, "0")

		if len(one) > len(two) {
			return 1
		}

		if len(one) < len(two) {
			return -1
		}
	}

	return strings.Compare(one, two)
}

// rpmvercmp is rpmvercmp from rpm 4.14.3 lib/rpmvercmp.c: 1 when a is newer,
// 0 when equal, -1 when b is newer. Character classes are ASCII only.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}

	i, j := 0, 0

	for i < len(a) || j < len(b) {
		i = skipSeparators(a, i)
		j = skipSeparators(b, j)
		ca, cb := charAt(a, i), charAt(b, j)

		if rc, sep := compareSeparator(ca, cb); sep {
			if rc != 0 {
				return rc
			}

			i++
			j++

			continue
		}

		if ca == 0 || cb == 0 {
			break
		}

		numeric := isDigit(ca)

		class := isAlpha
		if numeric {
			class = isDigit
		}

		ei, ej := i, j
		for ei < len(a) && class(a[ei]) {
			ei++
		}

		for ej < len(b) && class(b[ej]) {
			ej++
		}

		// A numeric segment is newer than an alpha one.
		if ej == j {
			if numeric {
				return 1
			}

			return -1
		}

		if rc := compareSegment(a[i:ei], b[j:ej], numeric); rc != 0 {
			return rc
		}

		i, j = ei, ej
	}

	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}
