package imap

import (
	"errors"
	"strconv"
	"strings"
)

// parseLine splits an IMAP command line into tag, command, and the raw
// remainder containing arguments. The tag is everything up to the first
// space, the command is the next whitespace-delimited token, and rest is
// whatever follows (possibly empty).
func parseLine(line string) (tag, cmd, rest string, err error) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", "", "", errors.New("empty line")
	}
	sp := strings.IndexByte(line, ' ')
	if sp == -1 {
		return "", "", "", errors.New("missing command")
	}
	tag = line[:sp]
	rem := strings.TrimLeft(line[sp+1:], " ")
	sp = strings.IndexByte(rem, ' ')
	if sp == -1 {
		return tag, strings.ToUpper(rem), "", nil
	}
	return tag, strings.ToUpper(rem[:sp]), strings.TrimLeft(rem[sp+1:], " "), nil
}

// tokenize splits an argument string into atoms, treating "double quoted"
// substrings as one token (without the quotes) and parenthesised groups as
// a single token (with the parens preserved so callers can distinguish a
// list from an atom).
func tokenize(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		switch {
		case s[i] == ' ':
			i++
		case s[i] == '"':
			// quoted string — read until closing quote (no escapes here;
			// callers don't need them for the commands we support)
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			out = append(out, s[i+1:j])
			i = j + 1
		case s[i] == '(':
			// parenthesised group — track depth
			depth := 1
			j := i + 1
			for j < len(s) && depth > 0 {
				switch s[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
				if depth > 0 {
					j++
				}
			}
			out = append(out, s[i:j+1])
			i = j + 1
		default:
			// Atoms continue across bracketed FETCH section specs so that
			// "BODY.PEEK[HEADER.FIELDS (Subject From)]" stays one token.
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '(' {
				if s[j] == '[' {
					depth := 1
					j++
					for j < len(s) && depth > 0 {
						switch s[j] {
						case '[':
							depth++
						case ']':
							depth--
						}
						j++
					}
					continue
				}
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

// parenContents strips one layer of outer parens and returns the inside,
// or the original string if it isn't paren-wrapped.
func parenContents(s string) string {
	if len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseSequenceSet expands an IMAP sequence set like "1:3,5,7:*" into a
// slice of 1-based numbers. The "*" wildcard is replaced with maxN. UIDs
// not in [1, maxN] are silently skipped (IMAP-conformant behaviour).
//
// When useUID is true, numbers in the input are treated as UIDs and the
// resolver maps them to sequence numbers via uidToSeq; UIDs not in the
// session are skipped.
func parseSequenceSet(spec string, maxN int, useUID bool, uidToSeq func(uint32) (int, bool)) ([]int, error) {
	if spec == "" {
		return nil, errors.New("empty sequence set")
	}
	seen := make(map[int]struct{})
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var lo, hi int
		if c := strings.IndexByte(part, ':'); c >= 0 {
			a, b := part[:c], part[c+1:]
			x, err := parseSeqNum(a, maxN, useUID)
			if err != nil {
				return nil, err
			}
			y, err := parseSeqNum(b, maxN, useUID)
			if err != nil {
				return nil, err
			}
			if x > y {
				x, y = y, x
			}
			lo, hi = x, y
		} else {
			n, err := parseSeqNum(part, maxN, useUID)
			if err != nil {
				return nil, err
			}
			lo, hi = n, n
		}
		for n := lo; n <= hi; n++ {
			if useUID {
				seq, ok := uidToSeq(uint32(n))
				if !ok {
					continue
				}
				if _, dup := seen[seq]; dup {
					continue
				}
				seen[seq] = struct{}{}
				out = append(out, seq)
			} else {
				if n < 1 || n > maxN {
					continue
				}
				if _, dup := seen[n]; dup {
					continue
				}
				seen[n] = struct{}{}
				out = append(out, n)
			}
		}
	}
	return out, nil
}

func parseSeqNum(s string, maxN int, useUID bool) (int, error) {
	if s == "*" {
		if useUID {
			// for UID sets the upper bound is the highest assigned UID,
			// which the caller signals by passing it in maxN as a UID
			return maxN, nil
		}
		return maxN, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return n, nil
}
