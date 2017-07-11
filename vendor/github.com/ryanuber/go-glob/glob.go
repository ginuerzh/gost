package glob

import "strings"

// The character which is treated like a glob
const GLOB = "*"

// Glob will test a string pattern, potentially containing globs, against a
// subject string. The result is a simple true/false, determining whether or
// not the glob pattern matched the subject text.
func Glob(pattern, subj string) bool {
	// Empty pattern can only match empty subject
	if pattern == "" {
		return subj == pattern
	}

	// If the pattern _is_ a glob, it matches everything
	if pattern == GLOB {
		return true
	}

	parts := strings.Split(pattern, GLOB)

	if len(parts) == 1 {
		// No globs in pattern, so test for equality
		return subj == pattern
	}

	leadingGlob := strings.HasPrefix(pattern, GLOB)
	trailingGlob := strings.HasSuffix(pattern, GLOB)
	end := len(parts) - 1

	for i, part := range parts {
		switch i {
		case 0:
			if leadingGlob {
				continue
			}
			if !strings.HasPrefix(subj, part) {
				return false
			}
		case end:
			if len(subj) > 0 {
				return trailingGlob || strings.HasSuffix(subj, part)
			}
		default:
			if !strings.Contains(subj, part) {
				return false
			}
		}

		// Trim evaluated text from subj as we loop over the pattern.
		idx := strings.Index(subj, part) + len(part)
		subj = subj[idx:]
	}

	// All parts of the pattern matched
	return true
}
