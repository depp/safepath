// Package safepath tests whether paths are safe to use.
//
// Safe can be passed to shell scripts, used as URIs, or stored as files on
// Windows without any special handling or escaping.
package safepath

import (
	"regexp"
	"strings"
)

var (
	safe   = regexp.MustCompile("^[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*$")
	unsafe = regexp.MustCompile(
		`^(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.[^.]*)?$`)
)

// IsSafeSegment returns true if the given string is a safe path segment.
//
// - Only contains alphanumeric characters and "-", ".", "_".
// - Must begin and end with alphanumeric character.
// - Cannot have two consecutive non-alphanumeric characters.
// - Cannot be a forbidden filename on Windows.
//
// Forbidden filenames on Windows are con, prn, aux, nul, com[1-9], and
// lpt[1-9].
func IsSafeSegment(name string) bool {
	return safe.MatchString(name) && !unsafe.MatchString(name)
}

// IsSafePath returns true if the given path is a safe path. A safe path
// consists of a non-empty list of safe segments separated by slashes.
func IsSafePath(name string) bool {
	for {
		if name == "" {
			return false
		}
		i := strings.IndexByte(name, '/')
		if i == -1 {
			return IsSafeSegment(name)
		}
		if !IsSafeSegment(name[:i]) {
			return false
		}
		name = name[i+1:]
	}
}
