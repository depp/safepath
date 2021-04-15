// Package safepath tests whether paths are safe to use.
//
// Safe can be passed to shell scripts, used as URIs, or stored as files on
// Windows without any special handling or escaping.
package safepath

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A Rules is a set of restrictions for file names. Rules are bitflags, and
// applying more bitflags applies stricter rules.
type Rules uint8

const (
	// URLUnescaped requires that paths do not need hex escaping in URLs.
	URLUnescaped Rules = 1 << iota
	// ShellSafe requires that paths are safe for use in a POSIX shell.
	ShellSafe
	// WindowsSafe requires that paths are safe for Windows filesystems.
	WindowsSafe
	// NotHidden requires that paths do not start with a period.
	NotHidden
	// laxRules are rules that always apply.
	laxRules
	// Strict is the strictest set of rules.
	Strict = URLUnescaped | ShellSafe | WindowsSafe | NotHidden
)

// GoString implements the GoStringer interface.
func (r Rules) GoString() string {
	var s []string
	if r&URLUnescaped != 0 {
		r &^= URLUnescaped
		s = append(s, "URLUnescaped")
	}
	if r&ShellSafe != 0 {
		r &^= ShellSafe
		s = append(s, "ShellSafe")
	}
	if r&WindowsSafe != 0 {
		r &^= WindowsSafe
		s = append(s, "WindowsSafe")
	}
	if r&NotHidden != 0 {
		r &^= NotHidden
		s = append(s, "NotHidden")
	}
	if r == 0 {
		if len(s) == 0 {
			return "0"
		}
		return strings.Join(s, "|")
	}
	s = append(s, fmt.Sprintf("0x%02x", r))
	return strings.Join(s, "|")
}

var flags [128]Rules
var windowsReserved map[string]bool

func init() {
	const strict = Strict | laxRules
	for c := 1; c <= 127; c++ {
		flags[c] = laxRules
	}
	// Alphanumerics are always safe.
	for c := '0'; c <= '9'; c++ {
		flags[c] = strict
	}
	for c := 'a'; c <= 'z'; c++ {
		flags[c] = strict
	}
	for c := 'A'; c <= 'Z'; c++ {
		flags[c] = strict
	}
	// Shell and Windows use blacklist, URLUnescaped uses whitelist.
	for c := 33; c <= 126; c++ {
		flags[c] |= ShellSafe | WindowsSafe
	}
	flags['/'] = 0

	// RFC 3986 section 3.3
	// https://tools.ietf.org/html/rfc3986#section-3.3
	// pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
	// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
	// sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
	//               / "*" / "+" / "," / ";" / "="
	// Colon is disallowed in the first segment of a relative path, so we
	// disallow it everywher.
	for _, c := range "-._~!$&'()*+,;=" {
		flags[c] |= URLUnescaped
	}

	// IEEE Std1003.1-2017 section C.2 Shell Command Language
	// https://pubs.opengroup.org/onlinepubs/9699919799/xrat/V4_xcu_chap02.html
	// Needs quoting: "|" / "&" / ";" / "<" / ">" / "(" / ")" / "$" / "`" / "\" / <"> / "'"
	for _, c := range "|&;<>()$`\\\"'" {
		flags[c] &^= ShellSafe
	}

	// MSDN: Naming Files, Paths, and Namespaces
	// https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file
	// Needs quoting: "<" / ">" / ":" / """ / "/" / "\" / "|" / "?" / "*"
	flags[' '] |= WindowsSafe
	for _, c := range "<>:\"/\\|?*" {
		flags[c] &^= WindowsSafe
	}
	windowsReserved = make(map[string]bool, 4+9*2)
	for _, name := range []string{"con", "prn", "aux", "nul"} {
		windowsReserved[name] = true
	}
	for _, name := range []string{"com", "lpt"} {
		for i := 1; i <= 9; i++ {
			windowsReserved[name+strconv.Itoa(i)] = true
		}
	}
}

const (
	// Path segment errors.
	errBad = iota
	errFirst
	errLast
	errAny
	errUnicode
	errWReserved

	// Path errors.
	errEmpty
	errAbsolute
	errTrailingSlash
	errDoubleSlash
)

type pathSegmentError struct {
	isPath bool
	path   string
	name   string
	err    int
	char   rune
	base   string
}

func (e *pathSegmentError) Error() string {
	var msg string
	switch e.err {
	case errBad:
	case errFirst:
		msg = fmt.Sprintf("starts with disallowed character %q", e.char)
	case errLast:
		msg = fmt.Sprintf("ends with disallowed character %q", e.char)
	case errAny:
		msg = fmt.Sprintf("contains disallowed character %q", e.char)
	case errUnicode:
		msg = fmt.Sprintf("contains non-ASCII character %q U+%04X", e.char, e.char)
	case errWReserved:
		msg = fmt.Sprintf("uses reserved Windows filename %q", e.base)
	case errEmpty:
		msg = "path is empty"
	case errAbsolute:
		msg = "path is absolute"
	case errTrailingSlash:
		msg = "path has trailing slash"
	case errDoubleSlash:
		msg = "path has double slash"
	default:
		panic("invalid pathSegmentError")
	}
	if e.err <= errWReserved {
		prefix := fmt.Sprintf("invalid path segment %q", e.name)
		if msg != "" {
			msg = prefix + ": " + msg
		} else {
			msg = prefix
		}
	}
	if e.isPath {
		prefix := fmt.Sprintf("invalid path %q", e.path)
		if msg != "" {
			msg = prefix + ": " + msg
		} else {
			msg = prefix
		}
	}
	return msg
}

// CheckPathSegment returns an error if the given name is not a safe path
// segment according to the chosen rules.
//
// The empty name, ".", and ".." are always unsafe, and '/' and is always an
// unsafe character
func (r Rules) CheckPathSegment(name string) error {
	r = (r & Strict) | laxRules
	if name == "" || name == "." || name == ".." {
		return &pathSegmentError{name: name, err: errBad}
	}
	first, _ := utf8.DecodeRuneInString(name)
	last, _ := utf8.DecodeLastRuneInString(name)
	if r&ShellSafe != 0 {
		if first == '-' || first == '~' {
			return &pathSegmentError{name: name, err: errFirst, char: first}
		}
	}
	if r&WindowsSafe != 0 {
		if last == '.' || last == ' ' {
			return &pathSegmentError{name: name, err: errLast, char: last}
		}
		i := strings.IndexByte(name, '.')
		if i == -1 || strings.IndexByte(name[i+1:], '.') == -1 {
			base := name
			if i != -1 {
				base = name[:i]
			}
			if i == 3 || i == 4 {
				base = strings.ToLower(base)
				if windowsReserved[base] {
					return &pathSegmentError{name: name, err: errWReserved, base: base}
				}
			}
		}
	}
	if r&NotHidden != 0 {
		if first == '.' {
			return &pathSegmentError{name: name, err: errFirst, char: first}
		}
	}
	r &^= NotHidden
	for _, c := range name {
		if c >= 128 {
			return &pathSegmentError{name: name, err: errUnicode, char: c}
		}
		f := flags[c]
		if f&r != r {
			return &pathSegmentError{name: name, err: errAny, char: c}
		}
	}
	return nil
}

// CheckPath returns an error if the given path is not a safe path. A safe path
// consists of a non-empty list of safe segments separated by slashes.
func (r Rules) CheckPath(name string) error {
	if len(name) == 0 {
		return &pathSegmentError{isPath: true, path: name, err: errEmpty}
	}
	if name[0] == '/' {
		return &pathSegmentError{isPath: true, path: name, err: errAbsolute}
	}
	for len(name) != 0 {
		var part string
		switch i := strings.IndexByte(name, '/'); {
		case i == 0:
			return &pathSegmentError{isPath: true, path: name, err: errDoubleSlash}
		case i == -1:
			part = name
			name = ""
		default:
			part = name[:i]
			name = name[i+1:]
			if len(name) == 0 {
				return &pathSegmentError{isPath: true, path: name, err: errTrailingSlash}
			}
		}
		if err := r.CheckPathSegment(part); err != nil {
			e := err.(*pathSegmentError)
			e.isPath = true
			e.path = name
			return e
		}
	}
	return nil
}