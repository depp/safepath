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
	// Any allows any path which can be used on lax systems like Linux.
	//
	// This only rejects path segments like ".." and ".", and only disallows the
	// '/' character and null byte. Any other bytestring is considered valid.
	Any Rules = 0
	// URLUnescaped requires that paths do not need hex escaping in URLs.
	//
	// This allows a fair number of punctuation marks, including !$&'()*+,;=,
	// which are referred to as "sub-delims" in RFC 3986. The colon character,
	// ":", does not need to be escaped in the path of absolute URIs, but is not
	// safe to use as the first segment of a relative URI, so it is not allowed
	// anywhere.
	//
	// The '@' character and '~' character have no special meaning in paths and
	// are allowed.
	URLUnescaped Rules = 1 << iota
	// ShellSafe requires that paths are safe for use in a POSIX shell.
	//
	// This excludes characters with special meaning in the shell: |&;<>()$`\"'.
	// Segments which begin with "~" are also rejected. You may want to combine
	// this flag with ArgumentSafe.
	ShellSafe
	// ArgumentSafe requires that paths are safe to pass as arguments to
	// command-line programs.
	//
	// This requires that path segments do not begin with '-', since that may be
	// interpreted as a command-line option.
	ArgumentSafe
	// WindowsSafe requires that paths are safe for Windows filesystems.
	//
	// On Windows, control characters in the range 1-31 are not allowed, the
	// reserved characters <>:"/\\|?* are not allowed, and a path segment may
	// not match one of the reserved names: con.*, prn.*, aux.*, etc. Segments
	// may not end with a space.
	//
	// See https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file.
	WindowsSafe
	// NotHidden requires that paths do not start with a period.
	NotHidden
	// laxRules are rules that always apply.
	laxRules
	// Strict is the strictest set of rules.
	//
	// This rule may get more strict in new versions of the library. Currently,
	// it allows only paths that follow all of the rulesets defined in this
	// library, and any future rulesets added to the libary will likely be added
	// to Strict.
	Strict = URLUnescaped | ShellSafe | ArgumentSafe | WindowsSafe | NotHidden
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
		flags[c] |= ShellSafe | ArgumentSafe | WindowsSafe
	}
	flags['/'] = 0

	// RFC 3986 section 3.3
	// https://tools.ietf.org/html/rfc3986#section-3.3
	// pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
	// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
	// sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
	//               / "*" / "+" / "," / ";" / "="
	// Colon is disallowed in the first segment of a relative path, so we
	// disallow it everywhere.
	for _, c := range "@-._~!$&'()*+,;=" {
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

// An Error indicates that a path is considered unsafe.
type Error struct {
	isPath bool
	path   string
	name   string
	err    int
	char   rune
	base   string
}

func (e *Error) Error() string {
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
		panic("invalid safepath.Error")
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
// The empty name, ".", and ".." are always unsafe. The '/' character and the
// null byte are always unsafe.
func (r Rules) CheckPathSegment(name string) error {
	r = (r & Strict) | laxRules
	if name == "" || name == "." || name == ".." {
		return &Error{name: name, err: errBad}
	}
	first, _ := utf8.DecodeRuneInString(name)
	last, _ := utf8.DecodeLastRuneInString(name)
	if r&ShellSafe != 0 && first == '~' {
		return &Error{name: name, err: errFirst, char: first}
	}
	if r&ArgumentSafe != 0 && first == '-' {
		return &Error{name: name, err: errFirst, char: first}
	}
	if r&WindowsSafe != 0 {
		if last == '.' || last == ' ' {
			return &Error{name: name, err: errLast, char: last}
		}
		i := strings.IndexByte(name, '.')
		if i == -1 || strings.IndexByte(name[i+1:], '.') == -1 {
			base := name
			if i != -1 {
				base = name[:i]
			}
			if len(base) == 3 || len(base) == 4 {
				base = strings.ToLower(base)
				if windowsReserved[base] {
					return &Error{name: name, err: errWReserved, base: base}
				}
			}
		}
	}
	if r&NotHidden != 0 {
		if first == '.' {
			return &Error{name: name, err: errFirst, char: first}
		}
	}
	r &^= NotHidden
	for _, c := range name {
		if c >= 128 {
			return &Error{name: name, err: errUnicode, char: c}
		}
		f := flags[c]
		if f&r != r {
			return &Error{name: name, err: errAny, char: c}
		}
	}
	return nil
}

// CheckPath returns an error if the given path is not a safe path. A safe path
// consists of a non-empty list of safe segments separated by slashes.
//
// This requires that the path be normalized first. Backslashes are treated as
// ordinary characters (not path separators), and double slashes are considered
// errors.
//
// Absolute paths are rejected. Occurrences of "." or ".." are rejected. The
// empty path is rejected. Paths which end with "/" are rejected. Individual
// path segments are validated according to the rules, see CheckPathSegment.
func (r Rules) CheckPath(name string) error {
	if len(name) == 0 {
		return &Error{isPath: true, path: name, err: errEmpty}
	}
	if name[0] == '/' {
		return &Error{isPath: true, path: name, err: errAbsolute}
	}
	for len(name) != 0 {
		var part string
		switch i := strings.IndexByte(name, '/'); {
		case i == 0:
			return &Error{isPath: true, path: name, err: errDoubleSlash}
		case i == -1:
			part = name
			name = ""
		default:
			part = name[:i]
			name = name[i+1:]
			if len(name) == 0 {
				return &Error{isPath: true, path: name, err: errTrailingSlash}
			}
		}
		if err := r.CheckPathSegment(part); err != nil {
			e := err.(*Error)
			e.isPath = true
			e.path = name
			return e
		}
	}
	return nil
}
