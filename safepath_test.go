package safepath

import (
	"strconv"
	"strings"
	"testing"
)

func testResult(t *testing.T, expect bool, r Rules, name, input string, err error) {
	t.Helper()
	if !expect {
		if err == nil {
			t.Errorf("%#v.%s(%q) = nil, expect error", r, name, input)
		}
	} else {
		if err != nil {
			t.Errorf("%#v.%s(%q) = %v, expect ok", r, name, input, err)
		}
	}
}

func testSegment(t *testing.T, r Rules, input string, expectOk bool) {
	t.Helper()
	err := r.CheckPathSegment(input)
	if expectOk {
		if err != nil {
			t.Errorf("rules: %#v; path: %q; err = %v, expect ok", r, input, err)
		}
	} else {
		if err == nil {
			t.Errorf("rules: %#v; path: %q; err = nil, expect error", r, input)
		}
	}
}

func TestASCIIOnly(t *testing.T) {
	for i := 0; i < 256; i++ {
		testSegment(t, ASCIIOnly, "text"+string(rune(i)), i != 0 && i != '/' && i < 128)
	}
	for i := 128; i < 256; i++ {
		testSegment(t, ASCIIOnly, "text"+string([]byte{byte(i)}), false)
	}
}

func TestValidUTF8(t *testing.T) {
	for i := 0; i < 256; i++ {
		testSegment(t, ValidUTF8, "text"+string(rune(i)), i != 0 && i != '/')
	}
	for i := 128; i < 256; i++ {
		testSegment(t, ValidUTF8, "text"+string([]byte{byte(i)}), false)
	}
}

func TestURLUnescaped(t *testing.T) {
	passcases := []string{
		"file",
		"file.txt",
		"file_underscore",
		"file-hyphen",
		"0123456789",
		// Don't apply Windows rules.
		"nul",
		"nul.txt",
		// "@" is actually ok in the path.
		"@",
		// "~" does not actually have any special meaning.
		"~user",
		// sub-delims are ok.
		"!",
		"$",
		"&",
		"'",
		"(",
		")",
		"*",
		"+",
		",",
		";",
		"=",
	}
	for _, c := range passcases {
		if err := URLUnescaped.CheckPathSegment(c); err != nil {
			t.Errorf("path %q: %v, expect ok", c, err)
		}
	}
	failcases := []string{
		"/",
		// Looks like a scheme.
		"colon:",
		"mailto:user",
		// Percent encoding.
		"%",
		"%20",
		"Untitled%20Document",
		// Various delimiters.
		"/",
		"\"",
		"<",
		">",
		"?",
		"[",
		"]",
		"\\",
		"^",
		"`",
		"{",
		"}",
		"|",
		// Control characters.
		"\x00",
		"\x1f",
		"\n",
	}
	for _, c := range failcases {
		if err := URLUnescaped.CheckPathSegment(c); err == nil {
			t.Errorf("path %q: ok, expect error", c)
		}
	}
}

func TestShellSafe(t *testing.T) {
	var invalid [128]bool
	for _, c := range " /|&;<>()$`\\\"'" {
		invalid[c] = true
	}
	for i := 0; i < 32; i++ {
		invalid[i] = true
	}
	invalid[127] = true
	for i, cinval := range invalid {
		s := "file" + string(rune(i))
		if cinval {
			if ShellSafe.CheckPathSegment(s) == nil {
				t.Errorf("path %q: ok, expect error", s)
			}
		} else {
			if err := ShellSafe.CheckPathSegment(s); err != nil {
				t.Errorf("path %q: %v, expect ok", s, err)
			}
		}
	}
	failcases := []string{
		"~",
		"~user",
	}
	for _, c := range failcases {
		if ShellSafe.CheckPathSegment(c) == nil {
			t.Errorf("path %q: ok, expect error", c)
		}
	}
	passcases := []string{
		"-",
		"-flag",
	}
	for _, c := range passcases {
		if err := ShellSafe.CheckPathSegment(c); err != nil {
			t.Errorf("path %q: %v, expect ok", c, err)
		}
	}
}

func TestWindowsReserved(t *testing.T) {
	reserved := []string{
		"con",
		"prn",
		"aux",
		"nul",
		"com1",
		"com2",
		"com8",
		"com9",
		"lpt1",
		"lpt2",
		"lpt8",
		"lpt9",
	}
	for _, c := range reserved {
		failcases := []string{
			c,
			strings.ToUpper(c),
			c + ".txt",
		}
		for _, s := range failcases {
			if WindowsSafe.CheckPathSegment(s) == nil {
				t.Errorf("path %q safe, expect error", s)
			}
		}
	}
}

func TestSafepath(t *testing.T) {
	allRules := []Rules{URLUnescaped, ShellSafe, ArgumentSafe, WindowsSafe, NotHidden, always}
	type testcase struct {
		rules Rules
		name  string
	}
	cases := []testcase{
		{0, ""},
		{0, "."},
		{0, ".."},
		{0, "\u0000"},
		{Strict &^ ValidUTF8, "abc\x80"},
		{Strict &^ ASCIIOnly, "\u0080"},
		{Strict, "a"},
		{Strict, "0123"},
		{Strict, "A"},
		{Strict, "file.txt"},
		{Strict, "My_Archive-v0.1.3.tar.gz"},
		{Strict, "nul.txt.foo"},
		{Strict &^ ShellSafe, "~username"},
		{Strict &^ WindowsSafe, "nul.txt"},
		{Strict &^ WindowsSafe, "LPT1"},
		{Strict &^ WindowsSafe, "lpt8.dat"},
		{Strict &^ ShellSafe, "$dollar$"},
		{Strict &^ NotHidden, ".foo"},
		{Strict &^ WindowsSafe, "a."},
		{ArgumentSafe | WindowsSafe | NotHidden, "a b"},
		{ArgumentSafe | NotHidden, "ab "},
		{Strict &^ WindowsSafe, "ab."},
		{Strict &^ ArgumentSafe, "-"},
		{Strict &^ ArgumentSafe, "--abc"},
	}
	for _, c := range cases {
		c := c
		t.Run(strconv.Quote(c.name), func(t *testing.T) {
			cr := c.rules
			if cr != 0 {
				cr |= always
			}
			for _, r := range allRules {
				expect := r&cr == r
				testResult(t, expect, r, "CheckPathSegment", c.name, r.CheckPathSegment(c.name))
				testResult(t, expect, r, "CheckPath", c.name, r.CheckPath(c.name))
				long := c.name + "/" + c.name + "/" + c.name
				testResult(t, expect, r, "CheckPath", long, r.CheckPath(long))
			}
		})
	}
	pcases := []string{
		"",
		"/",
		"abc//def",
		"/abc/def",
		"abc/def/",
	}
	for _, c := range pcases {
		c := c
		t.Run(strconv.Quote(c), func(t *testing.T) {
			if err := always.CheckPath(c); err == nil {
				t.Errorf("CheckPath(%q) = nil, expect error", c)
			}
		})
	}
}
