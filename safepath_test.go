package safepath

import (
	"strconv"
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

func TestSafepath(t *testing.T) {
	allRules := []Rules{URLUnescaped, ShellSafe, WindowsSafe, NotHidden, laxRules}
	type testcase struct {
		rules Rules
		name  string
	}
	cases := []testcase{
		{0, ""},
		{0, "."},
		{0, ".."},
		{0, "\u0080"},
		{0, "\u0000"},
		{Strict, "a"},
		{Strict, "0123"},
		{Strict, "A"},
		{Strict, "file.txt"},
		{Strict, "My_Archive-v0.1.3.tar.gz"},
		{Strict, "nul.txt.foo"},
		{Strict &^ ShellSafe, "~username"},
		{Strict &^ WindowsSafe, "nul.txt"},
		{Strict &^ ShellSafe, "$dollar$"},
		{Strict &^ NotHidden, ".foo"},
		{Strict &^ WindowsSafe, "a."},
		{WindowsSafe | NotHidden, "a b"},
		{NotHidden, "ab "},
		{Strict &^ WindowsSafe, "ab."},
		{Strict &^ ShellSafe, "-"},
		{Strict &^ ShellSafe, "--abc"},
	}
	for _, c := range cases {
		c := c
		t.Run(strconv.Quote(c.name), func(t *testing.T) {
			cr := c.rules
			if cr != 0 {
				cr |= laxRules
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
			if err := laxRules.CheckPath(c); err == nil {
				t.Errorf("CheckPath(%q) = nil, expect error", c)
			}
		})
	}
}
