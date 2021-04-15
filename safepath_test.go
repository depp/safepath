package safepath

import (
	"testing"
)

func TestSafepath(t *testing.T) {
	safeSeg := []string{
		"a", "0123", "A", "file.txt", "My_Archive-v0.1.3.tar.gz",
		"nul.txt.foo",
	}
	for _, s := range safeSeg {
		if !IsSafeSegment(s) {
			t.Errorf("IsSafeSegment(%q): false, expect true", s)
		}
	}
	unsafeSeg := []string{
		".foo", "a..b", "a__b", "a.", "a bc", ".", "-", "_",
		"nul", "com1", "com1.txt", "nul.html",
	}
	for _, s := range unsafeSeg {
		if IsSafeSegment(s) {
			t.Errorf("IsSafeSegment(%q): true, expect false", s)
		}
	}
	safePath := []string{
		"abc", "abc/def", "abc.dir/def.txt", "1/2/3/4/5/6_7_8",
	}
	for _, s := range safePath {
		if !IsSafePath(s) {
			t.Errorf("IsSafePath(%q): false, expect true", s)
		}
	}
	unsafePath := []string{
		".", "/", "abc/",
	}
	for _, s := range unsafePath {
		if IsSafePath(s) {
			t.Errorf("IsSafePath(%q): true, expect false", s)
		}
	}
}
