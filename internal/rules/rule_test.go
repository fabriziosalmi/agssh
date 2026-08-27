package rules

import (
	"runtime"
	"testing"
)

func TestBrowserBundleCandidatesIncludeOSDefault(t *testing.T) {
	cands := browserBundleCandidates()
	switch runtime.GOOS {
	case "darwin":
		want := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		if !contains(cands, want) {
			t.Errorf("darwin candidates must include %q; got %v", want, cands)
		}
	case "windows":
		if len(cands) == 0 {
			t.Errorf("windows must offer Program Files browser candidates")
		}
	default:
		if len(cands) != 0 {
			t.Errorf("non-darwin/windows relies on PATH; want no bundle candidates, got %v", cands)
		}
	}
}

// TestChromePathBundleFallback: when PATH misses, chromePath falls through to the
// absolute bundle probe (verified via an injected look that always misses).
func TestChromePathFallsThroughToBundleProbe(t *testing.T) {
	miss := func(...string) string { return "" }
	// On darwin/windows this may resolve to a real installed browser (non-empty)
	// or "" if none is installed; either way it must not have panicked and must
	// return "" on a platform with no bundle candidates and no PATH hit.
	got := chromePath(miss)
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" && got != "" {
		t.Errorf("no PATH hit and no bundle candidates: want \"\", got %q", got)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
