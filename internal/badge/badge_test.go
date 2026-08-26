package badge

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/agssh/internal/report"
)

func rec(conformant bool, profile, level string, pct float64) *report.Record {
	return &report.Record{Conformant: conformant, Profile: profile, Level: level, Score: report.Score{Pct: pct}}
}

func TestRenderModelE(t *testing.T) {
	// Conformant Gold: the earned metal medal, no number.
	pass := Render(rec(true, "Gold", "L2", 100))
	if !bytes.Contains(pass, []byte("#b8901f")) {
		t.Errorf("conformant Gold should wear the metallic gold chip")
	}
	if bytes.Contains(pass, []byte("%</text>")) { // a rendered score, not the sheen gradient's y2="100%"
		t.Errorf("a conformant medal carries no score number")
	}
	// Non-conformant targeting Gold: grey target tier + red score, no metal.
	fail := Render(rec(false, "Gold", "L2", 41))
	if !bytes.Contains(fail, []byte(colTarget)) {
		t.Errorf("non-conformant should show the grey target tier")
	}
	if !bytes.Contains(fail, []byte(colFail)) || !bytes.Contains(fail, []byte("41%")) {
		t.Errorf("non-conformant should carry the red score")
	}
	if bytes.Contains(fail, []byte("#b8901f")) {
		t.Errorf("non-conformant must not wear the metal it has not earned")
	}
}

func TestRenderIsSelfContainedAndClipped(t *testing.T) {
	svg := string(Render(rec(true, "Silver", "L1", 88)))
	if !strings.HasPrefix(svg, "<svg") || !strings.HasSuffix(strings.TrimSpace(svg), "</svg>") {
		t.Errorf("output is not a bare <svg> document")
	}
	for _, bad := range []string{"<image", "xlink:href", "@import", "src=", "<script"} {
		if strings.Contains(svg, bad) {
			t.Errorf("badge must be self-contained; found %q", bad)
		}
	}
	// The text group must be clipped so a wide fallback font cannot overflow.
	if strings.Count(svg, `clip-path="url(#r)"`) < 2 {
		t.Errorf("both the rect group and the text group must be clipped to the badge bounds")
	}
}

func TestRenderAggregate(t *testing.T) {
	all := RenderAggregate([]*report.Record{
		rec(true, "Gold", "L2", 100), rec(true, "Gold", "L2", 100),
	})
	if !bytes.Contains(all, []byte("#b8901f")) {
		t.Errorf("all-conformant Gold aggregate should wear the metal")
	}
	mixed := RenderAggregate([]*report.Record{
		rec(true, "Gold", "L2", 100), rec(false, "Gold", "L2", 40),
	})
	if !bytes.Contains(mixed, []byte(colFail)) || !bytes.Contains(mixed, []byte("40%")) {
		t.Errorf("a single failing surface should make the aggregate red and show its score")
	}
	if !bytes.Contains(mixed, []byte(colTarget)) {
		t.Errorf("a failing aggregate should still show the grey target tier")
	}
}

// TestRenderSamples writes content-variant badges to $AGSSH_BADGE_SAMPLE_DIR for
// visual review. Skipped unless that env var is set, so it never touches the tree.
func TestRenderSamples(t *testing.T) {
	dir := os.Getenv("AGSSH_BADGE_SAMPLE_DIR")
	if dir == "" {
		t.Skip("set AGSSH_BADGE_SAMPLE_DIR to emit sample SVGs")
	}
	samples := map[string]*report.Record{
		"gold":        rec(true, "Gold", "L2", 100),
		"silver":      rec(true, "Silver", "L1", 100),
		"bronze":      rec(true, "Bronze", "L0", 100),
		"gold-fail":   rec(false, "Gold", "L2", 41),
		"silver-fail": rec(false, "Silver", "L1", 63),
		"bronze-fail": rec(false, "Bronze", "L0", 22),
	}
	for name, r := range samples {
		if err := os.WriteFile(filepath.Join(dir, "agssh-"+name+".svg"), Render(r), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
