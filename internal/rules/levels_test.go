package rules

import (
	"context"
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/fabriziosalmi/agssh/internal/manifest"
)

// The per-level promises RULES.md makes, written out by hand and independent of the
// generator: if levels_gen.go ever drifts from the standard, this fails (issue #71).
func TestModeAtDocumentedLevels(t *testing.T) {
	req, adv, out, forb := LevelRequired, LevelAdvisory, LevelOutOfScope, LevelForbidden
	for _, tc := range []struct {
		id         string
		l0, l1, l2 LevelMode
	}{
		{"AG-NET-05", req, adv, out},
		{"AG-NET-06", req, req, adv},
		{"AG-NET-08", req, req, out},
		{"AG-CSP-06", req, req, adv},
		{"AG-PRV-01", req, req, out},
		{"AG-PRV-04", req, req, adv},
		{"AG-PRV-06", forb, forb, req},
		{"AG-GOV-06", req, req, out},
		// required at every level: no entry, and the explicit "conditional" qualifier
		{"AG-NET-04", req, req, req},
		{"AG-NET-01", req, req, req},
		{"AG-PRV-02", req, req, req},
	} {
		for l, want := range map[manifest.Level]LevelMode{manifest.L0: tc.l0, manifest.L1: tc.l1, manifest.L2: tc.l2} {
			if got := ModeAt(tc.id, l); got != want {
				t.Errorf("%s at %v: mode=%v, want %v", tc.id, l, got, want)
			}
		}
	}
}

// manifest.yaml (generated from the same `applies` strings) and the Go table must say
// the same thing for every rule.
func TestLevelModesMatchManifest(t *testing.T) {
	data, err := os.ReadFile("manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []struct {
			ID     string            `yaml:"id"`
			Levels map[string]string `yaml:"levels"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	names := map[LevelMode]string{LevelRequired: "required", LevelAdvisory: "advisory", LevelOutOfScope: "out_of_scope", LevelForbidden: "forbidden"}
	if len(doc.Rules) == 0 {
		t.Fatal("manifest has no rules")
	}
	for _, r := range doc.Rules {
		for lname, l := range map[string]manifest.Level{"L0": manifest.L0, "L1": manifest.L1, "L2": manifest.L2} {
			if got, want := names[ModeAt(r.ID, l)], r.Levels[lname]; got != want {
				t.Errorf("%s %s: runner=%q spec=%q (regenerate: cd standard && python build_pdf.py)", r.ID, lname, got, want)
			}
		}
	}
	for id := range levelModes {
		found := false
		for _, r := range doc.Rules {
			found = found || r.ID == id
		}
		if !found {
			t.Errorf("levels_gen.go has %s which is not in the manifest", id)
		}
	}
}

func TestEffectiveObligation(t *testing.T) {
	byID := map[string]Rule{}
	for _, r := range All() {
		byID[r.ID] = r
	}
	csp06 := byID["AG-CSP-06"] // MUST, advisory at L2
	if EffectiveObligation(csp06, manifest.L0) != Must || EffectiveObligation(csp06, manifest.L2) != Should {
		t.Error("AG-CSP-06 must be MUST at L0 and SHOULD (waivable) at L2")
	}
	net01 := byID["AG-NET-01"]
	if EffectiveObligation(net01, manifest.L2) != Must {
		t.Error("a rule with no level behaviour keeps its MUST at every level")
	}
}

// AG-PRV-06: below L2 a cross-origin iframe is forbidden even when sandboxed; at L2 the
// sandbox is what is demanded.
func TestEmbedsForbiddenBelowL2(t *testing.T) {
	body := `<iframe src="https://video.example/embed" sandbox="allow-scripts"></iframe>`
	doc := newDoc(200, body, nil)
	doc.FinalURL = "https://me.test/"
	for _, tc := range []struct {
		level manifest.Level
		want  Status
	}{{manifest.L0, Fail}, {manifest.L1, Fail}, {manifest.L2, Pass}} {
		if got := chkEmbedsSandboxed(context.Background(), &CheckCtx{Doc: doc, Level: tc.level}); got.Status != tc.want {
			t.Errorf("sandboxed third-party iframe at %v: %v, want %v", tc.level, got.Status, tc.want)
		}
	}
	// A same-origin iframe is not a third-party embed.
	same := newDoc(200, `<iframe src="/widget" sandbox></iframe>`, nil)
	same.FinalURL = "https://me.test/"
	if got := chkEmbedsSandboxed(context.Background(), &CheckCtx{Doc: same, Level: manifest.L0}); got.Status != Pass {
		t.Errorf("same-origin sandboxed iframe at L0: %v, want PASS", got.Status)
	}
}
