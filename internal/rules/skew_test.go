package rules

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// manifestRule mirrors one entry of standard/manifest.yaml, generated from the
// spec's single RULES source by standard/build_pdf.py.
type manifestRule struct {
	ID         string `yaml:"id"`
	Family     string `yaml:"family"`
	Obligation string `yaml:"obligation"`
	Severity   string `yaml:"severity"`
	Profile    string `yaml:"profile"`
}

// TestRegistryMatchesManifest turns the standard's headline promise — "the spec
// document, the tooling and the manifest cannot drift, they come from one source"
// — into an actual build-failing test. registry.All() (what the runner enforces)
// MUST match manifest.yaml (generated from the spec's RULES) on every id, family,
// obligation, severity and profile. If you change a rule in standard/build_pdf.py,
// regenerate the manifest (`cd standard && python build_pdf.py`) and update
// registry.go to match — this test will tell you exactly what diverged.
func TestRegistryMatchesManifest(t *testing.T) {
	data, err := os.ReadFile("manifest.yaml")
	if err != nil {
		t.Fatalf("read manifest.yaml (regenerate it with: cd standard && python build_pdf.py): %v", err)
	}
	var doc struct {
		Rules []manifestRule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse manifest.yaml: %v", err)
	}

	spec := make(map[string]manifestRule, len(doc.Rules))
	for _, r := range doc.Rules {
		if _, dup := spec[r.ID]; dup {
			t.Errorf("%s: duplicate id in the spec manifest", r.ID)
		}
		spec[r.ID] = r
	}

	seen := make(map[string]bool, len(doc.Rules))
	for _, r := range All() {
		seen[r.ID] = true
		m, ok := spec[r.ID]
		if !ok {
			t.Errorf("%s: implemented in registry.go but ABSENT from the spec manifest", r.ID)
			continue
		}
		if r.Family != m.Family {
			t.Errorf("%s family: registry=%q spec=%q", r.ID, r.Family, m.Family)
		}
		if got := r.Obligation.String(); got != m.Obligation {
			t.Errorf("%s obligation: registry=%q spec=%q", r.ID, got, m.Obligation)
		}
		if got := r.Severity.String(); got != m.Severity {
			t.Errorf("%s severity: registry=%q spec=%q", r.ID, got, m.Severity)
		}
		if got := r.Profile.String(); got != m.Profile {
			t.Errorf("%s profile: registry=%q spec=%q", r.ID, got, m.Profile)
		}
	}

	for id := range spec {
		if !seen[id] {
			t.Errorf("%s: in the spec manifest but NOT implemented in registry.go", id)
		}
	}
	if len(spec) != len(All()) {
		t.Errorf("rule count diverged: spec=%d registry=%d", len(spec), len(All()))
	}
}
