package manifest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseProfileAndLevel(t *testing.T) {
	for s, want := range map[string]Profile{"": Bronze, "bronze": Bronze, "Silver": Silver, "GOLD": Gold} {
		if got, err := ParseProfile(s); err != nil || got != want {
			t.Errorf("ParseProfile(%q) = %v,%v want %v", s, got, err, want)
		}
	}
	if _, err := ParseProfile("platinum"); err == nil {
		t.Error("unknown profile must error")
	}
	if _, err := ParseLevel("L9"); err == nil {
		t.Error("unknown level must error")
	}
}

func TestExpiryTime(t *testing.T) {
	if _, err := (Deviation{}).ExpiryTime(); err == nil {
		t.Error("missing expiry must error (treated as expired by governance)")
	}
	if _, err := (Deviation{Expires: "not-a-date"}).ExpiryTime(); err == nil {
		t.Error("malformed expiry must error")
	}
	got, err := (Deviation{Expires: "2026-06-16"}).ExpiryTime()
	if err != nil {
		t.Fatalf("valid expiry errored: %v", err)
	}
	want := time.Date(2026, 6, 16, 23, 59, 59, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("ExpiryTime = %v, want end-of-day %v", got, want)
	}
}

func TestLoadStrictDecode(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), ".airgap.yml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// A typo in a security manifest must be a hard error, never a silent pass.
	if _, err := Load(write("target_profile: Gold\nsurfaces:\n  - url: https://x\ntypoo: true\n")); err == nil {
		t.Error("unknown field must be rejected (strict decode)")
	}
	// No surfaces declared.
	if _, err := Load(write("target_profile: Bronze\n")); err == nil {
		t.Error("manifest with no surfaces must error")
	}
	// Valid minimal manifest, including the new multi-path field.
	cfg, err := Load(write("target_profile: Silver\nsurfaces:\n  - url: https://x\n    paths: [/a, /b]\n"))
	if err != nil {
		t.Fatalf("valid manifest errored: %v", err)
	}
	if len(cfg.Surfaces) != 1 || len(cfg.Surfaces[0].Paths) != 2 {
		t.Errorf("expected 1 surface with 2 paths, got %+v", cfg.Surfaces)
	}
}
