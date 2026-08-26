package mcpsrv

import (
	"testing"

	"github.com/fabriziosalmi/agssh/internal/report"
)

func rec(surface string, conformant bool, pct float64) *report.Record {
	return &report.Record{
		Surface:    surface,
		Conformant: conformant,
		Score:      report.Score{Pct: pct},
	}
}

// TestAggregateSurfaces pins the CLI-parity fix: the headline verdict is the AND
// of every surface, and the primary (detailed) record is the first FAILING one.
func TestAggregateSurfaces(t *testing.T) {
	t.Run("all conformant -> conformant, primary is first", func(t *testing.T) {
		primary, all, roster := aggregateSurfaces([]*report.Record{
			rec("https://a/", true, 100), rec("https://b/", true, 100),
		})
		if !all {
			t.Errorf("want allConformant=true")
		}
		if primary.Surface != "https://a/" {
			t.Errorf("primary = %s, want first surface", primary.Surface)
		}
		if len(roster) != 2 {
			t.Errorf("roster len = %d, want 2", len(roster))
		}
	})

	t.Run("one fails -> NON-conformant even if the first passes", func(t *testing.T) {
		// This is the exact bug: surfaces[0] conformant must NOT mask surfaces[1].
		primary, all, _ := aggregateSurfaces([]*report.Record{
			rec("https://ok/", true, 100), rec("https://bad/", false, 40),
		})
		if all {
			t.Errorf("want allConformant=false when any surface fails")
		}
		if primary.Surface != "https://bad/" {
			t.Errorf("primary = %s, want the failing surface for the detailed fix queue", primary.Surface)
		}
	})

	t.Run("first fails -> primary stays the first failing surface", func(t *testing.T) {
		primary, all, _ := aggregateSurfaces([]*report.Record{
			rec("https://bad1/", false, 10), rec("https://bad2/", false, 20),
		})
		if all {
			t.Errorf("want allConformant=false")
		}
		if primary.Surface != "https://bad1/" {
			t.Errorf("primary = %s, want the FIRST failing surface", primary.Surface)
		}
	})

	t.Run("nil records are skipped", func(t *testing.T) {
		primary, all, roster := aggregateSurfaces([]*report.Record{nil, rec("https://a/", true, 100)})
		if !all || primary == nil || primary.Surface != "https://a/" || len(roster) != 1 {
			t.Errorf("nil handling: all=%v primary=%v rosterLen=%d", all, primary, len(roster))
		}
	})
}
