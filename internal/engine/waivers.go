package engine

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/fabriziosalmi/agssh/internal/report"
	"github.com/fabriziosalmi/agssh/internal/rules"
)

// governance evaluates the waiver block and produces AG-GOV-01..04 results.
// This is the draconian heart: MUSTs are never waivable; expiry is enforced
// against the runner clock; the debt budget caps volume; Gold requires a
// signed approval by someone other than the author.
func governance(cfg *manifest.Config, profile manifest.Profile, byID map[string]rules.Rule,
	now time.Time, approvers map[string]bool, author string) (gov []rules.Result, active map[string]bool, recs []report.WaiverRec, violations []string) {

	active = map[string]bool{}
	budget := cfg.Waivers.Budget
	maxWindow := budget.MaxWindowDays
	if maxWindow <= 0 {
		maxWindow = 30
	}

	var v01, v02, v03, v04 []string
	var totalWeight, count int

	for _, dev := range cfg.Deviations {
		rec := report.WaiverRec{Rule: dev.Rule, Approver: dev.Approver, Expires: dev.Expires, Reason: dev.Reason}
		rule, known := byID[dev.Rule]
		if !known {
			rec.Valid, rec.Note = false, "unknown rule"
			v01 = append(v01, "waiver references unknown rule "+dev.Rule)
			recs = append(recs, rec)
			continue
		}
		// AG-GOV-01 — a MUST can never be waived.
		if rule.Obligation == rules.Must {
			rec.Valid, rec.Note = false, "MUST is non-waivable"
			v01 = append(v01, "waiver attempts to cover MUST "+dev.Rule)
			recs = append(recs, rec)
			continue
		}
		// AG-GOV-02 — runner-enforced expiry.
		exp, err := dev.ExpiryTime()
		if err != nil {
			rec.Valid, rec.Note = false, "invalid/missing expiry"
			v02 = append(v02, dev.Rule+": "+err.Error())
			recs = append(recs, rec)
			continue
		}
		if exp.Before(now) {
			rec.Valid, rec.Note = false, "expired"
			v02 = append(v02, dev.Rule+": expired "+dev.Expires)
			recs = append(recs, rec)
			continue
		}
		if exp.After(now.AddDate(0, 0, maxWindow)) {
			rec.Valid, rec.Note = false, "expiry beyond max window"
			v02 = append(v02, dev.Rule+": expiry beyond "+strconv.Itoa(maxWindow)+"d window")
			recs = append(recs, rec)
			continue
		}
		// AG-GOV-04 — segregation of duties (Gold).
		if profile == manifest.Gold {
			switch {
			case strings.TrimSpace(dev.Approver) == "":
				rec.Valid, rec.Note = false, "no approver"
			case dev.Approver == author:
				rec.Valid, rec.Note = false, "self-approved"
			case !approvers[dev.Approver]:
				rec.Valid, rec.Note = false, "approver not in allow-list"
			case strings.TrimSpace(dev.Signature) == "":
				rec.Valid, rec.Note = false, "unsigned"
			}
			if !rec.Valid && rec.Note != "" {
				v04 = append(v04, dev.Rule+": "+rec.Note)
				recs = append(recs, rec)
				continue
			}
		}
		// Valid, active waiver.
		rec.Valid = true
		active[dev.Rule] = true
		totalWeight += rule.Severity.Weight()
		count++
		recs = append(recs, rec)
	}

	// AG-GOV-03 — deviation debt ceiling.
	if budget.MaxCount > 0 && count > budget.MaxCount {
		v03 = append(v03, fmt.Sprintf("active waivers %d exceed max_count %d", count, budget.MaxCount))
	}
	if budget.MaxWeight > 0 && totalWeight > budget.MaxWeight {
		v03 = append(v03, fmt.Sprintf("deviation weight %d exceeds max_weight %d", totalWeight, budget.MaxWeight))
	}

	mk := func(id string, viols []string) {
		r, ok := byID[id]
		if !ok || !profile.AtLeast(r.Profile) {
			return // out of target profile -> not reported
		}
		if len(viols) == 0 {
			gov = append(gov, rules.Stamp(r, rules.PassOutcome("no governance violations", "")))
		} else {
			gov = append(gov, rules.Stamp(r, rules.FailOutcome(strings.Join(viols, "; "), "")))
		}
	}
	mk("AG-GOV-01", v01)
	mk("AG-GOV-02", v02)
	mk("AG-GOV-03", v03)
	mk("AG-GOV-04", v04)

	violations = append(violations, v01...)
	violations = append(violations, v02...)
	violations = append(violations, v03...)
	violations = append(violations, v04...)
	return gov, active, recs, violations
}
