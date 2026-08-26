// Package badge renders a self-contained SVG conformance badge from a report
// Record. It is deliberately dependency-free and egress-free: no web font, no
// external image, no third-party endpoint — a project can serve the badge from
// its own origin without violating the very standard it advertises (AG-NET-02).
package badge

import (
	"fmt"
	"math"
	"strings"

	"github.com/fabriziosalmi/agssh/internal/report"
)

const (
	colLabel  = "#2b3137" // brand slate (left label)
	colPass   = "#3fb911" // green — conformant
	colFail   = "#e05d44" // red — non-conformant
	colTarget = "#6b7280" // grey — the target tier, not yet earned
	colWhite  = "#ffffff"
)

// segment is one coloured chip of the badge: its text plus fill and text colour.
// A metallic segment uses a vertical gradient with dark, engraved text.
type segment struct {
	text    string
	solid   string // flat fill; empty when a gradient is used
	gradTop string
	gradBot string
	textCol string
	dark    bool // dark text -> emboss with a light lower highlight
}

func slate(text string) segment { return segment{text: text, solid: colLabel, textCol: colWhite} }

func verdict(text string, conformant bool) segment {
	if conformant {
		return segment{text: text, solid: colPass, textCol: colWhite}
	}
	return segment{text: text, solid: colFail, textCol: colWhite}
}

// tierLabel returns the display name of a known profile tier, or "" otherwise.
func tierLabel(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "gold":
		return "Gold"
	case "silver":
		return "Silver"
	case "bronze":
		return "Bronze"
	}
	return ""
}

// metal returns a metallic chip for an EARNED profile tier (Gold/Silver/Bronze);
// an unknown profile falls back to a plain slate chip.
func metal(profile string) segment {
	switch tierLabel(profile) {
	case "Gold":
		return segment{text: "Gold", gradTop: "#f0d97a", gradBot: "#b8901f", textCol: "#3a2c05", dark: true}
	case "Silver":
		return segment{text: "Silver", gradTop: "#e6eaed", gradBot: "#98a0a6", textCol: "#2a2e32", dark: true}
	case "Bronze":
		return segment{text: "Bronze", gradTop: "#e2a463", gradBot: "#a5631f", textCol: "#3a230a", dark: true}
	default:
		return slate(profileOr(profile, "AGSSH"))
	}
}

// grayTarget is the target tier a non-conformant surface is aiming for, shown in
// a muted grey — the medal it has not yet earned.
func grayTarget(profile string) segment {
	return segment{text: tierLabel(profile), solid: colTarget, textCol: colWhite}
}

// Render returns the default badge: the brand label, the profile tier as its
// metal when conformant, and the conformance score, coloured by verdict.
//
//	AGSSH · Gold · 94%     (conformant)
//	AGSSH · 41%            (non-conformant)
func Render(rec *report.Record) []byte {
	return buildSegments(defaultSegments(rec))
}

// RenderAggregate renders one badge for a whole config: conformant only if every
// record is (the CLI gate ANDs them); the score shown is the lowest surface's.
func RenderAggregate(records []*report.Record) []byte {
	if len(records) == 0 {
		return buildSegments([]segment{slate("AGSSH"), verdict("unknown", false)})
	}
	all := true
	var lead *report.Record
	worst := math.MaxFloat64
	for _, r := range records {
		if r == nil {
			continue
		}
		if lead == nil {
			lead = r
		}
		if !r.Conformant {
			all = false
		}
		if r.Score.Pct < worst {
			worst = r.Score.Pct
			lead = r
		}
	}
	return buildSegments(defaultSegments(lead, all))
}

// defaultSegments composes the default badge for a record, following model "E":
//   - conformant    -> AGSSH · <metallic tier>            (the medal, earned)
//   - non-conformant -> AGSSH · <grey target tier> · <score%>   (target + the gap)
//
// Every value is a deterministic read of the record — the target tier, the binary
// conformant verdict, and the exact weighted score — with no synthetic grade or
// threshold. The optional override forces the verdict (RenderAggregate's AND).
func defaultSegments(rec *report.Record, conformantOverride ...bool) []segment {
	conformant := rec != nil && rec.Conformant
	if len(conformantOverride) > 0 {
		conformant = conformantOverride[0]
	}
	profile := ""
	if rec != nil {
		profile = rec.Profile
	}
	segs := []segment{slate("AGSSH")}

	if conformant {
		if tierLabel(profile) != "" {
			return append(segs, metal(profile)) // earned medal — no number needed
		}
		return append(segs, verdict("conformant", true))
	}
	if tierLabel(profile) != "" {
		segs = append(segs, grayTarget(profile))
	}
	return append(segs, verdict(scoreText(rec), false))
}

func scoreText(rec *report.Record) string {
	if rec == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", rec.Score.Pct)
}

func profileOr(p, def string) string {
	if strings.TrimSpace(p) == "" {
		return def
	}
	return p
}

// buildSegments assembles a flat, N-segment badge with even padding. Each chip is
// sized to its text using EXACT Verdana advance widths (Verdana is the widest of
// the declared stack — DejaVu/generic fall inside it), and each chip's text is
// clipped to its own rect, so a label can never spill past its chip on any font.
func buildSegments(segs []segment) []byte {
	const (
		h   = 20
		pad = 6 // px each side of a chip's text — tight, even, shields-like
	)
	widths := make([]int, len(segs))
	total := 0
	for i, s := range segs {
		widths[i] = int(mathRound(textWidth(s.text))) + 2*pad
		total += widths[i]
	}

	var defs, body strings.Builder
	defs.WriteString(`<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`)
	// Rects (clipped to the rounded badge outline).
	body.WriteString(`<g clip-path="url(#r)">`)
	x := 0
	for i, s := range segs {
		fill := s.solid
		if s.gradTop != "" {
			gid := fmt.Sprintf("g%d", i)
			fmt.Fprintf(&defs, `<linearGradient id="%s" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/></linearGradient>`, gid, s.gradTop, s.gradBot)
			fill = "url(#" + gid + ")"
		}
		fmt.Fprintf(&defs, `<clipPath id="c%d"><rect x="%d" width="%d" height="%d"/></clipPath>`, i, x, widths[i], h)
		fmt.Fprintf(&body, `<rect x="%d" width="%d" height="%d" fill="%s"/>`, x, widths[i], h, fill)
		x += widths[i]
	}
	fmt.Fprintf(&body, `<rect width="%d" height="%d" fill="url(#s)"/>`, total, h)
	body.WriteString(`</g>`)
	// Text — each run clipped to its own chip.
	body.WriteString(`<g text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">`)
	x = 0
	for i, s := range segs {
		cx := (x + widths[i]/2) * 10
		shColor, shOp := "#010101", ".3"
		if s.dark {
			shColor, shOp = colWhite, ".5"
		}
		fmt.Fprintf(&body, `<g clip-path="url(#c%d)">`, i)
		fmt.Fprintf(&body, `<text transform="scale(.1)" x="%d" y="150" fill="%s" fill-opacity="%s">%s</text>`, cx, shColor, shOp, esc(s.text))
		fmt.Fprintf(&body, `<text transform="scale(.1)" x="%d" y="140" fill="%s">%s</text>`, cx, s.textCol, esc(s.text))
		body.WriteString(`</g>`)
		x += widths[i]
	}
	body.WriteString(`</g>`)

	var b strings.Builder
	label := aria(segs)
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" role="img" aria-label="%s">`, total, h, esc(label))
	fmt.Fprintf(&b, `<title>%s</title>`, esc(label))
	b.WriteString(defs.String())
	fmt.Fprintf(&b, `<clipPath id="r"><rect width="%d" height="%d" rx="3" fill="#fff"/></clipPath>`, total, h)
	b.WriteString(body.String())
	b.WriteString(`</svg>`)
	b.WriteString("\n")
	return []byte(b.String())
}

func aria(segs []segment) string {
	parts := make([]string, 0, len(segs))
	for _, s := range segs {
		parts = append(parts, s.text)
	}
	return strings.Join(parts, ": ")
}

func mathRound(f float64) float64 { return math.Floor(f + 0.5) }

// verdanaAdvance holds the exact Verdana glyph advance at font-size 11px (measured
// via canvas measureText). Verdana is declared first and is the widest of the
// stack, so sizing to it keeps every label inside its chip on DejaVu Sans and the
// generic sans fallback too. Unlisted runes fall back to a safe wide default.
var verdanaAdvance = map[rune]float64{
	'0': 6.99, '1': 6.99, '2': 6.99, '3': 6.99, '4': 6.99, '5': 6.99, '6': 6.99, '7': 6.99, '8': 6.99, '9': 6.99,
	'A': 7.52, 'B': 7.54, 'C': 7.68, 'D': 8.48, 'E': 6.96, 'F': 6.32, 'G': 8.53, 'H': 8.27, 'I': 4.63, 'J': 5,
	'K': 7.62, 'L': 6.12, 'M': 9.27, 'N': 8.23, 'O': 8.66, 'P': 6.63, 'Q': 8.66, 'R': 7.65, 'S': 7.52, 'T': 6.78,
	'U': 8.05, 'V': 7.52, 'W': 10.88, 'X': 7.54, 'Y': 6.77, 'Z': 7.54,
	'a': 6.61, 'b': 6.85, 'c': 5.73, 'd': 6.85, 'e': 6.55, 'f': 3.87, 'g': 6.85, 'h': 6.96, 'i': 3.02, 'j': 3.79,
	'k': 6.51, 'l': 3.02, 'm': 10.7, 'n': 6.96, 'o': 6.68, 'p': 6.85, 'q': 6.85, 'r': 4.69, 's': 5.73, 't': 4.33,
	'u': 6.96, 'v': 6.51, 'w': 9, 'x': 6.51, 'y': 6.51, 'z': 5.78,
	'%': 11.84, '·': 4, ' ': 3.87, '/': 5, '.': 3.87, '-': 5,
}

// textWidth is the exact Verdana rendered width of s at font-size 11px.
func textWidth(s string) float64 {
	w := 0.0
	for _, r := range s {
		if a, ok := verdanaAdvance[r]; ok {
			w += a
		} else {
			w += 8.0 // safe wide default for an unlisted glyph
		}
	}
	return w
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}
