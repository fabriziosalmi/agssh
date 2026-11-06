package rules

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// AG-HDR-07: cache discipline for fingerprinted assets. The standard's check:
//
//	hashed assets (/_astro/*, fingerprinted) => Cache-Control: public,
//	max-age=31536000, immutable ; HTML => no-cache / short
//
// Two halves, each decided only where the evidence is conclusive:
//
//   - The document: no-cache, no-store or max-age=0 is provably short. immutable or
//     a max-age of at least a year is provably long-cached, which the rule forbids.
//     Anything in between (or no Cache-Control at all, i.e. heuristic freshness) is
//     not decidable: the standard does not put a number on "short", and the runner
//     does not invent one. That half stays INCONCLUSIVE.
//   - The assets: every same-origin subresource the document references is
//     classified from its URL. A content-hashed filename that is not served
//     public, max-age>=31536000, immutable is a FAIL. A filename the runner
//     cannot classify either way must itself be long-cached immutable, or the
//     rule stays INCONCLUSIVE: an unrecognised hash is not proof of no hash. Only
//     a filename that is plainly not hashed is outside the rule.
//
// The verdict is FAIL on any conclusive violation, else INCONCLUSIVE on anything
// unproven, else PASS. Cross-origin subresources are not this surface's to cache
// (AG-NET-01/02 govern whether they may exist at all).
func chkCacheDiscipline(ctx context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	const expected = "hashed assets: Cache-Control public, max-age=31536000, immutable; HTML: no-cache / short"
	var fails, unproven, ok []string
	checked := 0

	docCC := c.Doc.Header.Get("Cache-Control")
	switch documentCacheClass(docCC) {
	case cacheShort:
		ok = append(ok, fmt.Sprintf("document Cache-Control %q", docCC))
	case cacheLong:
		fails = append(fails, fmt.Sprintf("document is long-cached (Cache-Control %q)", docCC))
	default:
		if strings.TrimSpace(docCC) == "" {
			unproven = append(unproven, "document has no Cache-Control (heuristic freshness, not provably short)")
		} else {
			unproven = append(unproven, fmt.Sprintf("document Cache-Control %q is neither no-cache nor long; the standard does not define \"short\"", docCC))
		}
	}

	base, err := url.Parse(c.Doc.FinalURL)
	if err != nil || base.Host == "" {
		return inconclusive("surface URL not parseable: cannot resolve its assets")
	}
	assets := sameOriginAssets(base, c.Doc.Body)
	const maxAssets = 64
	if len(assets) > maxAssets {
		unproven = append(unproven, fmt.Sprintf("%d same-origin assets referenced; only the first %d are inspected", len(assets), maxAssets))
		assets = assets[:maxAssets]
	}
	for _, a := range assets {
		cls := classifyAsset(a)
		if cls == assetUnhashed {
			continue // plainly not content-hashed: outside the rule
		}
		if c.HTTP == nil {
			unproven = append(unproven, a.String()+": not fetched (no HTTP client)")
			continue
		}
		d, err := c.HTTP.Fetch(ctx, a.String())
		switch {
		case err != nil:
			unproven = append(unproven, a.String()+": fetch failed: "+err.Error())
			continue
		case d.Status < 200 || d.Status > 299:
			unproven = append(unproven, fmt.Sprintf("%s: HTTP %d", a, d.Status))
			continue
		}
		if fu, err := url.Parse(d.FinalURL); err != nil || !strings.EqualFold(fu.Host, base.Host) || fu.Scheme != base.Scheme {
			unproven = append(unproven, a.String()+": redirected off-origin to "+d.FinalURL)
			continue
		}
		checked++
		cc := d.Header.Get("Cache-Control")
		if assetLongImmutable(cc) {
			ok = append(ok, fmt.Sprintf("%s: %q", a.Path, cc))
			continue
		}
		if cls == assetHashed {
			fails = append(fails, fmt.Sprintf("hashed asset %s served Cache-Control %q", a.Path, cc))
		} else {
			unproven = append(unproven, fmt.Sprintf("%s: cannot tell whether the filename is content-hashed, and it is served Cache-Control %q", a.Path, cc))
		}
	}

	detail := map[string]any{}
	if len(ok) > 0 {
		detail["conformant"] = ok
	}
	if len(unproven) > 0 {
		detail["unproven"] = unproven
	}
	if len(fails) > 0 {
		detail["violations"] = fails
		o := bad(strings.Join(fails, "; "), expected)
		o.Evidence.Detail = detail
		return o
	}
	if len(unproven) > 0 {
		o := inconclusive(strings.Join(unproven, "; "))
		o.Evidence = Evidence{Expected: expected, Detail: detail}
		return o
	}
	o := okay(fmt.Sprintf("document provably short-cached; %d possibly-hashed same-origin asset(s) long-cached immutable", checked), expected)
	o.Evidence.Detail = detail
	return o
}

type cacheClass int

const (
	cacheUndecided cacheClass = iota
	cacheShort
	cacheLong
)

const oneYear = 31536000

// parseCacheControl lowercases the directive names; a valueless directive maps to "".
func parseCacheControl(h string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		out[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return out
}

// documentCacheClass decides the HTML half: short (no-cache / no-store /
// max-age=0), long (immutable, or max-age of at least a year), or undecided.
func documentCacheClass(h string) cacheClass {
	d := parseCacheControl(h)
	if _, imm := d["immutable"]; imm {
		return cacheLong
	}
	if v, has := d["max-age"]; has {
		if n, err := strconv.Atoi(v); err == nil && n >= oneYear {
			return cacheLong
		}
	}
	if _, nc := d["no-cache"]; nc {
		return cacheShort
	}
	if _, ns := d["no-store"]; ns {
		return cacheShort
	}
	if v, has := d["max-age"]; has && v == "0" {
		return cacheShort
	}
	return cacheUndecided
}

// assetLongImmutable is the asset half's requirement: public, max-age of at
// least a year, immutable, and nothing that defeats the shared cache.
func assetLongImmutable(h string) bool {
	d := parseCacheControl(h)
	_, pub := d["public"]
	_, imm := d["immutable"]
	n, err := strconv.Atoi(d["max-age"])
	if !pub || !imm || err != nil || n < oneYear {
		return false
	}
	for _, k := range []string{"no-cache", "no-store", "private"} {
		if _, has := d[k]; has {
			return false
		}
	}
	return true
}

type assetClass int

const (
	assetUnknown assetClass = iota
	assetHashed
	assetUnhashed
)

var (
	hexTokenRe   = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	b64Token8Re  = regexp.MustCompile(`^[A-Za-z0-9_-]{8}$`)
	plainStemRe  = regexp.MustCompile(`^[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*$`)
	shortLowerRe = regexp.MustCompile(`^[a-z0-9]{1,7}$`)
	wordRe       = regexp.MustCompile(`^[A-Z]?[a-z]+$`)
	hasDigitRe   = regexp.MustCompile(`[0-9]`)
	hasUpperRe   = regexp.MustCompile(`[A-Z]`)
	hasLowerRe   = regexp.MustCompile(`[a-z]`)
	hasHexLetter = regexp.MustCompile(`[a-f]`)
)

// classifyAsset decides from the URL alone whether an asset is content-hashed.
// Hashed: the /_astro/ build directory (the standard's own example), or a stem
// carrying a hex digest (8-64 chars, mixing digits and a-f) as a '.'-token or
// after the last '-', or ending in an 8-char base64url digest (mixing digits,
// upper and lower case, as Rollup/Vite emit) after a '.' or '-'.
// Unhashed: no query string, no '_', and every '.'/'-' token of the stem is a
// word (lowercase, optionally capitalised) or a short lowercase/digit token
// (jquery-3.7.1.min, agssh-std, Inter-Bold). Mixed-case or long alphanumeric
// tokens are unknown, which the checker treats fail-closed.
func classifyAsset(u *url.URL) assetClass {
	if strings.Contains(u.Path, "/_astro/") {
		return assetHashed
	}
	base := path.Base(u.Path)
	stem := strings.TrimSuffix(base, path.Ext(base))
	if stem == "" || stem == "." || stem == "/" {
		return assetUnknown
	}
	isHex := func(t string) bool {
		return hexTokenRe.MatchString(t) && hasDigitRe.MatchString(t) && hasHexLetter.MatchString(t)
	}
	isB64 := func(t string) bool {
		return b64Token8Re.MatchString(t) && hasDigitRe.MatchString(t) && hasUpperRe.MatchString(t) && hasLowerRe.MatchString(t)
	}
	// A hex digest may sit between dots (main.3f2a1b9c.chunk), so every
	// '.'-separated token is tested; the trailing '-' token covers name-digest.
	tokens := strings.Split(stem, ".")
	if i := strings.LastIndex(stem, "-"); i >= 0 {
		tokens = append(tokens, stem[i+1:])
	}
	for _, t := range tokens {
		if isHex(t) || isB64(t) {
			return assetHashed
		}
	}
	// An 8-char base64url digest may itself contain '-' or '_' (index-BWq_3K-c).
	if len(stem) > 8 && (stem[len(stem)-9] == '.' || stem[len(stem)-9] == '-') && isB64(stem[len(stem)-8:]) {
		return assetHashed
	}
	if u.RawQuery == "" && plainStemRe.MatchString(stem) {
		for _, t := range strings.FieldsFunc(stem, func(r rune) bool { return r == '.' || r == '-' }) {
			if !shortLowerRe.MatchString(t) && !wordRe.MatchString(t) {
				return assetUnknown
			}
		}
		return assetUnhashed
	}
	return assetUnknown
}

// sameOriginAssets resolves the document's subresource references (scripts,
// stylesheets, preloads, icons, images, media) against the document URL and
// keeps the same-origin ones, de-duplicated and sorted for a stable evidence
// order. Embedded documents (iframe/embed/object) are other pages, not assets.
func sameOriginAssets(base *url.URL, body []byte) []*url.URL {
	seen := map[string]*url.URL{}
	for _, r := range subresourceRefs(body) {
		if embedTags[r.Tag] {
			continue
		}
		ref, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		switch strings.ToLower(ref.Scheme) {
		case "", "http", "https":
		default:
			continue // data:, blob:, javascript: … carry no HTTP caching
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != base.Scheme || !strings.EqualFold(abs.Host, base.Host) {
			continue
		}
		abs.Fragment = ""
		seen[abs.String()] = abs
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*url.URL, 0, len(keys))
	for _, k := range keys {
		out = append(out, seen[k])
	}
	return out
}
