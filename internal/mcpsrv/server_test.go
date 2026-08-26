package mcpsrv_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fabriziosalmi/agssh/internal/mcpsrv"
)

// connect wires a real MCP client to a real MCP server over the in-memory
// transport pair, exercising registration, schema, and the JSON round-trip.
func connect(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()

	srv := mcpsrv.New("test") // panics here if AddTool cannot infer a schema
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	cli := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0"}, nil)
	cs, err := cli.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, ctx
}

func scan(t *testing.T, cs *mcp.ClientSession, ctx context.Context, args map[string]any) (*mcp.CallToolResult, mcpsrv.ScanResult) {
	t.Helper()
	// httptest servers are always loopback; opt in so the SSRF guard lets them through.
	if _, ok := args["allow_private_targets"]; !ok {
		args["allow_private_targets"] = true
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "agssh_scan", Arguments: args})
	if err != nil {
		t.Fatalf("CallTool agssh_scan: %v", err)
	}
	var sr mcpsrv.ScanResult
	if res.StructuredContent != nil {
		raw, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(raw, &sr); err != nil {
			t.Fatalf("decode structured content: %v", err)
		}
	}
	return res, sr
}

func inFixQueue(sr mcpsrv.ScanResult, rule string) bool {
	for _, f := range sr.FixQueue {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestListToolsRegistersEverything(t *testing.T) {
	cs, ctx := connect(t)
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	want := map[string]bool{"agssh_scan": false, "agssh_scan_config": false, "agssh_list_rules": false}
	for _, tool := range lt.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has no input schema", tool.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tool %q not advertised", name)
		}
	}
}

func TestScanUnhardenedSurfaceIsNonConformant(t *testing.T) {
	// A bare surface: HTML, no security headers at all.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<!doctype html><html><head><title>t</title></head><body>hi</body></html>"))
	}))
	defer ts.Close()

	cs, ctx := connect(t)
	res, sr := scan(t, cs, ctx, map[string]any{"url": ts.URL})

	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	if sr.Surface == "" || sr.Score.Possible == 0 {
		t.Fatalf("empty/degenerate result: %+v", sr)
	}
	if sr.Conformant {
		t.Errorf("bare surface should be NON-CONFORMANT, got conformant")
	}
	// The header family must fire on a header-less surface.
	if !inFixQueue(sr, "AG-HDR-02") {
		t.Errorf("expected AG-HDR-02 (nosniff) in fix queue; got %v", ruleIDs(sr))
	}
	// Human content is present and mentions the standard.
	if txt := firstText(res); txt == "" || !strings.Contains(txt, "AGSSH-STD-001") {
		t.Errorf("text content missing standard banner: %q", txt)
	}
}

func TestScanReflectsServedHeaders(t *testing.T) {
	// Set X-Content-Type-Options: nosniff — AG-HDR-02 must then NOT be a finding.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write([]byte("<!doctype html><html><head><title>t</title></head><body>hi</body></html>"))
	}))
	defer ts.Close()

	cs, ctx := connect(t)
	_, sr := scan(t, cs, ctx, map[string]any{"url": ts.URL})
	if inFixQueue(sr, "AG-HDR-02") {
		t.Errorf("AG-HDR-02 should pass when nosniff is served; fix queue: %v", ruleIDs(sr))
	}
}

func TestScanBlocksLoopbackByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<!doctype html><title>secret internal service</title>"))
	}))
	defer ts.Close()

	cs, ctx := connect(t)
	// No allow_private_targets: a loopback target must be refused (SSRF guard).
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "agssh_scan", Arguments: map[string]any{"url": ts.URL},
	})
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected a loopback target to be blocked by default")
	}
}

func TestScanAllowsLoopbackWithOptIn(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<!doctype html><title>t</title>"))
	}))
	defer ts.Close()

	cs, ctx := connect(t)
	res, sr := scan(t, cs, ctx, map[string]any{"url": ts.URL, "allow_private_targets": true})
	if res.IsError {
		t.Fatalf("opt-in loopback scan should succeed: %+v", res.Content)
	}
	if sr.Surface == "" || sr.Score.Possible == 0 {
		t.Errorf("opt-in loopback scan produced no evaluation: %+v", sr)
	}
}

func TestScanDoesNotLeakTempPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<!doctype html><title>t</title>"))
	}))
	defer ts.Close()

	cs, ctx := connect(t)
	// Silver pulls in CI-plane checks whose INCONCLUSIVE evidence used to echo the
	// synthesized absent source root (a server temp path).
	res, sr := scan(t, cs, ctx, map[string]any{"url": ts.URL, "profile": "Silver"})
	blob := firstText(res)
	for _, r := range sr.Results {
		blob += r.Err + r.Evidence.Observed
	}
	if strings.Contains(blob, "agssh-mcp-norepo-") || strings.Contains(blob, os.TempDir()+"/agssh-mcp") {
		t.Errorf("scan output leaked the server temp path; results echo the absent source root")
	}
}

func TestScanBlocksInternalResolver(t *testing.T) {
	cs, ctx := connect(t)
	// Public URL (literal IP, no DNS) but an internal DNS resolver: the resolver is
	// an alternate SSRF vector and must be refused too. No allow_private_targets.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "agssh_scan",
		Arguments: map[string]any{"url": "http://8.8.8.8/", "resolver": "10.0.0.5:9999"},
	})
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected an internal resolver to be blocked")
	}
}

func TestScanRejectsBadScheme(t *testing.T) {
	cs, ctx := connect(t)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "agssh_scan", Arguments: map[string]any{"url": "ftp://example.org/"},
	})
	if err != nil {
		t.Fatalf("transport error (want tool error, not protocol error): %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError for a non-http scheme")
	}
}

func TestScanProfileLevelOverrides(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<!doctype html><title>t</title>"))
	}))
	defer ts.Close()
	cs, ctx := connect(t)

	_, bronze := scan(t, cs, ctx, map[string]any{"url": ts.URL, "profile": "Bronze", "level": "L0"})
	_, gold := scan(t, cs, ctx, map[string]any{"url": ts.URL, "profile": "Gold", "level": "L2"})
	// Gold is cumulative: strictly more rules are in scope than Bronze.
	if gold.Score.Possible <= bronze.Score.Possible {
		t.Errorf("Gold/L2 should evaluate more rules than Bronze/L0: gold=%d bronze=%d",
			gold.Score.Possible, bronze.Score.Possible)
	}
}

func TestScanInvalidProfileIsToolError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	cs, ctx := connect(t)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "agssh_scan", Arguments: map[string]any{"url": ts.URL, "profile": "Platinum"},
	})
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError for unknown profile")
	}
}

func TestListRulesAndFamilyFilter(t *testing.T) {
	cs, ctx := connect(t)

	all := callListRules(t, cs, ctx, nil)
	if all.Count < 40 {
		t.Fatalf("registry unexpectedly small: %d", all.Count)
	}
	net := callListRules(t, cs, ctx, map[string]any{"family": "AG-NET"})
	if net.Count == 0 || net.Count >= all.Count {
		t.Errorf("AG-NET filter ineffective: net=%d all=%d", net.Count, all.Count)
	}
	for _, r := range net.Rules {
		if r.ID[:6] != "AG-NET" {
			t.Errorf("family filter leaked non-AG-NET rule: %s", r.ID)
		}
	}
	bronze := callListRules(t, cs, ctx, map[string]any{"profile": "Bronze"})
	gold := callListRules(t, cs, ctx, map[string]any{"profile": "Gold"})
	if bronze.Count >= gold.Count {
		t.Errorf("Bronze subset should be smaller than Gold: bronze=%d gold=%d", bronze.Count, gold.Count)
	}
}

// ---- helpers ----

func callListRules(t *testing.T, cs *mcp.ClientSession, ctx context.Context, args map[string]any) mcpsrv.ListRulesOutput {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "agssh_list_rules", Arguments: args})
	if err != nil {
		t.Fatalf("CallTool agssh_list_rules: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_rules error: %+v", res.Content)
	}
	var out mcpsrv.ListRulesOutput
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode list_rules: %v", err)
	}
	return out
}

func ruleIDs(sr mcpsrv.ScanResult) []string {
	ids := make([]string, 0, len(sr.FixQueue))
	for _, f := range sr.FixQueue {
		ids = append(ids, f.Rule)
	}
	return ids
}

func firstText(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}
