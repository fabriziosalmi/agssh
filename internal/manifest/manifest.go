// Package manifest parses and validates the per-repo .airgap.yml declaration:
// target profile, conformance level, surfaces, DNS zone, pipeline scope, the
// explicit allow-lists, and the governed waiver/deviation block.
package manifest

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Level is the strictness band a surface is evaluated at.
type Level int

const (
	L0 Level = iota // strict air-gap: zero third-party egress
	L1              // scoped egress: explicit connect allow-list
	L2              // marketing: consented third-party, frame/base still locked
)

func ParseLevel(s string) (Level, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "L0", "":
		return L0, nil
	case "L1":
		return L1, nil
	case "L2":
		return L2, nil
	}
	return L0, fmt.Errorf("unknown level %q (want L0|L1|L2)", s)
}

func (l Level) String() string { return [...]string{"L0", "L1", "L2"}[l] }

// Profile is the cumulative conformance burden: Gold ⊃ Silver ⊃ Bronze.
type Profile int

const (
	Bronze Profile = iota + 1
	Silver
	Gold
)

func ParseProfile(s string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bronze", "":
		return Bronze, nil
	case "silver":
		return Silver, nil
	case "gold":
		return Gold, nil
	}
	return Bronze, fmt.Errorf("unknown profile %q (want Bronze|Silver|Gold)", s)
}

func (p Profile) String() string { return [...]string{"", "Bronze", "Silver", "Gold"}[p] }

// AtLeast reports whether p includes everything required at min.
func (p Profile) AtLeast(min Profile) bool { return p >= min }

// Budget caps the deviation debt a single surface may carry (AG-GOV-03).
type Budget struct {
	MaxCount      int `yaml:"max_count"`
	MaxWeight     int `yaml:"max_weight"`
	MaxWindowDays int `yaml:"max_window_days"`
}

type Waivers struct {
	Budget Budget `yaml:"budget"`
}

// Deviation is a recorded, governed waiver of a SHOULD rule. MUSTs can never
// be waived (AG-GOV-01); the runner enforces expiry (AG-GOV-02) and, at Gold,
// segregation of duties (AG-GOV-04).
type Deviation struct {
	Rule      string `yaml:"rule"`
	Reason    string `yaml:"reason"`
	Approver  string `yaml:"approver"`
	Author    string `yaml:"author"`
	Expires   string `yaml:"expires"` // YYYY-MM-DD
	Evidence  string `yaml:"evidence"`
	Signature string `yaml:"signature"`
}

// ExpiryTime parses the expiry as an end-of-day instant (UTC). A missing or
// malformed date is an error, which the governance layer treats as expired.
func (d Deviation) ExpiryTime() (time.Time, error) {
	if strings.TrimSpace(d.Expires) == "" {
		return time.Time{}, fmt.Errorf("missing expiry")
	}
	t, err := time.Parse("2006-01-02", strings.TrimSpace(d.Expires))
	if err != nil {
		return time.Time{}, fmt.Errorf("bad expiry %q: %w", d.Expires, err)
	}
	return t.Add(24*time.Hour - time.Second).UTC(), nil
}

type Surface struct {
	URL              string `yaml:"url"`
	Kind             string `yaml:"kind"` // client-tool | docs | site
	GeneratesFiles   bool   `yaml:"generates_files"`
	ThreadedWASM     bool   `yaml:"threaded_wasm"`
	HasServiceWorker bool   `yaml:"has_service_worker"`
	Stateless        bool   `yaml:"stateless"`
	PrivacySurface   bool   `yaml:"privacy_surface"`
}

// IsPrivacy reports whether referrer leakage matters for this surface. Client
// tools and documentation are privacy surfaces by default; a marketing "site"
// is one only when explicitly declared. Used by AG-NET-09.
func (s Surface) IsPrivacy() bool {
	return s.PrivacySurface || s.Kind == "client-tool" || s.Kind == "docs" || s.Kind == ""
}

type Allow struct {
	Connect []string `yaml:"connect"`
	Storage []string `yaml:"storage"`
	Embeds  []string `yaml:"embeds"`
}

type DNS struct {
	Zone string `yaml:"zone"`
	// Resolver is the DNS server (host or host:port) used for CAA/DNSSEC/dangling
	// probing. Empty means "use the host's configured resolver" (resolv.conf) —
	// no public IP is baked into the runner. Override per-repo or via -resolver.
	Resolver string `yaml:"resolver"`
}

type Pipeline struct {
	EnforceCIRules bool `yaml:"enforce_ci_rules"`
}

type Config struct {
	TargetProfile string      `yaml:"target_profile"`
	Level         string      `yaml:"level"`
	Surfaces      []Surface   `yaml:"surfaces"`
	Backend       string      `yaml:"backend"`
	DNS           DNS         `yaml:"dns"`
	Pipeline      Pipeline    `yaml:"pipeline"`
	Allow         Allow       `yaml:"allow"`
	Waivers       Waivers     `yaml:"waivers"`
	Deviations    []Deviation `yaml:"deviations"`
}

// Load reads, decodes (strict) and validates the manifest. Unknown keys are a
// hard error: a typo in a security manifest must not silently pass.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(c.Surfaces) == 0 {
		return nil, fmt.Errorf("%s: no surfaces declared", path)
	}
	if _, err := c.Profile(); err != nil {
		return nil, err
	}
	if _, err := c.LevelV(); err != nil {
		return nil, err
	}
	for i, s := range c.Surfaces {
		if strings.TrimSpace(s.URL) == "" {
			return nil, fmt.Errorf("%s: surface[%d] has no url", path, i)
		}
	}
	return &c, nil
}

func (c *Config) Profile() (Profile, error) { return ParseProfile(c.TargetProfile) }
func (c *Config) LevelV() (Level, error)    { return ParseLevel(c.Level) }
