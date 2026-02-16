package strmatcher

import (
	"testing"
)

// --- RollingHash ---

func TestRollingHashDeterministic(t *testing.T) {
	a := RollingHash("test.example.com")
	b := RollingHash("test.example.com")
	if a != b {
		t.Fatalf("RollingHash not deterministic: %d != %d", a, b)
	}
}

func TestRollingHashDifferentInputs(t *testing.T) {
	a := RollingHash("google.com")
	b := RollingHash("example.com")
	if a == b {
		t.Fatalf("RollingHash collision on distinct inputs: both %d", a)
	}
}

func TestRollingHashEmpty(t *testing.T) {
	h := RollingHash("")
	if h != 0 {
		t.Fatalf("RollingHash(\"\") = %d, want 0", h)
	}
}

func TestRollingHashSingleChar(t *testing.T) {
	h := RollingHash("a")
	if h != uint32('a') {
		t.Fatalf("RollingHash(\"a\") = %d, want %d", h, uint32('a'))
	}
}

// --- nextPow2 ---

func TestNextPow2(t *testing.T) {
	// nextPow2 returns the smallest power of 2 strictly greater than v,
	// except for v <= 1 which returns 1.
	tests := []struct {
		input int
		want  int
	}{
		{0, 1},
		{1, 1},
		{2, 4},    // strictly > 2
		{3, 4},
		{4, 8},    // strictly > 4
		{5, 8},
		{7, 8},
		{8, 16},   // strictly > 8
		{9, 16},
		{15, 16},
		{16, 32},  // strictly > 16
		{17, 32},
		{255, 256},
		{256, 512},   // strictly > 256
		{1023, 1024},
		{1024, 2048}, // strictly > 1024
	}
	for _, tt := range tests {
		got := nextPow2(tt.input)
		if got != tt.want {
			t.Errorf("nextPow2(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// --- MphMatcherGroup ---

func TestNewMphMatcherGroup(t *testing.T) {
	g := NewMphMatcherGroup()
	if g == nil {
		t.Fatal("NewMphMatcherGroup returned nil")
	}
	if g.Count != 1 {
		t.Fatalf("initial Count=%d, want 1", g.Count)
	}
	if g.RuleMap == nil {
		t.Fatal("RuleMap is nil")
	}
}

func TestMphMatcherGroupFullMatch(t *testing.T) {
	g := NewMphMatcherGroup()
	_, err := g.AddPattern("www.google.com", Full)
	if err != nil {
		t.Fatalf("AddPattern Full: %v", err)
	}
	g.Build()

	result := g.Match("www.google.com")
	if len(result) == 0 {
		t.Fatal("expected match for exact full pattern")
	}

	result = g.Match("mail.google.com")
	if len(result) != 0 {
		t.Fatalf("expected no match for different domain, got %v", result)
	}
}

func TestMphMatcherGroupDomainMatch(t *testing.T) {
	g := NewMphMatcherGroup()
	_, err := g.AddPattern("google.com", Domain)
	if err != nil {
		t.Fatalf("AddPattern Domain: %v", err)
	}
	g.Build()

	tests := []struct {
		input string
		match bool
	}{
		{"google.com", true},
		{"www.google.com", true},
		{"mail.google.com", true},
		{"notgoogle.com", false},
		{"example.com", false},
	}
	for _, tt := range tests {
		result := g.Match(tt.input)
		got := len(result) > 0
		if got != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestMphMatcherGroupSubstrMatch(t *testing.T) {
	g := NewMphMatcherGroup()
	_, err := g.AddPattern("google", Substr)
	if err != nil {
		t.Fatalf("AddPattern Substr: %v", err)
	}
	g.Build()

	tests := []struct {
		input string
		match bool
	}{
		{"www.google.com", true},
		{"googleapis.com", true},
		{"example.com", false},
	}
	for _, tt := range tests {
		result := g.Match(tt.input)
		got := len(result) > 0
		if got != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestMphMatcherGroupRegexMatch(t *testing.T) {
	g := NewMphMatcherGroup()
	_, err := g.AddPattern(`^www\..*\.com$`, Regex)
	if err != nil {
		t.Fatalf("AddPattern Regex: %v", err)
	}
	g.Build()

	tests := []struct {
		input string
		match bool
	}{
		{"www.google.com", true},
		{"www.example.com", true},
		{"mail.google.com", false},
		{"www.google.org", false},
	}
	for _, tt := range tests {
		result := g.Match(tt.input)
		got := len(result) > 0
		if got != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestMphMatcherGroupInvalidRegex(t *testing.T) {
	g := NewMphMatcherGroup()
	_, err := g.AddPattern("[invalid", Regex)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestMphMatcherGroupMixed(t *testing.T) {
	g := NewMphMatcherGroup()
	g.AddPattern("google.com", Domain)
	g.AddPattern("www.baidu.com", Full)
	g.AddPattern("api", Substr)
	g.Build()

	tests := []struct {
		input string
		match bool
	}{
		{"www.google.com", true},
		{"google.com", true},
		{"www.baidu.com", true},
		{"baidu.com", false},
		{"api.example.com", true},
		{"random.org", false},
	}
	for _, tt := range tests {
		result := g.Match(tt.input)
		got := len(result) > 0
		if got != tt.match {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.match)
		}
	}
}

func TestMphMatcherGroupNoMatch(t *testing.T) {
	g := NewMphMatcherGroup()
	g.AddPattern("example.com", Full)
	g.Build()

	result := g.Match("notexample.com")
	if result != nil {
		t.Fatalf("expected nil for non-matching input, got %v", result)
	}
}

func TestMphMatcherGroupEmpty(t *testing.T) {
	g := NewMphMatcherGroup()
	g.Build()

	result := g.Match("anything.com")
	if result != nil {
		t.Fatalf("expected nil from empty matcher, got %v", result)
	}
}

func TestMphMatcherGroupDomainCaseInsensitive(t *testing.T) {
	g := NewMphMatcherGroup()
	g.AddPattern("GOOGLE.COM", Domain)
	g.Build()

	// AddPattern lowercases Domain patterns, so lookup with lowercase should match.
	result := g.Match("google.com")
	if len(result) == 0 {
		t.Fatal("expected case-insensitive domain match")
	}
}

func TestMphMatcherGroupSize(t *testing.T) {
	g := NewMphMatcherGroup()
	g.AddPattern("a.com", Full)
	g.AddPattern("b.com", Full)
	// Size() returns Count which starts at 1 and is returned from AddPattern.
	if g.Size() != 1 {
		t.Fatalf("Size()=%d, want 1", g.Size())
	}
}

func TestMphMatcherGroupAddPatternUnknownTypeReturnsError(t *testing.T) {
	g := NewMphMatcherGroup()
	_, err := g.AddPattern("test", Type(99))
	if err == nil {
		t.Fatal("expected error for unknown pattern type")
	}
}

// --- Lookup ---

func TestMphMatcherGroupLookupAfterBuild(t *testing.T) {
	g := NewMphMatcherGroup()
	g.AddPattern("test.com", Full)
	g.Build()

	h := RollingHash("test.com")
	if !g.Lookup(h, "test.com") {
		t.Fatal("Lookup should find 'test.com'")
	}
	if g.Lookup(h, "other.com") {
		t.Fatal("Lookup should not find 'other.com' with test.com's hash")
	}
}

func BenchmarkMphMatcherGroupMatch(b *testing.B) {
	g := NewMphMatcherGroup()
	domains := []string{
		"google.com", "facebook.com", "twitter.com", "amazon.com",
		"apple.com", "microsoft.com", "netflix.com", "youtube.com",
	}
	for _, d := range domains {
		g.AddPattern(d, Domain)
	}
	g.Build()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Match("www.google.com")
	}
}
