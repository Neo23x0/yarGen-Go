package scoring

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestReloadWarnsOnInvalidRegexRule(t *testing.T) {
	store := newTestStore(t)

	engine, err := NewEngine(store)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	badRule := &Rule{
		Name:      "bad-regex",
		MatchType: MatchRegex,
		Pattern:   "(",
		Score:     1,
		Enabled:   true,
		Category:  "Test",
	}
	if err := store.Create(badRule); err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = oldStderr
	}()

	if err := engine.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed reading stderr output: %v", err)
	}

	output := string(out)
	if !strings.Contains(output, "Skipping invalid regex scoring rule") {
		t.Fatalf("expected warning for invalid regex rule, got output: %q", output)
	}
	if !strings.Contains(output, badRule.Name) {
		t.Fatalf("expected warning to include rule name %q, got output: %q", badRule.Name, output)
	}
}
