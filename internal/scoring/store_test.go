package scoring

import (
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := NewStore(filepath.Join(t.TempDir(), "scoring.db"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
}

func TestImport_DeduplicatesAndUpdatesExistingNonBuiltinRule(t *testing.T) {
	store := newTestStore(t)

	first := Rule{
		Name:        "dup-rule",
		Description: "v1",
		MatchType:   MatchContains,
		Pattern:     "abc",
		Score:       3,
		Enabled:     true,
		Category:    "Test",
	}
	second := Rule{
		Name:        "dup-rule",
		Description: "v2",
		MatchType:   MatchContains,
		Pattern:     "abc",
		Score:       9,
		Enabled:     false,
		Category:    "Test",
	}

	if err := store.Import([]Rule{first}, false); err != nil {
		t.Fatalf("first import failed: %v", err)
	}
	if err := store.Import([]Rule{second}, false); err != nil {
		t.Fatalf("second import failed: %v", err)
	}

	rules, err := store.List(true)
	if err != nil {
		t.Fatalf("failed to list rules: %v", err)
	}

	matches := 0
	var got Rule
	for _, r := range rules {
		if r.IsBuiltin {
			continue
		}
		if r.Name == second.Name && r.MatchType == second.MatchType && r.Pattern == second.Pattern && r.Category == second.Category {
			matches++
			got = r
		}
	}

	if matches != 1 {
		t.Fatalf("expected one matching non-builtin rule, got %d", matches)
	}

	if got.Description != second.Description {
		t.Fatalf("expected description %q, got %q", second.Description, got.Description)
	}
	if got.Score != second.Score {
		t.Fatalf("expected score %d, got %d", second.Score, got.Score)
	}
	if got.Enabled != second.Enabled {
		t.Fatalf("expected enabled %v, got %v", second.Enabled, got.Enabled)
	}
}
