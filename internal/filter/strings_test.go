package filter

import (
	"path/filepath"
	"testing"

	"github.com/Neo23x0/yarGen-go/internal/database"
	"github.com/Neo23x0/yarGen-go/internal/scoring"
)

func newTestEngine(t *testing.T) *scoring.Engine {
	t.Helper()

	store, err := scoring.NewStore(filepath.Join(t.TempDir(), "scoring.db"))
	if err != nil {
		t.Fatalf("failed to create scoring store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	engine, err := scoring.NewEngine(store)
	if err != nil {
		t.Fatalf("failed to create scoring engine: %v", err)
	}

	return engine
}

func TestFilterStrings_ExcludesWideGoodwareWithPrefixedKey(t *testing.T) {
	engine := newTestEngine(t)

	opts := DefaultFilterOptions()
	opts.ExcludeGoodware = true

	result := FilterStrings(
		[]string{"UTF16LE:cmd.exe"},
		database.Counter{"UTF16LE:cmd.exe": 1},
		engine,
		opts,
	)

	if len(result) != 0 {
		t.Fatalf("expected wide goodware string to be excluded, got %d results", len(result))
	}
}
