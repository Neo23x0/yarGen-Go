package scoring

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// MatchType represents the type of pattern matching for a scoring rule.
type MatchType string

const (
	MatchExact    MatchType = "exact"
	MatchContains MatchType = "contains"
	MatchRegex    MatchType = "regex"
)

// Rule represents a scoring rule for string evaluation.
type Rule struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MatchType   MatchType `json:"match_type"`
	Pattern     string    `json:"pattern"`
	Score       int       `json:"score"`
	Enabled     bool      `json:"enabled"`
	IsBuiltin   bool      `json:"is_builtin"`
	Category    string    `json:"category"`
}

// Store provides database operations for scoring rules.
type Store struct {
	db *sql.DB
}

// NewStore creates a new scoring rule store with the given database path.
func NewStore(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &Store{db: db}
	if err := store.initialize(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initialize() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scoring_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		match_type TEXT NOT NULL CHECK(match_type IN ('exact', 'contains', 'regex')),
		pattern TEXT NOT NULL,
		score INTEGER NOT NULL,
		enabled INTEGER DEFAULT 1,
		is_builtin INTEGER DEFAULT 0,
		category TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_scoring_rules_enabled ON scoring_rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_scoring_rules_builtin ON scoring_rules(is_builtin);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM scoring_rules WHERE is_builtin = 1").Scan(&count); err != nil {
		return err
	}

	if count == 0 {
		if err := s.seedBuiltinRules(); err != nil {
			return fmt.Errorf("failed to seed builtin rules: %w", err)
		}
	}

	return nil
}

func (s *Store) List(includeDisabled bool) ([]Rule, error) {
	query := "SELECT id, name, description, match_type, pattern, score, enabled, is_builtin, category FROM scoring_rules"
	if !includeDisabled {
		query += " WHERE enabled = 1"
	}
	query += " ORDER BY category, name"

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		var enabled, isBuiltin int
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.MatchType, &r.Pattern, &r.Score, &enabled, &isBuiltin, &r.Category); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		r.IsBuiltin = isBuiltin == 1
		rules = append(rules, r)
	}

	return rules, rows.Err()
}

func (s *Store) Get(id int64) (*Rule, error) {
	var r Rule
	var enabled, isBuiltin int
	err := s.db.QueryRow(
		"SELECT id, name, description, match_type, pattern, score, enabled, is_builtin, category FROM scoring_rules WHERE id = ?",
		id,
	).Scan(&r.ID, &r.Name, &r.Description, &r.MatchType, &r.Pattern, &r.Score, &enabled, &isBuiltin, &r.Category)
	if err != nil {
		return nil, err
	}
	r.Enabled = enabled == 1
	r.IsBuiltin = isBuiltin == 1
	return &r, nil
}

func (s *Store) Create(r *Rule) error {
	result, err := s.db.Exec(
		"INSERT INTO scoring_rules (name, description, match_type, pattern, score, enabled, is_builtin, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		r.Name, r.Description, r.MatchType, r.Pattern, r.Score, boolToInt(r.Enabled), boolToInt(r.IsBuiltin), r.Category,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	r.ID = id
	return nil
}

func (s *Store) Update(r *Rule) error {
	_, err := s.db.Exec(
		"UPDATE scoring_rules SET name = ?, description = ?, match_type = ?, pattern = ?, score = ?, enabled = ?, category = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		r.Name, r.Description, r.MatchType, r.Pattern, r.Score, boolToInt(r.Enabled), r.Category, r.ID,
	)
	return err
}

func (s *Store) Delete(id int64) error {
	_, err := s.db.Exec("DELETE FROM scoring_rules WHERE id = ? AND is_builtin = 0", id)
	return err
}

func (s *Store) Toggle(id int64, enabled bool) error {
	_, err := s.db.Exec("UPDATE scoring_rules SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", boolToInt(enabled), id)
	return err
}

func (s *Store) Export() ([]Rule, error) {
	return s.List(true)
}

func (s *Store) Import(rules []Rule, replaceAll bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if replaceAll {
		if _, err := tx.Exec("DELETE FROM scoring_rules WHERE is_builtin = 0"); err != nil {
			return err
		}
	}

	stmt, err := tx.Prepare("INSERT INTO scoring_rules (name, description, match_type, pattern, score, enabled, is_builtin, category) VALUES (?, ?, ?, ?, ?, ?, 0, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rules {
		if r.IsBuiltin {
			continue
		}
		if _, err := stmt.Exec(r.Name, r.Description, r.MatchType, r.Pattern, r.Score, boolToInt(r.Enabled), r.Category); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
