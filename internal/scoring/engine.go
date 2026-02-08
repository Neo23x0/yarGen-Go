package scoring

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Engine evaluates strings against scoring rules.
type Engine struct {
	store    *Store
	rules    []Rule
	compiled map[int64]*regexp.Regexp
	mu       sync.RWMutex
}

// NewEngine creates a new scoring engine with the given store.
func NewEngine(store *Store) (*Engine, error) {
	e := &Engine{
		store:    store,
		compiled: make(map[int64]*regexp.Regexp),
	}

	if err := e.Reload(); err != nil {
		return nil, err
	}

	return e, nil
}

func (e *Engine) Reload() error {
	rules, err := e.store.List(false)
	if err != nil {
		return err
	}

	compiled := make(map[int64]*regexp.Regexp)
	for _, r := range rules {
		if r.MatchType == MatchRegex {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[W] Skipping invalid regex scoring rule %q (id=%d): %v\n", r.Name, r.ID, err)
				continue
			}
			compiled[r.ID] = re
		}
	}

	e.mu.Lock()
	e.rules = rules
	e.compiled = compiled
	e.mu.Unlock()

	return nil
}

// ScoreResult contains the scoring results for a string.
type ScoreResult struct {
	TotalScore    float64
	MatchedRules  []MatchedRule
	EncodingBonus float64
}

// MatchedRule represents a scoring rule that matched a string.
type MatchedRule struct {
	RuleID   int64
	RuleName string
	Score    int
	Category string
}

func (e *Engine) Score(s string) ScoreResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := ScoreResult{
		TotalScore:   0,
		MatchedRules: make([]MatchedRule, 0),
	}

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		matched := false
		switch rule.MatchType {
		case MatchExact:
			matched = s == rule.Pattern
		case MatchContains:
			matched = strings.Contains(s, rule.Pattern)
		case MatchRegex:
			if re, ok := e.compiled[rule.ID]; ok {
				matched = re.MatchString(s)
			}
		}

		if matched {
			result.TotalScore += float64(rule.Score)
			result.MatchedRules = append(result.MatchedRules, MatchedRule{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Score:    rule.Score,
				Category: rule.Category,
			})
		}
	}

	return result
}

func (e *Engine) ScoreWithGoodware(s string, goodwareCount int, excludeGoodware bool) ScoreResult {
	result := e.Score(s)

	if goodwareCount > 0 {
		if excludeGoodware {
			result.TotalScore = -1000
		} else {
			goodwareScore := float64(goodwareCount*-1) + 5
			result.TotalScore += goodwareScore
		}
	}

	return result
}

// ScoredString contains a string with its scoring information.
type ScoredString struct {
	Value        string        `json:"value"`
	Score        float64       `json:"score"`
	IsWide       bool          `json:"is_wide"`
	MatchedRules []MatchedRule `json:"matched_rules,omitempty"`
	GoodwareHits int           `json:"goodware_hits,omitempty"`
	EncodingInfo *EncodingInfo `json:"encoding_info,omitempty"`
}

// EncodingInfo contains information about detected string encodings.
type EncodingInfo struct {
	Type         string `json:"type"`
	DecodedValue string `json:"decoded_value,omitempty"`
}

func (e *Engine) ScoreBatch(strings []string, goodwareDB map[string]int, excludeGoodware bool) []ScoredString {
	results := make([]ScoredString, 0, len(strings))

	for _, s := range strings {
		isWide := false
		displayStr := s
		if len(s) > 8 && s[:8] == "UTF16LE:" {
			isWide = true
			displayStr = s[8:]
		}

		goodwareCount := 0
		if goodwareDB != nil {
			goodwareCount = goodwareDB[displayStr]
		}

		scoreResult := e.ScoreWithGoodware(displayStr, goodwareCount, excludeGoodware)

		results = append(results, ScoredString{
			Value:        displayStr,
			Score:        scoreResult.TotalScore,
			IsWide:       isWide,
			MatchedRules: scoreResult.MatchedRules,
			GoodwareHits: goodwareCount,
		})
	}

	return results
}
