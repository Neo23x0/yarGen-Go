package rules

import (
	"strings"
	"testing"

	"github.com/Neo23x0/yarGen-go/internal/filter"
)

func TestGenerateSimpleRuleEscapesMetaValues(t *testing.T) {
	file := FileData{
		Name: `bad"name.exe`,
		Hash: "0123456789abcdef",
		Size: 512,
		Strings: []filter.FilteredString{
			{Value: "suspicious-string", Score: 10, IsHighScoring: true},
		},
	}

	opts := GenerateOptions{
		Prefix:    `pref"ix`,
		Author:    `auth"or\name`,
		Reference: "line1\nline2",
	}

	rule := generateSimpleRule(file, opts, make(map[string]int))

	if !strings.Contains(rule, `description = "pref\"ix - file bad\"name.exe"`) {
		t.Fatalf("expected escaped description in generated rule, got:\n%s", rule)
	}

	if !strings.Contains(rule, `author = "auth\"or\\name"`) {
		t.Fatalf("expected escaped author in generated rule, got:\n%s", rule)
	}

	if !strings.Contains(rule, `reference = "line1\nline2"`) {
		t.Fatalf("expected escaped reference in generated rule, got:\n%s", rule)
	}
}
