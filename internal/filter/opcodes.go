package filter

import (
	"strings"

	"github.com/Neo23x0/yarern-go/internal/database"
	"github.com/Neo23x0/yarern-go/internal/extractor"
)

var preferredOpcodePatterns = []string{
	"34",
	"ffffff",
}

func FilterOpcodes(opcodes []string, goodwareDB database.Counter) []string {
	if len(opcodes) == 0 {
		return nil
	}

	var preferred []string
	var normal []string

	for _, opcode := range opcodes {
		if goodwareDB != nil {
			if _, exists := goodwareDB[opcode]; exists {
				continue
			}
		}

		formatted := extractor.FormatOpcode(opcode)

		isPreferred := false
		for _, pref := range preferredOpcodePatterns {
			if strings.Contains(formatted, pref) {
				isPreferred = true
				break
			}
		}

		if isPreferred {
			preferred = append(preferred, formatted)
		} else {
			normal = append(normal, formatted)
		}
	}

	result := append(preferred, normal...)
	return result
}

func FilterOpcodesWithLimit(opcodes []string, goodwareDB database.Counter, limit int) []string {
	filtered := FilterOpcodes(opcodes, goodwareDB)
	if limit > 0 && len(filtered) > limit {
		return filtered[:limit]
	}
	return filtered
}
