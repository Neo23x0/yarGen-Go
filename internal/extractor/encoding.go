package extractor

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
)

type EncodingType string

const (
	EncodingNone     EncodingType = ""
	EncodingBase64   EncodingType = "base64"
	EncodingHex      EncodingType = "hex"
	EncodingReversed EncodingType = "reversed"
)

type EncodingDetection struct {
	Type         EncodingType
	Original     string
	Decoded      string
	BonusScore   float64
}

var (
	base64Pattern   = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	hexPattern      = regexp.MustCompile(`^[A-Fa-f0-9]+$`)
	base64MZHeaders = []string{
		"TVqQAAMAAAAEAAAA//8AALgAAAA",
		"TVpQAAIAAAAEAA8A//8AALgAAAA",
		"TVqAAAEAAAAEABAAAAAAAAAAAAA",
		"TVoAAAAAAAAAAAAAAAAAAAAAAAA",
		"TVpTAQEAAAAEAAAA//8AALgAAAA",
	}
)

func DetectEncoding(s string, goodwareDB map[string]int) *EncodingDetection {
	if det := detectBase64(s); det != nil {
		return det
	}

	if det := detectHexEncoded(s); det != nil {
		return det
	}

	if det := detectReversed(s, goodwareDB); det != nil {
		return det
	}

	return nil
}

func detectBase64(s string) *EncodingDetection {
	if len(s) < 12 {
		return nil
	}

	for _, header := range base64MZHeaders {
		if strings.Contains(s, header) {
			return &EncodingDetection{
				Type:       EncodingBase64,
				Original:   s,
				Decoded:    "[PE executable]",
				BonusScore: 5,
			}
		}
	}

	if len(s)%4 != 0 {
		return nil
	}

	if !base64Pattern.MatchString(s) {
		return nil
	}

	if !strings.ContainsAny(s, "0123456789") {
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		for _, suffix := range []string{"", "=", "=="} {
			padded := s + suffix
			if len(padded)%4 == 0 {
				decoded, err = base64.StdEncoding.DecodeString(padded)
				if err == nil {
					break
				}
			}
		}
	}

	if err != nil {
		return nil
	}

	if isASCIIPrintable(decoded) {
		return &EncodingDetection{
			Type:       EncodingBase64,
			Original:   s,
			Decoded:    string(decoded),
			BonusScore: 10,
		}
	}

	return nil
}

func detectHexEncoded(s string) *EncodingDetection {
	if len(s) < 16 || len(s)%2 != 0 {
		return nil
	}

	cleaned := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, s)

	if len(cleaned) < 16 || len(cleaned)%2 != 0 {
		return nil
	}

	if !hexPattern.MatchString(cleaned) {
		return nil
	}

	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil
	}

	if strings.Count(cleaned, "00") > len(cleaned)/4 {
		return nil
	}

	if isASCIIPrintable(decoded) {
		return &EncodingDetection{
			Type:       EncodingHex,
			Original:   s,
			Decoded:    string(decoded),
			BonusScore: 8,
		}
	}

	return nil
}

func detectReversed(s string, goodwareDB map[string]int) *EncodingDetection {
	if len(s) < 6 || goodwareDB == nil {
		return nil
	}

	reversed := reverseString(s)
	if _, exists := goodwareDB[reversed]; exists {
		return &EncodingDetection{
			Type:       EncodingReversed,
			Original:   s,
			Decoded:    reversed,
			BonusScore: 10,
		}
	}

	return nil
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func isASCIIPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	printableCount := 0
	for _, b := range data {
		if b == 0 {
			continue
		}
		if b >= 0x20 && b <= 0x7e {
			printableCount++
		} else if !unicode.IsSpace(rune(b)) {
			return false
		}
	}

	return printableCount > 0
}

func ApplyEncodingBonus(s string, baseScore float64, goodwareDB map[string]int) (float64, *EncodingDetection) {
	detection := DetectEncoding(s, goodwareDB)
	if detection != nil {
		return baseScore + detection.BonusScore, detection
	}
	return baseScore, nil
}
