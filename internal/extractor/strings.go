package extractor

import (
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	asciiStringPattern = regexp.MustCompile(`[\x20-\x7e]{6,}`)
	wideStringPattern  = regexp.MustCompile(`(?:[\x20-\x7e][\x00]){6,}`)
)

type ExtractedStrings struct {
	ASCII []string
	Wide  []string
}

func ExtractStrings(data []byte, minLen, maxLen int) ExtractedStrings {
	result := ExtractedStrings{
		ASCII: make([]string, 0),
		Wide:  make([]string, 0),
	}

	seen := make(map[string]bool)

	asciiMatches := asciiStringPattern.FindAll(data, -1)
	for _, match := range asciiMatches {
		s := string(match)
		if len(s) < minLen {
			continue
		}
		if len(s) > maxLen {
			s = s[:maxLen]
		}
		s = escapeString(s)
		if !seen[s] {
			seen[s] = true
			result.ASCII = append(result.ASCII, s)
		}
	}

	wideMatches := wideStringPattern.FindAll(data, -1)
	for _, match := range wideMatches {
		decoded := decodeWideString(match)
		if len(decoded) < minLen {
			continue
		}
		if len(decoded) > maxLen {
			decoded = decoded[:maxLen]
		}
		decoded = escapeString(decoded)
		if !seen[decoded] {
			seen[decoded] = true
			result.Wide = append(result.Wide, decoded)
		}
	}

	return result
}

func ExtractAllStrings(data []byte, minLen, maxLen int) []string {
	extracted := ExtractStrings(data, minLen, maxLen)

	result := make([]string, 0, len(extracted.ASCII)+len(extracted.Wide))
	result = append(result, extracted.ASCII...)

	for _, s := range extracted.Wide {
		result = append(result, "UTF16LE:"+s)
	}

	return result
}

func decodeWideString(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data)-1; i += 2 {
		if data[i+1] == 0x00 && data[i] >= 0x20 && data[i] <= 0x7e {
			sb.WriteByte(data[i])
		}
	}
	return sb.String()
}

func escapeString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func ExtractMagicHeader(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	return hex.EncodeToString(data[:2])
}

func IsPEFile(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return data[0] == 'M' && data[1] == 'Z'
}

func IsELFFile(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'
}
