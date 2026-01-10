package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Neo23x0/yarern-go/internal/filter"
	"github.com/Neo23x0/yarern-go/internal/scanner"
)

type GenerateOptions struct {
	Author           string
	Reference        string
	License          string
	Prefix           string
	ShowScores       bool
	NoMagic          bool
	NoFilesize       bool
	FilesizeMultiply int
	NoSimple         bool
	NoSuper          bool
	HighScoreThresh  float64
}

func DefaultGenerateOptions() GenerateOptions {
	return GenerateOptions{
		Author:           "yarGen",
		Reference:        "",
		License:          "",
		Prefix:           "Auto-generated rule",
		ShowScores:       false,
		NoMagic:          false,
		NoFilesize:       false,
		FilesizeMultiply: 3,
		NoSimple:         false,
		NoSuper:          false,
		HighScoreThresh:  30,
	}
}

type GeneratedRules struct {
	Header      string
	SimpleRules []string
	SuperRules  []string
}

func (g *GeneratedRules) String() string {
	var sb strings.Builder
	sb.WriteString(g.Header)
	sb.WriteString("\n")

	if len(g.SimpleRules) > 0 {
		sb.WriteString("/* Rule Set ----------------------------------------------------------------- */\n\n")
		for _, rule := range g.SimpleRules {
			sb.WriteString(rule)
			sb.WriteString("\n")
		}
	}

	if len(g.SuperRules) > 0 {
		sb.WriteString("/* Super Rules ------------------------------------------------------------- */\n\n")
		for _, rule := range g.SuperRules {
			sb.WriteString(rule)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

type FileData struct {
	Path    string
	Name    string
	Hash    string
	Size    int64
	Magic   string
	Strings []filter.FilteredString
	Opcodes []string
}

func Generate(files []FileData, identifier string, opts GenerateOptions) *GeneratedRules {
	result := &GeneratedRules{
		Header:      generateHeader(opts, identifier),
		SimpleRules: make([]string, 0),
		SuperRules:  make([]string, 0),
	}

	usedNames := make(map[string]int)

	if !opts.NoSimple {
		for _, file := range files {
			if len(file.Strings) == 0 {
				continue
			}
			rule := generateSimpleRule(file, opts, usedNames)
			result.SimpleRules = append(result.SimpleRules, rule)
		}
	}

	if !opts.NoSuper && len(files) > 1 {
		superRules := findSuperRules(files, opts)
		for _, sr := range superRules {
			rule := generateSuperRule(sr, opts, usedNames)
			result.SuperRules = append(result.SuperRules, rule)
		}
	}

	return result
}

func generateHeader(opts GenerateOptions, identifier string) string {
	var sb strings.Builder
	sb.WriteString("/*\n")
	sb.WriteString("   YARA Rule Set\n")
	sb.WriteString(fmt.Sprintf("   Author: %s\n", opts.Author))
	sb.WriteString(fmt.Sprintf("   Date: %s\n", time.Now().Format("2006-01-02")))
	sb.WriteString(fmt.Sprintf("   Identifier: %s\n", identifier))
	if opts.Reference != "" {
		sb.WriteString(fmt.Sprintf("   Reference: %s\n", opts.Reference))
	}
	if opts.License != "" {
		sb.WriteString(fmt.Sprintf("   License: %s\n", opts.License))
	}
	sb.WriteString("*/\n")
	return sb.String()
}

func generateSimpleRule(file FileData, opts GenerateOptions, usedNames map[string]int) string {
	ruleName := createRuleName(file.Name, usedNames)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("rule %s {\n", ruleName))

	sb.WriteString("   meta:\n")
	sb.WriteString(fmt.Sprintf("      description = \"%s - file %s\"\n", opts.Prefix, file.Name))
	sb.WriteString(fmt.Sprintf("      author = \"%s\"\n", opts.Author))
	if opts.Reference != "" {
		sb.WriteString(fmt.Sprintf("      reference = \"%s\"\n", opts.Reference))
	}
	sb.WriteString(fmt.Sprintf("      date = \"%s\"\n", time.Now().Format("2006-01-02")))
	sb.WriteString(fmt.Sprintf("      hash1 = \"%s\"\n", file.Hash))
	sb.WriteString("      score = 75\n")

	sb.WriteString("   strings:\n")
	highCount, lowCount := writeStrings(&sb, file.Strings, opts)
	opcodesIncluded := writeOpcodes(&sb, file.Opcodes)

	sb.WriteString("   condition:\n")
	condition := buildCondition(file, highCount, lowCount, opcodesIncluded, opts)
	sb.WriteString(fmt.Sprintf("      %s\n", condition))

	sb.WriteString("}\n")

	return sb.String()
}

func writeStrings(sb *strings.Builder, strs []filter.FilteredString, opts GenerateOptions) (highCount, lowCount int) {
	for i, s := range strs {
		prefix := "s"
		if s.IsHighScoring {
			prefix = "x"
			highCount++
		} else {
			lowCount++
		}

		encoding := "ascii"
		if s.IsWide {
			encoding = "wide"
		}

		var comments []string
		if opts.ShowScores {
			comments = append(comments, fmt.Sprintf("score: %.1f", s.Score))
		}
		if s.GoodwareCount > 0 {
			comments = append(comments, fmt.Sprintf("goodware: %d", s.GoodwareCount))
		}
		if s.EncodingInfo != nil {
			comments = append(comments, fmt.Sprintf("%s encoded", s.EncodingInfo.Type))
		}

		commentStr := ""
		if len(comments) > 0 {
			commentStr = fmt.Sprintf(" /* %s */", strings.Join(comments, ", "))
		}

		value := s.Value
		fullword := " fullword"
		if len(value) > 128 {
			value = value[:128]
			fullword = ""
		}

		sb.WriteString(fmt.Sprintf("      $%s%d = \"%s\"%s %s%s\n", prefix, i+1, value, fullword, encoding, commentStr))
	}
	return
}

func writeOpcodes(sb *strings.Builder, opcodes []string) bool {
	if len(opcodes) == 0 {
		return false
	}

	sb.WriteString("\n")
	for i, op := range opcodes {
		sb.WriteString(fmt.Sprintf("      $op%d = { %s }\n", i, op))
	}
	return true
}

func buildCondition(file FileData, highCount, lowCount int, opcodesIncluded bool, opts GenerateOptions) string {
	var conditions []string

	if !opts.NoMagic && file.Magic != "" {
		conditions = append(conditions, getMagicCondition(file.Magic))
	}

	if !opts.NoFilesize && file.Size > 0 {
		conditions = append(conditions, getFilesizeCondition(file.Size, opts.FilesizeMultiply))
	}

	stringCond := buildStringCondition(highCount, lowCount, opcodesIncluded)
	conditions = append(conditions, stringCond)

	return strings.Join(conditions, " and ")
}

func buildStringCondition(highCount, lowCount int, opcodesIncluded bool) string {
	var parts []string

	if highCount > 0 {
		parts = append(parts, "1 of ($x*)")
	}

	if lowCount > 0 {
		if lowCount > 10 {
			if highCount > 0 {
				parts = append(parts, "4 of ($s*)")
			} else {
				parts = append(parts, "8 of ($s*)")
			}
		} else {
			parts = append(parts, "all of ($s*)")
		}
	}

	cond := strings.Join(parts, " and ")
	if cond == "" {
		cond = "all of them"
	}

	if opcodesIncluded {
		cond = fmt.Sprintf("(%s) and all of ($op*)", cond)
	}

	return cond
}

func getMagicCondition(magic string) string {
	if len(magic) == 4 {
		return fmt.Sprintf("uint16(0) == 0x%s%s", magic[2:4], magic[0:2])
	}
	if len(magic) == 2 {
		return fmt.Sprintf("uint8(0) == 0x%s", magic)
	}
	return ""
}

func getFilesizeCondition(size int64, multiplier int) string {
	maxSize := size * int64(multiplier)
	if maxSize < 1024 {
		maxSize = 1024
	}

	maxSizeKB := maxSize / 1024

	switch {
	case maxSizeKB < 100:
		maxSizeKB = ((maxSizeKB + 9) / 10) * 10
	case maxSizeKB < 1000:
		maxSizeKB = ((maxSizeKB + 99) / 100) * 100
	default:
		maxSizeKB = ((maxSizeKB + 999) / 1000) * 1000
	}

	return fmt.Sprintf("filesize < %dKB", maxSizeKB)
}

var invalidChars = regexp.MustCompile(`[^\w]`)

func createRuleName(fileName string, usedNames map[string]int) string {
	name := strings.TrimSuffix(fileName, "."+getExtension(fileName))
	name = invalidChars.ReplaceAllString(name, "_")

	if len(name) < 8 {
		name = "file_" + name
	}

	if name[0] >= '0' && name[0] <= '9' {
		name = "sig_" + name
	}

	if count, exists := usedNames[name]; exists {
		usedNames[name] = count + 1
		name = fmt.Sprintf("%s_%d", name, count+1)
	} else {
		usedNames[name] = 1
	}

	return name
}

func getExtension(fileName string) string {
	parts := strings.Split(fileName, ".")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return ""
}

func ConvertScanResultToFileData(scanResult *scanner.ScanResult, fileStrings map[string][]filter.FilteredString, fileOpcodes map[string][]string) []FileData {
	result := make([]FileData, 0, len(scanResult.Files))

	for _, f := range scanResult.Files {
		fd := FileData{
			Path:    f.Path,
			Name:    f.Name,
			Hash:    f.Hash,
			Size:    f.Size,
			Magic:   f.Magic,
			Strings: fileStrings[f.Path],
			Opcodes: fileOpcodes[f.Path],
		}
		result = append(result, fd)
	}

	return result
}
