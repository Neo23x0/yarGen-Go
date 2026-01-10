package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Neo23x0/yarern-go/internal/filter"
)

type SuperRuleCandidate struct {
	Files   []FileData
	Strings []filter.FilteredString
}

func findSuperRules(files []FileData, opts GenerateOptions) []SuperRuleCandidate {
	stringToFiles := make(map[string][]int)

	for i, file := range files {
		for _, s := range file.Strings {
			stringToFiles[s.Value] = append(stringToFiles[s.Value], i)
		}
	}

	combinations := make(map[string]*SuperRuleCandidate)

	for str, fileIndices := range stringToFiles {
		if len(fileIndices) < 2 {
			continue
		}

		sort.Ints(fileIndices)
		key := intsToKey(fileIndices)

		if _, exists := combinations[key]; !exists {
			candidateFiles := make([]FileData, len(fileIndices))
			for i, idx := range fileIndices {
				candidateFiles[i] = files[idx]
			}
			combinations[key] = &SuperRuleCandidate{
				Files:   candidateFiles,
				Strings: make([]filter.FilteredString, 0),
			}
		}

		var matchingString filter.FilteredString
		for _, file := range files {
			for _, s := range file.Strings {
				if s.Value == str {
					matchingString = s
					break
				}
			}
		}
		combinations[key].Strings = append(combinations[key].Strings, matchingString)
	}

	var result []SuperRuleCandidate
	for _, candidate := range combinations {
		if len(candidate.Strings) >= 5 {
			sort.Slice(candidate.Strings, func(i, j int) bool {
				return candidate.Strings[i].Score > candidate.Strings[j].Score
			})

			if len(candidate.Strings) > 20 {
				candidate.Strings = candidate.Strings[:20]
			}

			result = append(result, *candidate)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return len(result[i].Files) > len(result[j].Files)
	})

	return result
}

func intsToKey(ints []int) string {
	strs := make([]string, len(ints))
	for i, n := range ints {
		strs[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(strs, ":")
}

func generateSuperRule(sr SuperRuleCandidate, opts GenerateOptions, usedNames map[string]int) string {
	var fileNames []string
	for _, f := range sr.Files {
		baseName := strings.TrimSuffix(f.Name, "."+getExtension(f.Name))
		fileNames = append(fileNames, baseName)
	}

	combinedName := strings.Join(fileNames, "_")
	if len(combinedName) > 100 {
		combinedName = combinedName[:100]
	}

	ruleName := createRuleName(combinedName+"_super", usedNames)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("rule %s {\n", ruleName))

	sb.WriteString("   meta:\n")
	fileList := make([]string, len(sr.Files))
	for i, f := range sr.Files {
		fileList[i] = f.Name
	}
	sb.WriteString(fmt.Sprintf("      description = \"%s - from files %s\"\n", opts.Prefix, strings.Join(fileList, ", ")))
	sb.WriteString(fmt.Sprintf("      author = \"%s\"\n", opts.Author))
	if opts.Reference != "" {
		sb.WriteString(fmt.Sprintf("      reference = \"%s\"\n", opts.Reference))
	}
	sb.WriteString(fmt.Sprintf("      date = \"%s\"\n", time.Now().Format("2006-01-02")))

	for i, f := range sr.Files {
		sb.WriteString(fmt.Sprintf("      hash%d = \"%s\"\n", i+1, f.Hash))
	}
	sb.WriteString("      score = 75\n")

	sb.WriteString("   strings:\n")
	highCount, lowCount := writeStrings(&sb, sr.Strings, opts)

	sb.WriteString("   condition:\n")

	var conditions []string

	var magics []string
	var sizes []int64
	for _, f := range sr.Files {
		if f.Magic != "" && !contains(magics, f.Magic) {
			magics = append(magics, f.Magic)
		}
		sizes = append(sizes, f.Size)
	}

	if !opts.NoMagic && len(magics) > 0 && len(magics) <= 5 {
		var magicConds []string
		for _, m := range magics {
			magicConds = append(magicConds, getMagicCondition(m))
		}
		if len(magicConds) == 1 {
			conditions = append(conditions, magicConds[0])
		} else {
			conditions = append(conditions, fmt.Sprintf("(%s)", strings.Join(magicConds, " or ")))
		}
	}

	if !opts.NoFilesize && len(sizes) > 0 {
		maxSize := sizes[0]
		for _, s := range sizes {
			if s > maxSize {
				maxSize = s
			}
		}
		conditions = append(conditions, getFilesizeCondition(maxSize, opts.FilesizeMultiply))
	}

	stringCond := buildStringCondition(highCount, lowCount, false)
	conditions = append(conditions, stringCond)

	sb.WriteString(fmt.Sprintf("      (%s)\n", strings.Join(conditions, " and ")))
	sb.WriteString(fmt.Sprintf("      or (all of them)\n"))

	sb.WriteString("}\n")

	return sb.String()
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
