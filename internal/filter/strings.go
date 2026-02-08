package filter

import (
	"sort"

	"github.com/Neo23x0/yarGen-go/internal/database"
	"github.com/Neo23x0/yarGen-go/internal/extractor"
	"github.com/Neo23x0/yarGen-go/internal/scoring"
)

type FilterOptions struct {
	MinScore        float64
	MaxStrings      int
	ExcludeGoodware bool
	HighScoreThresh float64
}

func DefaultFilterOptions() FilterOptions {
	return FilterOptions{
		MinScore:        0,
		MaxStrings:      20,
		ExcludeGoodware: false,
		HighScoreThresh: 30,
	}
}

type FilteredString struct {
	Value         string
	Score         float64
	IsWide        bool
	IsHighScoring bool
	GoodwareCount int
	EncodingInfo  *extractor.EncodingDetection
	MatchedRules  []scoring.MatchedRule
}

func FilterStrings(
	strings []string,
	goodwareDB database.Counter,
	scoringEngine *scoring.Engine,
	opts FilterOptions,
) []FilteredString {
	scored := make([]FilteredString, 0, len(strings))

	for _, s := range strings {
		isWide := false
		displayStr := s
		if len(s) > 8 && s[:8] == "UTF16LE:" {
			isWide = true
			displayStr = s[8:]
		}

		goodwareCount := 0
		if goodwareDB != nil {
			if count, exists := goodwareDB[s]; exists {
				goodwareCount = count
			} else {
				goodwareCount = goodwareDB[displayStr]
			}
		}

		scoreResult := scoringEngine.ScoreWithGoodware(displayStr, goodwareCount, opts.ExcludeGoodware)

		encodingInfo := extractor.DetectEncoding(displayStr, goodwareDB)
		if encodingInfo != nil {
			scoreResult.TotalScore += encodingInfo.BonusScore
		}

		if scoreResult.TotalScore < opts.MinScore {
			continue
		}

		scored = append(scored, FilteredString{
			Value:         displayStr,
			Score:         scoreResult.TotalScore,
			IsWide:        isWide,
			IsHighScoring: scoreResult.TotalScore >= opts.HighScoreThresh,
			GoodwareCount: goodwareCount,
			EncodingInfo:  encodingInfo,
			MatchedRules:  scoreResult.MatchedRules,
		})
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	if opts.MaxStrings > 0 && len(scored) > opts.MaxStrings {
		scored = scored[:opts.MaxStrings]
	}

	return scored
}

type FileStrings struct {
	FilePath string
	FileName string
	Strings  []FilteredString
	Opcodes  []string
}

func FilterFileStrings(
	filePath string,
	fileName string,
	strings []string,
	opcodes []string,
	goodwareDB database.Counter,
	opcodeDB database.Counter,
	scoringEngine *scoring.Engine,
	opts FilterOptions,
) FileStrings {
	filteredStrings := FilterStrings(strings, goodwareDB, scoringEngine, opts)
	filteredOpcodes := FilterOpcodes(opcodes, opcodeDB)

	return FileStrings{
		FilePath: filePath,
		FileName: fileName,
		Strings:  filteredStrings,
		Opcodes:  filteredOpcodes,
	}
}
