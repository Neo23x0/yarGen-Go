package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Neo23x0/yarGen-go/internal/config"
	"github.com/Neo23x0/yarGen-go/internal/database"
	"github.com/Neo23x0/yarGen-go/internal/filter"
	"github.com/Neo23x0/yarGen-go/internal/llm"
	"github.com/Neo23x0/yarGen-go/internal/rules"
	"github.com/Neo23x0/yarGen-go/internal/scanner"
	"github.com/Neo23x0/yarGen-go/internal/scoring"
)

type YarGen struct {
	config        *config.Config
	goodwareDB    *database.LoadedDatabases
	dbMu          sync.RWMutex
	scoringEngine *scoring.Engine
	scoringStore  *scoring.Store
	llmClient     llm.Client
}

type Result struct {
	Rules       string
	DebugLog    string
	FileStrings map[string][]filter.FilteredString
}

type Options struct {
	MalwareDir       string
	OutputFile       string
	Recursive        bool
	OnlyExecutables  bool
	MaxFileSizeMB    int
	MinStringLength  int
	MaxStringLength  int
	MinScore         float64
	MaxStrings       int
	ExcludeGoodware  bool
	HighScoreThresh  float64
	IncludeOpcodes   bool
	NumOpcodes       int
	NoMagic          bool
	NoFilesize       bool
	FilesizeMultiply int
	NoSimple         bool
	NoSuper          bool
	ShowScores       bool
	Author           string
	Reference        string
	License          string
	Prefix           string
	Identifier       string
	UseLLM           bool
	LLMMaxCandidates int
	Debug            bool
}

func DefaultOptions() Options {
	return Options{
		Recursive:        true,
		MaxFileSizeMB:    10,
		MinStringLength:  8,
		MaxStringLength:  128,
		MinScore:         0,
		MaxStrings:       20,
		HighScoreThresh:  30,
		IncludeOpcodes:   true,
		NumOpcodes:       3,
		FilesizeMultiply: 3,
		Author:           "yarGen",
		UseLLM:           true,
		LLMMaxCandidates: 500,
		Debug:            false,
	}
}

func New(cfg *config.Config) (*YarGen, error) {
	scoringStore, err := scoring.NewStore(cfg.Database.ScoringDb)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scoring store: %w", err)
	}

	scoringEngine, err := scoring.NewEngine(scoringStore)
	if err != nil {
		scoringStore.Close()
		return nil, fmt.Errorf("failed to initialize scoring engine: %w", err)
	}

	llmClient, err := llm.NewClient(cfg.LLM)
	if err != nil {
		scoringStore.Close()
		return nil, fmt.Errorf("failed to initialize LLM client: %w", err)
	}

	return &YarGen{
		config:        cfg,
		scoringEngine: scoringEngine,
		scoringStore:  scoringStore,
		llmClient:     llmClient,
	}, nil
}

func (y *YarGen) Close() error {
	if y.scoringStore != nil {
		return y.scoringStore.Close()
	}
	return nil
}

func (y *YarGen) LoadDatabases(includeOpcodes bool) error {
	return y.ensureDatabases(includeOpcodes)
}

func (y *YarGen) ensureDatabases(includeOpcodes bool) error {
	y.dbMu.RLock()
	needsLoad := y.goodwareDB == nil || (includeOpcodes && len(y.goodwareDB.Opcodes) == 0)
	y.dbMu.RUnlock()
	if !needsLoad {
		return nil
	}

	y.dbMu.Lock()
	defer y.dbMu.Unlock()

	needsLoad = y.goodwareDB == nil || (includeOpcodes && len(y.goodwareDB.Opcodes) == 0)
	if !needsLoad {
		return nil
	}

	dbs, err := database.LoadAllDatabases(y.config.Database.DbsDir, includeOpcodes)
	if err != nil {
		return err
	}
	y.goodwareDB = dbs
	return nil
}

func (y *YarGen) Generate(ctx context.Context, opts Options) (*Result, error) {
	var debugLog strings.Builder

	if err := y.ensureDatabases(opts.IncludeOpcodes); err != nil {
		return nil, err
	}

	y.dbMu.RLock()
	goodwareDB := y.goodwareDB
	y.dbMu.RUnlock()

	fmt.Printf("[+] Scanning malware directory: %s\n", opts.MalwareDir)

	scanOpts := scanner.ScanOptions{
		Recursive:       opts.Recursive,
		OnlyExecutables: opts.OnlyExecutables,
		MaxFileSizeMB:   opts.MaxFileSizeMB,
		MinStringLength: opts.MinStringLength,
		MaxStringLength: opts.MaxStringLength,
		IncludeOpcodes:  opts.IncludeOpcodes,
		NumOpcodes:      opts.NumOpcodes,
	}

	scanResult, err := scanner.ScanMalwareDir(opts.MalwareDir, scanOpts, func(path string) {
		fmt.Printf("[+] Processing %s ...\n", path)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan malware directory: %w", err)
	}

	if len(scanResult.Files) == 0 {
		return nil, fmt.Errorf("no files found in %s", opts.MalwareDir)
	}

	fmt.Printf("[+] Found %d files\n", len(scanResult.Files))

	filterOpts := filter.FilterOptions{
		MinScore:        opts.MinScore,
		MaxStrings:      opts.MaxStrings,
		ExcludeGoodware: opts.ExcludeGoodware,
		HighScoreThresh: opts.HighScoreThresh,
	}

	fileStrings := make(map[string][]filter.FilteredString)
	fileOpcodes := make(map[string][]string)

	for _, file := range scanResult.Files {
		fmt.Printf("[-] Filtering strings for %s ...\n", file.Name)

		filtered := filter.FilterStrings(
			file.Strings,
			goodwareDB.Strings,
			y.scoringEngine,
			filterOpts,
		)

		if opts.Debug && len(filtered) > 0 {
			msg := fmt.Sprintf("[D] === %s ===\n", file.Name)
			msg += fmt.Sprintf("[D] Top %d strings BEFORE LLM (showing max %d):\n", len(filtered), opts.MaxStrings)
			fmt.Print(msg)
			debugLog.WriteString(msg)
			for i, s := range filtered {
				if i >= opts.MaxStrings {
					break
				}
				line := fmt.Sprintf("[D]   %d. (%.1f) %s\n", i+1, s.Score, s.Value)
				fmt.Print(line)
				debugLog.WriteString(line)
			}
		}

		if opts.UseLLM && y.llmClient.IsConfigured() && len(filtered) > 0 {
			maxCandidates := opts.LLMMaxCandidates
			if maxCandidates <= 0 {
				maxCandidates = 500
			}

			candidates := filtered
			if len(candidates) > maxCandidates {
				candidates = candidates[:maxCandidates]
			}

			fmt.Printf("[-] Refining with LLM for %s (%d candidates -> select %d)...\n", file.Name, len(candidates), opts.MaxStrings)
			refined, llmDebug, err := y.refineWithLLM(ctx, file.Name, candidates, opts.MaxStrings, opts.Debug)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[W] LLM refinement failed for %s: %v, using heuristic order\n", file.Name, err)
			} else {
				if opts.Debug {
					fmt.Print(llmDebug)
					debugLog.WriteString(llmDebug)
					msg := fmt.Sprintf("[D] Top %d strings AFTER LLM:\n", len(refined))
					fmt.Print(msg)
					debugLog.WriteString(msg)
					for i, s := range refined {
						if i >= opts.MaxStrings {
							break
						}
						line := fmt.Sprintf("[D]   %d. (%.1f) %s\n", i+1, s.Score, s.Value)
						fmt.Print(line)
						debugLog.WriteString(line)
					}
					debugLog.WriteString("\n")
				}
				filtered = refined
			}
		}

		fileStrings[file.Path] = filtered

		if opts.IncludeOpcodes {
			filteredOpcodes := filter.FilterOpcodesWithLimit(file.Opcodes, goodwareDB.Opcodes, opts.NumOpcodes)
			fileOpcodes[file.Path] = filteredOpcodes
		}
	}

	identifier := opts.Identifier
	if identifier == "" {
		identifier = filepath.Base(opts.MalwareDir)
	}

	genOpts := rules.GenerateOptions{
		Author:           opts.Author,
		Reference:        opts.Reference,
		License:          opts.License,
		Prefix:           opts.Prefix,
		ShowScores:       opts.ShowScores,
		NoMagic:          opts.NoMagic,
		NoFilesize:       opts.NoFilesize,
		FilesizeMultiply: opts.FilesizeMultiply,
		NoSimple:         opts.NoSimple,
		NoSuper:          opts.NoSuper,
		HighScoreThresh:  opts.HighScoreThresh,
	}

	if genOpts.Prefix == "" {
		genOpts.Prefix = identifier
	}

	fileData := rules.ConvertScanResultToFileData(scanResult, fileStrings, fileOpcodes)

	fmt.Printf("[+] Generating rules ...\n")
	generated := rules.Generate(fileData, identifier, genOpts)

	output := generated.String()

	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, []byte(output), 0644); err != nil {
			return nil, fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("[+] Rules written to %s\n", opts.OutputFile)
	}

	fmt.Printf("[=] Generated %d simple rules, %d super rules\n", len(generated.SimpleRules), len(generated.SuperRules))

	return &Result{
		Rules:       output,
		DebugLog:    debugLog.String(),
		FileStrings: fileStrings,
	}, nil
}

func (y *YarGen) refineWithLLM(ctx context.Context, fileName string, strs []filter.FilteredString, maxStrings int, debug bool) ([]filter.FilteredString, string, error) {
	req := llm.ScoreRequest{
		FileName:   fileName,
		Strings:    strs,
		MaxStrings: maxStrings,
	}

	resp, err := y.llmClient.ScoreStrings(ctx, req)

	var debugInfo strings.Builder

	if err != nil {
		if debug {
			debugInfo.WriteString(fmt.Sprintf("[D] LLM scoring failed: %v\n", err))
		}
		return nil, debugInfo.String(), err
	}

	if debug {
		debugInfo.WriteString(fmt.Sprintf("[D] LLM raw response (first 1500 chars): %.1500s\n", resp.RawResponse))
		debugInfo.WriteString(fmt.Sprintf("[D] LLM scored %d candidates\n", len(resp.Scores)))
		if resp.Reasoning != "" {
			debugInfo.WriteString(fmt.Sprintf("[D] LLM reasoning: %s\n", resp.Reasoning))
		}
	}

	type scoredString struct {
		Index          int
		String         filter.FilteredString
		HeuristicScore float64
		LLMScore       int
		CombinedScore  float64
	}

	scored := make([]scoredString, len(strs))
	for i, s := range strs {
		llmScore := 0
		if resp.Scores != nil {
			if score, ok := resp.Scores[i+1]; ok {
				llmScore = score
			}
		}
		scored[i] = scoredString{
			Index:          i + 1,
			String:         s,
			HeuristicScore: s.Score,
			LLMScore:       llmScore,
			CombinedScore:  s.Score + float64(llmScore),
		}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].CombinedScore > scored[j].CombinedScore
	})

	if debug {
		debugInfo.WriteString("[D] Top candidates after LLM scoring:\n")
		showCount := maxStrings
		if showCount > 20 {
			showCount = 20
		}
		for i := 0; i < showCount && i < len(scored); i++ {
			s := scored[i]
			note := ""
			if resp.PerItemNote != nil {
				note = resp.PerItemNote[fmt.Sprintf("%d", s.Index)]
			}
			if s.LLMScore > 0 {
				if note != "" {
					debugInfo.WriteString(fmt.Sprintf("[D]   %d. [#%d] %.1f + %d = %.1f : %s\n        Note: %s\n",
						i+1, s.Index, s.HeuristicScore, s.LLMScore, s.CombinedScore, s.String.Value, note))
				} else {
					debugInfo.WriteString(fmt.Sprintf("[D]   %d. [#%d] %.1f + %d = %.1f : %s\n",
						i+1, s.Index, s.HeuristicScore, s.LLMScore, s.CombinedScore, s.String.Value))
				}
			} else {
				debugInfo.WriteString(fmt.Sprintf("[D]   %d. [#%d] %.1f (no LLM score) : %s\n",
					i+1, s.Index, s.HeuristicScore, s.String.Value))
			}
		}
	}

	result := make([]filter.FilteredString, 0, maxStrings)
	for i := 0; i < maxStrings && i < len(scored); i++ {
		result = append(result, scored[i].String)
	}

	return result, debugInfo.String(), nil
}

func (y *YarGen) ScoringStore() *scoring.Store {
	return y.scoringStore
}

func (y *YarGen) ScoringEngine() *scoring.Engine {
	return y.scoringEngine
}

func (y *YarGen) ReloadScoringRules() error {
	return y.scoringEngine.Reload()
}

func (y *YarGen) LLMClient() llm.Client {
	return y.llmClient
}
