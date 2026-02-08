package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Neo23x0/yarGen-go/internal/config"
	"github.com/Neo23x0/yarGen-go/internal/service"
	"github.com/Neo23x0/yarGen-go/internal/web"
)

var (
	version = "0.1.0"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		runServer()
		return
	}

	runCLI()
}

func runCLI() {
	var (
		malwareDir      = flag.String("m", "", "Path to malware directory")
		malwareFile     = flag.String("f", "", "Path to single malware file")
		outputFile      = flag.String("o", "yargen_rules.yar", "Output rule file")
		configPath      = flag.String("config", config.DefaultConfigPath(), "Config file path")
		minStrLen       = flag.Int("y", 8, "Minimum string length")
		minScore        = flag.Float64("z", 0, "Minimum score threshold")
		highScore       = flag.Float64("x", 30, "High-scoring string threshold")
		superOverlap    = flag.Int("w", 5, "Super rule overlap threshold")
		maxStrLen       = flag.Int("s", 128, "Maximum string length")
		maxStrings      = flag.Int("rc", 20, "Max strings per rule")
		excludeGoodware = flag.Bool("excludegood", false, "Exclude all goodware strings")
		author          = flag.String("a", "yarGen", "Author name")
		reference       = flag.String("r", "", "Reference")
		license         = flag.String("l", "", "License")
		prefix          = flag.String("p", "", "Rule description prefix")
		identifier      = flag.String("b", "", "Identifier")
		showScores      = flag.Bool("score", false, "Show scores as comments")
		noSimple        = flag.Bool("nosimple", false, "Skip simple rules in super rules")
		noMagic         = flag.Bool("nomagic", false, "No magic header condition")
		noFilesize      = flag.Bool("nofilesize", false, "No filesize condition")
		fsMultiplier    = flag.Int("fm", 3, "Filesize multiplier")
		noSuper         = flag.Bool("nosuper", false, "Disable super rules")
		notRecursive    = flag.Bool("nr", false, "Non-recursive scan")
		onlyExec        = flag.Bool("oe", false, "Only executable extensions")
		maxFileSize     = flag.Int("fs", 10, "Max file size in MB")
		noOpcodes       = flag.Bool("no-opcodes", false, "Exclude opcode analysis")
		numOpcodes      = flag.Int("n", 3, "Number of opcodes")
		noLLM           = flag.Bool("no-llm", false, "Disable LLM")
		debug           = flag.Bool("debug", false, "Debug output")
		showVersion     = flag.Bool("version", false, "Show version")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("yarGen-Go version %s\n", version)
		os.Exit(0)
	}

	resolvedDir, usingSingleFile, cleanup, err := resolveMalwareInput(*malwareDir, *malwareFile)
	if err != nil {
		printBanner()
		fmt.Printf("\n[E] %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	*malwareDir = resolvedDir

	if *malwareDir == "" {
		printBanner()
		flag.Usage()
		fmt.Println("\n[E] You must specify a malware directory with -m or a single file with -f")
		os.Exit(1)
	}

	printBanner()

	// Print recommendation for single file mode
	if usingSingleFile {
		printSingleFileRecommendation()
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to load config: %v\n", err)
		os.Exit(1)
	}

	yargen, err := service.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to initialize yarGen: %v\n", err)
		os.Exit(1)
	}
	defer yargen.Close()

	llmClient := yargen.LLMClient()
	if !*noLLM {
		if llmClient.IsConfigured() {
			fmt.Printf("[*] LLM: Checking availability (%s/%s)...\n", llmClient.Provider(), llmClient.Model())
			status := llmClient.CheckAvailability(context.Background())
			if status.Available {
				fmt.Printf("[+] LLM: Available and ready\n")
			} else {
				fmt.Printf("[!] LLM: Unavailable - %s\n", status.Error)
				fmt.Println("[!] LLM refinement will be skipped")
			}
		} else {
			fmt.Println("[-] LLM: Not configured (using heuristic string selection)")
			fmt.Println("    To enable AI-powered string selection:")
			fmt.Println("    1. Create config/config.yaml (or use ~/.yargen/config.yaml)")
			fmt.Println("    2. Copy config/config.example.yml and edit with your API key")
			fmt.Println("    3. Add your API key (OpenAI, Anthropic, Gemini, or Ollama)")
			fmt.Println("    4. Or use: --config /path/to/config.yaml")
			fmt.Printf("    (Checked: %s)\n", *configPath)
		}
	} else {
		fmt.Println("[-] LLM: Disabled by --no-llm flag")
	}

	opts := service.Options{
		MalwareDir:       *malwareDir,
		OutputFile:       *outputFile,
		Recursive:        !*notRecursive,
		OnlyExecutables:  *onlyExec,
		MaxFileSizeMB:    *maxFileSize,
		MinStringLength:  *minStrLen,
		MaxStringLength:  *maxStrLen,
		MinScore:         *minScore,
		MaxStrings:       *maxStrings,
		ExcludeGoodware:  *excludeGoodware,
		HighScoreThresh:  *highScore,
		IncludeOpcodes:   !*noOpcodes,
		NumOpcodes:       *numOpcodes,
		NoMagic:          *noMagic,
		NoFilesize:       *noFilesize,
		FilesizeMultiply: *fsMultiplier,
		NoSimple:         *noSimple,
		NoSuper:          *noSuper,
		ShowScores:       *showScores,
		Author:           *author,
		Reference:        *reference,
		License:          *license,
		Prefix:           *prefix,
		Identifier:       *identifier,
		UseLLM:           !*noLLM,
		LLMMaxCandidates: cfg.LLM.MaxCandidates,
		Debug:            *debug,
	}

	_ = *superOverlap

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Interrupted")
		cancel()
		os.Exit(0)
	}()

	_, err = yargen.Generate(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] yarGen completed successfully")
}

func runServer() {
	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	host := serveCmd.String("host", "127.0.0.1", "Bind address")
	port := serveCmd.Int("port", 8080, "HTTP port")
	configPath := serveCmd.String("config", config.DefaultConfigPath(), "Config file path")

	if err := serveCmd.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to parse flags: %v\n", err)
		serveCmd.Usage()
		os.Exit(1)
	}

	printBanner()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to load config: %v\n", err)
		os.Exit(1)
	}

	cfg.Server.Host = *host
	cfg.Server.Port = *port

	yargen, err := service.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to initialize yarGen: %v\n", err)
		os.Exit(1)
	}
	defer yargen.Close()

	llmClient := yargen.LLMClient()
	if llmClient.IsConfigured() {
		fmt.Printf("[*] LLM: Checking availability (%s/%s)...\n", llmClient.Provider(), llmClient.Model())
		status := llmClient.CheckAvailability(context.Background())
		if status.Available {
			fmt.Printf("[+] LLM: Available and ready\n")
		} else {
			fmt.Printf("[!] LLM: Unavailable - %s\n", status.Error)
		}
	} else {
		fmt.Println("[-] LLM: Not configured")
		fmt.Println("    To enable AI-powered string selection:")
		fmt.Println("    1. Create config/config.yaml (or use ~/.yargen/config.yaml)")
		fmt.Println("    2. Copy config/config.example.yml and edit with your API key")
		fmt.Println("    3. Add your API key (OpenAI, Anthropic, Gemini, or Ollama)")
		fmt.Println("    4. Or use: yargen serve --config /path/to/config.yaml")
		fmt.Printf("    (Checked: %s)\n", *configPath)
	}

	server := web.NewServer(cfg, yargen)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Shutting down server...")
		if err := server.Shutdown(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "[E] Error shutting down server: %v\n", err)
		}
	}()

	fmt.Printf("[+] Starting web server at http://%s:%d\n", *host, *port)
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Server error: %v\n", err)
		os.Exit(1)
	}
}

func printBanner() {
	fmt.Println("------------------------------------------------------------------------")
	fmt.Println("                   _____            ")
	fmt.Println("    __ _____ _____/ ___/__ ___      ")
	fmt.Println("   / // / _ `/ __/ (_ / -_) _ \\     ")
	fmt.Println("   \\_, /\\_,_/_/  \\___/\\__/_//_/     ")
	fmt.Println("  /___/  Yara Rule Generator        ")
	fmt.Printf("         yarGen-Go v%s\n", version)
	fmt.Println("   ")
	fmt.Println("  Note: Rules should be post-processed")
	fmt.Println("------------------------------------------------------------------------")
}

func printSingleFileRecommendation() {
	fmt.Println("------------------------------------------------------------------------")
	fmt.Println("[i] Single file mode: Database initialization may take 2-10 minutes.")
	fmt.Println("")
	fmt.Println("    Recommendation: If you plan to analyze more than one sample,")
	fmt.Println("    start the yarGen server once and submit samples to it:")
	fmt.Println("")
	fmt.Println("      ./yargen serve              # Start server (wait for init)")
	fmt.Println("      ./yargen-util submit file   # Submit samples (fast)")
	fmt.Println("      pkill -f 'yargen serve'     # Stop when done")
	fmt.Println("")
	fmt.Println("    This avoids re-loading databases for each sample.")
	fmt.Println("------------------------------------------------------------------------")
}

func resolveMalwareInput(malwareDir, malwareFile string) (resolvedDir string, usingSingleFile bool, cleanup func(), err error) {
	cleanup = func() {}

	if malwareFile == "" {
		return malwareDir, false, cleanup, nil
	}

	if malwareDir != "" {
		return "", false, cleanup, fmt.Errorf("cannot use both -f (single file) and -m (directory) flags")
	}

	info, err := os.Stat(malwareFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, cleanup, fmt.Errorf("file not found: %s", malwareFile)
		}
		return "", false, cleanup, fmt.Errorf("failed to access file %s: %w", malwareFile, err)
	}
	if info.IsDir() {
		return "", false, cleanup, fmt.Errorf("path is a directory, expected file: %s", malwareFile)
	}

	tempDir, err := os.MkdirTemp("", "yargen-single-")
	if err != nil {
		return "", false, cleanup, fmt.Errorf("failed to create temp directory: %w", err)
	}

	cleanup = func() {
		_ = os.RemoveAll(tempDir)
	}

	srcFile, err := os.Open(malwareFile)
	if err != nil {
		cleanup()
		return "", false, func() {}, fmt.Errorf("failed to open file: %w", err)
	}
	defer srcFile.Close()

	dstPath := filepath.Join(tempDir, filepath.Base(malwareFile))
	dstFile, err := os.Create(dstPath)
	if err != nil {
		cleanup()
		return "", false, func() {}, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		cleanup()
		return "", false, func() {}, fmt.Errorf("failed to copy file: %w", err)
	}

	return tempDir, true, cleanup, nil
}
