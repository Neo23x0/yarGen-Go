package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
		malwareDir      = flag.String("m", "", "Path to malware directory (required)")
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

	if *malwareDir == "" {
		printBanner()
		flag.Usage()
		fmt.Println("\n[E] You must specify a malware directory with -m")
		os.Exit(1)
	}

	printBanner()

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

	serveCmd.Parse(os.Args[2:])

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
		server.Shutdown(context.Background())
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
