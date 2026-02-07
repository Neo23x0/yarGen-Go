package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Neo23x0/yarGen-go/internal/database"
	"github.com/Neo23x0/yarGen-go/internal/scanner"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "update":
		cmdUpdate()
	case "create":
		cmdCreate()
	case "append":
		cmdAppend()
	case "inspect":
		cmdInspect()
	case "merge":
		cmdMerge()
	case "list":
		cmdList()
	case "submit":
		cmdSubmit()
	case "version":
		fmt.Printf("yargen-util version %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("yargen-util - Database management utility for yarGen")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  update              Download pre-built databases from GitHub")
	fmt.Println("  create              Create new database from goodware directory")
	fmt.Println("  append              Append to existing database")
	fmt.Println("  inspect <db-file>   Show database statistics")
	fmt.Println("  merge               Merge multiple databases")
	fmt.Println("  list                List all databases")
	fmt.Println("  submit <sample>     Submit sample to yarGen server for rule generation")
	fmt.Println("  version             Show version")
	fmt.Println("  help                Show this help")
	fmt.Println()
	fmt.Println("Use 'yargen-util <command> -h' for more information about a command.")
}

func cmdUpdate() {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	dbsDir := fs.String("dbs-dir", "./dbs", "Database directory")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to parse flags: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	fmt.Println("[+] Downloading databases...")

	err := database.DownloadDatabases(*dbsDir, func(filename string, current, total int) {
		fmt.Printf("[%d/%d] Downloading %s...\n", current, total, filename)
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] Databases downloaded successfully")
}

func cmdCreate() {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	goodwareDir := fs.String("g", "", "Goodware directory (required)")
	identifier := fs.String("i", "", "Database identifier")
	dbsDir := fs.String("dbs-dir", "./dbs", "Database directory")
	opcodes := fs.Bool("opcodes", false, "Include opcodes")
	recursive := fs.Bool("r", true, "Recursive scan")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to parse flags: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	if *goodwareDir == "" {
		fmt.Fprintln(os.Stderr, "[E] Goodware directory required (-g)")
		fs.Usage()
		os.Exit(1)
	}

	opts := scanner.DefaultScanOptions()
	opts.Recursive = *recursive
	opts.IncludeOpcodes = *opcodes

	fmt.Printf("[+] Scanning goodware directory: %s\n", *goodwareDir)

	result, err := scanner.ScanGoodwareDir(*goodwareDir, opts, func(path string) {
		fmt.Printf("[+] Processing %s\n", path)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	dbId := ""
	if *identifier != "" {
		dbId = "-" + *identifier
	}

	stringsDb := fmt.Sprintf("%s/good-strings%s.db", *dbsDir, dbId)
	opcodesDb := fmt.Sprintf("%s/good-opcodes%s.db", *dbsDir, dbId)

	if err := os.MkdirAll(*dbsDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Saving strings database: %s (%d entries)\n", stringsDb, len(result.Strings))
	if err := database.Save(result.Strings, stringsDb); err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	if *opcodes {
		fmt.Printf("[+] Saving opcodes database: %s (%d entries)\n", opcodesDb, len(result.Opcodes))
		if err := database.Save(result.Opcodes, opcodesDb); err != nil {
			fmt.Fprintf(os.Stderr, "[E] %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("[+] Databases created successfully")
}

func cmdAppend() {
	fs := flag.NewFlagSet("append", flag.ExitOnError)
	goodwareDir := fs.String("g", "", "Goodware directory (required)")
	identifier := fs.String("i", "", "Database identifier")
	dbsDir := fs.String("dbs-dir", "./dbs", "Database directory")
	opcodes := fs.Bool("opcodes", false, "Include opcodes")
	recursive := fs.Bool("r", true, "Recursive scan")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to parse flags: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	if *goodwareDir == "" {
		fmt.Fprintln(os.Stderr, "[E] Goodware directory required (-g)")
		fs.Usage()
		os.Exit(1)
	}

	opts := scanner.DefaultScanOptions()
	opts.Recursive = *recursive
	opts.IncludeOpcodes = *opcodes

	fmt.Printf("[+] Scanning goodware directory: %s\n", *goodwareDir)

	result, err := scanner.ScanGoodwareDir(*goodwareDir, opts, func(path string) {
		fmt.Printf("[+] Processing %s\n", path)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	dbId := ""
	if *identifier != "" {
		dbId = "-" + *identifier
	}

	stringsDb := fmt.Sprintf("%s/good-strings%s.db", *dbsDir, dbId)
	opcodesDb := fmt.Sprintf("%s/good-opcodes%s.db", *dbsDir, dbId)

	existing, err := database.Load(stringsDb)
	if err != nil {
		fmt.Printf("[+] Creating new database: %s\n", stringsDb)
		existing = make(database.Counter)
	} else {
		fmt.Printf("[+] Loaded existing database: %s (%d entries)\n", stringsDb, len(existing))
	}

	existing.Update(result.Strings)
	fmt.Printf("[+] Saving strings database: %s (%d entries)\n", stringsDb, len(existing))
	if err := database.Save(existing, stringsDb); err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	if *opcodes {
		existingOp, err := database.Load(opcodesDb)
		if err != nil {
			existingOp = make(database.Counter)
		}
		existingOp.Update(result.Opcodes)
		fmt.Printf("[+] Saving opcodes database: %s (%d entries)\n", opcodesDb, len(existingOp))
		if err := database.Save(existingOp, opcodesDb); err != nil {
			fmt.Fprintf(os.Stderr, "[E] %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("[+] Databases updated successfully")
}

func cmdInspect() {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	topN := fs.Int("top", 10, "Show top N entries")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to parse flags: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "[E] Database file required")
		os.Exit(1)
	}

	dbFile := fs.Arg(0)

	result, err := database.InspectDatabase(dbFile, *topN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Database: %s\n", result.Path)
	fmt.Printf("Total entries: %d\n", result.EntryCount)
	fmt.Println()
	fmt.Printf("Top %d entries:\n", len(result.TopEntries))
	for i, entry := range result.TopEntries {
		value := entry.Value
		if len(value) > 60 {
			value = value[:57] + "..."
		}
		fmt.Printf("  %d. [%d] %s\n", i+1, entry.Count, value)
	}
}

func cmdMerge() {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	output := fs.String("o", "", "Output database file (required)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to parse flags: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	if *output == "" {
		fmt.Fprintln(os.Stderr, "[E] Output file required (-o)")
		fs.Usage()
		os.Exit(1)
	}

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "[E] At least 2 input files required")
		os.Exit(1)
	}

	inputs := fs.Args()

	fmt.Printf("[+] Merging %d databases into %s\n", len(inputs), *output)

	if err := database.MergeDatabases(*output, inputs...); err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	result, _ := database.InspectDatabase(*output, 0)
	fmt.Printf("[+] Merged database has %d entries\n", result.EntryCount)
}

func cmdList() {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dbsDir := fs.String("dbs-dir", "./dbs", "Database directory")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to parse flags: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	databases, err := database.ListDatabases(*dbsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	if len(databases) == 0 {
		fmt.Println("No databases found")
		return
	}

	fmt.Printf("%-40s %-10s %-15s %s\n", "NAME", "TYPE", "IDENTIFIER", "ENTRIES")
	fmt.Println("--------------------------------------------------------------------------------")

	for _, db := range databases {
		fmt.Printf("%-40s %-10s %-15s %d\n", db.Name, db.Type, db.Identifier, db.EntryCount)
	}
}

// cmdSubmit submits a sample to the yarGen server and returns generated rules
func cmdSubmit() {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "yarGen server URL")
	author := fs.String("a", "yarGen", "Author name")
	reference := fs.String("r", "", "Reference")
	showScores := fs.Bool("show-scores", false, "Show scores as comments in rules")
	noOpcodes := fs.Bool("no-opcodes", false, "Disable opcode analysis")
	output := fs.String("o", "", "Output file (default: stdout)")
	maxWait := fs.Int("wait", 600, "Maximum wait time in seconds")
	verbose := fs.Bool("v", false, "Verbose output")

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to parse flags: %v\n", err)
		fs.Usage()
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "[E] Sample file required")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage: yargen-util submit [options] <sample-file>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -server <url>    yarGen server URL (default: http://127.0.0.1:8080)")
		fmt.Fprintln(os.Stderr, "  -a <author>      Author name (default: yarGen)")
		fmt.Fprintln(os.Stderr, "  -r <reference>   Reference string")
		fmt.Fprintln(os.Stderr, "  -show-scores     Show scores as comments in rules")
		fmt.Fprintln(os.Stderr, "  -no-opcodes      Disable opcode analysis")
		fmt.Fprintln(os.Stderr, "  -o <file>        Output file (default: stdout)")
		fmt.Fprintln(os.Stderr, "  -wait <seconds>  Maximum wait time (default: 600)")
		fmt.Fprintln(os.Stderr, "  -v               Verbose output")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  yargen-util submit malware.exe")
		fmt.Fprintln(os.Stderr, "  yargen-util submit -a 'Florian Roth' -show-scores malware.exe")
		fmt.Fprintln(os.Stderr, "  yargen-util submit -o rules.yar -v malware.exe")
		os.Exit(1)
	}

	samplePath := fs.Arg(0)

	// Check file exists
	if _, err := os.Stat(samplePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[E] File not found: %s\n", samplePath)
		os.Exit(1)
	}

	// Check server health
	if *verbose {
		fmt.Printf("[*] Checking server at %s ...\n", *server)
	}

	healthResp, err := http.Get(*server + "/api/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] yarGen server not running at %s\n", *server)
		fmt.Fprintln(os.Stderr, "    Start with: yargen serve")
		os.Exit(1)
	}
	healthResp.Body.Close()

	fileName := filepath.Base(samplePath)

	if *verbose {
		fmt.Printf("[+] Submitting: %s\n", fileName)
	}

	// Upload file
	jobID, err := uploadFile(*server, samplePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] Upload failed: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("[+] Job ID: %s\n", jobID)
		fmt.Println("[*] Starting rule generation...")
	}

	// Start generation
	if err := startGeneration(*server, jobID, *author, *reference, *showScores, *noOpcodes); err != nil {
		fmt.Fprintf(os.Stderr, "[E] Failed to start generation: %v\n", err)
		os.Exit(1)
	}

	// Wait for completion
	if *verbose {
		fmt.Printf("[*] Waiting for generation (max %ds)...\n", *maxWait)
	}

	rules, err := waitForRules(*server, jobID, *maxWait, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] %v\n", err)
		os.Exit(1)
	}

	// Output rules
	if *output != "" {
		if err := os.WriteFile(*output, []byte(rules), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[E] Failed to write output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Rules saved to: %s\n", *output)
	} else {
		fmt.Println(rules)
	}
}

func uploadFile(server, filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(part, file); err != nil {
		return "", err
	}
	writer.Close()

	resp, err := http.Post(server+"/api/upload", writer.FormDataContentType(), &buf)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upload failed: %s", resp.Status)
	}

	var result struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.ID == "" {
		return "", fmt.Errorf("no job ID received")
	}

	return result.ID, nil
}

func startGeneration(server, jobID, author, reference string, showScores, noOpcodes bool) error {
	req := struct {
		JobID          string `json:"job_id"`
		Author         string `json:"author"`
		Reference      string `json:"reference,omitempty"`
		ShowScores     bool   `json:"show_scores"`
		ExcludeOpcodes bool   `json:"exclude_opcodes"`
	}{
		JobID:          jobID,
		Author:         author,
		Reference:      reference,
		ShowScores:     showScores,
		ExcludeOpcodes: noOpcodes,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := http.Post(server+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("generation request failed: %s", resp.Status)
	}

	return nil
}

func waitForRules(server, jobID string, maxWait int, verbose bool) (string, error) {
	start := time.Now()
	lastStatus := ""

	for time.Since(start).Seconds() < float64(maxWait) {
		resp, err := http.Get(server + "/api/jobs/" + jobID)
		if err != nil {
			return "", err
		}

		var job struct {
			Status string `json:"status"`
			Rules  string `json:"rules"`
			Error  string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
			resp.Body.Close()
			return "", err
		}
		resp.Body.Close()

		if job.Status != lastStatus {
			lastStatus = job.Status
			if verbose {
				fmt.Printf("    Status: %s\n", job.Status)
			}
		}

		switch job.Status {
		case "completed":
			// Rules are in the job response itself
			if job.Rules == "" {
				return "", fmt.Errorf("generation completed but no rules returned")
			}
			return job.Rules, nil

		case "failed", "error":
			if job.Error != "" {
				return "", fmt.Errorf("generation failed: %s", job.Error)
			}
			return "", fmt.Errorf("generation failed")
		}

		time.Sleep(3 * time.Second)
	}

	return "", fmt.Errorf("timeout after %d seconds (job: %s)", maxWait, jobID)
}
