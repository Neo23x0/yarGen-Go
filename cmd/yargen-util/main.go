package main

import (
	"flag"
	"fmt"
	"os"

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

	result, err := database.InspectDatabase(*output, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[W] Merged database but failed to inspect output: %v\n", err)
		return
	}
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
