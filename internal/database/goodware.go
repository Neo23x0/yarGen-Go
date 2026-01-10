package database

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Counter map[string]int

func Load(filename string) (Counter, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open database %s: %w", filename, err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader for %s: %w", filename, err)
	}
	defer gzReader.Close()

	var counter Counter
	decoder := json.NewDecoder(gzReader)
	if err := decoder.Decode(&counter); err != nil {
		return nil, fmt.Errorf("failed to decode JSON from %s: %w", filename, err)
	}

	return counter, nil
}

func Save(counter Counter, filename string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()

	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	encoder := json.NewEncoder(gzWriter)
	if err := encoder.Encode(counter); err != nil {
		return fmt.Errorf("failed to encode JSON to %s: %w", filename, err)
	}

	return nil
}

func (c Counter) Update(other Counter) {
	for k, v := range other {
		c[k] += v
	}
}

func (c Counter) Merge(other Counter) Counter {
	result := make(Counter, len(c)+len(other))
	for k, v := range c {
		result[k] = v
	}
	for k, v := range other {
		result[k] += v
	}
	return result
}

type LoadedDatabases struct {
	Strings  Counter
	Opcodes  Counter
}

func LoadAllDatabases(dbsDir string, includeOpcodes bool) (*LoadedDatabases, error) {
	dbs := &LoadedDatabases{
		Strings: make(Counter),
		Opcodes: make(Counter),
	}

	entries, err := os.ReadDir(dbsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read database directory %s: %w", dbsDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}

		filePath := filepath.Join(dbsDir, entry.Name())
		name := entry.Name()

		if strings.HasPrefix(name, "good-strings") {
			counter, err := Load(filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[W] Failed to load %s: %v\n", filePath, err)
				continue
			}
			dbs.Strings.Update(counter)
			fmt.Printf("[+] Loaded %s (%d entries)\n", filePath, len(counter))
		}

		if includeOpcodes && strings.HasPrefix(name, "good-opcodes") {
			counter, err := Load(filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[W] Failed to load %s: %v\n", filePath, err)
				continue
			}
			dbs.Opcodes.Update(counter)
			fmt.Printf("[+] Loaded %s (%d entries)\n", filePath, len(counter))
		}
	}

	if len(dbs.Strings) == 0 {
		return nil, fmt.Errorf("no goodware string databases found in %s", dbsDir)
	}

	return dbs, nil
}
