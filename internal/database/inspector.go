package database

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DatabaseInfo struct {
	Path       string
	Name       string
	Type       string
	Identifier string
	EntryCount int
}

func ListDatabases(dbsDir string) ([]DatabaseInfo, error) {
	entries, err := os.ReadDir(dbsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read database directory: %w", err)
	}

	var databases []DatabaseInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}

		name := entry.Name()
		filePath := filepath.Join(dbsDir, name)

		info := DatabaseInfo{
			Path: filePath,
			Name: name,
		}

		if strings.HasPrefix(name, "good-strings") {
			info.Type = "strings"
			info.Identifier = extractIdentifier(name, "good-strings-")
		} else if strings.HasPrefix(name, "good-opcodes") {
			info.Type = "opcodes"
			info.Identifier = extractIdentifier(name, "good-opcodes-")
		} else {
			info.Type = "unknown"
		}

		counter, err := Load(filePath)
		if err == nil {
			info.EntryCount = len(counter)
		}

		databases = append(databases, info)
	}

	sort.Slice(databases, func(i, j int) bool {
		if databases[i].Type != databases[j].Type {
			return databases[i].Type < databases[j].Type
		}
		return databases[i].Name < databases[j].Name
	})

	return databases, nil
}

func InspectDatabase(filePath string, topN int) (*InspectionResult, error) {
	counter, err := Load(filePath)
	if err != nil {
		return nil, err
	}

	result := &InspectionResult{
		Path:       filePath,
		EntryCount: len(counter),
		TopEntries: make([]EntryInfo, 0, topN),
	}

	type kv struct {
		Key   string
		Value int
	}
	var sorted []kv
	for k, v := range counter {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	for i := 0; i < topN && i < len(sorted); i++ {
		result.TopEntries = append(result.TopEntries, EntryInfo{
			Value: sorted[i].Key,
			Count: sorted[i].Value,
		})
	}

	return result, nil
}

type InspectionResult struct {
	Path       string
	EntryCount int
	TopEntries []EntryInfo
}

type EntryInfo struct {
	Value string
	Count int
}

func MergeDatabases(outputPath string, inputPaths ...string) error {
	merged := make(Counter)

	for _, path := range inputPaths {
		counter, err := Load(path)
		if err != nil {
			return fmt.Errorf("failed to load %s: %w", path, err)
		}
		merged.Update(counter)
	}

	return Save(merged, outputPath)
}

func extractIdentifier(filename, prefix string) string {
	name := strings.TrimPrefix(filename, prefix)
	name = strings.TrimSuffix(name, ".db")
	return name
}
