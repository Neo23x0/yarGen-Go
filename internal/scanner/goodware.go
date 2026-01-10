package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Neo23x0/yarern-go/internal/database"
	"github.com/Neo23x0/yarern-go/internal/extractor"
)

func ScanGoodwareDir(dir string, opts ScanOptions, progressFn func(path string)) (*GoodwareResult, error) {
	result := &GoodwareResult{
		Strings: make(database.Counter),
		Opcodes: make(database.Counter),
	}

	err := walkDir(dir, opts.Recursive, func(path string) error {
		if progressFn != nil {
			progressFn(path)
		}

		info, err := os.Stat(path)
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if opts.OnlyExecutables {
			ext := strings.ToLower(filepath.Ext(path))
			if !RelevantExtensions[ext] {
				return nil
			}
		}

		if opts.MaxFileSizeMB > 0 && info.Size() > int64(opts.MaxFileSizeMB)*1024*1024 {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[W] Cannot read file: %s\n", path)
			return nil
		}

		strings := extractor.ExtractAllStrings(data, opts.MinStringLength, opts.MaxStringLength)
		for _, s := range strings {
			result.Strings[s]++
		}

		if opts.IncludeOpcodes {
			opcodes, err := extractor.ExtractOpcodes(data, opts.NumOpcodes*3)
			if err == nil {
				for _, op := range opcodes {
					result.Opcodes[op]++
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

type GoodwareResult struct {
	Strings database.Counter
	Opcodes database.Counter
}
