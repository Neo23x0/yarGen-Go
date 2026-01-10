package database

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const (
	ReleaseTag = "2020-1"
	BaseURL    = "https://github.com/Neo23x0/yarGen-dbs/releases/download/" + ReleaseTag + "/"
)

var DatabaseFiles = []string{
	"good-opcodes-part1.db", "good-opcodes-part2.db", "good-opcodes-part3.db",
	"good-opcodes-part4.db", "good-opcodes-part5.db", "good-opcodes-part6.db",
	"good-opcodes-part7.db", "good-opcodes-part8.db", "good-opcodes-part9.db",
	"good-opcodes-part10.db", "good-opcodes-part11.db",
	"good-strings-part1.db", "good-strings-part2.db", "good-strings-part3.db",
	"good-strings-part4.db", "good-strings-part5.db", "good-strings-part6.db",
	"good-strings-part7.db", "good-strings-part8.db", "good-strings-part9.db",
	"good-strings-part10.db", "good-strings-part11.db",
}

func DownloadDatabases(dbsDir string, progressFn func(filename string, current, total int)) error {
	if err := os.MkdirAll(dbsDir, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	total := len(DatabaseFiles)
	for i, filename := range DatabaseFiles {
		if progressFn != nil {
			progressFn(filename, i+1, total)
		}

		url := BaseURL + filename
		destPath := filepath.Join(dbsDir, filename)

		if err := downloadFile(url, destPath); err != nil {
			return fmt.Errorf("failed to download %s: %w", filename, err)
		}
	}

	return nil
}

func downloadFile(url, destPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
