package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveMalwareInput_DirectoryMode(t *testing.T) {
	dir := t.TempDir()

	resolvedDir, usingSingleFile, cleanup, err := resolveMalwareInput(dir, "")
	if err != nil {
		t.Fatalf("resolveMalwareInput returned unexpected error: %v", err)
	}
	if usingSingleFile {
		t.Fatalf("expected directory mode, got single-file mode")
	}
	if resolvedDir != dir {
		t.Fatalf("unexpected resolved directory: got %q want %q", resolvedDir, dir)
	}

	cleanup()
}

func TestResolveMalwareInput_RejectsBothFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(file, []byte("abc"), 0o644); err != nil {
		t.Fatalf("failed to create sample file: %v", err)
	}

	_, _, cleanup, err := resolveMalwareInput(dir, file)
	if err == nil {
		cleanup()
		t.Fatal("expected error when both -m and -f are provided")
	}
	if !strings.Contains(err.Error(), "cannot use both -f") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveMalwareInput_MissingFile(t *testing.T) {
	_, _, cleanup, err := resolveMalwareInput("", filepath.Join(t.TempDir(), "missing.bin"))
	if err == nil {
		cleanup()
		t.Fatal("expected missing-file error")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveMalwareInput_RejectsDirectoryInSingleFileMode(t *testing.T) {
	dir := t.TempDir()

	_, _, cleanup, err := resolveMalwareInput("", dir)
	if err == nil {
		cleanup()
		t.Fatal("expected error for directory input in single-file mode")
	}
	if !strings.Contains(err.Error(), "expected file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveMalwareInput_SingleFileCopiesToTempDirectory(t *testing.T) {
	tempRoot := t.TempDir()
	sourceFile := filepath.Join(tempRoot, "sample.bin")
	content := []byte("malware sample")
	if err := os.WriteFile(sourceFile, content, 0o644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	resolvedDir, usingSingleFile, cleanup, err := resolveMalwareInput("", sourceFile)
	if err != nil {
		t.Fatalf("resolveMalwareInput returned unexpected error: %v", err)
	}
	if !usingSingleFile {
		t.Fatal("expected single-file mode")
	}

	copiedPath := filepath.Join(resolvedDir, filepath.Base(sourceFile))
	copiedContent, err := os.ReadFile(copiedPath)
	if err != nil {
		cleanup()
		t.Fatalf("failed to read copied file: %v", err)
	}
	if string(copiedContent) != string(content) {
		cleanup()
		t.Fatalf("copied file content mismatch: got %q want %q", string(copiedContent), string(content))
	}

	cleanup()
	if _, err := os.Stat(resolvedDir); !os.IsNotExist(err) {
		t.Fatalf("expected temp directory to be removed, got err=%v", err)
	}
}
