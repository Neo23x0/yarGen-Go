package web

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSanitizeUploadFilename(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		shouldErr bool
	}{
		{name: "simple", input: "sample.exe", want: "sample.exe"},
		{name: "unix traversal", input: "../../etc/passwd", want: "passwd"},
		{name: "windows traversal", input: `..\..\secret\evil.dll`, want: "evil.dll"},
		{name: "absolute path", input: "/tmp/file.bin", want: "file.bin"},
		{name: "empty", input: "", shouldErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sanitizeUploadFilename(tc.input)
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tc.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("unexpected sanitized filename: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestIsWithinDir(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "uploads")
	inside := filepath.Join(baseDir, "sample.bin")
	outside := filepath.Join(baseDir, "..", "escape.bin")

	if !isWithinDir(baseDir, inside) {
		t.Fatal("expected inside path to be allowed")
	}

	if isWithinDir(baseDir, outside) {
		t.Fatal("expected outside path to be rejected")
	}
}

func TestCloneJobDeepCopy(t *testing.T) {
	original := &Job{
		ID:     "job1",
		Status: "completed",
		Files: []UploadedFile{
			{Name: "a.bin", Size: 1, Path: "/tmp/a.bin"},
		},
		Strings: map[string][]StringInfo{
			"a.bin": {
				{Value: "cmd.exe", Score: 8, Selected: true},
			},
		},
		Rules:     "rule x { condition: true }",
		DebugLog:  "debug",
		CreatedAt: time.Now(),
	}

	cloned := cloneJob(original)
	if cloned == nil {
		t.Fatal("expected cloned job")
	}

	cloned.Files[0].Name = "changed.bin"
	cloned.Strings["a.bin"][0].Value = "changed"

	if original.Files[0].Name != "a.bin" {
		t.Fatal("expected original files slice to remain unchanged")
	}

	if original.Strings["a.bin"][0].Value != "cmd.exe" {
		t.Fatal("expected original strings map to remain unchanged")
	}
}
