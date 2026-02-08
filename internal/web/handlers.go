package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Neo23x0/yarGen-go/internal/llm"
	"github.com/Neo23x0/yarGen-go/internal/scoring"
	"github.com/Neo23x0/yarGen-go/internal/service"
)

// Job represents a rule generation job.
type Job struct {
	ID        string                  `json:"id"`
	Status    string                  `json:"status"`
	Files     []UploadedFile          `json:"files"`
	Strings   map[string][]StringInfo `json:"strings,omitempty"`
	Rules     string                  `json:"rules,omitempty"`
	Error     string                  `json:"error,omitempty"`
	DebugLog  string                  `json:"debug_log,omitempty"`
	CreatedAt time.Time               `json:"created_at"`
}

// UploadedFile represents an uploaded malware sample file.
type UploadedFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Path string `json:"-"`
}

// StringInfo contains information about an extracted string.
type StringInfo struct {
	Value         string  `json:"value"`
	Score         float64 `json:"score"`
	IsWide        bool    `json:"is_wide"`
	IsHighScoring bool    `json:"is_high_scoring"`
	GoodwareCount int     `json:"goodware_count"`
	Selected      bool    `json:"selected"`
}

var (
	jobs   = make(map[string]*Job)
	jobsMu sync.RWMutex
)

// writeJSON encodes data as JSON and writes it to the response writer.
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// If encoding fails, the connection is likely broken
		// Log but don't try to write another response
		fmt.Printf("[E] Failed to encode JSON response: %v\n", err)
	}
}

func generateJobID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func cloneJob(job *Job) *Job {
	if job == nil {
		return nil
	}

	cloned := &Job{
		ID:        job.ID,
		Status:    job.Status,
		Rules:     job.Rules,
		Error:     job.Error,
		DebugLog:  job.DebugLog,
		CreatedAt: job.CreatedAt,
	}

	if len(job.Files) > 0 {
		cloned.Files = append([]UploadedFile(nil), job.Files...)
	}

	if len(job.Strings) > 0 {
		cloned.Strings = make(map[string][]StringInfo, len(job.Strings))
		for fileName, infos := range job.Strings {
			cloned.Strings[fileName] = append([]StringInfo(nil), infos...)
		}
	}

	return cloned
}

func sanitizeUploadFilename(filename string) (string, error) {
	normalized := strings.ReplaceAll(filename, "\\", "/")
	base := path.Base(path.Clean("/" + normalized))
	if base == "." || base == "/" || base == "" || base == ".." {
		return "", fmt.Errorf("invalid filename: %q", filename)
	}
	return base, nil
}

func dedupeFilename(name string, seen map[string]int) string {
	count := seen[name]
	seen[name] = count + 1
	if count == 0 {
		return name
	}

	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	return fmt.Sprintf("%s_%d%s", stem, count+1, ext)
}

func isWithinDir(baseDir, targetPath string) bool {
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}

	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return false
	}

	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return false
	}

	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	jobID := generateJobID()
	uploadDir := filepath.Join(os.TempDir(), "yargen", jobID)
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "Failed to create upload directory", http.StatusInternalServerError)
		return
	}

	var files []UploadedFile
	usedNames := make(map[string]int)

	for _, fileHeaders := range r.MultipartForm.File {
		for _, fileHeader := range fileHeaders {
			file, err := fileHeader.Open()
			if err != nil {
				continue
			}

			safeName, err := sanitizeUploadFilename(fileHeader.Filename)
			if err != nil {
				file.Close()
				continue
			}
			safeName = dedupeFilename(safeName, usedNames)

			destPath := filepath.Join(uploadDir, safeName)
			if !isWithinDir(uploadDir, destPath) {
				file.Close()
				continue
			}

			dest, err := os.Create(destPath)
			if err != nil {
				file.Close()
				continue
			}

			if _, err := io.Copy(dest, file); err != nil {
				file.Close()
				dest.Close()
				continue
			}
			file.Close()
			dest.Close()

			files = append(files, UploadedFile{
				Name: safeName,
				Size: fileHeader.Size,
				Path: destPath,
			})
		}
	}

	if len(files) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	job := &Job{
		ID:        jobID,
		Status:    "uploaded",
		Files:     files,
		CreatedAt: time.Now(),
	}

	jobsMu.Lock()
	jobs[jobID] = job
	jobsMu.Unlock()

	writeJSON(w, job)
}

// GenerateRequest contains parameters for rule generation.
type GenerateRequest struct {
	JobID           string  `json:"job_id"`
	Author          string  `json:"author"`
	Reference       string  `json:"reference"`
	ShowScores      bool    `json:"show_scores"`
	ExcludeOpcodes  bool    `json:"exclude_opcodes"`
	NoSuper         bool    `json:"no_super"`
	ExcludeGoodware bool    `json:"exclude_goodware"`
	NoMagic         bool    `json:"no_magic"`
	NoFilesize      bool    `json:"no_filesize"`
	UseLLM          bool    `json:"use_llm"`
	MinScore        float64 `json:"min_score"`
	MaxStrings      int     `json:"max_strings"`
	Debug           bool    `json:"debug"`
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	jobsMu.RLock()
	job, exists := jobs[req.JobID]
	var uploadDir string
	if exists && len(job.Files) > 0 {
		uploadDir = filepath.Dir(job.Files[0].Path)
	}
	jobsMu.RUnlock()

	if !exists {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}
	if uploadDir == "" {
		http.Error(w, "No files in job", http.StatusBadRequest)
		return
	}

	jobsMu.Lock()
	job.Status = "processing"
	job.Error = ""
	job.Rules = ""
	job.DebugLog = ""
	job.Strings = nil
	jobsMu.Unlock()

	go func() {
		ctx := context.Background()

		opts := service.Options{
			MalwareDir:       uploadDir,
			Author:           req.Author,
			Reference:        req.Reference,
			ShowScores:       req.ShowScores,
			IncludeOpcodes:   !req.ExcludeOpcodes,
			NoSuper:          req.NoSuper,
			ExcludeGoodware:  req.ExcludeGoodware,
			NoMagic:          req.NoMagic,
			NoFilesize:       req.NoFilesize,
			UseLLM:           req.UseLLM,
			MinScore:         req.MinScore,
			MaxStrings:       req.MaxStrings,
			MinStringLength:  8,
			MaxStringLength:  128,
			LLMMaxCandidates: s.config.LLM.MaxCandidates,
			Debug:            req.Debug,
		}

		if opts.MaxStrings == 0 {
			opts.MaxStrings = 20
		}
		if opts.Author == "" {
			opts.Author = "yarGen"
		}

		result, err := s.yargen.Generate(ctx, opts)

		jobsMu.Lock()
		if err != nil {
			job.Status = "error"
			job.Error = err.Error()
		} else {
			job.Status = "completed"
			job.Rules = result.Rules
			job.DebugLog = result.DebugLog
			job.Strings = make(map[string][]StringInfo, len(result.FileStrings))
			for filePath, strs := range result.FileStrings {
				fileName := filepath.Base(filePath)
				info := make([]StringInfo, 0, len(strs))
				for _, s := range strs {
					info = append(info, StringInfo{
						Value:         s.Value,
						Score:         s.Score,
						IsWide:        s.IsWide,
						IsHighScoring: s.IsHighScoring,
						GoodwareCount: s.GoodwareCount,
						Selected:      true,
					})
				}
				job.Strings[fileName] = info
			}
		}
		jobsMu.Unlock()
	}()

	writeJSON(w, map[string]string{"status": "processing"})
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	parts := strings.Split(path, "/")

	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Job ID required", http.StatusBadRequest)
		return
	}

	jobID := parts[0]

	jobsMu.RLock()
	job, exists := jobs[jobID]
	jobCopy := cloneJob(job)
	jobsMu.RUnlock()

	if !exists {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	if len(parts) > 1 && parts[1] == "rules" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"yargen_rules_%s.yar\"", jobID[:8]))
		if _, err := w.Write([]byte(jobCopy.Rules)); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			return
		}
		return
	}

	writeJSON(w, jobCopy)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	store := s.yargen.ScoringStore()

	switch r.Method {
	case http.MethodGet:
		rules, err := store.List(true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rules)

	case http.MethodPost:
		var rule scoring.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		rule.Enabled = true
		rule.IsBuiltin = false
		if err := store.Create(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.yargen.ReloadScoringRules(); err != nil {
			http.Error(w, fmt.Sprintf("Failed to reload scoring rules: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rule)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRulesById(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/rules/")

	if path == "export" || path == "import" {
		return
	}

	var id int64
	if _, err := fmt.Sscanf(path, "%d", &id); err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	store := s.yargen.ScoringStore()

	switch r.Method {
	case http.MethodGet:
		rule, err := store.Get(id)
		if err != nil {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}
		writeJSON(w, rule)

	case http.MethodPut:
		var rule scoring.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		rule.ID = id
		if err := store.Update(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.yargen.ReloadScoringRules(); err != nil {
			http.Error(w, fmt.Sprintf("Failed to reload scoring rules: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rule)

	case http.MethodDelete:
		if err := store.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.yargen.ReloadScoringRules(); err != nil {
			http.Error(w, fmt.Sprintf("Failed to reload scoring rules: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRulesExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rules, err := s.yargen.ScoringStore().Export()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"scoring_rules.json\"")
	if err := json.NewEncoder(w).Encode(rules); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleRulesImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rules []scoring.Rule
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := s.yargen.ScoringStore().Import(rules, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.yargen.ReloadScoringRules(); err != nil {
		// Log error but continue - rules import may have partially succeeded
		fmt.Printf("[W] Failed to reload scoring rules after import: %v\n", err)
	}

	writeJSON(w, map[string]int{"imported": len(rules)})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	llmClient := s.yargen.LLMClient()
	llmStatus := llmClient.CheckAvailability(r.Context())

	response := map[string]interface{}{
		"llm_configured": llmClient.IsConfigured(),
		"llm_provider":   llmClient.Provider(),
		"llm_model":      llmClient.Model(),
		"llm_available":  llmStatus.Available,
		"llm_error":      llmStatus.Error,
	}

	writeJSON(w, response)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

// SuggestNameRequest contains parameters for rule name suggestion.
type SuggestNameRequest struct {
	JobID       string   `json:"job_id"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
}

func (s *Server) handleSuggestName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SuggestNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	jobsMu.RLock()
	job, exists := jobs[req.JobID]
	jobCopy := cloneJob(job)
	jobsMu.RUnlock()

	if !exists {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	if len(jobCopy.Files) == 0 {
		http.Error(w, "No files in job", http.StatusBadRequest)
		return
	}

	var strings []string
	for _, file := range jobCopy.Files {
		if strInfo, ok := jobCopy.Strings[file.Name]; ok {
			for _, s := range strInfo {
				if s.Score > 5 {
					strings = append(strings, s.Value)
				}
			}
		}
	}

	if len(strings) == 0 {
		strings = []string{"(no high-scoring strings)"}
	}

	llmReq := llm.RuleNameRequest{
		FileName:    jobCopy.Files[0].Name,
		FileSize:    jobCopy.Files[0].Size,
		Strings:     strings,
		UserTags:    req.Tags,
		Description: req.Description,
	}

	resp, err := s.yargen.LLMClient().SuggestRuleName(r.Context(), llmReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("LLM error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp)
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, llm.CommonTags)
}
