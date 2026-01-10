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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Neo23x0/yarern-go/internal/llm"
	"github.com/Neo23x0/yarern-go/internal/scoring"
	"github.com/Neo23x0/yarern-go/internal/service"
)

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

type UploadedFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Path string `json:"-"`
}

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

func generateJobID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
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

	for _, fileHeaders := range r.MultipartForm.File {
		for _, fileHeader := range fileHeaders {
			file, err := fileHeader.Open()
			if err != nil {
				continue
			}

			destPath := filepath.Join(uploadDir, fileHeader.Filename)
			dest, err := os.Create(destPath)
			if err != nil {
				file.Close()
				continue
			}

			io.Copy(dest, file)
			file.Close()
			dest.Close()

			files = append(files, UploadedFile{
				Name: fileHeader.Filename,
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

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
	jobsMu.RUnlock()

	if !exists {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	jobsMu.Lock()
	job.Status = "processing"
	jobsMu.Unlock()

	go func() {
		ctx := context.Background()

		uploadDir := filepath.Dir(job.Files[0].Path)

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
		}
		jobsMu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "processing"})
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
	jobsMu.RUnlock()

	if !exists {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	if len(parts) > 1 && parts[1] == "rules" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"yargen_rules_%s.yar\"", jobID[:8]))
		w.Write([]byte(job.Rules))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)

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
		s.yargen.ReloadScoringRules()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rule)

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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rule)

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
		s.yargen.ReloadScoringRules()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rule)

	case http.MethodDelete:
		if err := store.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.yargen.ReloadScoringRules()
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
	json.NewEncoder(w).Encode(rules)
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

	s.yargen.ReloadScoringRules()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"imported": len(rules)})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

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
	jobsMu.RUnlock()

	if !exists {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	if len(job.Files) == 0 {
		http.Error(w, "No files in job", http.StatusBadRequest)
		return
	}

	var strings []string
	for _, file := range job.Files {
		if strInfo, ok := job.Strings[file.Name]; ok {
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
		FileName:    job.Files[0].Name,
		FileSize:    job.Files[0].Size,
		Strings:     strings,
		UserTags:    req.Tags,
		Description: req.Description,
	}

	resp, err := s.yargen.LLMClient().SuggestRuleName(r.Context(), llmReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("LLM error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(llm.CommonTags)
}
