package web

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/Neo23x0/yarern-go/internal/config"
	"github.com/Neo23x0/yarern-go/internal/service"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	httpServer *http.Server
	yargen     *service.YarGen
	config     *config.Config
}

func NewServer(cfg *config.Config, yargen *service.YarGen) *Server {
	s := &Server{
		yargen: yargen,
		config: cfg,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/upload", s.corsMiddleware(s.handleUpload))
	mux.HandleFunc("/api/generate", s.corsMiddleware(s.handleGenerate))
	mux.HandleFunc("/api/jobs/", s.corsMiddleware(s.handleJobs))
	mux.HandleFunc("/api/rules", s.corsMiddleware(s.handleRules))
	mux.HandleFunc("/api/rules/", s.corsMiddleware(s.handleRulesById))
	mux.HandleFunc("/api/rules/export", s.corsMiddleware(s.handleRulesExport))
	mux.HandleFunc("/api/rules/import", s.corsMiddleware(s.handleRulesImport))
	mux.HandleFunc("/api/config", s.corsMiddleware(s.handleConfig))
	mux.HandleFunc("/api/health", s.corsMiddleware(s.handleHealth))
	mux.HandleFunc("/api/suggest-name", s.corsMiddleware(s.handleSuggestName))
	mux.HandleFunc("/api/tags", s.corsMiddleware(s.handleTags))

	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("/", fileServer)

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		fmt.Printf("[%s] %s %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:"+fmt.Sprintf("%d", s.config.Server.Port))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}
