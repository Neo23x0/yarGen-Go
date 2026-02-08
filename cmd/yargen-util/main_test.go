package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStartGeneration_SendsFlagFields(t *testing.T) {
	type requestBody struct {
		JobID          string `json:"job_id"`
		Author         string `json:"author"`
		Reference      string `json:"reference"`
		ShowScores     bool   `json:"show_scores"`
		ExcludeOpcodes bool   `json:"exclude_opcodes"`
	}

	var received requestBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := startGeneration(srv.URL, "job-123", "neo", "ref-1", true, true); err != nil {
		t.Fatalf("startGeneration returned error: %v", err)
	}

	if received.JobID != "job-123" {
		t.Fatalf("unexpected job id: %q", received.JobID)
	}
	if received.Author != "neo" {
		t.Fatalf("unexpected author: %q", received.Author)
	}
	if received.Reference != "ref-1" {
		t.Fatalf("unexpected reference: %q", received.Reference)
	}
	if !received.ShowScores {
		t.Fatalf("expected show_scores=true")
	}
	if !received.ExcludeOpcodes {
		t.Fatalf("expected exclude_opcodes=true")
	}
}

func TestWaitForRules_ReturnsRulesOnCompletedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/jobs/job-123" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"completed","rules":"rule x { condition: true }"}`))
	}))
	defer srv.Close()

	rules, err := waitForRules(srv.URL, "job-123", 10, false)
	if err != nil {
		t.Fatalf("waitForRules returned error: %v", err)
	}
	if !strings.Contains(rules, "rule x") {
		t.Fatalf("unexpected rules output: %q", rules)
	}
}

func TestWaitForRules_ReturnsGenerationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"failed","error":"backend failed"}`))
	}))
	defer srv.Close()

	_, err := waitForRules(srv.URL, "job-123", 10, false)
	if err == nil {
		t.Fatal("expected failure error")
	}
	if !strings.Contains(err.Error(), "backend failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWaitForRules_TimeoutRespectsWaitFlag(t *testing.T) {
	// maxWait=0 should time out immediately without polling.
	rules, err := waitForRules("http://127.0.0.1:1", "job-123", 0, false)
	if err == nil {
		t.Fatalf("expected timeout error, got rules: %q", rules)
	}
	if !strings.Contains(err.Error(), "timeout after 0 seconds") {
		t.Fatalf("unexpected error: %v", err)
	}
}
