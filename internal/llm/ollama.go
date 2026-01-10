package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Neo23x0/yarGen-go/internal/config"
)

type ollamaClient struct {
	model    string
	endpoint string
	apiKey   string
	timeout  time.Duration
	prompt   string
}

func newOllamaClient(cfg config.LLMConfig) (*ollamaClient, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}

	endpoint = strings.TrimSuffix(endpoint, "/")

	model := cfg.Model
	if model == "" {
		model = "llama3"
	}

	return &ollamaClient{
		model:    model,
		endpoint: endpoint,
		apiKey:   cfg.APIKey,
		timeout:  time.Duration(cfg.Timeout) * time.Second,
		prompt:   cfg.PromptTemplate,
	}, nil
}

func (c *ollamaClient) IsConfigured() bool {
	return c.endpoint != ""
}

func (c *ollamaClient) Provider() string {
	return "ollama"
}

func (c *ollamaClient) Model() string {
	return c.model
}

func (c *ollamaClient) isCloudAPI() bool {
	return strings.Contains(c.endpoint, "ollama.com")
}

func (c *ollamaClient) CheckAvailability(ctx context.Context) *AvailabilityStatus {
	status := &AvailabilityStatus{
		Provider: "ollama",
		Model:    c.model,
	}

	if c.isCloudAPI() {
		return c.checkCloudAvailability(ctx, status)
	}
	return c.checkLocalAvailability(ctx, status)
}

func (c *ollamaClient) checkLocalAvailability(ctx context.Context, status *AvailabilityStatus) *AvailabilityStatus {
	tagsURL := c.endpoint + "/api/tags"

	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(testCtx, "GET", tagsURL, nil)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		status.Error = fmt.Sprintf("Ollama not running: %v", err)
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		status.Error = fmt.Sprintf("Ollama returned status %d", resp.StatusCode)
		return status
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		status.Error = fmt.Sprintf("failed to read response: %v", err)
		return status
	}

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		status.Error = fmt.Sprintf("failed to parse response: %v", err)
		return status
	}

	modelFound := false
	for _, m := range result.Models {
		if m.Name == c.model || m.Name == c.model+":latest" {
			modelFound = true
			break
		}
	}

	if !modelFound {
		status.Error = fmt.Sprintf("model '%s' not found locally (run: ollama pull %s)", c.model, c.model)
		return status
	}

	status.Available = true
	return status
}

func (c *ollamaClient) checkCloudAvailability(ctx context.Context, status *AvailabilityStatus) *AvailabilityStatus {
	if c.apiKey == "" {
		status.Error = "API key required for Ollama cloud (ollama.com)"
		return status
	}

	requestBody := map[string]interface{}{
		"model":  c.model,
		"prompt": "ping",
		"stream": false,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status
	}

	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	generateURL := c.endpoint + "/api/generate"
	httpReq, err := http.NewRequestWithContext(testCtx, "POST", generateURL, bytes.NewReader(jsonBody))
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		status.Error = fmt.Sprintf("connection failed: %v", err)
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		status.Error = "invalid API key"
		return status
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		status.Error = fmt.Sprintf("API error (status %d): %s", resp.StatusCode, string(body))
		return status
	}

	status.Available = true
	return status
}

func (c *ollamaClient) ScoreStrings(ctx context.Context, req ScoreRequest) (*ScoreResponse, error) {
	prompt := renderPrompt(c.prompt, req.FileName, req.Strings, req.MaxStrings)

	requestBody := map[string]interface{}{
		"model":  c.model,
		"prompt": prompt,
		"stream": false,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	generateURL := c.endpoint + "/api/generate"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", generateURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama API error: %s", string(body))
	}

	var result struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Response == "" {
		return nil, fmt.Errorf("no response from Ollama")
	}

	return parseResponse(result.Response)
}

func (c *ollamaClient) SuggestRuleName(ctx context.Context, req RuleNameRequest) (*RuleNameResponse, error) {
	prompt := renderRuleNamePrompt(req)

	requestBody := map[string]interface{}{
		"model":  c.model,
		"prompt": prompt,
		"stream": false,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	generateURL := c.endpoint + "/api/generate"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", generateURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama API error: %s", string(body))
	}

	var result struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Response == "" {
		return nil, fmt.Errorf("no response from Ollama")
	}

	return parseRuleNameResponse(result.Response)
}
