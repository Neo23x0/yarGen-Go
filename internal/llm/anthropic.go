package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Neo23x0/yarGen-go/internal/config"
)

type anthropicClient struct {
	apiKey   string
	model    string
	endpoint string
	timeout  time.Duration
	prompt   string
}

func newAnthropicClient(cfg config.LLMConfig) (*anthropicClient, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.anthropic.com/v1/messages"
	}

	model := cfg.Model
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}

	return &anthropicClient{
		apiKey:   cfg.APIKey,
		model:    model,
		endpoint: endpoint,
		timeout:  time.Duration(cfg.Timeout) * time.Second,
		prompt:   cfg.PromptTemplate,
	}, nil
}

func (c *anthropicClient) IsConfigured() bool {
	return c.apiKey != ""
}

func (c *anthropicClient) Provider() string {
	return "anthropic"
}

func (c *anthropicClient) Model() string {
	return c.model
}

func (c *anthropicClient) CheckAvailability(ctx context.Context) *AvailabilityStatus {
	status := &AvailabilityStatus{
		Provider: "anthropic",
		Model:    c.model,
	}

	if c.apiKey == "" {
		status.Error = "API key not configured"
		return status
	}

	requestBody := map[string]interface{}{
		"model":      c.model,
		"max_tokens": 1,
		"messages": []map[string]string{
			{"role": "user", "content": "ping"},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status
	}

	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(testCtx, "POST", c.endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

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

func (c *anthropicClient) ScoreStrings(ctx context.Context, req ScoreRequest) (*ScoreResponse, error) {
	prompt := renderPrompt(c.prompt, req.FileName, req.Strings, req.MaxStrings)

	requestBody := map[string]interface{}{
		"model":      c.model,
		"max_tokens": 4096,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Anthropic API error: %s", string(body))
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if len(result.Content) == 0 {
		return nil, fmt.Errorf("no response from Anthropic")
	}

	return parseResponse(result.Content[0].Text)
}

func (c *anthropicClient) SuggestRuleName(ctx context.Context, req RuleNameRequest) (*RuleNameResponse, error) {
	prompt := renderRuleNamePrompt(req)

	requestBody := map[string]interface{}{
		"model":      c.model,
		"max_tokens": 1024,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Anthropic API error: %s", string(body))
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if len(result.Content) == 0 {
		return nil, fmt.Errorf("no response from Anthropic")
	}

	return parseRuleNameResponse(result.Content[0].Text)
}
