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

type openAIClient struct {
	apiKey   string
	model    string
	endpoint string
	timeout  time.Duration
	prompt   string
}

func newOpenAIClient(cfg config.LLMConfig) (*openAIClient, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/chat/completions"
	}

	return &openAIClient{
		apiKey:   cfg.APIKey,
		model:    cfg.Model,
		endpoint: endpoint,
		timeout:  time.Duration(cfg.Timeout) * time.Second,
		prompt:   cfg.PromptTemplate,
	}, nil
}

func (c *openAIClient) IsConfigured() bool {
	return c.apiKey != ""
}

func (c *openAIClient) Provider() string {
	return "openai"
}

func (c *openAIClient) Model() string {
	return c.model
}

func (c *openAIClient) CheckAvailability(ctx context.Context) *AvailabilityStatus {
	status := &AvailabilityStatus{
		Provider: "openai",
		Model:    c.model,
	}

	if c.apiKey == "" {
		status.Error = "API key not configured"
		return status
	}

	requestBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "user", "content": "ping"},
		},
		"max_completion_tokens": 5,
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

func (c *openAIClient) ScoreStrings(ctx context.Context, req ScoreRequest) (*ScoreResponse, error) {
	prompt := renderPrompt(c.prompt, req.FileName, req.Strings, req.MaxStrings)

	requestBody := map[string]interface{}{
		"model": c.model,
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
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OpenAI request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API error: %s", string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from OpenAI")
	}

	return parseResponse(result.Choices[0].Message.Content)
}

func (c *openAIClient) SuggestRuleName(ctx context.Context, req RuleNameRequest) (*RuleNameResponse, error) {
	prompt := renderRuleNamePrompt(req)

	requestBody := map[string]interface{}{
		"model": c.model,
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
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OpenAI request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API error: %s", string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from OpenAI")
	}

	return parseRuleNameResponse(result.Choices[0].Message.Content)
}
