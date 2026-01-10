package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Neo23x0/yarern-go/internal/config"
)

type geminiClient struct {
	apiKey   string
	model    string
	endpoint string
	timeout  time.Duration
	prompt   string
}

func newGeminiClient(cfg config.LLMConfig) (*geminiClient, error) {
	model := cfg.Model
	if model == "" {
		model = "gemini-1.5-pro"
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", model)
	}

	return &geminiClient{
		apiKey:   cfg.APIKey,
		model:    model,
		endpoint: endpoint,
		timeout:  time.Duration(cfg.Timeout) * time.Second,
		prompt:   cfg.PromptTemplate,
	}, nil
}

func (c *geminiClient) IsConfigured() bool {
	return c.apiKey != ""
}

func (c *geminiClient) Provider() string {
	return "gemini"
}

func (c *geminiClient) Model() string {
	return c.model
}

func (c *geminiClient) CheckAvailability(ctx context.Context) *AvailabilityStatus {
	status := &AvailabilityStatus{
		Provider: "gemini",
		Model:    c.model,
	}

	if c.apiKey == "" {
		status.Error = "API key not configured"
		return status
	}

	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": "ping"},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"maxOutputTokens": 1,
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status
	}

	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := c.endpoint + "?key=" + c.apiKey
	httpReq, err := http.NewRequestWithContext(testCtx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		status.Error = fmt.Sprintf("connection failed: %v", err)
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
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

func (c *geminiClient) ScoreStrings(ctx context.Context, req ScoreRequest) (*ScoreResponse, error) {
	prompt := renderPrompt(c.prompt, req.FileName, req.Strings, req.MaxStrings)

	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	url := c.endpoint + "?key=" + c.apiKey
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Gemini API error: %s", string(body))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response from Gemini")
	}

	return parseResponse(result.Candidates[0].Content.Parts[0].Text)
}

func (c *geminiClient) SuggestRuleName(ctx context.Context, req RuleNameRequest) (*RuleNameResponse, error) {
	prompt := renderRuleNamePrompt(req)

	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	url := c.endpoint + "?key=" + c.apiKey
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Gemini API error: %s", string(body))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response from Gemini")
	}

	return parseRuleNameResponse(result.Candidates[0].Content.Parts[0].Text)
}
