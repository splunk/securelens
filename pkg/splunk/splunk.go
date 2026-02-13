package splunk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Config struct {
	HECEndpoint string
	Token       string
}

type Client struct {
	config Config
	client *http.Client
}

func NewClient(cfg Config) *Client {
	return &Client{
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) SendEvent(event interface{}) error {
	if err := ValidateConfig(c.config); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"event": event,
		"time":  time.Now().Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequest("POST", c.config.HECEndpoint, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+c.config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("received non-2xx response: %s: %s", resp.Status, string(respBody))
	}

	if len(respBody) == 0 {
		return nil
	}

	var hecResp struct {
		Code int    `json:"code"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(respBody, &hecResp); err != nil {
		return fmt.Errorf("failed to parse Splunk response: %w: %s", err, string(respBody))
	}
	if hecResp.Code != 0 {
		return fmt.Errorf("splunk HEC returned error code %d: %s", hecResp.Code, hecResp.Text)
	}

	return nil
}

func ValidateConfig(cfg Config) error {
	if cfg.HECEndpoint == "" {
		return fmt.Errorf("splunk HEC endpoint is required")
	}
	if cfg.Token == "" {
		return fmt.Errorf("splunk HEC token is required")
	}
	parsed, err := url.Parse(cfg.HECEndpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("splunk HEC endpoint must be a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("splunk HEC endpoint must use http or https")
	}
	return nil
}
