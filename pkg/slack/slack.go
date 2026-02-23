package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Config struct {
	Token     string
	Channel   string
	Username  string
	IconEmoji string
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

func (c *Client) SendMessage(text string) (string, error) {
	if err := ValidateConfig(c.config); err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"channel":      c.config.Channel,
		"text":         text,
		"unfurl_links": false,
		"unfurl_media": false,
	}
	if c.config.Username != "" {
		payload["username"] = c.config.Username
	}
	if c.config.IconEmoji != "" {
		payload["icon_emoji"] = c.config.IconEmoji
	}

	return c.sendChatMessage(payload)
}

func (c *Client) SendThreadMessage(threadTS, text string) (string, error) {
	if err := ValidateConfig(c.config); err != nil {
		return "", err
	}
	if threadTS == "" {
		return "", fmt.Errorf("thread timestamp is required")
	}

	payload := map[string]interface{}{
		"channel":      c.config.Channel,
		"text":         text,
		"thread_ts":    threadTS,
		"unfurl_links": false,
		"unfurl_media": false,
	}
	if c.config.Username != "" {
		payload["username"] = c.config.Username
	}
	if c.config.IconEmoji != "" {
		payload["icon_emoji"] = c.config.IconEmoji
	}

	return c.sendChatMessage(payload)
}

func (c *Client) sendChatMessage(payload map[string]interface{}) (string, error) {
	const maxRetries = 3

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Slack payload %w", err)
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", bytes.NewBuffer(data))
		if err != nil {
			return "", fmt.Errorf("failed to create request %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.config.Token)

		resp, err := c.client.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to send request %w", err)
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return "", fmt.Errorf("failed to read response body %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			if attempt == maxRetries {
				return "", fmt.Errorf("received rate limit response after retries: %d - %s", resp.StatusCode, string(respBody))
			}
			retryAfter := parseRetryAfterSeconds(resp.Header.Get("Retry-After"))
			if retryAfter <= 0 {
				retryAfter = 1
			}
			time.Sleep(time.Duration(retryAfter) * time.Second)
			continue
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return "", fmt.Errorf("received non-2xx response: %d - %s", resp.StatusCode, string(respBody))
		}

		var slackResp struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
			TS    string `json:"ts"`
		}
		if err := json.Unmarshal(respBody, &slackResp); err != nil {
			return "", fmt.Errorf("failed to parse Slack response %w: %s", err, string(respBody))
		}
		if !slackResp.OK {
			return "", fmt.Errorf("slack api returned error: %s", slackResp.Error)
		}

		return slackResp.TS, nil
	}

	return "", fmt.Errorf("failed to send Slack message after retries")
}

func parseRetryAfterSeconds(value string) int {
	if value == "" {
		return 0
	}
	var seconds int
	_, err := fmt.Sscanf(value, "%d", &seconds)
	if err != nil {
		return 0
	}
	return seconds
}

func ValidateConfig(cfg Config) error {
	if cfg.Token == "" {
		return fmt.Errorf("slack bot token is required")
	}
	if cfg.Channel == "" {
		return fmt.Errorf("slack channel is required")
	}
	return nil
}
