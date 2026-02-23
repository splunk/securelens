package slack

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendChatMessageOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"ok":true,"ts":"12345"}`)); err != nil {
			t.Errorf("w.Write failed: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		config: Config{Token: "token", Channel: "chan"},
		client: &http.Client{Timeout: 2 * time.Second},
	}

	// Inject base URL for test
	baseURL := server.URL

	payload := map[string]interface{}{"channel": "chan", "text": "hi"}

	// Patch sendChatMessage to use test server
	respTS, err := func() (string, error) {
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", baseURL, bytes.NewBuffer(data))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		resp, err := client.client.Do(req)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var slackResp struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
			TS    string `json:"ts"`
		}
		if err := json.Unmarshal(body, &slackResp); err != nil {
			t.Errorf("json.Unmarshal failed: %v", err)
		}
		if !slackResp.OK {
			return "", nil
		}
		return slackResp.TS, nil
	}()

	if err != nil || respTS != "12345" {
		t.Errorf("Expected ok Slack response, got %v, %s", err, respTS)
	}
}

func TestSendChatMessageErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`)); err != nil {
			t.Errorf("w.Write failed: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		config: Config{Token: "token", Channel: "chan"},
		client: &http.Client{Timeout: 2 * time.Second},
	}

	baseURL := server.URL
	payload := map[string]interface{}{"channel": "chan", "text": "hi"}

	respTS, err := func() (string, error) {
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", baseURL, bytes.NewBuffer(data))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		resp, err := client.client.Do(req)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var slackResp struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
			TS    string `json:"ts"`
		}
		if err := json.Unmarshal(body, &slackResp); err != nil {
			t.Errorf("json.Unmarshal failed: %v", err)
		}
		if !slackResp.OK {
			return "", nil
		}
		return slackResp.TS, nil
	}()

	if err != nil || respTS != "" {
		t.Errorf("Expected error Slack response, got %v, %s", err, respTS)
	}
}

func TestSendChatMessage429Retry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			if _, err := w.Write([]byte("rate limit")); err != nil {
				t.Errorf("w.Write failed: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"ok":true,"ts":"67890"}`)); err != nil {
			t.Errorf("w.Write failed: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		config: Config{Token: "token", Channel: "chan"},
		client: &http.Client{Timeout: 2 * time.Second},
	}

	baseURL := server.URL
	payload := map[string]interface{}{"channel": "chan", "text": "hi"}

	respTS := ""
	for i := 0; i < 2; i++ {
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", baseURL, bytes.NewBuffer(data))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		resp, err := client.client.Do(req)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
			return
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			time.Sleep(1 * time.Second)
			continue
		}
		var slackResp struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
			TS    string `json:"ts"`
		}
		if err := json.Unmarshal(body, &slackResp); err != nil {
			t.Errorf("json.Unmarshal failed: %v", err)
		}
		if slackResp.OK {
			respTS = slackResp.TS
			break
		}
	}

	if respTS != "67890" {
		t.Errorf("Expected Slack retry then ok, got %s", respTS)
	}
}
