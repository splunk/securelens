package slack

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestSlackClient(serverURL string) *Client {
	return &Client{
		config: Config{Token: "token", Channel: "chan"},
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

func TestSendMessageOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"ok":true,"ts":"12345"}`)); err != nil {
			t.Errorf("w.Write failed: %v", err)
		}
	}))
	defer server.Close()

	client := newTestSlackClient(server.URL)
	ts, err := client.SendMessage("hi")
	if err != nil || ts != "12345" {
		t.Errorf("Expected ok Slack response, got %v, %s", err, ts)
	}
}

func TestSendMessageErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`)); err != nil {
			t.Errorf("w.Write failed: %v", err)
		}
	}))
	defer server.Close()

	client := newTestSlackClient(server.URL)
	ts, err := client.SendMessage("hi")
	if err == nil || ts != "" {
		t.Errorf("Expected error Slack response, got %v, %s", err, ts)
	}
}

func TestSendMessage429Retry(t *testing.T) {
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

	client := newTestSlackClient(server.URL)
	ts, err := client.SendMessage("hi")
	if err != nil || ts != "67890" {
		t.Errorf("Expected Slack retry then ok, got %v, %s", err, ts)
	}
}
