package splunk

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	contentTypeHeader      = "Content-Type"
	applicationJSON        = "application/json"
	sendEventExpectedError = "SendEvent expected error, got nil"
)

func TestSendEventSuccess(t *testing.T) {
	token := "test-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Splunk "+token {
			t.Errorf("Authorization header = %q, want %q", got, "Splunk "+token)
		}
		if got := r.Header.Get(contentTypeHeader); got != applicationJSON {
			t.Errorf("Content-Type header = %q, want %q", got, applicationJSON)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}
		if _, ok := payload["event"]; !ok {
			t.Error("payload missing event field")
		}
		if _, ok := payload["time"]; !ok {
			t.Error("payload missing time field")
		}

		w.Header().Set(contentTypeHeader, applicationJSON)
		_, _ = w.Write([]byte(`{"code":0,"text":"Success"}`))
	}))
	defer srv.Close()

	client := NewClient(Config{HECEndpoint: srv.URL, Token: token})

	err := client.SendEvent(map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatalf("SendEvent returned error: %v", err)
	}
}

func TestSendEventNon2xxResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	client := NewClient(Config{HECEndpoint: srv.URL, Token: "token"})

	err := client.SendEvent(map[string]interface{}{"foo": "bar"})
	if err == nil {
		t.Fatal(sendEventExpectedError)
	}
	if !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("SendEvent error = %q, want response body", err.Error())
	}
}

func TestSendEventHECErrorCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(contentTypeHeader, applicationJSON)
		_, _ = w.Write([]byte(`{"code":7,"text":"Invalid token"}`))
	}))
	defer srv.Close()

	client := NewClient(Config{HECEndpoint: srv.URL, Token: "token"})

	err := client.SendEvent(map[string]interface{}{"foo": "bar"})
	if err == nil {
		t.Fatal(sendEventExpectedError)
	}
	if !strings.Contains(err.Error(), "Invalid token") {
		t.Fatalf("SendEvent error = %q, want HEC text", err.Error())
	}
}

func TestSendEventInvalidConfig(t *testing.T) {
	client := NewClient(Config{})

	err := client.SendEvent(map[string]interface{}{"foo": "bar"})
	if err == nil {
		t.Fatal(sendEventExpectedError)
	}
	if !strings.Contains(err.Error(), "HEC endpoint") {
		t.Fatalf("SendEvent error = %q, want endpoint error", err.Error())
	}
}
