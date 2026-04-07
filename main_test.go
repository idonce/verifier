package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDemo(t *testing.T) {
	req := httptest.NewRequest("GET", "/demo", nil)
	w := httptest.NewRecorder()
	handleDemo(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Verify") {
		t.Error("expected Verify content in demo page")
	}
}

func TestDemoRoot(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handleDemo(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 for /, got %d", w.Code)
	}
}

func TestDemo404(t *testing.T) {
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()
	handleDemo(w, req)
	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCreateVPSession(t *testing.T) {
	body := `{"client_id":"test"}`
	req := httptest.NewRequest("POST", "/vp/sessions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleCreateVPSession(w, req)
	if w.Code != 201 {
		t.Errorf("expected 201, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	for _, field := range []string{"session_id", "qr_data", "deeplink", "poll_url", "request_uri"} {
		if resp[field] == nil {
			t.Errorf("expected %s in response", field)
		}
	}
}

func TestCreateVPSessionDefault(t *testing.T) {
	req := httptest.NewRequest("POST", "/vp/sessions", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleCreateVPSession(w, req)
	if w.Code != 201 {
		t.Errorf("expected 201, got %d", w.Code)
	}
}

func TestVPRequest(t *testing.T) {
	body := `{"client_id":"test"}`
	req := httptest.NewRequest("POST", "/vp/sessions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleCreateVPSession(w, req)
	var cr map[string]any
	json.NewDecoder(w.Body).Decode(&cr)
	sid := cr["session_id"].(string)

	req2 := httptest.NewRequest("GET", "/vp/request/"+sid, nil)
	w2 := httptest.NewRecorder()
	handleVPRequest(w2, req2)
	var ar map[string]any
	json.NewDecoder(w2.Body).Decode(&ar)

	if ar["response_type"] != "vp_token" {
		t.Errorf("expected vp_token, got %v", ar["response_type"])
	}
	if ar["response_mode"] != "direct_post" {
		t.Errorf("expected direct_post, got %v", ar["response_mode"])
	}
	if ar["nonce"] == nil {
		t.Error("expected nonce")
	}
	if ar["dcql_query"] == nil {
		t.Error("expected dcql_query")
	}
}

func TestVPRequestNotFound(t *testing.T) {
	req := httptest.NewRequest("GET", "/vp/request/nonexistent", nil)
	w := httptest.NewRecorder()
	handleVPRequest(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestVPSessionPoll(t *testing.T) {
	body := `{"client_id":"test"}`
	req := httptest.NewRequest("POST", "/vp/sessions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleCreateVPSession(w, req)
	var cr map[string]any
	json.NewDecoder(w.Body).Decode(&cr)
	sid := cr["session_id"].(string)

	req2 := httptest.NewRequest("GET", "/vp/sessions/"+sid, nil)
	w2 := httptest.NewRecorder()
	handleGetVPSession(w2, req2)
	var resp map[string]any
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["status"] != "pending" {
		t.Errorf("expected pending, got %v", resp["status"])
	}
}

func TestVPSessionNotFound(t *testing.T) {
	req := httptest.NewRequest("GET", "/vp/sessions/nonexistent", nil)
	w := httptest.NewRecorder()
	handleGetVPSession(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestVPResponseMissingFields(t *testing.T) {
	req := httptest.NewRequest("POST", "/vp/response", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleVPResponse(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestVPResponseSessionNotFound(t *testing.T) {
	body := `{"vp_token":"fake","state":"nonexistent"}`
	req := httptest.NewRequest("POST", "/vp/response", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleVPResponse(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDCQLQuery(t *testing.T) {
	creds := []requestedCredential{
		{ID: "test", VCT: "https://example.com/test/v1", Claims: []string{"name", "age"}},
	}
	query := buildDCQLQuery(creds)
	credentials, ok := query["credentials"].([]map[string]any)
	if !ok || len(credentials) != 1 {
		t.Fatalf("expected 1 credential in query, got %v", query)
	}
	if credentials[0]["format"] != "dc+sd-jwt" {
		t.Error("expected dc+sd-jwt format")
	}
}

func TestParseSDJWTVC(t *testing.T) {
	parsed, err := parseSDJWTVC("eyJ0eXAiOiJkYytzZC1qd3QifQ.eyJpc3MiOiJ0ZXN0In0.c2ln~ZGlzY2xvc3VyZQ~")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parsed.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure, got %d", len(parsed.Disclosures))
	}
}

func TestParseSDJWTVCEmpty(t *testing.T) {
	_, err := parseSDJWTVC("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}
