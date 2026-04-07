package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// VPSession represents an OpenID4VP verification session.
type VPSession struct {
	ID         string     `json:"session_id"`
	Status     string     `json:"status"` // pending, presented, expired
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Nonce      string     `json:"nonce"`
	ClientID   string     `json:"client_id"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`

	// Request
	RequestedCredentials []requestedCredential `json:"-"`

	// Result (filled after presentation)
	DisclosedClaims map[string]any `json:"disclosed_claims,omitempty"`
	Subject         string         `json:"subject,omitempty"`
	VCT             string         `json:"vct,omitempty"`
}

type vpSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*VPSession
}

var globalVPStore = &vpSessionStore{sessions: make(map[string]*VPSession)}

func (s *vpSessionStore) Create(clientID string) *VPSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateSessionID()
	nonce := generateNonce()
	now := time.Now()

	session := &VPSession{
		ID:        id,
		Status:    "pending",
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
		Nonce:     nonce,
		ClientID:  clientID,
	}
	s.sessions[id] = session

	// Cleanup old sessions
	if len(s.sessions) > 1000 {
		for k, v := range s.sessions {
			if now.After(v.ExpiresAt.Add(10 * time.Minute)) {
				delete(s.sessions, k)
			}
		}
	}

	return session
}

func (s *vpSessionStore) Get(id string) *VPSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, exists := s.sessions[id]
	if !exists {
		return nil
	}
	if sess.Status == "pending" && time.Now().After(sess.ExpiresAt) {
		sess.Status = "expired"
	}
	return sess
}

func (s *vpSessionStore) Complete(id string, result *VerifiedPresentation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, exists := s.sessions[id]
	if !exists {
		return fmt.Errorf("session not found")
	}
	if sess.Status != "pending" {
		return fmt.Errorf("session is %s", sess.Status)
	}
	if time.Now().After(sess.ExpiresAt) {
		sess.Status = "expired"
		return fmt.Errorf("session has expired")
	}
	now := time.Now()
	sess.Status = "presented"
	sess.VerifiedAt = &now
	sess.DisclosedClaims = result.DisclosedClaims
	sess.Subject = result.Subject
	sess.VCT = result.VCT
	return nil
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "vp_" + hex.EncodeToString(b)
}

type requestedCredential struct {
	ID     string   `json:"id"`
	VCT    string   `json:"vct"`
	Claims []string `json:"claims,omitempty"`
}

func buildDCQLQuery(creds []requestedCredential) map[string]any {
	var credentials []map[string]any
	for _, c := range creds {
		cred := map[string]any{
			"id":     c.ID,
			"format": "dc+sd-jwt",
			"meta": map[string]any{
				"vct_values": []string{c.VCT},
			},
		}
		if len(c.Claims) > 0 {
			var claims []map[string]any
			for _, cl := range c.Claims {
				claims = append(claims, map[string]any{"path": []string{cl}})
			}
			cred["claims"] = claims
		}
		credentials = append(credentials, cred)
	}
	return map[string]any{"credentials": credentials}
}

func generateNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// POST /vp/sessions — Verifier creates a VP request session
func handleCreateVPSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID             string                `json:"client_id"`
		RequestedCredentials []requestedCredential `json:"requested_credentials"`
	}
	// Decode is best-effort: empty body = use defaults
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.ClientID == "" {
		req.ClientID = "anonymous"
	}
	// Default: request HumanVerification
	if len(req.RequestedCredentials) == 0 {
		req.RequestedCredentials = []requestedCredential{{
			ID:     "human_verification",
			VCT:    "https://idonce.com/credentials/HumanVerification/v1",
			Claims: []string{"biometricConfirmed", "deviceBound", "attestationPlatform"},
		}}
	}

	session := globalVPStore.Create(req.ClientID)
	session.RequestedCredentials = req.RequestedCredentials
	baseURL := baseURLOrDefault()

	requestURI := fmt.Sprintf("%s/vp/request/%s", baseURL, session.ID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id":  session.ID,
		"status":      session.Status,
		"expires_at":  session.ExpiresAt,
		"request_uri": requestURI,
		"qr_data":     fmt.Sprintf("openid4vp://authorize?request_uri=%s&client_id=%s", requestURI, req.ClientID),
		"deeplink":    fmt.Sprintf("idonce://vp?request_uri=%s", requestURI),
		"poll_url":    fmt.Sprintf("%s/vp/sessions/%s", baseURL, session.ID),
	})
}

// GET /vp/request/{session_id} — Wallet fetches the Authorization Request
func handleVPRequest(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/vp/request/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing session_id"})
		return
	}

	session := globalVPStore.Get(id)
	if session == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	baseURL := baseURLOrDefault()

	// Authorization Request per OpenID4VP
	authRequest := map[string]any{
		"response_type":    "vp_token",
		"client_id":        session.ClientID,
		"client_id_scheme": "redirect_uri",
		"response_mode":    "direct_post",
		"response_uri":     baseURL + "/vp/response",
		"nonce":            session.Nonce,
		"state":            session.ID,
		"dcql_query": buildDCQLQuery(session.RequestedCredentials),
	}

	writeJSON(w, http.StatusOK, authRequest)
}

// POST /vp/response — Wallet submits VP Token (direct_post response mode)
func handleVPResponse(w http.ResponseWriter, r *http.Request) {
	// Per OpenID4VP, this can be form-encoded or JSON
	var vpToken, state string

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			VPToken string `json:"vp_token"`
			State   string `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		vpToken = req.VPToken
		state = req.State
	} else {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form data"})
			return
		}
		vpToken = r.FormValue("vp_token")
		state = r.FormValue("state")
	}

	if vpToken == "" || state == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "vp_token and state are required"})
		return
	}

	// Look up session
	session := globalVPStore.Get(state)
	if session == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if session.Status != "pending" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session is " + session.Status})
		return
	}

	// Verify the SD-JWT-VC presentation
	result, err := verifySDJWTVCPresentation(vpToken, session.ClientID, session.Nonce)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_presentation",
			"error_description": err.Error(),
		})
		return
	}

	// Mark session as complete
	if err := globalVPStore.Complete(state, result); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "session_error",
			"error_description": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": true,
		"presentation_submission": map[string]any{
			"id":            "ps_" + state,
			"definition_id": "dcql",
			"descriptor_map": []map[string]any{
				{
					"id":     result.VCT,
					"path":   "$",
					"format": "dc+sd-jwt",
				},
			},
		},
	})
}

// GET /vp/sessions/{session_id} — Verifier polls for result
func handleGetVPSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/vp/sessions/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing session_id"})
		return
	}

	session := globalVPStore.Get(id)
	if session == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	resp := map[string]any{
		"session_id": session.ID,
		"status":     session.Status,
	}
	if session.Status == "presented" {
		resp["verified_at"] = session.VerifiedAt
		resp["subject"] = session.Subject
		resp["vct"] = session.VCT
		resp["disclosed_claims"] = session.DisclosedClaims
	}

	writeJSON(w, http.StatusOK, resp)
}
