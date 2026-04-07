package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	mux := http.NewServeMux()

	// OpenID4VP — Credential Verification
	mux.HandleFunc("POST /vp/sessions", handleCreateVPSession)
	mux.HandleFunc("GET /vp/request/", handleVPRequest)
	mux.HandleFunc("POST /vp/response", handleVPResponse)
	mux.HandleFunc("GET /vp/sessions/", handleGetVPSession)

	// Demo + static assets
	mux.HandleFunc("GET /demo", handleDemo)
	mux.HandleFunc("GET /", handleDemo)
	mux.HandleFunc("GET /static/", handleStatic)

	// Health
	mux.HandleFunc("GET /health", handleHealth)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      withCORS(withRateLimit(mux)),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("idonce Verifier listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func handleDemo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/demo" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(demoHTML))
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	http.StripPrefix("/static/", http.FileServer(http.Dir("static"))).ServeHTTP(w, r)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func baseURLOrDefault() string {
	if u := os.Getenv("BASE_URL"); u != "" {
		return u
	}
	return "http://localhost:9090"
}

func withRateLimit(next http.Handler) http.Handler {
	type client struct {
		count   int
		resetAt time.Time
	}
	var mu sync.Mutex
	clients := make(map[string]*client)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		now := time.Now()
		mu.Lock()
		c, ok := clients[ip]
		if !ok || now.After(c.resetAt) {
			clients[ip] = &client{1, now.Add(time.Minute)}
		} else {
			c.count++
			if c.count > 60 {
				mu.Unlock()
				writeJSON(w, 429, map[string]string{"error": "rate limit"})
				return
			}
		}
		if len(clients) > 10000 {
			for k, v := range clients {
				if now.After(v.resetAt) {
					delete(clients, k)
				}
			}
		}
		mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler) http.Handler {
	origin := os.Getenv("ALLOWED_ORIGIN")
	if origin == "" {
		origin = "*"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}
