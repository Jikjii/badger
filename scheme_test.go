package badger

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakePangolin stands in for the Pangolin API and approves every session
// exchange, so Badger answers with its redirect back to the original URL.
func fakePangolin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/badger/exchange-session" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"valid":  true,
				"cookie": "p_session_token=abc; Path=/; Secure; HttpOnly",
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Issue #40: behind a trusted proxy that terminates TLS, the session-exchange
// redirect must stay on https.
func TestSessionExchangeRedirectScheme(t *testing.T) {
	api := fakePangolin(t)

	cfg := CreateConfig()
	cfg.APIBaseUrl = api.URL
	cfg.UserSessionCookieName = "p_session_token"
	cfg.ResourceSessionRequestParam = "p_session_request"
	cfg.DisableDefaultCFIPs = true
	cfg.TrustIP = []string{"10.0.0.0/8"} // the trusted load balancer

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // should never be reached here
	})
	handler, err := New(context.Background(), backend, cfg, "badger-test")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		tls        bool
		headers    map[string]string
		want       string
	}{
		{
			name:       "TLS terminated at Traefik",
			remoteAddr: "203.0.113.9:4000",
			tls:        true,
			want:       "https://app.example.com/dashboard",
		},
		{
			name:       "trusted proxy sends X-Forwarded-Proto https",
			remoteAddr: "10.0.0.5:4000",
			headers:    map[string]string{"X-Forwarded-Proto": "https"},
			want:       "https://app.example.com/dashboard",
		},
		{
			name:       "trusted proxy sends CF-Visitor https",
			remoteAddr: "10.0.0.5:4000",
			headers:    map[string]string{"CF-Visitor": `{"scheme":"https"}`},
			want:       "https://app.example.com/dashboard",
		},
		{
			name:       "untrusted client spoofs X-Forwarded-Proto",
			remoteAddr: "203.0.113.9:4000",
			headers:    map[string]string{"X-Forwarded-Proto": "https"},
			want:       "http://app.example.com/dashboard",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"http://app.example.com/dashboard?p_session_request=xyz", nil)
			req.RemoteAddr = tc.remoteAddr
			req.TLS = nil
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
			}
			if got := rec.Header().Get("Location"); got != tc.want {
				t.Errorf("redirect = %q, want %q", got, tc.want)
			}
		})
	}
}
