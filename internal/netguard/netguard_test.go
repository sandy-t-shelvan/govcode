package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckURL(t *testing.T) {
	ok := []string{"http://127.0.0.1:11434", "http://localhost:8000/v1", "http://[::1]:80", "http://127.1.2.3:9"}
	bad := []string{"http://10.0.0.5:11434", "https://huggingface.co", "http://example.com", "ftp://127.0.0.1", "http://0.0.0.0:11434", "http://169.254.169.254/"}
	for _, u := range ok {
		if err := CheckURL(u); err != nil {
			t.Errorf("CheckURL(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if err := CheckURL(u); err == nil {
			t.Errorf("CheckURL(%q) = nil, want error", u)
		}
	}
}

func TestClientRefusesNonLoopback(t *testing.T) {
	c := Client(2 * time.Second)
	for _, u := range []string{"http://1.1.1.1/", "http://example.com/", "http://[2606:4700::1111]/"} {
		_, err := c.Get(u)
		if err == nil || !errors.Is(err, ErrNotLoopback) {
			t.Errorf("GET %s: err=%v, want ErrNotLoopback", u, err)
		}
	}
}

func TestClientIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://10.9.9.9:3128")
	t.Setenv("HTTPS_PROXY", "http://10.9.9.9:3128")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	resp, err := Client(2 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("loopback GET failed: %v", err)
	}
	resp.Body.Close()
}

func TestRedirectOffHostRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/exfil", http.StatusFound)
	}))
	defer srv.Close()
	_, err := Client(2 * time.Second).Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("redirect off-host: err=%v, want refusal", err)
	}
}
