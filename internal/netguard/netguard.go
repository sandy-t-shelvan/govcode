// Package netguard provides the only network client govcode uses.
//
// Every connection is resolved and checked before dialing: only loopback
// addresses (127.0.0.0/8, ::1) are permitted. Proxies are ignored, so
// HTTP(S)_PROXY cannot redirect traffic off-host. This is the enforcement
// point for the "localhost only" requirement; nothing else in the module
// imports net/http's default client.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrNotLoopback is returned for any attempt to reach a non-loopback host.
var ErrNotLoopback = errors.New("netguard: non-loopback destination refused (air-gapped mode)")

// CheckURL validates that a URL points at a loopback host with http scheme.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("netguard: bad url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("netguard: scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %s", ErrNotLoopback, host)
	}
	return nil
}

// dialLoopback resolves addr locally and only dials loopback IPs. "localhost"
// is pinned to 127.0.0.1 rather than trusting /etc/hosts or DNS.
func dialLoopback(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %s", ErrNotLoopback, host)
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

// Client returns an HTTP client that can only reach loopback addresses.
// timeout of 0 means no overall timeout (streaming model responses).
func Client(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil, // never honor proxy env vars
		DialContext:           dialLoopback,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 30 * time.Minute, // CPU inference can be slow to first token
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := CheckURL(req.URL.String()); err != nil {
				return err
			}
			if len(via) >= 3 {
				return errors.New("netguard: too many redirects")
			}
			return nil
		},
	}
}
