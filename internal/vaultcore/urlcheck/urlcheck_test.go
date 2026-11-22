package urlcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

func loginCipher(id, name, username string, uris ...string) *state.Cipher {
	l := &state.Login{Username: username}
	for _, u := range uris {
		l.URIs = append(l.URIs, state.LoginURI{URI: u})
	}
	return &state.Cipher{
		ID:    id,
		Name:  name,
		Type:  api.CipherTypeLogin,
		Login: l,
	}
}

func TestIsWhitelisted(t *testing.T) {
	if len(majorDomains) < 180 {
		t.Fatalf("majorDomains has %d entries, want ~200", len(majorDomains))
	}
	yes := []string{
		"google.com",
		"GOOGLE.COM",
		"accounts.google.com",
		"sub.accounts.google.com.",
		"gist.github.com",
		"my-app.workers.dev",
		"console.aws.amazon.com",
		"github.com:443",
		"claude.ai",
		"deepseek.com",
	}
	for _, h := range yes {
		if !IsWhitelisted(h) {
			t.Errorf("IsWhitelisted(%q) = false, want true", h)
		}
	}

	no := []string{
		"",
		"notgoogle.com",
		"evil-github.com",
		"myworkers.dev",
		"example.com",
		"com",
		"dead.example.org",
	}
	for _, h := range no {
		if IsWhitelisted(h) {
			t.Errorf("IsWhitelisted(%q) = true, want false", h)
		}
	}
}

func TestIsPrivateOrLocalHost(t *testing.T) {
	privateHosts := []string{
		"",
		"localhost",
		"LOCALHOST.",
		"app.localhost",
		"printer.local",
		"service.internal",
		"router.lan",
		"nas.home.arpa",
		"home.arpa",
		"intranet",
		"nas",
		"127.0.0.1",
		"127.5.6.7",
		"::1",
		"[::1]",
		"[::1]:8080",
		"10.0.0.1",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.1.10",
		"::ffff:192.168.1.10",
		"169.254.169.254",
		"fe80::1%en0",
		"fd12:3456:789a::1",
		"100.64.0.1",
		"100.103.214.51",
		"100.127.255.254",
		"0.0.0.0",
		"::",
	}
	for _, h := range privateHosts {
		if !IsPrivateOrLocalHost(h) {
			t.Errorf("IsPrivateOrLocalHost(%q) = false, want true", h)
		}
	}

	publicHosts := []string{
		"example.com",
		"sub.example.co.uk",
		"1.1.1.1",
		"8.8.8.8",
		"100.63.255.254",
		"100.128.0.1",
		"172.15.255.1",
		"172.32.0.1",
		"2606:4700:4700::1111",
		"[2606:4700:4700::1111]:443",
	}
	for _, h := range publicHosts {
		if IsPrivateOrLocalHost(h) {
			t.Errorf("IsPrivateOrLocalHost(%q) = true, want false", h)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func makeResponse(req *http.Request, code int, hdr http.Header, body string) *http.Response {
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Header:     hdr,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestPrivacyInvariantAndTargetExtraction(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var authHeaders []string
	var cookieHeaders []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		cookieHeaders = append(cookieHeaders, r.Header.Get("Cookie"))
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "secret-cookie"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	deletedAt := time.Now()
	trashed := loginCipher("c-trashed", "Trashed", "u", "https://dead-trashed.example.com")
	trashed.DeletedDate = &deletedAt

	ciphers := []*state.Cipher{
		loginCipher("c-secret-path", "Path Item", "alice", srv.URL+"/vault/login?token=supersecret&pw=123#frag"),
		loginCipher("c-creds", "Creds Item", "bob", strings.Replace(srv.URL, "http://", "http://alice:hunter2@", 1)+"/admin"),
		loginCipher("c-whitelist", "GitHub", "u", "https://gist.github.com/user/repo"),
		loginCipher("c-local", "Local", "u", "http://localhost:8080/ui", "https://nas.local", "https://100.100.10.5"),
		loginCipher("c-nonhttp", "App", "u", "androidapp://com.example.app", "ssh://git.example.com"),
		trashed,
		{ID: "c-card", Name: "Card", Type: api.CipherTypeCard, Card: &state.Card{Brand: "Visa"}},
	}

	report := Scan(context.Background(), ciphers[:2], Options{
		IncludePrivate: true,
		HTTPClient:     srv.Client(),
	})
	if len(report.Dead) != 0 {
		t.Fatalf("Dead = %+v, want none", report.Dead)
	}
	if report.TotalTargets != 1 || report.CheckedTargets != 1 {
		t.Fatalf("targets = %d/%d, want 1/1 (deduped across both ciphers)", report.CheckedTargets, report.TotalTargets)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "HEAD /" {
		t.Fatalf("requests sent = %v, want single [HEAD /]", seen)
	}
	for _, a := range authHeaders {
		if a != "" {
			t.Fatalf("sent Authorization header %q", a)
		}
	}
	for _, c := range cookieHeaders {
		if c != "" {
			t.Fatalf("sent Cookie header %q", c)
		}
	}

	// Non-active/non-http/whitelisted/private entries in ciphers[2:] must trigger zero probes.
	neverClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			t.Fatalf("unexpected network probe to %s", r.URL.String())
			return nil, errors.New("unexpected")
		}),
	}
	skippedReport := Scan(context.Background(), ciphers[2:], Options{
		IncludePrivate: false,
		HTTPClient:     neverClient,
	})
	if skippedReport.SkippedWhitelisted != 1 || skippedReport.SkippedPrivate != 3 || skippedReport.TotalTargets != 0 || len(skippedReport.Dead) != 0 {
		t.Fatalf("skippedReport = %+v", skippedReport)
	}
}

func TestSkippingCountsAndInvalidURLDeduplication(t *testing.T) {
	var probed []string
	var mu sync.Mutex

	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			probed = append(probed, r.Method+" "+r.URL.String())
			mu.Unlock()
			if r.URL.Host == "dead.example.net" {
				return makeResponse(r, http.StatusNotFound, nil, ""), nil
			}
			return makeResponse(r, http.StatusOK, nil, ""), nil
		}),
	}

	ciphers := []*state.Cipher{
		loginCipher("c-wl-1", "Google", "u", "https://mail.google.com/mail/u/0/"),
		loginCipher("c-wl-2", "Google 2", "u", "https://google.com/"),
		loginCipher("c-priv-1", "Home", "u", "http://192.168.1.1/login"),
		loginCipher("c-priv-2", "Tailscale", "u", "https://100.64.0.42:8443/"),
		loginCipher("c-priv-3", "Intranet", "u", "http://intranet/"),
		loginCipher("c-priv-4", "NAS", "u", "https://nas.home.arpa/"),
		loginCipher("c-bad", "Broken", "u", "https://user:secret@bad host.example/path?k=v", "https://dead.example.net/"),
		loginCipher("c-dup-dead", "MultiDead", "u", "https://dead.example.net/a", "https://dead.example.net/b"),
		loginCipher("c-mixed", "Mixed", "u", "https://alive.example.net/", "https://dead.example.net/"),
	}

	report := Scan(context.Background(), ciphers, Options{
		HTTPClient: client,
	})

	if report.SkippedWhitelisted != 2 {
		t.Fatalf("SkippedWhitelisted = %d, want 2", report.SkippedWhitelisted)
	}
	if report.SkippedPrivate != 4 {
		t.Fatalf("SkippedPrivate = %d, want 4", report.SkippedPrivate)
	}
	if report.TotalTargets != 2 || report.CheckedTargets != 2 {
		t.Fatalf("targets = %d/%d, want 2/2", report.CheckedTargets, report.TotalTargets)
	}
	if report.InvalidCount != 1 {
		t.Fatalf("InvalidCount = %d, want 1", report.InvalidCount)
	}
	if len(report.Dead) != 3 {
		t.Fatalf("Dead = %+v, want 3 deduplicated items", report.Dead)
	}

	byID := map[string]DeadItem{}
	for _, d := range report.Dead {
		byID[d.CipherID] = d
	}
	if got := byID["c-bad"]; got.Reason != ReasonInvalidURL || strings.Contains(got.Domain, "secret") || strings.Contains(got.Domain, "k=v") {
		t.Fatalf("c-bad = %+v", got)
	}
	if got := byID["c-dup-dead"]; got.Reason != ReasonNotFound || got.StatusCode != 404 || got.ReasonLabel() != "HTTP 404" {
		t.Fatalf("c-dup-dead = %+v", got)
	}
	if got := byID["c-mixed"]; got.Reason != ReasonNotFound || got.Domain != "dead.example.net" {
		t.Fatalf("c-mixed = %+v", got)
	}
	if len(probed) != 2 {
		t.Fatalf("probed = %v, want exactly 2 unique targets", probed)
	}
}

func TestHeadToGetFallbackAndOneKiBCap(t *testing.T) {
	for _, headStatus := range []int{http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		t.Run(fmt.Sprintf("HEAD_%d", headStatus), func(t *testing.T) {
			var methods []string
			var bytesWritten atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				methods = append(methods, r.Method)
				if r.Method == http.MethodHead {
					w.WriteHeader(headStatus)
					return
				}
				w.WriteHeader(http.StatusOK)
				payload := strings.Repeat("A", 64*1024)
				n, _ := w.Write([]byte(payload))
				bytesWritten.Add(int64(n))
			}))
			defer srv.Close()

			report := Scan(context.Background(), []*state.Cipher{
				loginCipher("c-1", "Fallback", "u", srv.URL),
			}, Options{
				IncludePrivate: true,
				HTTPClient:     srv.Client(),
			})
			if len(report.Dead) != 0 {
				t.Fatalf("Dead = %+v, want alive after GET fallback", report.Dead)
			}
			if len(methods) != 2 || methods[0] != "HEAD" || methods[1] != "GET" {
				t.Fatalf("methods = %v, want [HEAD GET]", methods)
			}
		})
	}

	// Verify GET fallback body cap limits client read to 1 KiB even on streaming server.
	var sawMethods []string
	largeBody := strings.Repeat("X", 8192)
	var trackReader *countingReadCloser
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			sawMethods = append(sawMethods, r.Method)
			if r.Method == http.MethodHead {
				return makeResponse(r, http.StatusMethodNotAllowed, nil, ""), nil
			}
			trackReader = &countingReadCloser{r: strings.NewReader(largeBody)}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       trackReader,
				Request:    r,
			}, nil
		}),
	}
	report := Scan(context.Background(), []*state.Cipher{
		loginCipher("c-cap", "Cap", "u", "https://cap.example.net/"),
	}, Options{HTTPClient: client})
	if len(report.Dead) != 0 {
		t.Fatalf("Dead = %+v, want alive", report.Dead)
	}
	if trackReader == nil || trackReader.readBytes > MaxProbeBodyBytes {
		t.Fatalf("readBytes = %d, want <= %d", trackReader.readBytes, MaxProbeBodyBytes)
	}
	if !trackReader.closed {
		t.Fatal("GET response body was not closed")
	}
}

type countingReadCloser struct {
	r         io.Reader
	readBytes int
	closed    bool
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.readBytes += n
	return n, err
}

func (c *countingReadCloser) Close() error {
	c.closed = true
	return nil
}

func TestClassificationMatrixAndRedirects(t *testing.T) {
	// Alive status codes + 503 with Cloudflare/bot challenge headers
	aliveClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Host {
			case "s200.example.net":
				return makeResponse(r, 200, nil, ""), nil
			case "s204.example.net":
				return makeResponse(r, 204, nil, ""), nil
			case "s401.example.net":
				return makeResponse(r, 401, nil, ""), nil
			case "s403.example.net":
				return makeResponse(r, 403, nil, ""), nil
			case "s405.example.net":
				return makeResponse(r, 405, nil, ""), nil
			case "s429.example.net":
				return makeResponse(r, 429, nil, ""), nil
			case "cf1.example.net":
				return makeResponse(r, 503, http.Header{"Cf-Ray": {"8a1234-SJC"}}, ""), nil
			case "cf2.example.net":
				return makeResponse(r, 503, http.Header{"Server": {"cloudflare"}}, ""), nil
			case "cf3.example.net":
				return makeResponse(r, 503, http.Header{"Cf-Mitigated": {"challenge"}}, ""), nil
			case "dead503.example.net":
				return makeResponse(r, 503, nil, ""), nil
			case "dead404.example.net":
				return makeResponse(r, 404, nil, ""), nil
			case "dead500.example.net":
				return makeResponse(r, 500, nil, ""), nil
			case "dns.example.net":
				return nil, &net.DNSError{Err: "no such host", Name: "dns.example.net", IsNotFound: true}
			case "refused.example.net":
				return nil, syscall.ECONNREFUSED
			case "timeout.example.net":
				return nil, context.DeadlineExceeded
			case "tls.example.net":
				return nil, &tls.CertificateVerificationError{Err: errors.New("bad cert")}
			default:
				return makeResponse(r, 200, nil, ""), nil
			}
		}),
	}

	ciphers := []*state.Cipher{
		loginCipher("a1", "200", "u", "https://s200.example.net"),
		loginCipher("a2", "204", "u", "https://s204.example.net"),
		loginCipher("a3", "401", "u", "https://s401.example.net"),
		loginCipher("a4", "403", "u", "https://s403.example.net"),
		loginCipher("a5", "405", "u", "https://s405.example.net"),
		loginCipher("a6", "429", "u", "https://s429.example.net"),
		loginCipher("a7", "CF Ray", "u", "https://cf1.example.net"),
		loginCipher("a8", "CF Server", "u", "https://cf2.example.net"),
		loginCipher("a9", "CF Mitigated", "u", "https://cf3.example.net"),
		loginCipher("d-503", "Plain 503", "u", "https://dead503.example.net"),
		loginCipher("d-404", "Not Found", "u", "https://dead404.example.net"),
		loginCipher("d-500", "Server 500", "u", "https://dead500.example.net"),
		loginCipher("d-dns", "DNS", "u", "https://dns.example.net"),
		loginCipher("d-ref", "Refused", "u", "https://refused.example.net"),
		loginCipher("d-to", "Timeout", "u", "https://timeout.example.net"),
		loginCipher("d-tls", "TLS", "u", "https://tls.example.net"),
	}

	report := Scan(context.Background(), ciphers, Options{HTTPClient: aliveClient})
	if len(report.Dead) != 7 {
		t.Fatalf("len(Dead) = %d, want 7; got %+v", len(report.Dead), report.Dead)
	}
	wantReasons := map[string]Reason{
		"d-503": ReasonServerError,
		"d-404": ReasonNotFound,
		"d-500": ReasonServerError,
		"d-dns": ReasonDNSNotFound,
		"d-ref": ReasonRefused,
		"d-to":  ReasonTimeout,
		"d-tls": ReasonTLSError,
	}
	for _, item := range report.Dead {
		if want, ok := wantReasons[item.CipherID]; !ok || item.Reason != want {
			t.Errorf("cipher %s got reason %q, want %q", item.CipherID, item.Reason, want)
		}
	}
}

func TestRealLocalServerErrorsTLSRefusedTimeoutRedirectsAndLookupHost(t *testing.T) {
	// 1. Real TLS server with untrusted self-signed cert -> ReasonTLSError
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()

	// 2. Real closed local port -> ReasonRefused
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	// 3. Real slow server -> ReasonTimeout
	slowRelease := make(chan struct{})
	defer close(slowRelease)
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-slowRelease:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer slowSrv.Close()

	// 4. Redirect chain server: 5 redirects -> OK; 7-redirect loop stops at 5 redirects
	var loopHits atomic.Int32
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.URL.Query().Get("step") == "" {
			http.Redirect(w, r, "/?step=1", http.StatusFound)
			return
		}
		switch r.URL.Query().Get("step") {
		case "1":
			http.Redirect(w, r, "/?step=2", http.StatusFound)
		case "2":
			http.Redirect(w, r, "/?step=3", http.StatusFound)
		case "3":
			http.Redirect(w, r, "/?step=4", http.StatusFound)
		case "4":
			http.Redirect(w, r, "/?step=5", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer redirSrv.Close()

	loopSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loopHits.Add(1)
		http.Redirect(w, r, fmt.Sprintf("/?n=%d", loopHits.Load()), http.StatusFound)
	}))
	defer loopSrv.Close()

	ciphers := []*state.Cipher{
		loginCipher("c-tls", "Self Signed", "u", tlsSrv.URL),
		loginCipher("c-ref", "Closed Port", "u", "http://"+closedAddr),
		loginCipher("c-redir", "Five Hop", "u", redirSrv.URL),
		loginCipher("c-loop", "Loop", "u", loopSrv.URL),
		loginCipher("c-nx", "Missing DNS", "u", "https://missing.invalid.test"),
	}

	report := Scan(context.Background(), ciphers, Options{
		IncludePrivate: true,
		Timeout:        2 * time.Second,
		LookupHost: func(ctx context.Context, host string) ([]string, error) {
			if host == "missing.invalid.test" {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			return []string{"127.0.0.1"}, nil
		},
	})

	byID := map[string]DeadItem{}
	for _, d := range report.Dead {
		byID[d.CipherID] = d
	}
	if byID["c-tls"].Reason != ReasonTLSError {
		t.Errorf("c-tls = %+v, want ReasonTLSError", byID["c-tls"])
	}
	if byID["c-ref"].Reason != ReasonRefused {
		t.Errorf("c-ref = %+v, want ReasonRefused", byID["c-ref"])
	}
	if byID["c-nx"].Reason != ReasonDNSNotFound {
		t.Errorf("c-nx = %+v, want ReasonDNSNotFound", byID["c-nx"])
	}
	if _, dead := byID["c-redir"]; dead {
		t.Errorf("c-redir was flagged dead: %+v", byID["c-redir"])
	}
	if got := loopHits.Load(); got > DefaultMaxRedirects+1 {
		t.Errorf("redirect loop made %d hits, want <= %d", got, DefaultMaxRedirects+1)
	}

	slowReport := Scan(context.Background(), []*state.Cipher{
		loginCipher("c-slow", "Slow", "u", slowSrv.URL),
	}, Options{
		IncludePrivate: true,
		Timeout:        100 * time.Millisecond,
	})
	if len(slowReport.Dead) != 1 || slowReport.Dead[0].Reason != ReasonTimeout {
		t.Errorf("slowReport.Dead = %+v, want single ReasonTimeout", slowReport.Dead)
	}
}

func TestProgressCallbackAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var started atomic.Int32
	gate := make(chan struct{})
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			n := started.Add(1)
			if n == 2 {
				<-gate
			}
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			default:
			}
			return makeResponse(r, http.StatusNotFound, nil, ""), nil
		}),
	}

	var mu sync.Mutex
	var progress []Progress
	ciphers := []*state.Cipher{
		loginCipher("c-1", "One", "u", "https://one.example.net"),
		loginCipher("c-2", "Two", "u", "https://two.example.net"),
		loginCipher("c-3", "Three", "u", "https://three.example.net"),
	}

	done := make(chan Report, 1)
	go func() {
		done <- Scan(ctx, ciphers, Options{
			Concurrency: 2,
			Timeout:     2 * time.Second,
			HTTPClient:  client,
			OnProgress: func(p Progress) {
				mu.Lock()
				progress = append(progress, p)
				mu.Unlock()
				if p.Checked >= 1 {
					cancel()
				}
			},
		})
	}()

	time.Sleep(30 * time.Millisecond)
	close(gate)

	report := <-done
	if !report.Canceled {
		t.Fatalf("report.Canceled = false, want true")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(progress) == 0 || progress[0].Checked != 0 || progress[0].Total != 3 {
		t.Fatalf("unexpected initial progress: %+v", progress)
	}
	for i := 1; i < len(progress); i++ {
		if progress[i].Checked < progress[i-1].Checked {
			t.Fatalf("non-monotonic progress: %+v", progress)
		}
	}
}
