// Package urlcheck performs opt-in reachability checks for login website
// domains. It contacts only scheme://host[:port]/ and never sends URL paths,
// query parameters, fragments, cookies, or vault secrets.
package urlcheck

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

const (
	DefaultConcurrency  = 8
	DefaultTimeout      = 5 * time.Second
	DefaultMaxRedirects = 5
	MaxProbeBodyBytes   = 1024 // 1 KiB cap for GET fallback
)

// Reason classifies why a login website could not be reached.
type Reason string

const (
	ReasonDNSNotFound Reason = "dns_not_found"
	ReasonRefused     Reason = "refused"
	ReasonTimeout     Reason = "timeout"
	ReasonTLSError    Reason = "tls_error"
	ReasonNotFound    Reason = "not_found"
	ReasonServerError Reason = "server_error"
	ReasonInvalidURL  Reason = "invalid_url"
)

// Label returns a human-readable badge label for r and an optional HTTP status code.
func (r Reason) Label(statusCode int) string {
	switch r {
	case ReasonDNSNotFound:
		return "DNS not found"
	case ReasonRefused:
		return "Connection refused"
	case ReasonTimeout:
		return "Timeout"
	case ReasonTLSError:
		return "TLS error"
	case ReasonNotFound:
		if statusCode > 0 {
			return fmt.Sprintf("HTTP %d", statusCode)
		}
		return "Not found"
	case ReasonServerError:
		if statusCode > 0 {
			return fmt.Sprintf("HTTP %d", statusCode)
		}
		return "Server error"
	case ReasonInvalidURL:
		return "Invalid URL"
	default:
		return "Unreachable"
	}
}

// Options configures a website reachability scan.
type Options struct {
	Concurrency    int
	Timeout        time.Duration
	IncludePrivate bool
	HTTPClient     *http.Client
	LookupHost     func(ctx context.Context, host string) ([]string, error)
	OnProgress     func(Progress)
}

// Progress reports live progress across unique probed targets.
type Progress struct {
	Checked   int
	Total     int
	DeadCount int
}

// DeadItem represents one active Login cipher flagged as unreachable or invalid.
// It never carries secret values or URL paths/queries/credentials.
type DeadItem struct {
	CipherID   string
	Name       string
	Username   string
	Domain     string
	TargetURL  string
	Reason     Reason
	StatusCode int
	ReadOnly   bool
}

// ReasonLabel returns the human-readable failure badge label for this item.
func (d DeadItem) ReasonLabel() string {
	return d.Reason.Label(d.StatusCode)
}

// Report summarizes a completed or canceled website reachability scan.
type Report struct {
	Dead               []DeadItem
	TotalTargets       int
	CheckedTargets     int
	SkippedWhitelisted int
	SkippedPrivate     int
	InvalidCount       int
	Canceled           bool
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// IsPrivateOrLocalHost reports whether host refers to a local, private,
// link-local, loopback, CGNAT/Tailscale, or single-label host.
func IsPrivateOrLocalHost(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return true
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() ||
			cgnatPrefix.Contains(addr) {
			return true
		}
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") ||
		strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".lan") || h == "home.arpa" || strings.HasSuffix(h, ".home.arpa") {
		return true
	}
	return !strings.Contains(h, ".")
}

type targetSpec struct {
	url    string
	domain string
}

type cipherCandidate struct {
	cipherID string
	name     string
	username string
	readOnly bool
	invalid  bool
	domain   string
	target   string
}

type probeResult struct {
	dead       bool
	canceled   bool
	reason     Reason
	statusCode int
}

type probeOutcome struct {
	target string
	result probeResult
}

// Scan checks reachability of unique scheme://host[:port]/ targets extracted from
// active Login ciphers. It is safe for concurrent cancellation via ctx.
func Scan(ctx context.Context, ciphers []*state.Cipher, opts Options) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	var (
		skippedPrivate     = map[string]struct{}{}
		skippedWhitelisted = map[string]struct{}{}
		targetSeen         = map[string]struct{}{}
		targets            []targetSpec
		targetCiphers      = map[string][]string{}
		candidatesByCipher = map[string][]cipherCandidate{}
		cipherOrder        []string
		initialDeadCiphers = map[string]struct{}{}
	)

	for _, c := range ciphers {
		if c == nil || c.DeletedDate != nil || c.Type != api.CipherTypeLogin || c.Login == nil {
			continue
		}
		username := c.Login.Username
		for _, u := range c.Login.URIs {
			raw := strings.TrimSpace(u.URI)
			if raw == "" || !hasHTTPSchemePrefix(raw) {
				continue
			}
			targetURL, domain, host, ok := extractHTTPTarget(raw)
			if !ok {
				if _, exists := candidatesByCipher[c.ID]; !exists {
					cipherOrder = append(cipherOrder, c.ID)
				}
				candidatesByCipher[c.ID] = append(candidatesByCipher[c.ID], cipherCandidate{
					cipherID: c.ID,
					name:     c.Name,
					username: username,
					readOnly: c.ReadOnly,
					invalid:  true,
					domain:   sanitizeInvalidDisplay(raw),
				})
				initialDeadCiphers[c.ID] = struct{}{}
				continue
			}
			if !opts.IncludePrivate && IsPrivateOrLocalHost(host) {
				skippedPrivate[targetURL] = struct{}{}
				continue
			}
			if IsWhitelisted(host) {
				skippedWhitelisted[targetURL] = struct{}{}
				continue
			}
			if _, exists := targetSeen[targetURL]; !exists {
				targetSeen[targetURL] = struct{}{}
				targets = append(targets, targetSpec{url: targetURL, domain: domain})
			}
			if _, exists := candidatesByCipher[c.ID]; !exists {
				cipherOrder = append(cipherOrder, c.ID)
			}
			candidatesByCipher[c.ID] = append(candidatesByCipher[c.ID], cipherCandidate{
				cipherID: c.ID,
				name:     c.Name,
				username: username,
				readOnly: c.ReadOnly,
				domain:   domain,
				target:   targetURL,
			})
			targetCiphers[targetURL] = append(targetCiphers[targetURL], c.ID)
		}
	}

	report := Report{
		TotalTargets:       len(targets),
		SkippedWhitelisted: len(skippedWhitelisted),
		SkippedPrivate:     len(skippedPrivate),
	}

	if ctx.Err() != nil {
		report.Canceled = true
		return report
	}

	deadCipherSet := make(map[string]struct{}, len(initialDeadCiphers))
	for id := range initialDeadCiphers {
		deadCipherSet[id] = struct{}{}
	}

	if opts.OnProgress != nil {
		opts.OnProgress(Progress{
			Checked:   0,
			Total:     len(targets),
			DeadCount: len(deadCipherSet),
		})
	}

	targetOutcomes := make(map[string]probeResult, len(targets))
	if len(targets) > 0 {
		client, cleanup := buildHTTPClient(opts, timeout)
		defer cleanup()

		workers := min(concurrency, len(targets))
		jobs := make(chan targetSpec)
		outcomes := make(chan probeOutcome, workers)

		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for spec := range jobs {
					res := probeOne(ctx, client, spec.url, timeout)
					outcomes <- probeOutcome{target: spec.url, result: res}
				}
			}()
		}

		go func() {
			defer close(jobs)
			for _, spec := range targets {
				select {
				case <-ctx.Done():
					return
				case jobs <- spec:
				}
			}
		}()

		go func() {
			wg.Wait()
			close(outcomes)
		}()

		checked := 0
		for out := range outcomes {
			if out.result.canceled || ctx.Err() != nil {
				report.Canceled = true
				continue
			}
			checked++
			targetOutcomes[out.target] = out.result
			if out.result.dead {
				for _, cid := range targetCiphers[out.target] {
					deadCipherSet[cid] = struct{}{}
				}
			}
			if opts.OnProgress != nil {
				opts.OnProgress(Progress{
					Checked:   checked,
					Total:     len(targets),
					DeadCount: len(deadCipherSet),
				})
			}
		}
		report.CheckedTargets = checked
	}

	if ctx.Err() != nil {
		report.Canceled = true
	}

	seenCiphers := make(map[string]struct{}, len(cipherOrder))
	for _, cid := range cipherOrder {
		if _, done := seenCiphers[cid]; done {
			continue
		}
		for _, cand := range candidatesByCipher[cid] {
			if cand.invalid {
				seenCiphers[cid] = struct{}{}
				report.InvalidCount++
				report.Dead = append(report.Dead, DeadItem{
					CipherID: cand.cipherID,
					Name:     cand.name,
					Username: cand.username,
					Domain:   cand.domain,
					Reason:   ReasonInvalidURL,
					ReadOnly: cand.readOnly,
				})
				break
			}
			res, probed := targetOutcomes[cand.target]
			if probed && res.dead {
				seenCiphers[cid] = struct{}{}
				report.Dead = append(report.Dead, DeadItem{
					CipherID:   cand.cipherID,
					Name:       cand.name,
					Username:   cand.username,
					Domain:     cand.domain,
					TargetURL:  cand.target,
					Reason:     res.reason,
					StatusCode: res.statusCode,
					ReadOnly:   cand.readOnly,
				})
				break
			}
		}
	}

	slices.SortFunc(report.Dead, func(a, b DeadItem) int {
		return cmp.Or(
			strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)),
			strings.Compare(a.CipherID, b.CipherID),
		)
	})

	return report
}

func hasHTTPSchemePrefix(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:")
}

func sanitizeInvalidDisplay(raw string) string {
	// Never keep credentials, paths, or query parameters in displayed domain text
	// if a partial parse reveals them.
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if at := strings.IndexByte(rest, '@'); at >= 0 {
			rest = rest[at+1:]
		}
		if cut := strings.IndexAny(rest, "/?#"); cut >= 0 {
			rest = rest[:cut]
		}
		if rest != "" {
			return rest
		}
	}
	if len(raw) > 64 {
		return raw[:64]
	}
	return raw
}

func extractHTTPTarget(raw string) (targetURL, displayDomain, host string, ok bool) {
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", "", "", false
	}
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", "", "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || strings.HasSuffix(u.Host, ":") {
		return "", "", "", false
	}
	host = strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", "", "", false
	}
	port := u.Port()
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", "", "", false
		}
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			port = ""
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.String()
	} else if !validHostname(host) {
		return "", "", "", false
	}

	var hostPort string
	switch {
	case port != "":
		hostPort = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		hostPort = "[" + host + "]"
	default:
		hostPort = host
	}
	return scheme + "://" + hostPort + "/", hostPort, host, true
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

func buildHTTPClient(opts Options, timeout time.Duration) (*http.Client, func()) {
	if opts.HTTPClient != nil {
		c := *opts.HTTPClient
		c.Jar = nil
		inner := opts.HTTPClient.CheckRedirect
		c.CheckRedirect = makeCheckRedirect(opts.IncludePrivate, inner)
		return &c, func() {}
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 15 * time.Second,
	}
	dialContext := dialer.DialContext
	if opts.LookupHost != nil {
		lookup := opts.LookupHost
		dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return dialer.DialContext(ctx, network, addr)
			}
			if _, parseErr := netip.ParseAddr(host); parseErr == nil {
				return dialer.DialContext(ctx, network, addr)
			}
			ips, err := lookup(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			var lastErr error
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		}
	}

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       15 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: makeCheckRedirect(opts.IncludePrivate, nil),
	}
	return client, tr.CloseIdleConnections
}

func makeCheckRedirect(includePrivate bool, inner func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if req.URL != nil {
			req.URL.User = nil
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return http.ErrUseLastResponse
			}
			if !includePrivate && IsPrivateOrLocalHost(req.URL.Hostname()) {
				return http.ErrUseLastResponse
			}
		}
		if len(via) > DefaultMaxRedirects {
			return http.ErrUseLastResponse
		}
		if inner != nil {
			return inner(req, via)
		}
		return nil
	}
}

func probeOne(parentCtx context.Context, client *http.Client, targetURL string, timeout time.Duration) probeResult {
	probeCtx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, targetURL, nil)
	if err != nil {
		return probeResult{dead: true, reason: ReasonInvalidURL}
	}
	resp, err := client.Do(req)
	if err != nil {
		return classifyError(parentCtx, err)
	}
	code := resp.StatusCode
	hdr := resp.Header
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxProbeBodyBytes))
	_ = resp.Body.Close()

	if code == http.StatusBadRequest || code == http.StatusMethodNotAllowed || code == http.StatusNotImplemented {
		getReq, err := http.NewRequestWithContext(probeCtx, http.MethodGet, targetURL, nil)
		if err != nil {
			return probeResult{dead: true, reason: ReasonInvalidURL}
		}
		getResp, err := client.Do(getReq)
		if err != nil {
			return classifyError(parentCtx, err)
		}
		code = getResp.StatusCode
		hdr = getResp.Header
		_, _ = io.Copy(io.Discard, io.LimitReader(getResp.Body, MaxProbeBodyBytes))
		_ = getResp.Body.Close()
	}

	return classifyStatus(code, hdr)
}

func classifyStatus(code int, hdr http.Header) probeResult {
	switch {
	case code >= 200 && code < 400:
		return probeResult{statusCode: code}
	case code == http.StatusUnauthorized,
		code == http.StatusForbidden,
		code == http.StatusMethodNotAllowed,
		code == http.StatusTooManyRequests:
		return probeResult{statusCode: code}
	case code == http.StatusServiceUnavailable && hasChallengeHeader(hdr):
		return probeResult{statusCode: code}
	case code == http.StatusNotFound, code == http.StatusGone:
		return probeResult{dead: true, reason: ReasonNotFound, statusCode: code}
	case code == http.StatusRequestTimeout:
		return probeResult{dead: true, reason: ReasonTimeout, statusCode: code}
	default:
		return probeResult{dead: true, reason: ReasonServerError, statusCode: code}
	}
}

func hasChallengeHeader(hdr http.Header) bool {
	if hdr == nil {
		return false
	}
	if hdr.Get("CF-Ray") != "" || hdr.Get("CF-Mitigated") != "" || hdr.Get("CF-Chl-Bypass") != "" {
		return true
	}
	if hdr.Get("X-Sucuri-ID") != "" || hdr.Get("X-Bot-Challenge") != "" || hdr.Get("X-Amz-Waf-Action") != "" {
		return true
	}
	server := strings.ToLower(hdr.Get("Server"))
	if strings.Contains(server, "cloudflare") || strings.Contains(server, "ddos-guard") {
		return true
	}
	return strings.Contains(strings.ToLower(hdr.Get("WWW-Authenticate")), "challenge")
}

func classifyError(parentCtx context.Context, err error) probeResult {
	if parentCtx.Err() != nil {
		return probeResult{canceled: true}
	}
	if isTLSError(err) {
		return probeResult{dead: true, reason: ReasonTLSError}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return probeResult{dead: true, reason: ReasonTimeout}
		}
		return probeResult{dead: true, reason: ReasonDNSNotFound}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return probeResult{dead: true, reason: ReasonTimeout}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return probeResult{dead: true, reason: ReasonTimeout}
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, io.EOF) ||
		strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return probeResult{dead: true, reason: ReasonRefused}
	}
	return probeResult{dead: true, reason: ReasonServerError}
}

func isTLSError(err error) bool {
	var (
		certVerify    *tls.CertificateVerificationError
		recordErr     tls.RecordHeaderError
		certInvalid   x509.CertificateInvalidError
		hostErr       x509.HostnameError
		unknownAuth   x509.UnknownAuthorityError
		constraintErr x509.ConstraintViolationError
		sysRoots      x509.SystemRootsError
	)
	if errors.As(err, &certVerify) ||
		errors.As(err, &recordErr) ||
		errors.As(err, &certInvalid) ||
		errors.As(err, &hostErr) ||
		errors.As(err, &unknownAuth) ||
		errors.As(err, &constraintErr) ||
		errors.As(err, &sysRoots) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "server gave http response to https client")
}
