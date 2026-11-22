package ui

import (
	"bytes"
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
)

const (
	faviconTimeout     = 5 * time.Second
	faviconMaxBytes    = 128 << 10
	faviconWorkers     = 4
	faviconQueueSize   = 512
	faviconMemEntries  = 256
	faviconNegativeTTL = 30 * time.Minute
)

// IconDomain returns the lowercase host of the first http(s) URI that names
// a public-looking hostname, or "" when none does.
func IconDomain(uris []string) string {
	for _, raw := range uris {
		if d := iconDomain(raw); d != "" {
			return d
		}
	}
	return ""
}

func iconDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !validIconHost(host) {
		return ""
	}
	return host
}

func validIconHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func isImageData(b []byte) bool {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")),
		bytes.HasPrefix(b, []byte("\xff\xd8\xff")),
		bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")),
		bytes.HasPrefix(b, []byte("\x00\x00\x01\x00")),
		len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return true
	}
	return false
}

type FaviconStoreConfig struct {
	CacheDir   string
	HTTPClient *http.Client
}

// FaviconStore fetches site icons from a Vaultwarden server's /icons
// service, caching them in memory (LRU), on disk, and remembering misses.
type FaviconStore struct {
	cfg     FaviconStoreConfig
	client  *http.Client
	enabled atomic.Bool
	offline atomic.Bool
	fetches atomic.Int64

	mu         sync.Mutex
	lru        *list.List
	entries    map[string]*list.Element
	failed     map[string]time.Time
	inflight   map[string]bool
	generation uint64
	// account scopes the disk cache: icons live in a directory of the
	// account's, under names that do not reveal the domain.
	account   string
	jobs      chan faviconJob
	startOnce sync.Once
	onLoaded  func(domain string)
}

type faviconEntry struct {
	domain string
	data   []byte
}

type faviconJob struct {
	serverURL, domain string
	generation        uint64
}

func NewFaviconStore(cfg FaviconStoreConfig) *FaviconStore {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: faviconTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("favicon: too many redirects")
				}
				return nil
			},
		}
	}
	s := &FaviconStore{
		cfg:      cfg,
		client:   client,
		lru:      list.New(),
		entries:  map[string]*list.Element{},
		failed:   map[string]time.Time{},
		inflight: map[string]bool{},
		jobs:     make(chan faviconJob, faviconQueueSize),
	}
	s.enabled.Store(true)
	// Icons older versions saved under their domain names go as soon as
	// the cache opens, whether icons are on or off.
	s.removeLegacyFiles()
	return s
}

func (s *FaviconStore) SetEnabled(on bool) { s.enabled.Store(on) }

// SetOffline keeps icons to what is cached: a local-only vault sends no
// site domains to the server.
func (s *FaviconStore) SetOffline(on bool) { s.offline.Store(on) }

// SetOnLoaded sets what runs, on a worker goroutine, once a domain's icon is cached.
func (s *FaviconStore) SetOnLoaded(fn func(domain string)) {
	s.mu.Lock()
	s.onLoaded = fn
	s.mu.Unlock()
}

// Lookup returns the cached icon for domain, queueing a load on a miss.
func (s *FaviconStore) Lookup(serverURL, domain string) []byte {
	if domain == "" || !s.enabled.Load() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.entries[domain]; ok {
		s.lru.MoveToFront(el)
		return el.Value.(*faviconEntry).data
	}
	if until, ok := s.failed[domain]; ok && time.Now().Before(until) {
		return nil
	}
	if s.inflight[domain] || strings.TrimSpace(serverURL) == "" {
		return nil
	}
	select {
	case s.jobs <- faviconJob{serverURL: serverURL, domain: domain, generation: s.generation}:
		s.inflight[domain] = true
		s.startOnce.Do(func() {
			for range faviconWorkers {
				go s.worker()
			}
		})
	default:
	}
	return nil
}

// SetAccount scopes the cache to accountID; "" keeps icons in memory only.
func (s *FaviconStore) SetAccount(accountID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.account == accountID {
		return
	}
	s.account = accountID
	s.generation++
	s.lru.Init()
	clear(s.entries)
	clear(s.failed)
	clear(s.inflight)
}

// ClearAccount removes accountID's icons from memory and disk.
func (s *FaviconStore) ClearAccount(accountID string) error {
	s.ResetMemory()
	s.removeLegacyFiles()
	if s.cfg.CacheDir == "" || accountID == "" {
		return nil
	}
	return os.RemoveAll(s.accountDir(accountID))
}

// removeLegacyFiles deletes icons older versions saved under their domain
// names at the top of the cache.
func (s *FaviconStore) removeLegacyFiles() {
	if s.cfg.CacheDir == "" {
		return
	}
	old, _ := filepath.Glob(filepath.Join(s.cfg.CacheDir, "*.png"))
	for _, p := range old {
		_ = os.Remove(p)
	}
}

func (s *FaviconStore) accountDir(accountID string) string {
	sum := sha256.Sum256([]byte("govault-favicons\x00" + accountID))
	return filepath.Join(s.cfg.CacheDir, "acct-"+hex.EncodeToString(sum[:8]))
}

// accountKey is a random key per account, kept with its icons, that names
// them: the cache shows which files exist, not which sites they are for.
func (s *FaviconStore) accountKey(dir string) []byte {
	path := filepath.Join(dir, "key")
	if k, err := os.ReadFile(path); err == nil && len(k) == 32 {
		return k
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil
	}
	if writeFileAtomic(path, k) != nil {
		return nil
	}
	return k
}

func (s *FaviconStore) ResetMemory() {
	s.mu.Lock()
	s.generation++
	s.lru.Init()
	clear(s.entries)
	clear(s.failed)
	clear(s.inflight)
	s.mu.Unlock()
}

func (s *FaviconStore) Clear() error {
	s.ResetMemory()
	if s.cfg.CacheDir == "" {
		return nil
	}
	return os.RemoveAll(s.cfg.CacheDir)
}

func (s *FaviconStore) worker() {
	for job := range s.jobs {
		data, err := s.load(job)
		s.mu.Lock()
		if job.generation != s.generation {
			s.mu.Unlock()
			continue
		}
		delete(s.inflight, job.domain)
		if err != nil {
			s.failed[job.domain] = time.Now().Add(faviconNegativeTTL)
			s.mu.Unlock()
			continue
		}
		s.putLocked(job.domain, data)
		onLoaded := s.onLoaded
		s.mu.Unlock()
		if onLoaded != nil {
			onLoaded(job.domain)
		}
	}
}

func (s *FaviconStore) putLocked(domain string, data []byte) {
	s.entries[domain] = s.lru.PushFront(&faviconEntry{domain: domain, data: data})
	for s.lru.Len() > faviconMemEntries {
		old := s.lru.Back()
		s.lru.Remove(old)
		delete(s.entries, old.Value.(*faviconEntry).domain)
	}
}

func (s *FaviconStore) diskPath(domain string) string {
	s.mu.Lock()
	account := s.account
	s.mu.Unlock()
	if s.cfg.CacheDir == "" || account == "" || !validIconHost(domain) {
		return ""
	}
	dir := s.accountDir(account)
	key := s.accountKey(dir)
	if key == nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	return filepath.Join(dir, hex.EncodeToString(mac.Sum(nil)[:16])+".png")
}

// writeIfCurrent saves an icon only while job's generation is current, so
// an icon fetched before Clear, lock or logout is never written after it.
func (s *FaviconStore) writeIfCurrent(job faviconJob, path string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.generation == s.generation {
		_ = writeFileAtomic(path, data)
	}
}

func (s *FaviconStore) load(job faviconJob) ([]byte, error) {
	path := s.diskPath(job.domain)
	if path != "" {
		if data, err := os.ReadFile(path); err == nil && isImageData(data) {
			if !needsNormalizing(data) {
				return data, nil
			}
			if fixed, err := normalizeIcon(data); err == nil {
				s.writeIfCurrent(job, path, fixed)
				return fixed, nil
			}
			_ = os.Remove(path)
		}
	}
	if !s.enabled.Load() {
		return nil, errors.New("favicon: disabled")
	}
	if s.offline.Load() {
		return nil, errors.New("favicon: offline")
	}
	data, err := s.fetch(job.serverURL, job.domain)
	if err != nil {
		return nil, err
	}
	if data, err = normalizeIcon(data); err != nil {
		return nil, err
	}
	if path != "" {
		s.writeIfCurrent(job, path, data)
	}
	return data, nil
}

func (s *FaviconStore) fetch(serverURL, domain string) ([]byte, error) {
	s.fetches.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), faviconTimeout)
	defer cancel()
	endpoint := strings.TrimRight(strings.TrimSpace(serverURL), "/") + "/icons/" + domain + "/icon.png"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "image/*")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("favicon: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, faviconMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > faviconMaxBytes || !isImageData(data) {
		return nil, errors.New("favicon: not an image")
	}
	return data, nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".icon-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

func (m *AppModel) setupFavicons() {
	m.iconEpoch = core.NewSignal(m.Scope, 0)
	m.iconSigs = map[string]*core.Signal[int]{}
	m.faviconsOn = core.NewMemo(m.Scope, func() bool { return m.Prefs.Get().FaviconsEnabled() })
	m.iconServer = core.NewMemo(m.Scope, func() string { return m.Prefs.Get().ServerURL })
	m.iconAccount = core.NewMemo(m.Scope, func() string { return m.Prefs.Get().AccountID })
	f := m.Hooks.Favicons
	if f == nil {
		return
	}
	f.SetOnLoaded(func(domain string) {
		m.Scope.Post(func() {
			if sig := m.iconSigs[domain]; sig != nil {
				sig.Update(func(v int) int { return v + 1 })
			}
		})
	})
	f.SetEnabled(m.Prefs.Get().FaviconsEnabled())
}

// SiteIcon returns the cached icon bytes for the first web URI, tracking
// its arrival; nil while it loads, when unavailable or when icons are off.
func (m *AppModel) SiteIcon(uris []string) []byte {
	f := m.Hooks.Favicons
	if f == nil || !m.faviconsOn.Get() {
		return nil
	}
	domain := IconDomain(uris)
	if domain == "" {
		return nil
	}
	m.iconEpoch.Get()
	f.SetAccount(m.iconAccount.Get())
	sig := m.iconSigs[domain]
	if sig == nil {
		sig = core.NewSignal(m.Scope, 0)
		m.iconSigs[domain] = sig
	}
	sig.Get()
	return f.Lookup(m.iconServer.Get(), domain)
}

func (m *AppModel) SetShowFavicons(on bool) {
	if f := m.Hooks.Favicons; f != nil {
		f.SetEnabled(on)
	}
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.ShowFavicons = &on
		return p
	})
}

func (m *AppModel) ClearIconCache() {
	if f := m.Hooks.Favicons; f != nil {
		if err := f.Clear(); err != nil {
			m.ShowToast(ui.ToastError, m.T("favicons.toast.clear_failed"), err.Error())
			return
		}
	}
	m.iconEpoch.Update(func(v int) int { return v + 1 })
	m.ShowToast(ui.ToastSuccess, m.T("favicons.toast.cleared"), "")
}

func (m *AppModel) resetFaviconMemory() {
	if f := m.Hooks.Favicons; f != nil {
		f.ResetMemory()
	}
	m.iconEpoch.Update(func(v int) int { return v + 1 })
}

func siteEmblem(m *AppModel, uris []string, name string, t api.CipherType, brand string, size core.Points) core.Node {
	if data := m.SiteIcon(uris); data != nil {
		return faviconTile(data, size)
	}
	return itemEmblem(name, t, brand, size)
}

func faviconTile(data []byte, size core.Points) core.Node {
	inner := size * 0.68
	return core.View{
		Style: core.Style{
			Width: core.Pt(size), Height: core.Pt(size), FlexShrink: 0,
			CornerRadius: size * 0.26, BorderCurve: core.BorderCurveContinuous,
			AlignItems: core.AlignCenter, JustifyContent: core.JustifyCenter,
			Background: core.RGB(0xffffff),
			Shadows:    []core.BoxShadow{core.Ring(0.5, core.RGBA(0x000000, 0.12))},
		},
		Children: []core.Node{
			core.Image{
				Source:         core.ImageSource{Data: data},
				ResizeMode:     core.Contain,
				FadeDuration:   time.Millisecond,
				ElementsHidden: true,
				Style:          core.Style{Width: core.Pt(inner), Height: core.Pt(inner), CornerRadius: size * 0.08},
			},
		},
	}
}
