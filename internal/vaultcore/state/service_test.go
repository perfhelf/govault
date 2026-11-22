package state

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/realtime"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type memSecretStore struct {
	mu sync.Mutex
	m  map[string]string
}

func newMemSecretStore() *memSecretStore {
	return &memSecretStore{m: make(map[string]string)}
}

func (s *memSecretStore) Get(account string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[account]
	return v, ok, nil
}

func (s *memSecretStore) Set(account, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[account] = value
	return nil
}

func (s *memSecretStore) Delete(account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, account)
	return nil
}

type fakeRealtimeClient struct {
	events  chan realtime.Event
	connect bool
}

func (f *fakeRealtimeClient) Run(ctx context.Context, _ realtime.Tokens, onConnect func(), onEvent func(realtime.Event)) error {
	if f.connect && onConnect != nil {
		onConnect()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-f.events:
			onEvent(ev)
		}
	}
}

type vaultTestEnv struct {
	server    *httptest.Server
	userKey   *crypto.SymmetricKey
	cipherKey *crypto.SymmetricKey
	encCKey   string
	kdf       crypto.KDFConfig
	password  []byte
	email     string

	mu            sync.Mutex
	revDate       time.Time
	ciphers       map[string]api.EncryptedCipher
	folders       map[string]api.EncryptedFolder
	conflictOnID  string
	lastUpdateKey *string
	lastUpdateRev *time.Time
	require2FA    bool
	emailSends    int
	blobs         map[string][]byte
	blobAuth      []string

	profileID   string
	accessTok   string
	authSeen    []string
	syncStarted chan struct{}
	syncGate    chan struct{}
	lastBody    []byte
	// syncStale makes a gated sync answer with the vault as it was when
	// the request arrived, not when the gate opens.
	syncStale bool
	syncResp  func() []byte
	// onSync runs during each sync request, after its answer is fixed.
	onSync func()
	// rotateRefresh makes each refresh token valid once, as servers that
	// rotate them do.
	rotateRefresh bool
	noNewRefresh  bool
	// noPremium sends a profile without premium; oldServer answers the
	// archive endpoints 404, as Vaultwarden before 1.36 does.
	noPremium    bool
	oldServer    bool
	archiveCalls []string
	// archiveApplyThen404 applies an archive change and answers 404, as
	// Bitwarden can for an item it will not send back; onArchive runs
	// after the change is applied, before the answer.
	archiveApplyThen404 bool
	onArchive           func()
	bulkHandler         func(w http.ResponseWriter, r *http.Request) bool
	refreshes           int
	refreshSpent        map[string]bool
}

func (env *vaultTestEnv) syncBody() []byte { return env.syncResp() }

func (env *vaultTestEnv) hasCipher(id string) bool {
	env.mu.Lock()
	defer env.mu.Unlock()
	_, ok := env.ciphers[id]
	return ok && !strings.Contains(id, "/")
}

func newVaultTestEnv(t *testing.T) *vaultTestEnv {
	t.Helper()
	email := "alice@example.com"
	password := []byte("correct-horse-battery-staple")
	kdf := crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}

	masterKey, err := crypto.DeriveMasterKey(password, email, kdf)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	stretched, err := crypto.StretchMasterKey(masterKey)
	if err != nil {
		t.Fatalf("StretchMasterKey: %v", err)
	}

	rawUserKey := make([]byte, 64)
	rawCipherKey := make([]byte, 64)
	for i := range 64 {
		rawUserKey[i] = byte(i + 1)
		rawCipherKey[i] = byte(i + 100)
	}
	userKey, _ := crypto.SymmetricKeyFromBytes(rawUserKey)
	cipherKey, _ := crypto.SymmetricKeyFromBytes(rawCipherKey)

	protectedUserKey, err := crypto.EncryptBytes(rawUserKey, stretched)
	if err != nil {
		t.Fatalf("EncryptBytes userKey: %v", err)
	}
	encCipherKey, err := crypto.EncryptBytes(rawCipherKey, userKey)
	if err != nil {
		t.Fatalf("EncryptBytes cipherKey: %v", err)
	}
	expectedHash := crypto.HashMasterPasswordForServer(masterKey, password)

	encFolderName, _ := crypto.EncryptString("Work", userKey)
	folderID := "f-work"
	rev1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

	encC1Name, _ := crypto.EncryptString("GitHub", cipherKey)
	encC1User, _ := crypto.EncryptString("alice", cipherKey)
	encC1Pass, _ := crypto.EncryptString("gh-secret", cipherKey)
	encC1TOTP, _ := crypto.EncryptString("JBSWY3DPEHPK3PXP", cipherKey)
	encC1URI, _ := crypto.EncryptString("https://github.com", cipherKey)
	encCKeyStr := encCipherKey.String()

	encC2Name, _ := crypto.EncryptString("Old Note", userKey)
	deletedAt := rev1.Add(-time.Hour)

	env := &vaultTestEnv{
		userKey:   userKey,
		cipherKey: cipherKey,
		encCKey:   encCKeyStr,
		kdf:       kdf,
		password:  password,
		email:     email,
		revDate:   rev1,
		profileID: "acct-1",
		accessTok: "tok-1",
		folders: map[string]api.EncryptedFolder{
			folderID: {ID: folderID, Name: encFolderName, RevisionDate: &rev1},
		},
		ciphers: map[string]api.EncryptedCipher{
			"c-1": {
				ID:           "c-1",
				Type:         api.CipherTypeLogin,
				FolderID:     &folderID,
				Favorite:     true,
				Key:          &encCKeyStr,
				Name:         encC1Name,
				RevisionDate: &rev1,
				Login: &api.EncryptedLogin{
					Username: &encC1User,
					Password: &encC1Pass,
					TOTP:     &encC1TOTP,
					URIs:     []api.EncryptedLoginURI{{URI: &encC1URI}},
				},
			},
			"c-trash": {
				ID:           "c-trash",
				Type:         api.CipherTypeSecureNote,
				Name:         encC2Name,
				RevisionDate: &rev1,
				DeletedDate:  &deletedAt,
				SecureNote:   &api.EncryptedSecureNote{Type: 0},
			},
		},
	}

	env.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		if auth := r.Header.Get("Authorization"); auth != "" {
			env.authSeen = append(env.authSeen, auth)
		}
		env.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/identity/accounts/prelogin":
			_ = json.NewEncoder(w).Encode(kdf)

		case r.Method == http.MethodPost && r.URL.Path == "/identity/connect/token":
			_ = r.ParseForm()
			switch r.FormValue("grant_type") {
			case "password":
				if r.FormValue("password") != expectedHash {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				resp := api.TokenResponse{
					AccessToken:  env.accessTok,
					RefreshToken: "ref-1",
					ExpiresIn:    3600,
					TokenType:    "Bearer",
					Key:          protectedUserKey.String(),
				}
				env.mu.Lock()
				require2FA := env.require2FA
				env.mu.Unlock()
				if require2FA {
					provider, code := r.FormValue("twoFactorProvider"), r.FormValue("twoFactorToken")
					switch {
					case provider == "5" && code == "remembered-device":
					case provider == "0" && code == "123456":
						if r.FormValue("twoFactorRemember") == "1" {
							resp.TwoFactorToken = "remembered-device"
						}
					default:
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"error":"invalid_grant","TwoFactorProviders":["0","1"],"TwoFactorProviders2":{"0":null,"1":{"Email":"a***@example.com"}}}`))
						return
					}
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "refresh_token":
				env.mu.Lock()
				env.refreshes++
				n, rotate, used := env.refreshes, env.rotateRefresh, r.FormValue("refresh_token")
				if rotate && (env.refreshSpent[used] || used == "") {
					env.mu.Unlock()
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				if env.refreshSpent == nil {
					env.refreshSpent = map[string]bool{}
				}
				env.refreshSpent[used] = true
				env.mu.Unlock()
				next := "ref-2"
				if rotate {
					next = fmt.Sprintf("ref-rot-%d", n)
				}
				env.mu.Lock()
				if env.noNewRefresh {
					next = ""
				}
				env.mu.Unlock()
				_ = json.NewEncoder(w).Encode(api.TokenResponse{
					AccessToken:  "tok-2",
					RefreshToken: next,
					ExpiresIn:    3600,
					TokenType:    "Bearer",
				})
			}

		case r.Method == http.MethodPost && r.URL.Path == "/api/two-factor/send-email-login":
			var body struct {
				MasterPasswordHash string `json:"masterPasswordHash"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.MasterPasswordHash != expectedHash {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			env.mu.Lock()
			env.emailSends++
			env.mu.Unlock()

		case r.Method == http.MethodGet && r.URL.Path == "/api/accounts/revision-date":
			env.mu.Lock()
			ms := env.revDate.UnixMilli()
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(ms)

		case r.Method == http.MethodGet && r.URL.Path == "/api/sync":
			env.mu.Lock()
			started, gate := env.syncStarted, env.syncGate
			stale := env.syncStale
			env.mu.Unlock()
			var frozen []byte
			if gate != nil && stale {
				frozen = env.syncBody()
			}
			env.mu.Lock()
			hook := env.onSync
			env.mu.Unlock()
			if hook != nil {
				frozen = env.syncBody()
				hook()
			}
			if gate != nil {
				close(started)
				select {
				case <-gate:
				case <-r.Context().Done():
					return
				}
			}
			if frozen == nil {
				frozen = env.syncBody()
			}
			_, _ = w.Write(frozen)

		case r.Method == http.MethodPost && r.URL.Path == "/api/ciphers":
			body, _ := io.ReadAll(r.Body)
			var p api.CipherPayload
			_ = json.Unmarshal(body, &p)
			env.mu.Lock()
			env.lastBody = body
			env.mu.Unlock()
			now := time.Now().UTC()
			created := api.EncryptedCipher{
				ID:           "c-created",
				Type:         p.Type,
				FolderID:     p.FolderID,
				Favorite:     p.Favorite,
				Key:          p.Key,
				Name:         p.Name,
				Notes:        p.Notes,
				RevisionDate: &now,
				Login:        p.Login,
				SecureNote:   p.SecureNote,
				SSHKey:       p.SSHKey,
				Card:         p.Card,
				Identity:     p.Identity,
				Fields:       p.Fields,
				Extra:        p.Extra,
			}
			env.mu.Lock()
			env.ciphers[created.ID] = created
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(created)

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/ciphers/") && env.hasCipher(strings.TrimPrefix(r.URL.Path, "/api/ciphers/")):
			env.mu.Lock()
			c := env.ciphers[strings.TrimPrefix(r.URL.Path, "/api/ciphers/")]
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(c)

		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/ciphers/") && env.hasCipher(strings.TrimPrefix(r.URL.Path, "/api/ciphers/")):
			id := strings.TrimPrefix(r.URL.Path, "/api/ciphers/")
			body, _ := io.ReadAll(r.Body)
			var p api.CipherPayload
			_ = json.Unmarshal(body, &p)
			env.mu.Lock()
			if env.conflictOnID == id {
				env.mu.Unlock()
				w.WriteHeader(http.StatusConflict)
				return
			}
			env.lastBody = body
			env.lastUpdateKey = p.Key
			env.lastUpdateRev = p.LastKnownRevisionDate
			now := env.revDate.Add(time.Minute)
			env.revDate = now
			updated := env.ciphers[id]
			updated.Name = p.Name
			updated.Notes = p.Notes
			updated.Key = p.Key
			updated.Favorite = p.Favorite
			updated.FolderID = p.FolderID
			updated.Login = p.Login
			updated.Card = p.Card
			updated.Identity = p.Identity
			updated.SecureNote = p.SecureNote
			updated.SSHKey = p.SSHKey
			updated.Fields = p.Fields
			updated.PasswordHistory = p.PasswordHistory
			updated.Extra = p.Extra
			updated.ArchivedDate = p.ArchivedDate
			updated.RevisionDate = &now
			env.ciphers[id] = updated
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(updated)

		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/delete") && env.hasCipher(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/ciphers/"), "/delete")):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/ciphers/"), "/delete")
			now := time.Now().UTC()
			env.mu.Lock()
			c := env.ciphers[id]
			c.DeletedDate = &now
			env.ciphers[id] = c
			env.mu.Unlock()
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPut && (strings.HasSuffix(r.URL.Path, "/archive") || strings.HasSuffix(r.URL.Path, "/unarchive")) && strings.HasPrefix(r.URL.Path, "/api/ciphers/"):
			rest := strings.TrimPrefix(r.URL.Path, "/api/ciphers/")
			id, action, _ := strings.Cut(rest, "/")
			body, _ := io.ReadAll(r.Body)
			env.mu.Lock()
			env.archiveCalls = append(env.archiveCalls, r.Method+" "+r.URL.Path+" body="+string(body))
			old, applyThen404, hook := env.oldServer, env.archiveApplyThen404, env.onArchive
			c, ok := env.ciphers[id]
			if ok && (!old || applyThen404) {
				now := env.revDate.Add(time.Minute)
				env.revDate = now
				c.RevisionDate = &now
				if action == "archive" {
					c.ArchivedDate = &now
				} else {
					c.ArchivedDate = nil
				}
				env.ciphers[id] = c
			}
			env.mu.Unlock()
			if hook != nil {
				hook()
			}
			switch {
			case old || applyThen404:
				w.WriteHeader(http.StatusNotFound)
			case !ok:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"Cipher doesn't exist"}`))
			default:
				_ = json.NewEncoder(w).Encode(c)
			}

		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/c-created/restore":
			env.mu.Lock()
			c := env.ciphers["c-created"]
			c.DeletedDate = nil
			env.ciphers["c-created"] = c
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(c)

		case r.Method == http.MethodDelete && r.URL.Path == "/api/ciphers/c-created":
			env.mu.Lock()
			delete(env.ciphers, "c-created")
			env.mu.Unlock()
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPost && r.URL.Path == "/api/folders":
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f := api.EncryptedFolder{ID: "f-new", Name: body.Name}
			env.mu.Lock()
			env.folders[f.ID] = f
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(f)

		case r.Method == http.MethodPut && r.URL.Path == "/api/folders/f-new":
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f := api.EncryptedFolder{ID: "f-new", Name: body.Name}
			env.mu.Lock()
			env.folders[f.ID] = f
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(f)

		case r.Method == http.MethodDelete && r.URL.Path == "/api/folders/f-new":
			env.mu.Lock()
			delete(env.folders, "f-new")
			env.mu.Unlock()
			w.WriteHeader(http.StatusOK)

		default:
			if env.bulkHandler != nil && env.bulkHandler(w, r) {
				return
			}
			if !env.handleAttachments(w, r) {
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
	env.syncResp = func() []byte {
		env.mu.Lock()
		defer env.mu.Unlock()
		var folders []api.EncryptedFolder
		for _, f := range env.folders {
			folders = append(folders, f)
		}
		var ciphers []api.EncryptedCipher
		for _, c := range env.ciphers {
			ciphers = append(ciphers, c)
		}
		raw, _ := json.Marshal(api.SyncResponse{
			Profile: api.Profile{ID: env.profileID, Email: email, Key: protectedUserKey.String(),
				Extra: map[string]json.RawMessage{"premium": json.RawMessage(fmt.Sprint(!env.noPremium))}},
			Folders: folders,
			Ciphers: ciphers,
		})
		return raw
	}
	t.Cleanup(env.server.Close)
	return env
}

func TestService_LifecycleOfflineUnlockAndLogout(t *testing.T) {
	env := newVaultTestEnv(t)
	fileStore := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()

	svc, err := NewService(ServiceConfig{
		Store:      fileStore,
		Secrets:    secrets,
		DeviceID:   "dev-1",
		DeviceName: "macos",
		DeviceType: 7,
		HTTPClient: env.server.Client(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.Status() != StatusLoggedOut {
		t.Fatalf("initial status = %v, want StatusLoggedOut", svc.Status())
	}

	ctx := context.Background()
	if err := svc.Login(ctx, LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if svc.Status() != StatusUnlocked {
		t.Fatalf("after Login status = %v, want StatusUnlocked", svc.Status())
	}

	all := svc.Search("", SearchFilter{Category: FilterAll})
	if len(all) != 1 || all[0].Name != "GitHub" || !all[0].HasTOTP {
		t.Fatalf("Search(All) = %+v", all)
	}
	if favs := svc.Search("gthb", SearchFilter{Category: FilterFavorites}); len(favs) != 1 {
		t.Fatalf("fuzzy Search(Favorites) = %+v, want 1 match", favs)
	}
	if trash := svc.Search("", SearchFilter{Category: FilterTrash}); len(trash) != 1 || trash[0].ID != "c-trash" {
		t.Fatalf("Search(Trash) = %+v", trash)
	}
	loginType := api.CipherTypeLogin
	if byFolder := svc.Search("", SearchFilter{FolderID: "f-work", Type: &loginType}); len(byFolder) != 1 {
		t.Fatalf("Search(Folder+Type) = %+v", byFolder)
	}

	c1, err := svc.GetCipher("c-1")
	if err != nil || c1.Login == nil || c1.Login.Password != "gh-secret" {
		t.Fatalf("GetCipher(c-1) = (%+v, %v)", c1, err)
	}

	if err := svc.EnableBiometricUnlock(secrets); err != nil {
		t.Fatalf("EnableBiometricUnlock: %v", err)
	}

	svc.Lock()
	if svc.Status() != StatusLocked {
		t.Fatalf("after Lock status = %v, want StatusLocked", svc.Status())
	}
	if got := svc.Search("", SearchFilter{}); len(got) != 0 {
		t.Fatalf("expected empty search results while locked, got %d", len(got))
	}
	if _, err := svc.GetCipher("c-1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("GetCipher while locked = %v, want ErrLocked", err)
	}

	// Shut down server to prove UnlockWithPassword and UnlockWithUserKey work offline.
	env.server.Close()

	if err := svc.UnlockWithPassword(ctx, env.password); err != nil {
		t.Fatalf("offline UnlockWithPassword: %v", err)
	}
	if c, err := svc.GetCipher("c-1"); err != nil || c.Name != "GitHub" {
		t.Fatalf("after password unlock GetCipher = (%+v, %v)", c, err)
	}

	svc.Lock()
	encodedKey, ok, err := secrets.Get("userkey:acct-1")
	if err != nil || !ok {
		t.Fatalf("biometric userkey missing: ok=%v err=%v", ok, err)
	}
	rawKey, _ := base64.StdEncoding.DecodeString(encodedKey)
	uk, err := crypto.SymmetricKeyFromBytes(rawKey)
	if err != nil {
		t.Fatalf("SymmetricKeyFromBytes: %v", err)
	}
	if err := svc.UnlockWithUserKey(ctx, uk); err != nil {
		t.Fatalf("offline UnlockWithUserKey: %v", err)
	}
	if svc.Status() != StatusUnlocked {
		t.Fatalf("after UnlockWithUserKey status = %v", svc.Status())
	}

	if err := svc.Logout(ctx, secrets); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if svc.Status() != StatusLoggedOut {
		t.Fatalf("after Logout status = %v, want StatusLoggedOut", svc.Status())
	}
	if _, err := fileStore.LoadSnapshot("acct-1"); !errors.Is(err, store.ErrSnapshotNotFound) {
		t.Fatalf("snapshot not deleted on Logout: %v", err)
	}
	if _, ok, _ := secrets.Get("refresh_token:acct-1"); ok {
		t.Fatalf("refresh_token not deleted on Logout")
	}
	if _, ok, _ := secrets.Get("userkey:acct-1"); ok {
		t.Fatalf("userkey not deleted on Logout")
	}
}

func TestService_CRUDPerCipherKeyAndConflict(t *testing.T) {
	env := newVaultTestEnv(t)
	svc, err := NewService(ServiceConfig{
		Store:      store.NewFileStore(t.TempDir()),
		Secrets:    newMemSecretStore(),
		HTTPClient: env.server.Client(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ctx := context.Background()
	if err := svc.Login(ctx, LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Update cipher with per-cipher key and verify key + lastKnownRevisionDate preservation.
	c1, err := svc.GetCipher("c-1")
	if err != nil {
		t.Fatalf("GetCipher: %v", err)
	}
	c1.Name = "GitHub Enterprise"
	updated, err := svc.SaveCipher(ctx, c1)
	if err != nil {
		t.Fatalf("SaveCipher(update): %v", err)
	}
	if updated.Name != "GitHub Enterprise" {
		t.Fatalf("updated.Name = %q", updated.Name)
	}

	env.mu.Lock()
	gotKey := env.lastUpdateKey
	gotRev := env.lastUpdateRev
	storedName := env.ciphers["c-1"].Name
	env.mu.Unlock()
	if gotKey == nil || *gotKey != env.encCKey {
		t.Fatalf("per-cipher key was not preserved on update")
	}
	if gotRev == nil {
		t.Fatalf("lastKnownRevisionDate was not sent on update")
	}
	if decName, err := crypto.DecryptString(storedName, env.cipherKey); err != nil || decName != "GitHub Enterprise" {
		t.Fatalf("updated cipher name was not encrypted with per-cipher key: (%q, %v)", decName, err)
	}

	// Revision conflict propagates api.ErrRevisionConflict.
	env.mu.Lock()
	env.conflictOnID = "c-1"
	env.mu.Unlock()
	if _, err := svc.SaveCipher(ctx, updated); !errors.Is(err, api.ErrRevisionConflict) {
		t.Fatalf("conflict update = %v, want ErrRevisionConflict", err)
	}

	// Create -> SoftDelete -> Restore -> HardDelete cipher.
	created, err := svc.SaveCipher(ctx, &Cipher{
		Type:       api.CipherTypeSecureNote,
		Name:       "Temp Note",
		Notes:      "body",
		SecureNote: &SecureNote{Type: 0},
	})
	if err != nil || created.ID != "c-created" {
		t.Fatalf("SaveCipher(create) = (%+v, %v)", created, err)
	}
	if err := svc.SoftDeleteCipher(ctx, created.ID); err != nil {
		t.Fatalf("SoftDeleteCipher: %v", err)
	}
	if trash := svc.Search("Temp Note", SearchFilter{Category: FilterTrash}); len(trash) != 1 {
		t.Fatalf("soft-deleted cipher not found in trash")
	}
	if err := svc.RestoreCipher(ctx, created.ID); err != nil {
		t.Fatalf("RestoreCipher: %v", err)
	}
	if active := svc.Search("Temp Note", SearchFilter{Category: FilterAll}); len(active) != 1 {
		t.Fatalf("restored cipher not found in active list")
	}
	if err := svc.HardDeleteCipher(ctx, created.ID); err != nil {
		t.Fatalf("HardDeleteCipher: %v", err)
	}
	if _, err := svc.GetCipher(created.ID); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("hard-deleted cipher still present: %v", err)
	}

	// Folder create -> rename -> delete.
	f, err := svc.SaveFolder(ctx, &Folder{Name: "Personal"})
	if err != nil || f.ID != "f-new" || f.Name != "Personal" {
		t.Fatalf("SaveFolder(create) = (%+v, %v)", f, err)
	}
	f.Name = "Personal 2"
	f2, err := svc.SaveFolder(ctx, f)
	if err != nil || f2.Name != "Personal 2" {
		t.Fatalf("SaveFolder(rename) = (%+v, %v)", f2, err)
	}
	if err := svc.DeleteFolder(ctx, f2.ID); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if folders := svc.Folders(); len(folders) != 1 || folders[0].ID != "f-work" {
		t.Fatalf("Folders after delete = %+v", folders)
	}
}

func TestService_RealtimeSyncAndLogout(t *testing.T) {
	env := newVaultTestEnv(t)
	rtClient := &fakeRealtimeClient{events: make(chan realtime.Event, 4)}
	updatedCh := make(chan struct{}, 4)
	statusCh := make(chan LockStatus, 4)

	svc, err := NewService(ServiceConfig{
		Store:      store.NewFileStore(t.TempDir()),
		Secrets:    newMemSecretStore(),
		DeviceID:   "dev-self",
		HTTPClient: env.server.Client(),
		NewRealtimeClient: func(string) (realtime.Client, error) {
			return rtClient, nil
		},
		OnVaultUpdated: func() {
			updatedCh <- struct{}{}
		},
		OnStatusChange: func(st LockStatus) {
			statusCh <- st
		},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := svc.Login(ctx, LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Drain initial login notifications.
	<-updatedCh
	<-statusCh

	if err := svc.StartRealtime(ctx); err != nil {
		t.Fatalf("StartRealtime: %v", err)
	}

	// Mutate cipher on server and trigger SyncCipherUpdate from another device.
	encUpdatedName, _ := crypto.EncryptString("GitHub Synced", env.cipherKey)
	env.mu.Lock()
	c := env.ciphers["c-1"]
	c.Name = encUpdatedName
	env.ciphers["c-1"] = c
	env.revDate = env.revDate.Add(2 * time.Minute)
	env.mu.Unlock()

	rtClient.events <- realtime.Event{Type: realtime.SyncCipherUpdate, ContextID: "other-dev", ItemID: "c-1"}

	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	select {
	case <-updatedCh:
	case <-timeout.C:
		t.Fatalf("timed out waiting for realtime sync update")
	}

	synced, err := svc.GetCipher("c-1")
	if err != nil || synced.Name != "GitHub Synced" {
		t.Fatalf("after realtime sync GetCipher = (%+v, %v)", synced, err)
	}

	// LogOut push forces StatusLoggedOut.
	rtClient.events <- realtime.Event{Type: realtime.LogOut}
	select {
	case st := <-statusCh:
		if st != StatusLoggedOut {
			t.Fatalf("status after LogOut push = %v, want StatusLoggedOut", st)
		}
	case <-timeout.C:
		t.Fatalf("timed out waiting for LogOut push")
	}
}

func TestService_TwoFactorLoginAndRememberDevice(t *testing.T) {
	env := newVaultTestEnv(t)
	env.require2FA = true
	fileStore := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()
	svc, err := NewService(ServiceConfig{Store: fileStore, Secrets: secrets, DeviceID: "dev-1", HTTPClient: env.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	req := LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}

	err = svc.Login(ctx, req)
	var tfErr *api.TwoFactorRequiredError
	if !errors.As(err, &tfErr) || !tfErr.Challenge.Has(api.TwoFactorAuthenticator) || !tfErr.Challenge.Has(api.TwoFactorEmail) {
		t.Fatalf("Login without code = %v, want 2FA challenge", err)
	}
	if svc.Status() != StatusLoggedOut {
		t.Fatalf("status after challenge = %v", svc.Status())
	}
	if _, err := fileStore.LoadSnapshot("acct-1"); err == nil {
		t.Fatal("snapshot persisted before 2FA completed")
	}

	if err := svc.SendEmailTwoFactorCode(ctx, req); err != nil || env.emailSends != 1 {
		t.Fatalf("SendEmailTwoFactorCode = %v, sends = %d", err, env.emailSends)
	}

	wrong := req
	wrong.TwoFactorCode = "000000"
	if err := svc.Login(ctx, wrong); !errors.Is(err, api.ErrTwoFactorRequired) {
		t.Fatalf("wrong code = %v", err)
	}

	ok := req
	ok.TwoFactorProvider, ok.TwoFactorCode, ok.RememberDevice = api.TwoFactorAuthenticator, "123456", true
	if err := svc.Login(ctx, ok); err != nil {
		t.Fatalf("Login with code: %v", err)
	}
	if svc.Status() != StatusUnlocked || len(svc.Search("", SearchFilter{})) != 1 {
		t.Fatalf("status = %v after 2FA login", svc.Status())
	}

	if err := svc.Logout(ctx, secrets); err != nil {
		t.Fatal(err)
	}
	if err := svc.Login(ctx, req); err != nil {
		t.Fatalf("remembered device login: %v", err)
	}
}
