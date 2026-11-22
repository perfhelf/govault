package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type apiKeyTestEnv struct {
	server       *httptest.Server
	password     []byte
	email        string
	clientID     string
	clientSecret string
	profileID    string
	kdf          crypto.KDFConfig
	userKey      *crypto.SymmetricKey

	mu            sync.Mutex
	omitTokenKDF  bool
	rejectAuth    bool
	preloginCalls int
	syncCalls     int
	requestsSeen  [][]byte
}

func newAPIKeyTestEnv(t *testing.T, kdf crypto.KDFConfig) *apiKeyTestEnv {
	t.Helper()
	email := "alice@example.com"
	password := []byte("super-secret-master-password-99")
	masterKey, err := crypto.DeriveMasterKey(password, email, kdf)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	defer crypto.ZeroBytes(masterKey[:])
	stretched, err := crypto.StretchMasterKey(masterKey)
	if err != nil {
		t.Fatalf("StretchMasterKey: %v", err)
	}
	defer stretched.Zero()

	rawUserKey := make([]byte, 64)
	for i := range rawUserKey {
		rawUserKey[i] = byte(i + 11)
	}
	userKey, _ := crypto.SymmetricKeyFromBytes(rawUserKey)
	protectedUserKey, err := crypto.EncryptBytes(rawUserKey, stretched)
	if err != nil {
		t.Fatalf("EncryptBytes: %v", err)
	}

	encCipherName, _ := crypto.EncryptString("API Key Vault Item", userKey)
	encUser, _ := crypto.EncryptString("alice", userKey)
	rev := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

	env := &apiKeyTestEnv{
		password:     password,
		email:        email,
		clientID:     "user.11111111-2222-3333-4444-555555555555",
		clientSecret: "api-key-secret-value",
		profileID:    "acct-api-1",
		kdf:          kdf,
		userKey:      userKey,
	}

	env.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		env.mu.Lock()
		env.requestsSeen = append(env.requestsSeen, body)
		omitKDF := env.omitTokenKDF
		rejectAuth := env.rejectAuth
		env.mu.Unlock()

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/identity/accounts/prelogin":
			env.mu.Lock()
			env.preloginCalls++
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(kdf)

		case r.Method == http.MethodPost && r.URL.Path == "/identity/connect/token":
			r.Body = io.NopCloser(bytes.NewReader(body))
			_ = r.ParseForm()
			if r.FormValue("grant_type") != "client_credentials" ||
				r.FormValue("scope") != "api" ||
				r.FormValue("client_id") != env.clientID ||
				r.FormValue("client_secret") != env.clientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			resp := map[string]any{
				"access_token": "api-tok-1",
				"expires_in":   3600,
				"token_type":   "Bearer",
				"Key":          protectedUserKey.String(),
			}
			if !omitKDF {
				resp["Kdf"] = int(kdf.Type)
				resp["KdfIterations"] = int(kdf.Iterations)
				if kdf.Type == crypto.KDFArgon2id {
					resp["KdfMemory"] = int(kdf.MemoryMB)
					resp["KdfParallelism"] = int(kdf.Parallelism)
				}
			}
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodGet && r.URL.Path == "/api/accounts/revision-date":
			if rejectAuth || r.Header.Get("Authorization") != "Bearer api-tok-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(rev.UnixMilli())

		case r.Method == http.MethodGet && r.URL.Path == "/api/sync":
			if rejectAuth || r.Header.Get("Authorization") != "Bearer api-tok-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			env.mu.Lock()
			env.syncCalls++
			env.mu.Unlock()
			_ = json.NewEncoder(w).Encode(api.SyncResponse{
				Profile: api.Profile{ID: env.profileID, Email: env.email, Key: protectedUserKey.String()},
				Ciphers: []api.EncryptedCipher{{
					ID:   "c-api-1",
					Type: api.CipherTypeLogin,
					Name: encCipherName,
					Login: &api.EncryptedLogin{
						Username: &encUser,
					},
				}},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(env.server.Close)
	return env
}

func TestService_LoginWithAPIKey_TokenKDFAndNeverSendsMasterPassword(t *testing.T) {
	kdf := crypto.KDFConfig{Type: crypto.KDFArgon2id, Iterations: 2, MemoryMB: 16, Parallelism: 1}
	env := newAPIKeyTestEnv(t, kdf)
	st := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()

	svc, err := NewService(ServiceConfig{
		Store:      st,
		Secrets:    secrets,
		DeviceID:   "dev-api",
		DeviceName: "macos",
		DeviceType: 7,
		HTTPClient: env.server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := LoginAPIKeyRequest{
		ServerURL:      env.server.URL,
		ClientID:       env.clientID,
		ClientSecret:   env.clientSecret,
		Email:          " " + strings.ToUpper(env.email) + " ",
		MasterPassword: append([]byte(nil), env.password...),
	}
	if err := svc.LoginWithAPIKey(context.Background(), req); err != nil {
		t.Fatalf("LoginWithAPIKey: %v", err)
	}

	if svc.Status() != StatusUnlocked || svc.LocalOnly() {
		t.Fatalf("status=%v localOnly=%v, want unlocked online", svc.Status(), svc.LocalOnly())
	}
	c, err := svc.GetCipher("c-api-1")
	if err != nil || c.Name != "API Key Vault Item" || c.Login.Username != "alice" {
		t.Fatalf("GetCipher = (%+v, %v)", c, err)
	}

	env.mu.Lock()
	prelogins := env.preloginCalls
	reqs := append([][]byte(nil), env.requestsSeen...)
	env.mu.Unlock()
	if prelogins != 0 {
		t.Fatalf("Prelogin called %d times when token response already carried KDF", prelogins)
	}
	for _, body := range reqs {
		if bytes.Contains(body, env.password) {
			t.Fatal("master password was sent over the network")
		}
	}

	// Client secret must never be persisted to Snapshot or SecretStore.
	snap, err := st.LoadSnapshot(env.profileID)
	if err != nil {
		t.Fatal(err)
	}
	rawSnap, _ := json.Marshal(snap)
	if strings.Contains(string(rawSnap), env.clientSecret) || strings.Contains(string(rawSnap), string(env.password)) {
		t.Fatal("snapshot contains client_secret or master password")
	}
	secrets.mu.Lock()
	for k, v := range secrets.m {
		if strings.Contains(v, env.clientSecret) || strings.Contains(k, env.clientSecret) || strings.Contains(v, string(env.password)) {
			secrets.mu.Unlock()
			t.Fatalf("secret store persisted client_secret or password under %q", k)
		}
	}
	_, hasRefresh := secrets.m[refreshTokenKeyPrefix+env.profileID]
	secrets.mu.Unlock()
	if hasRefresh {
		t.Fatal("client_credentials session unexpectedly stored a refresh token")
	}
	if got := svc.TrustedServerURL(env.profileID); got != env.server.URL {
		t.Fatalf("TrustedServerURL = %q, want %q", got, env.server.URL)
	}

	// Live session can sync until access token expires, then prompts Sign In Again cleanly.
	if err := svc.SyncNow(context.Background()); err != nil {
		t.Fatalf("SyncNow while access token valid = %v", err)
	}
	env.mu.Lock()
	env.rejectAuth = true
	env.mu.Unlock()
	if err := svc.SyncNow(context.Background()); !errors.Is(err, api.ErrUnauthorized) {
		t.Fatalf("SyncNow after access token expiry = %v, want api.ErrUnauthorized", err)
	}

	// Lock & unlock offline with master password: opens local-only since no refresh token exists.
	svc.Lock()
	if err := svc.UnlockWithPassword(context.Background(), env.password); err != nil {
		t.Fatalf("UnlockWithPassword: %v", err)
	}
	if !svc.LocalOnly() {
		t.Fatal("expected LocalOnly after unlocking API-key session without refresh token")
	}
	if err := svc.SyncNow(context.Background()); !errors.Is(err, ErrSignInRequired) {
		t.Fatalf("SyncNow after unlock = %v, want ErrSignInRequired", err)
	}
}

func TestService_LoginWithAPIKey_PreloginFallbackAndWrongPassword(t *testing.T) {
	kdf := crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}
	env := newAPIKeyTestEnv(t, kdf)
	env.omitTokenKDF = true
	st := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()

	svc, err := NewService(ServiceConfig{Store: st, Secrets: secrets, HTTPClient: env.server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	// Wrong master password fails locally before /api/sync is called.
	err = svc.LoginWithAPIKey(context.Background(), LoginAPIKeyRequest{
		ServerURL:      env.server.URL,
		ClientID:       env.clientID,
		ClientSecret:   env.clientSecret,
		Email:          env.email,
		MasterPassword: []byte("wrong-password"),
	})
	if !errors.Is(err, crypto.ErrInvalidMAC) {
		t.Fatalf("wrong master password = %v, want crypto.ErrInvalidMAC", err)
	}
	env.mu.Lock()
	prelogins := env.preloginCalls
	syncs := env.syncCalls
	env.mu.Unlock()
	if prelogins != 1 || syncs != 0 {
		t.Fatalf("after wrong master password: prelogins=%d syncs=%d, want 1 and 0", prelogins, syncs)
	}

	// Right master password uses Prelogin fallback and succeeds.
	if err := svc.LoginWithAPIKey(context.Background(), LoginAPIKeyRequest{
		ServerURL:      env.server.URL,
		ClientID:       env.clientID,
		ClientSecret:   env.clientSecret,
		Email:          env.email,
		MasterPassword: env.password,
	}); err != nil {
		t.Fatalf("LoginWithAPIKey with Prelogin fallback: %v", err)
	}
	if c, err := svc.GetCipher("c-api-1"); err != nil || c.Name != "API Key Vault Item" {
		t.Fatalf("GetCipher = (%+v, %v)", c, err)
	}
}

func TestService_LoginWithAPIKey_ValidationSameAccountRevokeAndPriorRefreshCleared(t *testing.T) {
	kdf := crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}
	env := newAPIKeyTestEnv(t, kdf)
	secrets := newMemSecretStore()
	st := store.NewFileStore(t.TempDir())
	svc, err := NewService(ServiceConfig{Store: st, Secrets: secrets, HTTPClient: env.server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	for _, bad := range []LoginAPIKeyRequest{
		{ClientID: "id", ClientSecret: "sec", Email: "a@b.com", MasterPassword: []byte("pw")},
		{ServerURL: env.server.URL, ClientSecret: "sec", Email: "a@b.com", MasterPassword: []byte("pw")},
		{ServerURL: env.server.URL, ClientID: "id", Email: "a@b.com", MasterPassword: []byte("pw")},
		{ServerURL: env.server.URL, ClientID: "id", ClientSecret: "sec", MasterPassword: []byte("pw")},
		{ServerURL: env.server.URL, ClientID: "id", ClientSecret: "sec", Email: "a@b.com"},
	} {
		if err := svc.LoginWithAPIKey(context.Background(), bad); err == nil {
			t.Fatalf("expected validation error for %+v", bad)
		}
	}
	env.mu.Lock()
	reqs := len(env.requestsSeen)
	env.mu.Unlock()
	if reqs != 0 {
		t.Fatalf("validation error hit server %d times", reqs)
	}

	// Revoked attempt never publishes.
	attempt := svc.AuthAttempt()
	svc.RevokeAuthAttempts()
	err = svc.LoginWithAPIKey(WithAuthAttempt(context.Background(), attempt), LoginAPIKeyRequest{
		ServerURL:      env.server.URL,
		ClientID:       env.clientID,
		ClientSecret:   env.clientSecret,
		Email:          env.email,
		MasterPassword: env.password,
	})
	if !errors.Is(err, ErrLocked) || svc.Status() == StatusUnlocked {
		t.Fatalf("revoked attempt = (%v, status=%v)", err, svc.Status())
	}

	// SameAccount rejects mismatched server or account ID before persisting anything.
	for _, want := range []Account{
		{ID: "other-acct", ServerURL: env.server.URL},
		{ID: env.profileID, ServerURL: "https://other.example"},
	} {
		err := svc.LoginWithAPIKey(context.Background(), LoginAPIKeyRequest{
			ServerURL:      env.server.URL,
			ClientID:       env.clientID,
			ClientSecret:   env.clientSecret,
			Email:          env.email,
			MasterPassword: env.password,
			SameAccount:    &want,
		})
		if !errors.Is(err, ErrDifferentAccount) {
			t.Fatalf("SameAccount(%+v) = %v, want ErrDifferentAccount", want, err)
		}
	}
	if _, err := st.LoadSnapshot(env.profileID); !errors.Is(err, store.ErrSnapshotNotFound) {
		t.Fatalf("refused SameAccount wrote snapshot: %v", err)
	}

	// Pre-populate a stale refresh token from an earlier password session and verify API key login clears it.
	if err := svc.saveRefreshToken(env.profileID, env.server.URL, "stale-refresh-token"); err != nil {
		t.Fatal(err)
	}
	if err := svc.saveSignInRecord(env.profileID, env.server.URL); err != nil {
		t.Fatal(err)
	}
	attackerHits := 0
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer attacker.Close()
	if err := svc.LoginWithAPIKey(context.Background(), LoginAPIKeyRequest{
		ServerURL:      attacker.URL,
		ClientID:       env.clientID,
		ClientSecret:   env.clientSecret,
		Email:          env.email,
		MasterPassword: env.password,
		SameAccount:    &Account{ID: env.profileID, ServerURL: env.server.URL},
	}); !errors.Is(err, ErrDifferentAccount) || attackerHits != 0 {
		t.Fatalf("trusted origin check: err=%v attackerHits=%d", err, attackerHits)
	}

	if err := svc.LoginWithAPIKey(context.Background(), LoginAPIKeyRequest{
		ServerURL:      env.server.URL,
		ClientID:       env.clientID,
		ClientSecret:   env.clientSecret,
		Email:          env.email,
		MasterPassword: env.password,
		SameAccount:    &Account{ID: env.profileID, ServerURL: env.server.URL},
	}); err != nil {
		t.Fatalf("SameAccount API key login: %v", err)
	}
	if _, ok, _ := secrets.Get(refreshTokenKeyPrefix + env.profileID); ok {
		t.Fatal("stale refresh token survived API key login")
	}
}
