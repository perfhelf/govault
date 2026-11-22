package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

func TestClient_AuthAndPrelogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/accounts/prelogin":
			if r.Method != http.MethodPost {
				t.Errorf("prelogin method = %s", r.Method)
			}
			var body struct {
				Email string `json:"email"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Email != "alice@example.com" {
				t.Errorf("prelogin email = %q, want normalized", body.Email)
			}
			_, _ = w.Write([]byte(`{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4}`))

		case "/identity/connect/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm: %v", err)
			}
			switch r.FormValue("grant_type") {
			case "password":
				wantAuthEmail := base64.RawURLEncoding.EncodeToString([]byte("alice@example.com"))
				if r.Header.Get("Auth-Email") != wantAuthEmail {
					t.Errorf("Auth-Email = %q, want %q", r.Header.Get("Auth-Email"), wantAuthEmail)
				}
				if r.FormValue("password") == "needs-2fa" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant","TwoFactorProviders":["0"]}`))
					return
				}
				if r.FormValue("deviceIdentifier") != "dev-1" || r.FormValue("deviceType") != "7" {
					t.Errorf("unexpected device params: id=%q type=%q", r.FormValue("deviceIdentifier"), r.FormValue("deviceType"))
				}
				_, _ = w.Write([]byte(`{"access_token":"tok-1","refresh_token":"ref-1","expires_in":3600,"token_type":"Bearer","Key":"2.iv|ct|mac","Kdf":1,"KdfIterations":3}`))

			case "refresh_token":
				if r.FormValue("refresh_token") != "ref-1" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"access_token":"tok-2","refresh_token":"ref-2","expires_in":3600,"token_type":"Bearer"}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{
		ServerURL:  srv.URL + "/",
		DeviceID:   "dev-1",
		DeviceName: "macos",
		DeviceType: 7,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx := context.Background()
	kdf, err := c.Prelogin(ctx, " ALICE@example.com ")
	if err != nil {
		t.Fatalf("Prelogin: %v", err)
	}
	if kdf.Type != crypto.KDFArgon2id || kdf.Iterations != 3 || kdf.MemoryMB != 64 || kdf.Parallelism != 4 {
		t.Fatalf("unexpected KDF: %+v", kdf)
	}

	tok, err := c.LoginPassword(ctx, "Alice@Example.com", "pw-hash", nil)
	if err != nil {
		t.Fatalf("LoginPassword: %v", err)
	}
	if tok.AccessToken != "tok-1" || tok.RefreshToken != "ref-1" || tok.Key != "2.iv|ct|mac" {
		t.Fatalf("unexpected token response: %+v", tok)
	}

	if _, err := c.LoginPassword(ctx, "alice@example.com", "needs-2fa", nil); !errors.Is(err, ErrTwoFactorRequired) {
		t.Fatalf("2FA login got %v, want ErrTwoFactorRequired", err)
	}

	refreshed, err := c.RefreshToken(ctx, "ref-1")
	if err != nil || refreshed.AccessToken != "tok-2" {
		t.Fatalf("RefreshToken = (%+v, %v)", refreshed, err)
	}
}

func TestClient_RevisionDateSyncCRUDAndErrors(t *testing.T) {
	var revCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/accounts/revision-date":
			if revCalls.Add(1) == 1 {
				_, _ = w.Write([]byte(`1700000000000`))
			} else {
				_, _ = w.Write([]byte(`"2026-11-20T12:00:00Z"`))
			}

		case r.Method == http.MethodGet && r.URL.Path == "/api/sync":
			if r.URL.Query().Get("excludeDomains") != "true" {
				t.Errorf("expected excludeDomains=true")
			}
			_, _ = w.Write([]byte(`{"profile":{"id":"u1","email":"a@b.com","key":"2.a|b|c"},"folders":[{"id":"f1","name":"2.f|n|m"}],"ciphers":[{"id":"c1","type":1,"name":"2.x|y|z"}]}`))

		case r.Method == http.MethodPost && r.URL.Path == "/api/ciphers":
			_, _ = w.Write([]byte(`{"id":"c-new","type":1,"name":"2.n|c|m"}`))

		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/c-conflict":
			// Vaultwarden's stale-write answer, verbatim (src/api/core/ciphers.rs, src/error.rs).
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(vaultwardenStaleWrite))

		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/c1":
			var body CipherPayload
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.LastKnownRevisionDate == nil || body.Key == nil || *body.Key != "2.ck|ct|mac" {
				t.Errorf("expected lastKnownRevisionDate and key in update payload: %+v", body)
			}
			_, _ = w.Write([]byte(`{"id":"c1","type":1,"key":"2.ck|ct|mac","name":"2.updated|c|m"}`))

		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/c1/delete":
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/c1/restore":
			_, _ = w.Write([]byte(`{"id":"c1","type":1,"name":"2.restored|c|m"}`))

		case r.Method == http.MethodDelete && r.URL.Path == "/api/ciphers/c1":
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPost && r.URL.Path == "/api/folders":
			_, _ = w.Write([]byte(`{"id":"f-new","name":"2.fn|c|m"}`))

		case r.Method == http.MethodPut && r.URL.Path == "/api/folders/f-new":
			_, _ = w.Write([]byte(`{"id":"f-new","name":"2.fn2|c|m"}`))

		case r.Method == http.MethodDelete && r.URL.Path == "/api/folders/f-new":
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()

	// DoWithRefresh retries once on HTTP 401.
	revMS, err := DoWithRefresh(ctx, "expired-token", func(context.Context) (string, error) {
		return "valid-token", nil
	}, func(tok string) (time.Time, error) {
		return c.RevisionDate(ctx, tok)
	})
	if err != nil || revMS.UnixMilli() != 1700000000000 {
		t.Fatalf("RevisionDate(ms) with refresh = (%v, %v)", revMS, err)
	}

	revISO, err := c.RevisionDate(ctx, "valid-token")
	if err != nil || revISO.Year() != 2026 {
		t.Fatalf("RevisionDate(iso) = (%v, %v)", revISO, err)
	}

	syncResp, raw, err := c.Sync(ctx, "valid-token")
	if err != nil || len(raw) == 0 || len(syncResp.Ciphers) != 1 || len(syncResp.Folders) != 1 {
		t.Fatalf("Sync = (%+v, len=%d, %v)", syncResp, len(raw), err)
	}

	created, err := c.CreateCipher(ctx, "valid-token", &CipherPayload{Type: CipherTypeLogin, Name: "2.n|c|m"})
	if err != nil || created.ID != "c-new" {
		t.Fatalf("CreateCipher = (%+v, %v)", created, err)
	}

	revTime := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cipherKey := "2.ck|ct|mac"
	updated, err := c.UpdateCipher(ctx, "valid-token", "c1", &CipherPayload{
		Type:                  CipherTypeLogin,
		Key:                   &cipherKey,
		Name:                  "2.updated|c|m",
		LastKnownRevisionDate: &revTime,
	})
	if err != nil || updated.Key == nil || *updated.Key != cipherKey {
		t.Fatalf("UpdateCipher = (%+v, %v)", updated, err)
	}

	if _, err := c.UpdateCipher(ctx, "valid-token", "c-conflict", &CipherPayload{}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("409 conflict got %v, want ErrRevisionConflict", err)
	}

	if err := c.SoftDeleteCipher(ctx, "valid-token", "c1"); err != nil {
		t.Fatalf("SoftDeleteCipher: %v", err)
	}
	if restored, err := c.RestoreCipher(ctx, "valid-token", "c1"); err != nil || restored.ID != "c1" {
		t.Fatalf("RestoreCipher = (%+v, %v)", restored, err)
	}
	if err := c.HardDeleteCipher(ctx, "valid-token", "c1"); err != nil {
		t.Fatalf("HardDeleteCipher: %v", err)
	}

	f, err := c.CreateFolder(ctx, "valid-token", "2.fn|c|m")
	if err != nil || f.ID != "f-new" {
		t.Fatalf("CreateFolder = (%+v, %v)", f, err)
	}
	if f2, err := c.UpdateFolder(ctx, "valid-token", "f-new", "2.fn2|c|m"); err != nil || f2.Name != "2.fn2|c|m" {
		t.Fatalf("UpdateFolder = (%+v, %v)", f2, err)
	}
	if err := c.DeleteFolder(ctx, "valid-token", "f-new"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
}

func TestEncryptedCipher_LosslessUnknownFieldRoundTrip(t *testing.T) {
	input := `{
		"id": "ssh-1",
		"type": 5,
		"folderId": null,
		"organizationId": null,
		"favorite": false,
		"reprompt": 0,
		"name": "2.iv|ct|mac",
		"notes": null,
		"archivedDate": "2026-11-20T12:00:00Z",
		"encryptedFor": "user-1",
		"encryptedByKeyId": "key-1",
		"data": {"v2": "opaque"},
		"sshKey": {"privateKey": "2.a|b|c", "publicKey": "2.d|e|f"},
		"futureField": {"nested": [1, 2, 3]}
	}`

	var cipher EncryptedCipher
	if err := json.Unmarshal([]byte(input), &cipher); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cipher.Type != CipherTypeSSHKey || cipher.ArchivedDate == nil || cipher.EncryptedFor == nil || cipher.EncryptedByKeyID == nil {
		t.Fatalf("missing typed fields: %+v", cipher)
	}

	out, err := json.Marshal(cipher)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var roundTripped map[string]any
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("Unmarshal roundTripped: %v", err)
	}
	if _, ok := roundTripped["sshKey"]; !ok {
		t.Errorf("lost non-MVP sshKey field")
	}
	if _, ok := roundTripped["futureField"]; !ok {
		t.Errorf("lost unknown futureField")
	}
	if _, ok := roundTripped["data"]; !ok {
		t.Errorf("lost v2 data field")
	}
}

const vaultwardenStaleWrite = `{"message":"The client copy of this cipher is out of date. Resync the client and try again.","validationErrors":{"":["The client copy of this cipher is out of date. Resync the client and try again."]},"errorModel":{"message":"The client copy of this cipher is out of date. Resync the client and try again.","object":"error"},"error":"","error_description":"","exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"}`

func TestClassifyVaultwardenErrors(t *testing.T) {
	if err := classifyError(400, []byte(vaultwardenStaleWrite)); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale write = %v, want ErrRevisionConflict", err)
	}
	missing := `{"message":"Cipher doesn't exist","validationErrors":{"":["Cipher doesn't exist"]},"errorModel":{"message":"Cipher doesn't exist","object":"error"},"error":"","error_description":"","exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"}`
	if err := classifyError(400, []byte(missing)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing cipher = %v, want ErrNotFound", err)
	}
	if err := classifyError(404, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 = %v, want ErrNotFound", err)
	}
	if err := classifyError(400, []byte(`{"message":"Invalid password"}`)); errors.Is(err, ErrNotFound) || errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("plain 400 = %v", err)
	}
}

func TestAPIRequestsNeverFollowRedirectsOffOrigin(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{ServerURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoginPassword(context.Background(), "a@b.com", "hash", nil); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("login = %v, want ErrRedirectRefused", err)
	}
	if _, err := c.RefreshToken(context.Background(), "refresh"); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("refresh = %v, want ErrRedirectRefused", err)
	}
	if _, _, err := c.Sync(context.Background(), "token"); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("sync = %v, want ErrRedirectRefused", err)
	}
	if leaked {
		t.Fatal("a credential-bearing request reached another origin")
	}
}

func TestInsecureServer(t *testing.T) {
	for u, want := range map[string]bool{
		"https://vault.example.com": false,
		"http://vault.example.com":  true,
		"http://192.168.1.10:8080":  true,
		"http://localhost:8080":     false,
		"http://127.0.0.1":          false,
		"http://[::1]:8000":         false,
	} {
		if got := InsecureServer(u); got != want {
			t.Errorf("InsecureServer(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestArchiveRequests(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization")+" body="+string(body))
		_, _ = w.Write([]byte(`{"id":"c 1","type":1,"name":"2.n|c|m","archivedDate":"2026-11-22T03:40:28.812Z"}`))
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{ServerURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.ArchiveCipher(context.Background(), "tok", "c 1")
	if err != nil || got.ArchivedDate == nil {
		t.Fatalf("archive = %+v, %v", got, err)
	}
	if _, err := c.UnarchiveCipher(context.Background(), "tok", "c 1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT /api/ciphers/c 1/archive auth=Bearer tok body=", "PUT /api/ciphers/c 1/unarchive auth=Bearer tok body="}
	if len(seen) != 2 || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("requests = %q, want %q", seen, want)
	}
}

func TestUpdatePayloadAlwaysCarriesArchivedDate(t *testing.T) {
	raw, _ := json.Marshal(CipherPayload{Name: "2.n|c|m"})
	if !strings.Contains(string(raw), `"archivedDate":null`) {
		t.Fatalf("payload = %s, want archivedDate present", raw)
	}
}

func TestClient_LoginAPIKey(t *testing.T) {
	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/connect/token" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("Content-Type = %q, want form-urlencoded", ct)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected Authorization header: %q", r.Header.Get("Authorization"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" ||
			r.FormValue("scope") != "api" ||
			r.FormValue("client_id") != "user.abc-123" ||
			r.FormValue("client_secret") != "secret-xyz" ||
			r.FormValue("deviceIdentifier") != "dev-1" ||
			r.FormValue("deviceName") != "macos" ||
			r.FormValue("deviceType") != "7" {
			t.Errorf("unexpected form values: %v", r.Form)
		}
		if r.FormValue("username") != "" || r.FormValue("password") != "" {
			t.Errorf("unexpected username/password fields in API key login: %v", r.Form)
		}

		switch mode {
		case "argon2id":
			_, _ = w.Write([]byte(`{"access_token":"tok-api","expires_in":3600,"token_type":"Bearer","Key":"2.iv|ct|mac","PrivateKey":"2.pk","Kdf":1,"KdfIterations":3,"KdfMemory":64,"KdfParallelism":4}`))
		case "pbkdf2-lowercase":
			_, _ = w.Write([]byte(`{"access_token":"tok-api","expires_in":3600,"token_type":"Bearer","Key":"2.iv|ct|mac","kdf":0,"kdfIterations":600000}`))
		case "no-kdf":
			_, _ = w.Write([]byte(`{"access_token":"tok-api","expires_in":3600,"token_type":"Bearer","Key":"2.iv|ct|mac"}`))
		case "incomplete-argon2":
			_, _ = w.Write([]byte(`{"access_token":"tok-api","expires_in":3600,"token_type":"Bearer","Key":"2.iv|ct|mac","Kdf":1,"KdfIterations":3}`))
		case "unauthorized":
			w.WriteHeader(http.StatusUnauthorized)
		case "bad-request":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Invalid client credentials"}`))
		}
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{
		ServerURL:  srv.URL,
		DeviceID:   "dev-1",
		DeviceName: "macos",
		DeviceType: 7,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()

	if _, err := c.LoginAPIKey(ctx, " ", "secret"); err == nil {
		t.Fatal("expected error for blank client_id")
	}
	if _, err := c.LoginAPIKey(ctx, "user.abc-123", ""); err == nil {
		t.Fatal("expected error for blank client_secret")
	}

	mode = "argon2id"
	tok, err := c.LoginAPIKey(ctx, " user.abc-123 ", " secret-xyz ")
	if err != nil {
		t.Fatalf("LoginAPIKey(argon2id): %v", err)
	}
	if tok.AccessToken != "tok-api" || tok.RefreshToken != "" || tok.Key != "2.iv|ct|mac" || tok.PrivateKey != "2.pk" {
		t.Fatalf("unexpected token response: %+v", tok)
	}
	kdf, ok := tok.KDFConfig()
	if !ok || kdf.Type != crypto.KDFArgon2id || kdf.Iterations != 3 || kdf.MemoryMB != 64 || kdf.Parallelism != 4 {
		t.Fatalf("KDFConfig(argon2id) = (%+v, %v)", kdf, ok)
	}

	mode = "pbkdf2-lowercase"
	tok, err = c.LoginAPIKey(ctx, "user.abc-123", "secret-xyz")
	if err != nil {
		t.Fatalf("LoginAPIKey(pbkdf2): %v", err)
	}
	kdf, ok = tok.KDFConfig()
	if !ok || kdf.Type != crypto.KDFPBKDF2 || kdf.Iterations != 600000 {
		t.Fatalf("KDFConfig(pbkdf2) = (%+v, %v)", kdf, ok)
	}

	for _, m := range []string{"no-kdf", "incomplete-argon2"} {
		mode = m
		tok, err = c.LoginAPIKey(ctx, "user.abc-123", "secret-xyz")
		if err != nil {
			t.Fatalf("LoginAPIKey(%s): %v", m, err)
		}
		if _, ok := tok.KDFConfig(); ok {
			t.Fatalf("KDFConfig(%s) = true, want false", m)
		}
	}

	mode = "unauthorized"
	if _, err := c.LoginAPIKey(ctx, "user.abc-123", "secret-xyz"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("401 = %v, want ErrUnauthorized", err)
	}

	mode = "bad-request"
	var apiErr *APIError
	if _, err := c.LoginAPIKey(ctx, "user.abc-123", "secret-xyz"); !errors.As(err, &apiErr) || apiErr.StatusCode != 400 {
		t.Fatalf("400 = %v, want *APIError(400)", err)
	}
}

func TestClient_LoginAPIKeyRefusesCrossOriginRedirect(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer other.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoginAPIKey(context.Background(), "user.1", "secret-1"); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("redirect = %v, want ErrRedirectRefused", err)
	}
	if leaked {
		t.Fatal("client_credentials request reached another origin")
	}
}
