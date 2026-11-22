package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

const defaultUserAgent = "GoVault/0.1"

type ClientConfig struct {
	ServerURL  string
	DeviceID   string
	DeviceName string
	DeviceType int
	HTTPClient *http.Client
}

type Client struct {
	baseURL    string
	httpClient *http.Client
	// apiHTTP sends every request to the server's API: login, two-factor,
	// token refresh and authenticated calls. It never follows a redirect
	// to another scheme, host or port, so credentials stay on the origin
	// the user signed in to.
	apiHTTP    *http.Client
	deviceID   string
	deviceName string
	deviceType int
	userAgent  string
}

func NewClient(cfg ClientConfig) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	if base == "" {
		return nil, errors.New("api: ServerURL is required")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("api: invalid ServerURL %q", cfg.ServerURL)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	apiHTTP := *httpClient
	inner := httpClient.CheckRedirect
	apiHTTP.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("api: too many redirects")
		}
		if !sameOrigin(next.URL, u) {
			return fmt.Errorf("%w to %s://%s", ErrRedirectRefused, next.URL.Scheme, next.URL.Host)
		}
		if inner != nil {
			return inner(next, via)
		}
		return nil
	}

	return &Client{
		baseURL:    base,
		httpClient: httpClient,
		apiHTTP:    &apiHTTP,
		deviceID:   cfg.DeviceID,
		deviceName: cfg.DeviceName,
		deviceType: cfg.DeviceType,
		userAgent:  defaultUserAgent,
	}, nil
}

func (c *Client) Prelogin(ctx context.Context, email string) (crypto.KDFConfig, error) {
	var cfg crypto.KDFConfig
	body, err := json.Marshal(struct {
		Email string `json:"email"`
	}{Email: crypto.NormalizeEmail(email)})
	if err != nil {
		return cfg, err
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/accounts/prelogin", "application/json", "", nil, body)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Client) LoginPassword(ctx context.Context, email, masterPasswordHash string, twoFactor *TwoFactorLogin) (*TokenResponse, error) {
	normEmail := crypto.NormalizeEmail(email)
	form := url.Values{
		"grant_type":       {"password"},
		"username":         {normEmail},
		"password":         {masterPasswordHash},
		"scope":            {"api offline_access"},
		"client_id":        {"desktop"},
		"deviceIdentifier": {c.deviceID},
		"deviceName":       {c.deviceName},
		"deviceType":       {strconv.Itoa(c.deviceType)},
	}
	if twoFactor != nil {
		form.Set("twoFactorProvider", strconv.Itoa(int(twoFactor.Provider)))
		form.Set("twoFactorToken", strings.Join(strings.Fields(twoFactor.Token), ""))
		if twoFactor.Remember {
			form.Set("twoFactorRemember", "1")
		} else {
			form.Set("twoFactorRemember", "0")
		}
	}
	headers := map[string]string{
		"Auth-Email": base64.RawURLEncoding.EncodeToString([]byte(normEmail)),
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", "", headers, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"desktop"},
	}

	raw, err := c.do(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", "", nil, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var resp TokenResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RevisionDate(ctx context.Context, accessToken string) (time.Time, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/accounts/revision-date", "", accessToken, nil, nil)
	if err != nil {
		return time.Time{}, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if ms, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), nil
	}

	var iso string
	if err := json.Unmarshal(raw, &iso); err != nil {
		return time.Time{}, fmt.Errorf("api: invalid revision-date %q: %w", trimmed, err)
	}
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func (c *Client) Sync(ctx context.Context, accessToken string) (*SyncResponse, []byte, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/sync?excludeDomains=true", "", accessToken, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	var resp SyncResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, nil, err
	}
	return &resp, raw, nil
}

func (c *Client) CreateCipher(ctx context.Context, accessToken string, payload *CipherPayload) (*EncryptedCipher, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/ciphers", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) UpdateCipher(ctx context.Context, accessToken, cipherID string, payload *CipherPayload) (*EncryptedCipher, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID), "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) SoftDeleteCipher(ctx context.Context, accessToken, cipherID string) error {
	_, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/delete", "", accessToken, nil, nil)
	return err
}

func (c *Client) RestoreCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/restore", "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

// ArchiveCipher moves a cipher to the user's Archive
// (PUT /api/ciphers/{id}/archive, Vaultwarden 1.36 or later) and returns it.
func (c *Client) ArchiveCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	return c.putCipherAction(ctx, accessToken, cipherID, "archive")
}

// UnarchiveCipher moves a cipher out of the user's Archive
// (PUT /api/ciphers/{id}/unarchive) and returns it.
func (c *Client) UnarchiveCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	return c.putCipherAction(ctx, accessToken, cipherID, "unarchive")
}

func (c *Client) putCipherAction(ctx context.Context, accessToken, cipherID, action string) (*EncryptedCipher, error) {
	raw, err := c.do(ctx, http.MethodPut, "/api/ciphers/"+url.PathEscape(cipherID)+"/"+action, "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func (c *Client) HardDeleteCipher(ctx context.Context, accessToken, cipherID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/ciphers/"+url.PathEscape(cipherID), "", accessToken, nil, nil)
	return err
}

func (c *Client) bulkCiphers(ctx context.Context, method, path, accessToken string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, method, path, "application/json", accessToken, nil, body)
	return err
}

func nonNilIDs(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

// BulkSoftDeleteCiphers moves ciphers to Trash on the server.
func (c *Client) BulkSoftDeleteCiphers(ctx context.Context, accessToken string, ids []string) error {
	return c.bulkCiphers(ctx, http.MethodPut, "/api/ciphers/delete", accessToken, struct {
		IDs []string `json:"ids"`
	}{IDs: nonNilIDs(ids)})
}

// BulkMoveCiphers moves ciphers to folderID (or removes them from any folder when folderID is nil).
func (c *Client) BulkMoveCiphers(ctx context.Context, accessToken string, ids []string, folderID *string) error {
	if folderID != nil && *folderID == "" {
		folderID = nil
	}
	return c.bulkCiphers(ctx, http.MethodPut, "/api/ciphers/move", accessToken, struct {
		IDs      []string `json:"ids"`
		FolderID *string  `json:"folderId"`
	}{IDs: nonNilIDs(ids), FolderID: folderID})
}

// BulkRestoreCiphers restores trashed ciphers on the server.
func (c *Client) BulkRestoreCiphers(ctx context.Context, accessToken string, ids []string) error {
	return c.bulkCiphers(ctx, http.MethodPut, "/api/ciphers/restore", accessToken, struct {
		IDs []string `json:"ids"`
	}{IDs: nonNilIDs(ids)})
}

// BulkHardDeleteCiphers permanently deletes ciphers on the server.
func (c *Client) BulkHardDeleteCiphers(ctx context.Context, accessToken string, ids []string) error {
	return c.bulkCiphers(ctx, http.MethodDelete, "/api/ciphers/delete", accessToken, struct {
		IDs []string `json:"ids"`
	}{IDs: nonNilIDs(ids)})
}

func (c *Client) CreateFolder(ctx context.Context, accessToken, encryptedName string) (*EncryptedFolder, error) {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: encryptedName})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/folders", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var folder EncryptedFolder
	if err := json.Unmarshal(raw, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

func (c *Client) UpdateFolder(ctx context.Context, accessToken, folderID, encryptedName string) (*EncryptedFolder, error) {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: encryptedName})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPut, "/api/folders/"+url.PathEscape(folderID), "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var folder EncryptedFolder
	if err := json.Unmarshal(raw, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

func (c *Client) DeleteFolder(ctx context.Context, accessToken, folderID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/folders/"+url.PathEscape(folderID), "", accessToken, nil, nil)
	return err
}

func DoWithRefresh[T any](
	ctx context.Context,
	accessToken string,
	refresh func(context.Context) (string, error),
	fn func(token string) (T, error),
) (T, error) {
	res, err := fn(accessToken)
	if err == nil || !errors.Is(err, ErrUnauthorized) || refresh == nil {
		return res, err
	}
	newToken, refreshErr := refresh(ctx)
	if refreshErr != nil {
		var zero T
		return zero, refreshErr
	}
	return fn(newToken)
}

func (c *Client) do(
	ctx context.Context,
	method, path, contentType, accessToken string,
	headers map[string]string,
	body []byte,
) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.apiHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, ErrRedirectRefused) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrNetworkOffline, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	return nil, classifyError(resp.StatusCode, raw)
}

func classifyError(status int, body []byte) error {
	if status == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if status == http.StatusConflict {
		return ErrRevisionConflict
	}
	if status == http.StatusNotFound {
		return ErrNotFound
	}

	if status == http.StatusBadRequest {
		if tfErr, ok := parseTwoFactorChallenge(body); ok {
			return tfErr
		}
	}

	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
		ErrorModel       *struct {
			Message string `json:"message"`
		} `json:"errorModel"`
	}
	_ = json.Unmarshal(body, &parsed)

	msg := parsed.Message
	if msg == "" && parsed.ErrorModel != nil {
		msg = parsed.ErrorModel.Message
	}
	if msg == "" {
		msg = parsed.ErrorDescription
	}
	if msg == "" {
		msg = parsed.Error
	}

	// Vaultwarden answers a stale write and a missing cipher with HTTP 400
	// (src/api/core/ciphers.rs): "The client copy of this cipher is out of
	// date. Resync the client and try again." and "Cipher doesn't exist".
	if status == http.StatusBadRequest {
		switch lower := strings.ToLower(msg); {
		case strings.Contains(lower, "out of date"), strings.Contains(lower, "revision"):
			return ErrRevisionConflict
		case strings.Contains(lower, "doesn't exist"), strings.Contains(lower, "does not exist"):
			return &notFoundError{APIError{StatusCode: status, Message: msg, Body: string(body)}}
		}
	}

	return &APIError{
		StatusCode: status,
		Message:    msg,
		Body:       string(body),
	}
}

const (
	// MaxAttachmentSize limits attachment plaintext.
	MaxAttachmentSize = 100 << 20
	// MaxAttachmentWireSize limits encrypted attachment data: the plaintext
	// limit plus the EncArrayBuffer header and one block of padding.
	MaxAttachmentWireSize = MaxAttachmentSize + 1 + 16 + 32 + 16
)

var ErrAttachmentTooLarge = errors.New("api: attachment exceeds the 100 MiB limit")

func (c *Client) GetCipher(ctx context.Context, accessToken, cipherID string) (*EncryptedCipher, error) {
	raw, err := c.do(ctx, http.MethodGet, "/api/ciphers/"+url.PathEscape(cipherID), "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var cipher EncryptedCipher
	if err := json.Unmarshal(raw, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

func attachmentPath(cipherID, attachmentID string) string {
	return "/api/ciphers/" + url.PathEscape(cipherID) + "/attachment/" + url.PathEscape(attachmentID)
}

func (c *Client) GetAttachment(ctx context.Context, accessToken, cipherID, attachmentID string) (*EncryptedAttachment, error) {
	raw, err := c.do(ctx, http.MethodGet, attachmentPath(cipherID, attachmentID), "", accessToken, nil, nil)
	if err != nil {
		return nil, err
	}
	var att EncryptedAttachment
	if err := json.Unmarshal(raw, &att); err != nil {
		return nil, err
	}
	return &att, nil
}

// DownloadAttachmentBytes fetches encrypted attachment data. The access token
// is only sent to the origin of the server, and it is stripped from every
// redirect hop that leaves that origin.
func (c *Client) DownloadAttachmentBytes(ctx context.Context, accessToken, downloadURL string) ([]byte, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, err
	}
	target, err := base.Parse(downloadURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return nil, fmt.Errorf("api: invalid attachment URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	if accessToken != "" && sameOrigin(target, base) {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	hc := *c.httpClient
	inner := c.httpClient.CheckRedirect
	hc.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("api: too many redirects")
		}
		if next.URL.Scheme != "http" && next.URL.Scheme != "https" {
			return errors.New("api: invalid attachment redirect")
		}
		if !sameOrigin(next.URL, base) {
			next.Header.Del("Authorization")
		}
		if inner != nil {
			return inner(next, via)
		}
		return nil
	}

	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", ErrNetworkOffline, err)
	}
	defer resp.Body.Close()
	if resp.ContentLength > MaxAttachmentWireSize {
		return nil, ErrAttachmentTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxAttachmentWireSize+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, classifyError(resp.StatusCode, raw)
	}
	if len(raw) > MaxAttachmentWireSize {
		return nil, ErrAttachmentTooLarge
	}
	return raw, nil
}

// sameOrigin compares scheme, host and port, with default ports made explicit.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && originPort(a) == originPort(b)
}

func originPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func (c *Client) CreateAttachmentV2(ctx context.Context, accessToken, cipherID string, req AttachmentUploadRequest) (*AttachmentUploadResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/api/ciphers/"+url.PathEscape(cipherID)+"/attachment/v2", "application/json", accessToken, nil, body)
	if err != nil {
		return nil, err
	}
	var resp AttachmentUploadResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) UploadAttachmentData(ctx context.Context, accessToken, cipherID, attachmentID, fileName string, encryptedData []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("data", fileName)
	if err != nil {
		return err
	}
	if _, err := part.Write(encryptedData); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, attachmentPath(cipherID, attachmentID), w.FormDataContentType(), accessToken, nil, buf.Bytes())
	return err
}

func (c *Client) DeleteAttachment(ctx context.Context, accessToken, cipherID, attachmentID string) error {
	_, err := c.do(ctx, http.MethodDelete, attachmentPath(cipherID, attachmentID), "", accessToken, nil, nil)
	return err
}

// InsecureServer reports that serverURL is plain HTTP to a host other than
// this machine, so passwords and vault data cross the network unencrypted.
func InsecureServer(serverURL string) bool {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}
