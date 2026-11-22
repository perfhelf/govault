package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/nsgotest"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type mockVaultService struct {
	mu       sync.RWMutex
	status   state.LockStatus
	password string
	ciphers  map[string]*state.Cipher
	order    []string
	folders  []state.Folder

	twoFactorCode string
	emailSends    int

	organizations []state.Organization
	collections   []state.Collection

	downloadGate chan struct{}

	// localCopyFails makes saves succeed on the "server" but report a
	// failed local copy, as state.Service does when the snapshot write fails.
	localCopyFails bool
	creates        int

	syncErrs  []error
	syncCalls int

	unreadable []string
	noPremium  bool
	// session names the mock's current session; archiveSessions records
	// the session each archive request was bound to.
	session            int
	archiveSessions    []any
	uploads            int
	attempt            uint64
	revokes            int
	localOnly          bool
	credsUnsaved       bool
	lastLogin          state.LoginRequest
	apiClientID        string
	apiClientSecret    string
	lastAPIKeyLogin    state.LoginAPIKeyRequest
	apiKeyLoginStarted chan struct{}
	apiKeyLoginGate    chan struct{}
	// trustedServer is the server the trusted sign-in record names.
	trustedServer string
	// emailGate, when set, holds SendEmailTwoFactorCode until closed.
	emailGate chan struct{}
	// unlockCommitted, when set, holds UnlockWithPassword after it commits
	// until the test answers.
	unlockCommitted chan struct{}
	// saveGate, when set, holds SaveCipher until it is closed.
	saveGate chan struct{}
	// batchGate, when set, holds Bulk* operations until it is closed.
	batchGate chan struct{}
	bulkErr   error
	bulkCalls []string
}

func newMockVaultService(initial state.LockStatus) *mockVaultService {
	c1 := &state.Cipher{
		ID:       "c-github",
		Type:     api.CipherTypeLogin,
		Name:     "GitHub",
		Favorite: true,
		Login: &state.Login{
			Username: "alice@example.com",
			Password: "gh-secret-password",
			TOTP:     "JBSWY3DPEHPK3PXP",
			URIs:     []state.LoginURI{{URI: "https://github.com"}},
		},
	}
	c2 := &state.Cipher{
		ID:         "c-note",
		Type:       api.CipherTypeSecureNote,
		Name:       "SSH Recovery Note",
		Notes:      "Keep safe",
		SecureNote: &state.SecureNote{Type: 0},
	}
	return &mockVaultService{
		status:          initial,
		password:        "master-password",
		apiClientID:     "user.api-client-id",
		apiClientSecret: "api-client-secret",
		ciphers: map[string]*state.Cipher{
			c1.ID: c1,
			c2.ID: c2,
		},
		order: []string{c1.ID, c2.ID},
		folders: []state.Folder{
			{ID: "f-work", Name: "Work"},
		},
	}
}

func (m *mockVaultService) Status() state.LockStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *mockVaultService) Login(_ context.Context, req state.LoginRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLogin = req
	if string(req.MasterPassword) != m.password {
		return api.ErrUnauthorized
	}
	if m.twoFactorCode != "" && (req.TwoFactorProvider != api.TwoFactorEmail || req.TwoFactorCode != m.twoFactorCode) {
		if req.TwoFactorCode != "" {
			return &api.APIError{StatusCode: 400, Message: "Invalid TOTP code"}
		}
		return &api.TwoFactorRequiredError{Challenge: api.TwoFactorChallenge{
			Providers:    []api.TwoFactorProvider{api.TwoFactorAuthenticator, api.TwoFactorEmail},
			ProviderData: map[api.TwoFactorProvider]json.RawMessage{api.TwoFactorEmail: json.RawMessage(`{"Email":"a***@example.com"}`)},
		}}
	}
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) LoginWithAPIKey(_ context.Context, req state.LoginAPIKeyRequest) error {
	m.mu.RLock()
	started, gate := m.apiKeyLoginStarted, m.apiKeyLoginGate
	m.mu.RUnlock()
	if started != nil {
		close(started)
	}
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := req
	cp.MasterPassword = slices.Clone(req.MasterPassword)
	m.lastAPIKeyLogin = cp
	if req.ClientID != m.apiClientID || req.ClientSecret != m.apiClientSecret {
		return api.ErrUnauthorized
	}
	if string(req.MasterPassword) != m.password {
		return crypto.ErrInvalidMAC
	}
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) SendEmailTwoFactorCode(_ context.Context, req state.LoginRequest) error {
	m.mu.RLock()
	gate := m.emailGate
	m.mu.RUnlock()
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if string(req.MasterPassword) != m.password {
		return api.ErrUnauthorized
	}
	m.emailSends++
	return nil
}

func (m *mockVaultService) UnlockWithPassword(_ context.Context, pw []byte) error {
	m.mu.Lock()
	if string(pw) != m.password {
		m.mu.Unlock()
		return crypto.ErrInvalidMAC
	}
	m.status = state.StatusUnlocked
	committed := m.unlockCommitted
	m.mu.Unlock()
	if committed != nil {
		// The service has committed the session; the UI has not heard yet.
		committed <- struct{}{}
		<-committed
	}
	return nil
}

func (m *mockVaultService) UnlockWithUserKey(_ context.Context, _ *crypto.SymmetricKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = state.StatusUnlocked
	return nil
}

func (m *mockVaultService) EnableBiometricUnlock(_ store.SecretStore) error  { return nil }
func (m *mockVaultService) DisableBiometricUnlock(_ store.SecretStore) error { return nil }

func (m *mockVaultService) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status == state.StatusUnlocked {
		m.status = state.StatusLocked
	}
}

func (m *mockVaultService) Logout(_ context.Context, _ store.SecretStore) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = state.StatusLoggedOut
	return nil
}

func (m *mockVaultService) SyncNow(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncCalls++
	if len(m.syncErrs) == 0 {
		return nil
	}
	err := m.syncErrs[0]
	m.syncErrs = m.syncErrs[1:]
	return err
}

func (m *mockVaultService) Search(query string, filter state.SearchFilter) []state.CipherSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	var out []state.CipherSummary
	for _, id := range m.order {
		c := m.ciphers[id]
		if c == nil {
			continue
		}
		deleted := c.DeletedDate != nil
		if filter.Category == state.FilterTrash {
			if !deleted {
				continue
			}
		} else if deleted {
			continue
		} else if (filter.Category == state.FilterArchive) != (c.ArchivedDate != nil) {
			continue
		}
		if filter.Category == state.FilterFavorites && !c.Favorite {
			continue
		}
		if filter.Type != nil && c.Type != *filter.Type {
			continue
		}
		if filter.OrganizationID != "" && (c.OrganizationID == nil || *c.OrganizationID != filter.OrganizationID) {
			continue
		}
		if filter.CollectionID != "" && !slices.Contains(c.CollectionIDs, filter.CollectionID) {
			continue
		}
		if filter.FolderID != "" {
			if c.FolderID == nil || *c.FolderID != filter.FolderID {
				continue
			}
		} else if filter.Category == state.FilterNoFolder && (c.FolderID != nil && *c.FolderID != "") {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
			continue
		}
		sub := ""
		hasTOTP := false
		if c.Login != nil {
			sub = c.Login.Username
			hasTOTP = strings.TrimSpace(c.Login.TOTP) != ""
		}
		out = append(out, state.CipherSummary{
			ID:       c.ID,
			Type:     c.Type,
			FolderID: c.FolderID,
			Favorite: c.Favorite,
			Deleted:  deleted,
			Archived: c.ArchivedDate != nil,
			Name:     c.Name,
			Subtitle: sub,
			HasTOTP:  hasTOTP,
			Reprompt: c.Reprompt,
			URIs:     loginURIs(c),

			OrganizationID: c.OrganizationID,
			CollectionIDs:  c.CollectionIDs,
			ReadOnly:       m.isReadOnlyLocked(c),
		})
	}
	return out
}

func (m *mockVaultService) GetCipher(id string) (*state.Cipher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	c, ok := m.ciphers[id]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *mockVaultService) SaveCipher(_ context.Context, c *state.Cipher) (*state.Cipher, error) {
	m.mu.RLock()
	gate := m.saveGate
	m.mu.RUnlock()
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	cp := *c
	if cp.ID == "" {
		cp.ID = "c-new"
		for i := 2; m.ciphers[cp.ID] != nil; i++ {
			cp.ID = fmt.Sprintf("c-new-%d", i)
		}
		m.order = append(m.order, cp.ID)
		m.creates++
	}
	m.ciphers[cp.ID] = &cp
	if m.localCopyFails {
		out := cp
		return &out, &state.LocalCopyError{Cipher: &out, Err: errors.New("disk full")}
	}
	return &cp, nil
}

func (m *mockVaultService) SoftDeleteCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	now := time.Now()
	c.DeletedDate = &now
	return nil
}

func (m *mockVaultService) RestoreCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	c.DeletedDate = nil
	return nil
}

func (m *mockVaultService) HardDeleteCipher(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ciphers, id)
	return nil
}

func (m *mockVaultService) isReadOnlyLocked(c *state.Cipher) bool {
	if c.ReadOnly {
		return true
	}
	if len(c.CollectionIDs) == 0 || len(m.collections) == 0 {
		return false
	}
	known := 0
	for _, id := range c.CollectionIDs {
		idx := slices.IndexFunc(m.collections, func(col state.Collection) bool { return col.ID == id })
		if idx < 0 {
			continue
		}
		if !m.collections[idx].ReadOnly {
			return false
		}
		known++
	}
	return known > 0
}

func (m *mockVaultService) prepareMockBulk(ctx context.Context, op string, ids []string) ([]string, error) {
	m.mu.RLock()
	gate := m.batchGate
	m.mu.RUnlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != state.StatusUnlocked {
		return nil, state.ErrLocked
	}
	if m.localOnly {
		return nil, state.ErrSignInRequired
	}
	if m.bulkErr != nil {
		return nil, m.bulkErr
	}
	seen := make(map[string]bool, len(ids))
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		c, ok := m.ciphers[id]
		if !ok {
			return nil, state.ErrCipherNotFound
		}
		if m.isReadOnlyLocked(c) {
			return nil, state.ErrReadOnlyCipher
		}
		unique = append(unique, id)
	}
	m.bulkCalls = append(m.bulkCalls, fmt.Sprintf("%s:%s", op, strings.Join(unique, ",")))
	return unique, nil
}

func (m *mockVaultService) BulkSoftDelete(ctx context.Context, ids []string) error {
	unique, err := m.prepareMockBulk(ctx, "soft-delete", ids)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, id := range unique {
		ts := now
		m.ciphers[id].DeletedDate = &ts
	}
	if m.localCopyFails {
		return &state.LocalCopyError{Err: errors.New("disk full")}
	}
	return nil
}

func (m *mockVaultService) BulkMoveFolder(ctx context.Context, ids []string, folderID *string) error {
	unique, err := m.prepareMockBulk(ctx, "move", ids)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var target *string
	if folderID != nil && *folderID != "" {
		v := *folderID
		target = &v
	}
	for _, id := range unique {
		if target == nil {
			m.ciphers[id].FolderID = nil
		} else {
			v := *target
			m.ciphers[id].FolderID = &v
		}
	}
	if m.localCopyFails {
		return &state.LocalCopyError{Err: errors.New("disk full")}
	}
	return nil
}

func (m *mockVaultService) BulkRestore(ctx context.Context, ids []string, targetFolderID *string) error {
	tag := "restore"
	if targetFolderID != nil {
		tag = "restore:" + *targetFolderID
	}
	unique, err := m.prepareMockBulk(ctx, tag, ids)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range unique {
		m.ciphers[id].DeletedDate = nil
		if targetFolderID != nil {
			if *targetFolderID == "" {
				m.ciphers[id].FolderID = nil
			} else {
				v := *targetFolderID
				m.ciphers[id].FolderID = &v
			}
		}
	}
	if m.localCopyFails {
		return &state.LocalCopyError{Err: errors.New("disk full")}
	}
	return nil
}

func (m *mockVaultService) BulkHardDelete(ctx context.Context, ids []string) error {
	unique, err := m.prepareMockBulk(ctx, "hard-delete", ids)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range unique {
		delete(m.ciphers, id)
	}
	if m.localCopyFails {
		return &state.LocalCopyError{Err: errors.New("disk full")}
	}
	return nil
}

func (m *mockVaultService) Account() state.Account {
	return state.Account{ID: "acct-1", Email: "alice@example.com"}
}

func (m *mockVaultService) TrustedServerURL(string) string { return m.trustedServer }

func (m *mockVaultService) AuthAttempt() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attempt
}

func (m *mockVaultService) RevokeAuthAttempts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempt++
	m.revokes++
	if m.status == state.StatusUnlocked {
		m.status = state.StatusLocked
	}
}

func (m *mockVaultService) LocalOnly() bool { return m.localOnly }

func (m *mockVaultService) CredentialsNotSaved() bool { return m.credsUnsaved }

func (m *mockVaultService) BackupData() state.BackupData {
	return state.BackupData{Ciphers: m.AllCiphers(), Folders: m.Folders(), Unreadable: m.unreadable}
}

func (m *mockVaultService) UnreadableItems() []string { return m.unreadable }

type mockSessionKey struct{}

func (m *mockVaultService) SessionContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	m.mu.RLock()
	session := m.session
	m.mu.RUnlock()
	ctx, cancel := context.WithCancel(context.WithValue(parent, mockSessionKey{}, session))
	return ctx, cancel, nil
}

func (m *mockVaultService) CanArchive() bool { return !m.noPremium }

func (m *mockVaultService) ArchiveCipher(ctx context.Context, id string) error {
	m.mu.Lock()
	m.archiveSessions = append(m.archiveSessions, ctx.Value(mockSessionKey{}))
	m.mu.Unlock()
	return m.setArchived(id, true)
}

func (m *mockVaultService) UnarchiveCipher(_ context.Context, id string) error {
	return m.setArchived(id, false)
}

func (m *mockVaultService) setArchived(id string, archive bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[id]
	if !ok {
		return state.ErrCipherNotFound
	}
	if archive && m.noPremium {
		return state.ErrPremiumRequired
	}
	if archive {
		now := time.Now()
		c.ArchivedDate = &now
	} else {
		c.ArchivedDate = nil
	}
	return nil
}

func (m *mockVaultService) TrashSelection() state.TrashSelection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var sel state.TrashSelection
	for id, c := range m.ciphers {
		switch {
		case c.DeletedDate == nil:
		case c.ReadOnly:
			sel.ReadOnly++
		default:
			sel.Items = append(sel.Items, state.TrashItem{ID: id, RevisionDate: c.RevisionDate})
		}
	}
	return sel
}

func (m *mockVaultService) EmptyTrash(_ context.Context, sel state.TrashSelection) (state.TrashResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := state.TrashResult{ReadOnly: sel.ReadOnly}
	for _, it := range sel.Items {
		if c, ok := m.ciphers[it.ID]; !ok || c.DeletedDate == nil {
			res.Skipped++
			continue
		}
		delete(m.ciphers, it.ID)
		res.Deleted++
	}
	return res, nil
}

func (m *mockVaultService) Folders() []state.Folder {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Folder(nil), m.folders...)
}

func (m *mockVaultService) SaveFolder(_ context.Context, f *state.Folder) (*state.Folder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.ID == "" {
		f.ID = "f-new"
		m.folders = append(m.folders, *f)
	}
	return f, nil
}

func (m *mockVaultService) Organizations() []state.Organization {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Organization(nil), m.organizations...)
}

func (m *mockVaultService) Collections() []state.Collection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]state.Collection(nil), m.collections...)
}

func (m *mockVaultService) DeleteFolder(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, f := range m.folders {
		if f.ID == id {
			m.folders = append(m.folders[:i], m.folders[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

func TestCoreStateTransitions(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	app.Find("id:login-screen")
	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)

	app.Type("id:vault-search", "GitHub")
	app.Find("id:vault-item-list >> text:GitHub")
	app.Press("id:vault-row")
	app.Find("id:detail-view")
	app.Find("id:detail-view >> text:alice@example.com")

	app.Press("id:detail-edit")
	app.Find("id:editor-pane")
	app.Clear("id:editor-name")
	app.Type("id:editor-name", "GitHub Enterprise")
	app.Press("id:editor-save")
	app.WaitFor("id:detail-view", 2*time.Second)
	app.Find("id:detail-title")
	app.Find("id:detail-view >> text:GitHub Enterprise")

	app.Press("id:toolbar-lock")
	app.WaitFor("id:lock-screen", 2*time.Second)

	app.Type("id:lock-password", "master-password")
	app.Press("id:lock-submit")
	app.WaitFor("id:vault-shell", 2*time.Second)
}

func TestLoginTwoFactorEmailVerify(t *testing.T) {
	svc := newMockVaultService(state.StatusLoggedOut)
	svc.twoFactorCode = "654321"
	var releases []bool

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model := NewAppModel(cx, svc, PlatformHooks{ReleaseSecureInput: func(force bool) { releases = append(releases, force) }})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 720))

	app.Type("id:login-server", "https://vault.example.com")
	app.Type("id:login-email", "alice@example.com")
	app.Type("id:login-password", "master-password")
	app.Press("id:login-submit")
	app.WaitFor("id:twofactor-screen", 2*time.Second)

	app.Press("id:twofactor-provider-email")
	app.Press("id:twofactor-send-email")
	app.WaitFor("text:A verification code was sent to a***@example.com.", 2*time.Second)

	app.Type("id:twofactor-code", "111111")
	app.Press("id:twofactor-verify")
	app.WaitFor("id:twofactor-error", 2*time.Second)

	app.Type("id:twofactor-code", "654 321")
	app.Press("id:twofactor-remember")
	app.Press("id:twofactor-verify")
	app.WaitFor("id:vault-shell", 2*time.Second)

	svc.mu.RLock()
	sends := svc.emailSends
	svc.mu.RUnlock()
	if sends != 1 {
		t.Fatalf("email sends = %d, want 1", sends)
	}
	if len(releases) == 0 || !releases[len(releases)-1] {
		t.Fatalf("secure input not force-released after login: %v", releases)
	}
}

func TestTOTPTickerVisibilityGating(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	if model.TOTPTickerActive() {
		t.Fatal("expected TOTP ticker stopped before selecting a TOTP item")
	}

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-github")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive() && model.TOTPCode.Get() != ""
	})

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-note")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})

	app.Post(func() {
		model.SelectCipher(model.Scope, "c-github")
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive()
	})

	app.Post(func() {
		model.MainWinVisible.Set(false)
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})

	app.Post(func() {
		model.MainWinVisible.Set(true)
	})
	app.WaitUntil(2*time.Second, func() bool {
		return model.TOTPTickerActive()
	})

	app.Post(func() {
		model.Lock()
	})
	app.WaitUntil(2*time.Second, func() bool {
		return !model.TOTPTickerActive()
	})
}

func TestTrayIconOffKeepsDockReachable(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	var trayCalls, dockCalls []bool

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{
			SetTrayVisible: func(on bool) { trayCalls = append(trayCalls, on) },
			SetDockVisible: func(on bool) { dockCalls = append(dockCalls, on) },
		})
		model.MainWinVisible.Set(true)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	if !model.Prefs.Get().ShowTrayIcon {
		t.Fatal("expected the tray icon to be shown by default")
	}

	app.Post(func() {
		model.UpdatePrefs(func(p UserPrefs) UserPrefs { p.HideDockIcon = true; return p })
		model.SetShowTrayIcon(false)
	})
	app.Settle()

	p := model.Prefs.Get()
	if p.ShowTrayIcon || p.HideDockIcon {
		t.Fatalf("expected tray off and Dock shown, got ShowTrayIcon=%v HideDockIcon=%v", p.ShowTrayIcon, p.HideDockIcon)
	}
	if len(trayCalls) != 1 || trayCalls[0] || len(dockCalls) != 1 || !dockCalls[0] {
		t.Fatalf("expected tray hidden and Dock shown, got tray=%v dock=%v", trayCalls, dockCalls)
	}
	if raw, ok := app.Storage().GetItem("govault.prefs"); !ok || !strings.Contains(raw, `"showTrayIcon":false`) {
		t.Fatalf("expected showTrayIcon persisted, got ok=%v raw=%q", ok, raw)
	}
}

func TestSearchStaysInSectionUntilWidened(t *testing.T) {
	svc := newMockVaultService(state.StatusUnlocked)
	svc.ciphers["c-github"].FolderID = ptr("f-work")
	var model *AppModel

	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(1100, 640))

	noteType := api.CipherTypeSecureNote
	app.Post(func() { model.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll, Type: &noteType}) })
	app.Type("id:vault-search", "GitHub")
	app.Settle()
	if n := model.FilteredItems.Len(); n != 0 || model.SearchIsGlobal() {
		t.Fatalf("search left Secure Notes by default: %d items, global=%v", n, model.SearchIsGlobal())
	}
	app.Find("id:search-scope >> text:In Secure Notes")
	app.Find("id:search-empty-all")

	app.Press("id:search-scope-all")
	app.WaitUntil(2*time.Second, func() bool {
		return model.FilteredItems.Len() == 1 && model.FilteredItems.KeyAt(0) == "c-github"
	})
	app.Find("id:search-scope >> text:In All Items")

	app.Press("id:search-scope-section")
	app.WaitUntil(2*time.Second, func() bool { return model.FilteredItems.Len() == 0 })

	app.Post(func() { model.SetSidebarFilter(state.SearchFilter{FolderID: "f-work"}) })
	app.WaitUntil(2*time.Second, func() bool {
		return model.FilteredItems.Len() == 1 && !model.SearchIsGlobal()
	})
	app.Find("id:search-scope >> text:In Work")
}

func ptr[T any](v T) *T { return &v }

func TestLockOnSleepPreferenceAndSystemEvent(t *testing.T) {
	var legacy UserPrefs
	if err := json.Unmarshal([]byte(`{"autoLockMinutes":5}`), &legacy); err != nil || !legacy.LockOnSleep {
		t.Fatalf("legacy prefs LockOnSleep = %v (err %v), want true", legacy.LockOnSleep, err)
	}

	svc := newMockVaultService(state.StatusUnlocked)
	var model *AppModel
	var releases []bool
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model = NewAppModel(cx, svc, PlatformHooks{
			SleepLockSupported: true,
			ReleaseSecureInput: func(force bool) { releases = append(releases, force) },
		})
		model.MainWinVisible.Set(true)
		model.Route.Set(RouteSettings)
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 720))

	app.Press("id:settings-lock-on-sleep")
	app.WaitUntil(time.Second, func() bool { return !model.Prefs.Get().LockOnSleep })

	systemLock := func() bool {
		done, result := false, false
		app.Post(func() { result, done = model.LockOnSystemEvent(), true })
		app.WaitUntil(time.Second, func() bool { return done })
		return result
	}
	if systemLock() || svc.Status() != state.StatusUnlocked {
		t.Fatal("system event locked the vault with LockOnSleep off")
	}

	app.Press("id:settings-lock-on-sleep")
	app.WaitUntil(time.Second, func() bool { return model.Prefs.Get().LockOnSleep })

	releases = nil
	if !systemLock() {
		t.Fatal("system event did not lock the unlocked vault")
	}
	app.WaitFor("id:lock-screen", 2*time.Second)
	if svc.Status() != state.StatusLocked || model.TOTPTickerActive() || len(releases) == 0 || !releases[len(releases)-1] {
		t.Fatalf("after lock: status=%v ticker=%v releases=%v", svc.Status(), model.TOTPTickerActive(), releases)
	}
	if systemLock() {
		t.Fatal("system event re-locked an already locked vault")
	}
}

func loginURIs(c *state.Cipher) []string {
	if c.Login == nil {
		return nil
	}
	out := make([]string, 0, len(c.Login.URIs))
	for _, u := range c.Login.URIs {
		out = append(out, u.URI)
	}
	return out
}

func TestSidebarCollectionsFilterItems(t *testing.T) {
	personal := newMockVaultService(state.StatusUnlocked)
	app := nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model := NewAppModel(cx, personal, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))
	app.WaitFor("id:vault-item-list >> text:GitHub", 2*time.Second)
	if app.Exists("id:sidebar-collections-toggle") {
		t.Fatal("personal-only vault shows a Collections section")
	}

	svc := newMockVaultService(state.StatusUnlocked)
	org := "org-1"
	svc.organizations = []state.Organization{{ID: org, Name: "Acme", Enabled: true}}
	svc.collections = []state.Collection{{ID: "col-eng", OrganizationID: org, Name: "Engineering", ReadOnly: true}}
	svc.ciphers["c-github"].OrganizationID = &org
	svc.ciphers["c-github"].CollectionIDs = []string{"col-eng"}

	app = nsgotest.Start(t, func(cx *core.Scope) core.Node {
		model := NewAppModel(cx, svc, PlatformHooks{})
		model.MainWinVisible.Set(true)
		model.RefreshVaultData()
		return MainWindowView(cx, model)
	}, nsgotest.Size(980, 640))

	app.WaitFor("id:sidebar-collections >> text:Engineering", 2*time.Second)
	app.Press("id:sidebar-collection")
	app.WaitForGone("id:vault-item-list >> text:SSH Recovery Note", 2*time.Second)
	app.Find("id:vault-item-list >> text:GitHub")

	app.Press("id:vault-row")
	app.WaitFor("id:detail-view >> text:Acme", 2*time.Second)
	app.Find("id:detail-view >> text:View only")
}

func (m *mockVaultService) DownloadAttachment(_ context.Context, cipherID, attachmentID string) ([]byte, string, error) {
	if m.downloadGate != nil {
		<-m.downloadGate
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, "", state.ErrCipherNotFound
	}
	for _, a := range c.Attachments {
		if a.ID == attachmentID {
			return []byte("contents of " + a.FileName), a.FileName, nil
		}
	}
	return nil, "", state.ErrAttachmentNotFound
}

func (m *mockVaultService) UploadAttachment(_ context.Context, cipherID, fileName string, plain []byte) (*state.Cipher, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	c.Attachments = append(slices.Clone(c.Attachments), state.Attachment{ID: "att-" + fileName, FileName: fileName, Size: int64(len(plain))})
	m.uploads++
	cp := *c
	if m.localCopyFails {
		return &cp, &state.LocalCopyError{Cipher: &cp, Err: errors.New("disk full")}
	}
	return &cp, nil
}

func (m *mockVaultService) DeleteAttachment(_ context.Context, cipherID, attachmentID string) (*state.Cipher, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ciphers[cipherID]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	c.Attachments = slices.DeleteFunc(slices.Clone(c.Attachments), func(a state.Attachment) bool { return a.ID == attachmentID })
	cp := *c
	return &cp, nil
}

func (m *mockVaultService) AllCiphers() []*state.Cipher {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status != state.StatusUnlocked {
		return nil
	}
	out := make([]*state.Cipher, 0, len(m.order))
	for _, id := range m.order {
		if c := m.ciphers[id]; c != nil {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out
}
