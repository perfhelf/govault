package ui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/dedup"
	"github.com/txchen/govault/internal/vaultcore/gen"
	"github.com/txchen/govault/internal/vaultcore/health"
	"github.com/txchen/govault/internal/vaultcore/sshagent"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
	"github.com/txchen/govault/internal/vaultcore/totp"
)

type SyncStatus int

const (
	SyncIdle SyncStatus = iota
	SyncInProgress
	SyncOffline
	SyncAuthExpired
	// SyncPending: a sync fetched nothing it could apply, because changes
	// were committed meanwhile. One automatic retry follows.
	SyncPending
)

// scheduleSyncRetry runs the one retry of a deferred sync, shortly after.
var scheduleSyncRetry = func(retry func()) { time.AfterFunc(2*time.Second, retry) }

type MainRoute int

const (
	RouteVault MainRoute = iota
	RouteGenerator
	RouteSettings
	RouteHealth
	RouteImport
	RouteDedup
)

type UserPrefs struct {
	DeviceID              string                `json:"deviceId"`
	AccountID             string                `json:"accountId"`
	ServerURL             string                `json:"serverUrl"`
	Email                 string                `json:"email"`
	KDFSummary            string                `json:"kdfSummary"`
	BiometricEnabled      bool                  `json:"biometricEnabled"`
	AutoPromptBiometric   bool                  `json:"autoPromptBiometric"`
	AutoLockMinutes       int                   `json:"autoLockMinutes"`
	LockOnSleep           bool                  `json:"lockOnSleep"`
	SSHAgentEnabled       bool                  `json:"sshAgentEnabled"`
	ShowFavicons          *bool                 `json:"showFavicons,omitempty"`
	ClipboardClearSeconds int                   `json:"clipboardClearSeconds"`
	LaunchAtLogin         bool                  `json:"launchAtLogin"`
	HideDockIcon          bool                  `json:"hideDockIcon"`
	ShowTrayIcon          bool                  `json:"showTrayIcon"`
	SidebarWidth          float32               `json:"sidebarWidth"`
	ListWidth             float32               `json:"listWidth"`
	FoldersCollapsed      bool                  `json:"foldersCollapsed"`
	CollectionsCollapsed  bool                  `json:"collectionsCollapsed"`
	GeneratorMode         string                `json:"generatorMode"`
	PasswordOpts          gen.PasswordOptions   `json:"passwordOpts"`
	PassphraseOpts        gen.PassphraseOptions `json:"passphraseOpts"`
	MainWindow            *WindowState          `json:"mainWindow,omitempty"`
}

func DefaultUserPrefs() UserPrefs {
	return UserPrefs{
		AutoPromptBiometric:   false,
		AutoLockMinutes:       15,
		LockOnSleep:           true,
		ClipboardClearSeconds: 30,
		ShowTrayIcon:          true,
		SidebarWidth:          DefaultSidebarWidth,
		ListWidth:             DefaultListWidth,
		GeneratorMode:         "password",
		PasswordOpts: gen.PasswordOptions{
			Length:         20,
			Uppercase:      true,
			Lowercase:      true,
			Numbers:        true,
			Special:        true,
			MinNumbers:     1,
			MinSpecial:     1,
			AvoidAmbiguous: false,
		},
		PassphraseOpts: gen.PassphraseOptions{
			NumWords:   4,
			Separator:  "-",
			Capitalize: true,
			IncludeNum: true,
		},
	}
}

func (p UserPrefs) FaviconsEnabled() bool { return p.ShowFavicons == nil || *p.ShowFavicons }

func (p *UserPrefs) UnmarshalJSON(data []byte) error {
	type plain UserPrefs
	v := plain(DefaultUserPrefs())
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*p = UserPrefs(v)
	return nil
}

const (
	DefaultSidebarWidth float32 = 224
	DefaultListWidth    float32 = 300
	MinSidebarWidth     float32 = 180
	MaxSidebarWidth     float32 = 340
	MinListWidth        float32 = 220
	MaxListWidth        float32 = 460
	MinDetailWidth      float32 = 380
)

type AccountSnapshotMeta struct {
	AccountID  string
	ServerURL  string
	Email      string
	KDFSummary string
	LastSyncAt time.Time
}

type PlatformHooks struct {
	Secrets              store.SecretStore
	CopySecret           func(secret string, clearAfter time.Duration) (concealed bool, err error)
	CopyPlain            func(text string)
	IsClipboardConcealed func() bool
	SetLaunchAtLogin     func(on bool)
	SetDockVisible       func(on bool)
	SetTrayVisible       func(on bool)
	ReleaseSecureInput   func(force bool)
	SleepLockSupported   bool
	Favicons             *FaviconStore
	DiscoverSnapshot     func(preferredAccountID string) *AccountSnapshotMeta
	// VerifyMasterPassword checks password against accountID's vault. It
	// runs on a worker, so it takes the account as an argument rather than
	// reading app state.
	VerifyMasterPassword func(accountID string, password []byte) error
	PrefsKey             string
	SSHAgent             SSHAgentHost
	// BiometricHardwareBound reports whether the biometric key of an account is
	// in a keychain that macOS releases only after its own Touch ID check.
	BiometricHardwareBound func(accountID string) bool
	// ChooseSavePath asks where to save a file without creating or changing
	// it. done may run on any goroutine.
	ChooseSavePath func(name string, done func(path string, ok bool, err error))
}

var ErrBiometricCancelled = errors.New("biometric authentication cancelled")

// SSHAgentHost runs the local ssh-agent socket that serves vault SSH keys.
type SSHAgentHost interface {
	SocketPath() string
	Start() error
	Stop()
	SetKeys(keys []sshagent.Key)
	Clear()
}

const DefaultPrefsKey = "govault.prefs"

// EditURIDraft is one website in the editor. orig is the URI it was opened
// with, whose match setting, checksum and unknown fields a save keeps.
type EditURIDraft struct {
	URI  string
	orig *state.LoginURI
}

// EditFieldDraft is one custom field in the editor. orig keeps the linked
// field and unknown fields of the field it was opened with.
type EditFieldDraft struct {
	Name  string
	Value string
	Type  int
	orig  *state.CustomField
}

type EditDraft struct {
	ID         string
	IsNew      bool
	Type       api.CipherType
	Name       string
	FolderID   string
	Favorite   bool
	Reprompt   bool
	Notes      string
	Username   string
	Password   string
	TOTP       string
	URIs       []EditURIDraft
	Cardholder string
	Brand      string
	CardNumber string
	ExpMonth   string
	ExpYear    string
	CardCode   string
	IdentTitle string
	FirstName  string
	MiddleName string
	LastName   string
	Company    string
	Email      string
	Phone      string
	Address1   string
	City       string
	State      string
	PostalCode string
	Country    string
	IdentUser  string
	SSN        string
	Passport   string
	License    string
	SSHPrivate string
	SSHPublic  string
	SSHFinger  string
	Fields     []EditFieldDraft
	Revision   *time.Time
	Source     *state.Cipher
	// session identifies one opening of the editor; edits keep it, so a
	// save that finishes late knows whether its draft is still open.
	session uint64
	// RemovedPasskeys are indexes into Source.Login.Fido2Credentials of the
	// passkeys the user removed. They go only when the draft is saved.
	RemovedPasskeys []int
}

// DraftPasskeys are the passkeys of the item being edited, removed or not.
func (d *EditDraft) DraftPasskeys() []state.Fido2Credential {
	if d == nil || d.Source == nil || d.Source.Login == nil || d.Type != api.CipherTypeLogin {
		return nil
	}
	return d.Source.Login.Fido2Credentials
}

func (d *EditDraft) PasskeyRemoved(i int) bool {
	return d != nil && slices.Contains(d.RemovedPasskeys, i)
}

type RepromptModal struct {
	Open    bool
	Title   string
	Action  string
	OnAllow func()
}

type FolderModal struct {
	Open     bool
	FolderID string
	Name     string
}

type TOTPController struct {
	mu      sync.Mutex
	active  bool
	stopCh  chan struct{}
	cfg     *totp.TOTPConfig
	rawSeed string
}

func (tc *TOTPController) Active() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.active
}

func (tc *TOTPController) Update(raw string, onTick func(code string, remaining, period int)) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		tc.Stop()
		return
	}

	cfg, err := totp.ParseTOTP(trimmed)
	if err != nil {
		tc.Stop()
		return
	}

	tc.mu.Lock()
	if tc.active && tc.rawSeed == trimmed {
		tc.mu.Unlock()
		return
	}
	if tc.stopCh != nil {
		close(tc.stopCh)
	}
	stopCh := make(chan struct{})
	tc.stopCh = stopCh
	tc.cfg = cfg
	tc.rawSeed = trimmed
	tc.active = true
	tc.mu.Unlock()

	if code, rem, period, err := totp.Generate(cfg, time.Now()); err == nil {
		onTick(code, rem, period)
	}

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				if code, rem, period, err := totp.Generate(cfg, now); err == nil {
					onTick(code, rem, period)
				}
			}
		}
	}()
}

func (tc *TOTPController) Stop() {
	tc.mu.Lock()
	if tc.stopCh != nil {
		close(tc.stopCh)
		tc.stopCh = nil
	}
	tc.active = false
	tc.cfg = nil
	tc.rawSeed = ""
	tc.mu.Unlock()
}

type IdleTimer struct {
	mu    sync.Mutex
	timer *time.Timer
}

func (it *IdleTimer) Reset(d time.Duration, fn func()) {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.timer != nil {
		it.timer.Stop()
		it.timer = nil
	}
	if d <= 0 {
		return
	}
	it.timer = time.AfterFunc(d, fn)
}

func (it *IdleTimer) Stop() {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.timer != nil {
		it.timer.Stop()
		it.timer = nil
	}
}

type AppModel struct {
	Scope *core.Scope
	Core  state.VaultService
	Hooks PlatformHooks
	Prefs *core.Persisted[UserPrefs]

	LockState *core.Signal[state.LockStatus]
	SyncState *core.Signal[SyncStatus]
	// LocalOnly: the vault is open but its saved sign-in could not be
	// validated, so it does not sync until the user signs in again.
	LocalOnly *core.Signal[bool]
	// CredentialsNotSaved: a new sign-in this session could not be saved.
	CredentialsNotSaved *core.Signal[bool]
	// ReSignIn shows the sign-in form over a locked vault.
	ReSignIn *core.Signal[bool]
	// ReSignInServer is the trusted server Sign In Again signs in to, or ""
	// when the user must enter it.
	ReSignInServer *core.Signal[string]
	LastSync       *core.Signal[time.Time]
	Route          *core.Signal[MainRoute]

	BiometricKind     *core.Signal[core.BiometricKind]
	BiometricHardware *core.Signal[bool]

	LoginServer   *core.Signal[string]
	LoginEmail    *core.Signal[string]
	LoginPassword *core.Signal[string]
	LoginBusy     *core.Signal[bool]
	LoginError    *core.Signal[string]
	LoginShowPW   *core.Signal[bool]

	TwoFactor         *core.Signal[*TwoFactorPrompt]
	TwoFactorProvider *core.Signal[api.TwoFactorProvider]
	TwoFactorCode     *core.Signal[string]
	TwoFactorRemember *core.Signal[bool]
	TwoFactorSending  *core.Signal[bool]
	TwoFactorNotice   *core.Signal[string]

	LockPassword    *core.Signal[string]
	LockBusy        *core.Signal[bool]
	LockError       *core.Signal[string]
	LockShowPW      *core.Signal[bool]
	LockAutoFired   bool
	LockPasswordRef core.Ref

	SidebarFilter     *core.Signal[state.SearchFilter]
	SearchQuery       *core.Signal[string]
	SearchRef         core.Ref
	Folders           *core.Signal[[]state.Folder]
	Organizations     *core.Signal[[]state.Organization]
	Collections       *core.Signal[[]state.Collection]
	AllCounts         *core.Signal[VaultCounts]
	Health            *core.Signal[health.Report]
	DedupReport       *core.Signal[dedup.Report]
	DedupFilter       *core.Signal[DedupFilterTab]
	DedupSelected     *core.Signal[map[string]bool]
	DedupKeepIDs      *core.Signal[map[string]string]
	DedupTitles       *core.Signal[map[string]string]
	DedupSimplifyURLs *core.Signal[bool]
	DedupBusy         *core.Signal[bool]
	DedupProgress     *core.Signal[dedup.Progress]
	DedupResult       *core.Signal[*dedup.ExecuteReport]
	dedupMu           sync.Mutex
	dedupCancel       context.CancelFunc
	FilteredItems     *core.Collection[string, state.CipherSummary]
	SelectedID        *core.Signal[string]
	IsSelected        func(id string) bool
	ActiveCipher      *core.Signal[*state.Cipher]
	RevealPW          *core.Signal[bool]
	RevealCard        *core.Signal[bool]
	// TOTPRevealedID is the item whose protected TOTP code was revealed.
	TOTPRevealedID *core.Signal[string]

	EditMode  *core.Signal[bool]
	EditDraft *core.Signal[*EditDraft]
	EditDirty *core.Signal[bool]
	EditBusy  *core.Signal[bool]
	EditError *core.Signal[string]

	TOTPCode      *core.Signal[string]
	TOTPRemaining *core.Signal[int]
	TOTPPeriod    *core.Signal[int]

	MainWinVisible *core.Signal[bool]
	// SearchAll widens a search typed in a section to the whole vault.
	SearchAll *core.Signal[bool]

	HealthFilter *core.Signal[HealthCategory]
	CanGoBack    *core.Signal[bool]
	CanGoForward *core.Signal[bool]

	SidebarW *core.Signal[float32]
	ListW    *core.Signal[float32]

	GenResult *core.Signal[string]

	Reprompt      *core.Signal[RepromptModal]
	RepromptPW    *core.Signal[string]
	RepromptError *core.Signal[string]
	RepromptBusy  *core.Signal[bool]

	FolderDialog *core.Signal[FolderModal]
	FolderError  *core.Signal[string]
	FolderBusy   *core.Signal[bool]

	AttachmentBusy *core.Signal[string]
	TrashBusy      *core.Signal[bool]

	BackupDialog        *core.Signal[BackupMode]
	BackupPW            *core.Signal[string]
	BackupPW2           *core.Signal[string]
	BackupError         *core.Signal[string]
	BackupBusy          *core.Signal[bool]
	ImportSession       *core.Signal[*ImportSession]
	ImportRev           *core.Signal[int]
	ImportShowIdentical *core.Signal[bool]
	ImportBusy          *core.Signal[bool]
	importPending       *importPending
	// backupOp counts backup dialog operations, so a worker finishing after
	// Cancel, lock or a newer attempt is ignored.
	backupOp uint64
	draftSeq uint64

	SSHAgentError *core.Signal[string]
	vaultRev      *core.Signal[int]

	Toaster *ui.Toaster

	faviconsOn  *core.Memo[bool]
	iconServer  *core.Memo[string]
	iconAccount *core.Memo[string]
	iconEpoch   *core.Signal[int]
	iconSigs    map[string]*core.Signal[int]

	totpCtrl  TOTPController
	idleTimer IdleTimer

	// lockGen advances on every transition to locked or logged out. Pending
	// secret actions that started under an older generation are dropped.
	// publishMu orders that advance with publishing a saved attachment.
	lockGen   atomic.Uint64
	publishMu sync.Mutex

	nav         navHistory
	windowScope *core.Scope
}

func (m *AppModel) LockGeneration() uint64 { return m.lockGen.Load() }

// StillUnlocked reports whether the vault stayed unlocked since gen.
func (m *AppModel) StillUnlocked(gen uint64) bool {
	return m.lockGen.Load() == gen && m.LockState.Get() == state.StatusUnlocked
}

// RevokePending invalidates every pending secret action. It is safe to call
// from any goroutine, and the platform calls it as soon as the vault service
// leaves the unlocked state.
func (m *AppModel) RevokePending() {
	m.publishMu.Lock()
	m.lockGen.Add(1)
	m.publishMu.Unlock()
}

// publishIfUnlocked runs publish only while gen is still current, holding
// publishMu so a lock cannot interleave.
func (m *AppModel) publishIfUnlocked(gen uint64, publish func() error) (bool, error) {
	m.publishMu.Lock()
	defer m.publishMu.Unlock()
	if m.lockGen.Load() != gen {
		return false, nil
	}
	if err := publish(); err != nil {
		return false, err
	}
	return true, nil
}

type VaultCounts struct {
	All        int
	Favorites  int
	Trash      int
	Archive    int
	NoFolder   int
	Login      int
	Card       int
	Identity   int
	SecureNote int
	SSHKey     int
	ByFolder   map[string]int

	ByCollection map[string]int
}

func NewAppModel(app *core.Scope, coreSvc state.VaultService, hooks PlatformHooks) *AppModel {
	settleSecureInput = func() {
		if hooks.ReleaseSecureInput != nil {
			hooks.ReleaseSecureInput(false)
		}
	}
	prefsKey := hooks.PrefsKey
	if prefsKey == "" {
		prefsKey = DefaultPrefsKey
	}
	prefs := core.NewPersisted(app, prefsKey, DefaultUserPrefs(), core.PersistOptions{Version: 1})
	p := EnsureDeviceID(prefs)

	m := &AppModel{
		Scope:               app,
		Core:                coreSvc,
		Hooks:               hooks,
		Prefs:               prefs,
		LockState:           core.NewSignal(app, coreSvc.Status()),
		SyncState:           core.NewSignal(app, SyncIdle),
		LocalOnly:           core.NewSignal(app, false),
		CredentialsNotSaved: core.NewSignal(app, false),
		ReSignIn:            core.NewSignal(app, false),
		ReSignInServer:      core.NewSignal(app, ""),
		LastSync:            core.NewSignal(app, time.Time{}),
		Route:               core.NewSignal(app, RouteVault),
		BiometricKind:       core.NewSignal(app, core.BiometricNone),
		BiometricHardware:   core.NewSignal(app, false),
		LoginServer:         core.NewSignal(app, p.ServerURL),
		LoginEmail:          core.NewSignal(app, p.Email),
		LoginPassword:       core.NewSignal(app, ""),
		LoginBusy:           core.NewSignal(app, false),
		LoginError:          core.NewSignal(app, ""),
		LoginShowPW:         core.NewSignal(app, false),
		TwoFactor:           core.NewSignal[*TwoFactorPrompt](app, nil),
		TwoFactorProvider:   core.NewSignal(app, api.TwoFactorAuthenticator),
		TwoFactorCode:       core.NewSignal(app, ""),
		TwoFactorRemember:   core.NewSignal(app, false),
		TwoFactorSending:    core.NewSignal(app, false),
		TwoFactorNotice:     core.NewSignal(app, ""),
		LockPassword:        core.NewSignal(app, ""),
		LockBusy:            core.NewSignal(app, false),
		LockError:           core.NewSignal(app, ""),
		LockShowPW:          core.NewSignal(app, false),
		SidebarFilter:       core.NewSignal(app, state.SearchFilter{Category: state.FilterAll}),
		SearchQuery:         core.NewSignal(app, ""),
		Folders:             core.NewSignalFunc(app, []state.Folder(nil), nil),
		Organizations:       core.NewSignalFunc(app, []state.Organization(nil), nil),
		Collections:         core.NewSignalFunc(app, []state.Collection(nil), nil),
		AllCounts:           core.NewSignalFunc(app, VaultCounts{ByFolder: map[string]int{}}, nil),
		Health:              core.NewSignalFunc(app, health.Report{}, nil),
		DedupReport:         core.NewSignalFunc(app, dedup.Report{}, nil),
		DedupFilter:         core.NewSignal(app, DedupAll),
		DedupSelected:       core.NewSignalFunc(app, map[string]bool(nil), nil),
		DedupKeepIDs:        core.NewSignalFunc(app, map[string]string(nil), nil),
		DedupTitles:         core.NewSignalFunc(app, map[string]string(nil), nil),
		DedupSimplifyURLs:   core.NewSignal(app, false),
		DedupBusy:           core.NewSignal(app, false),
		DedupProgress:       core.NewSignal(app, dedup.Progress{}),
		DedupResult:         core.NewSignalFunc[*dedup.ExecuteReport](app, nil, nil),
		FilteredItems:       core.NewCollectionFunc(app, func(c state.CipherSummary) string { return c.ID }, cipherSummaryEqual, nil),
		SelectedID:          core.NewSignal(app, ""),
		ActiveCipher:        core.NewSignal[*state.Cipher](app, nil),
		RevealPW:            core.NewSignal(app, false),
		RevealCard:          core.NewSignal(app, false),
		TOTPRevealedID:      core.NewSignal(app, ""),
		EditMode:            core.NewSignal(app, false),
		EditDraft:           core.NewSignal[*EditDraft](app, nil),
		EditDirty:           core.NewSignal(app, false),
		EditBusy:            core.NewSignal(app, false),
		EditError:           core.NewSignal(app, ""),
		TOTPCode:            core.NewSignal(app, ""),
		TOTPRemaining:       core.NewSignal(app, 0),
		TOTPPeriod:          core.NewSignal(app, 30),
		MainWinVisible:      core.NewSignal(app, false),
		SearchAll:           core.NewSignal(app, false),
		HealthFilter:        core.NewSignal(app, HealthAll),
		CanGoBack:           core.NewSignal(app, false),
		CanGoForward:        core.NewSignal(app, false),
		SidebarW:            core.NewSignal(app, clampWidth(p.SidebarWidth, MinSidebarWidth, MaxSidebarWidth, DefaultSidebarWidth)),
		ListW:               core.NewSignal(app, clampWidth(p.ListWidth, MinListWidth, MaxListWidth, DefaultListWidth)),
		GenResult:           core.NewSignal(app, ""),
		Reprompt:            core.NewSignalFunc(app, RepromptModal{}, nil),
		RepromptPW:          core.NewSignal(app, ""),
		RepromptError:       core.NewSignal(app, ""),
		RepromptBusy:        core.NewSignal(app, false),
		FolderDialog:        core.NewSignal(app, FolderModal{}),
		FolderError:         core.NewSignal(app, ""),
		FolderBusy:          core.NewSignal(app, false),
		AttachmentBusy:      core.NewSignal(app, ""),
		TrashBusy:           core.NewSignal(app, false),
		BackupDialog:        core.NewSignal(app, BackupNone),
		BackupPW:            core.NewSignal(app, ""),
		BackupPW2:           core.NewSignal(app, ""),
		BackupError:         core.NewSignal(app, ""),
		BackupBusy:          core.NewSignal(app, false),
		ImportSession:       core.NewSignalFunc[*ImportSession](app, nil, nil),
		ImportRev:           core.NewSignal(app, 0),
		ImportShowIdentical: core.NewSignal(app, false),
		ImportBusy:          core.NewSignal(app, false),
		SSHAgentError:       core.NewSignal(app, ""),
		vaultRev:            core.NewSignal(app, 0),
		Toaster:             ui.NewToaster(app),
	}
	m.IsSelected = core.NewSelector(app, m.SelectedID.Get)
	m.clearHistory()
	m.setupNavigation()
	m.setupFavicons()

	m.RegenerateSecret()

	m.RefreshBiometricAvailability()

	app.Effect(func() {
		m.reconcileTOTPTicker()
	})

	app.Effect(func() {
		if m.LockState.Get() != state.StatusUnlocked {
			m.RevokePending()
			m.TOTPRevealedID.Set("")
		}
	})

	app.Effect(func() {
		lock := m.LockState.Get()
		mins := m.Prefs.Get().AutoLockMinutes
		if lock == state.StatusUnlocked && mins > 0 {
			m.ResetIdleTimer()
		} else {
			m.idleTimer.Stop()
		}
	})

	agentOn := core.NewMemo(app, func() bool { return m.Prefs.Get().SSHAgentEnabled })
	app.Effect(func() {
		agentOn.Get()
		m.LockState.Get()
		m.vaultRev.Get()
		app.Untrack(m.syncSSHAgent)
	})

	app.Cleanup(func() {
		m.cancelDedupMerge()
		m.totpCtrl.Stop()
		m.idleTimer.Stop()
		if m.Hooks.SSHAgent != nil {
			m.Hooks.SSHAgent.Stop()
		}
	})

	if m.LockState.Get() == state.StatusUnlocked {
		m.RefreshVaultData()
	}

	return m
}

func cipherSummaryEqual(a, b state.CipherSummary) bool {
	if a.ID != b.ID || a.Type != b.Type || a.Favorite != b.Favorite || a.Deleted != b.Deleted ||
		a.Name != b.Name || a.Subtitle != b.Subtitle || a.HasTOTP != b.HasTOTP || a.Reprompt != b.Reprompt ||
		!slices.Equal(a.URIs, b.URIs) {
		return false
	}
	if a.FolderID == nil && b.FolderID == nil {
		return true
	}
	if a.FolderID == nil || b.FolderID == nil {
		return false
	}
	return *a.FolderID == *b.FolderID
}

func (m *AppModel) TOTPTickerActive() bool {
	return m.totpCtrl.Active()
}

func (m *AppModel) reconcileTOTPTicker() {
	lock := m.LockState.Get()
	mainVis := m.MainWinVisible.Get()
	route := m.Route.Get()
	edit := m.EditMode.Get()
	active := m.ActiveCipher.Get()

	if lock != state.StatusUnlocked {
		m.stopTOTP()
		return
	}

	var totpSeed string
	if mainVis && route == RouteVault && !edit && active != nil && active.Login != nil && strings.TrimSpace(active.Login.TOTP) != "" {
		totpSeed = active.Login.TOTP
	}

	if totpSeed == "" {
		m.stopTOTP()
		return
	}

	m.totpCtrl.Update(totpSeed, func(code string, remaining, period int) {
		m.Scope.Post(func() {
			if m.LockState.Get() != state.StatusUnlocked {
				return
			}
			m.TOTPCode.Set(code)
			m.TOTPRemaining.Set(remaining)
			m.TOTPPeriod.Set(period)
		})
	})
}

func (m *AppModel) stopTOTP() {
	m.totpCtrl.Stop()
	m.TOTPCode.Set("")
	m.TOTPRemaining.Set(0)
}

func (m *AppModel) ResetIdleTimer() {
	if m.LockState.Get() != state.StatusUnlocked {
		m.idleTimer.Stop()
		return
	}
	mins := m.Prefs.Get().AutoLockMinutes
	if mins <= 0 {
		m.idleTimer.Stop()
		return
	}
	m.idleTimer.Reset(time.Duration(mins)*time.Minute, func() {
		m.Scope.Post(func() {
			if m.LockState.Get() == state.StatusUnlocked {
				m.Lock()
				m.ShowToast(ui.ToastInfo, "Vault locked", "Locked automatically due to inactivity.")
			}
		})
	})
}

func (m *AppModel) ShowToast(kind ui.ToastType, title, desc string) {
	if m.Toaster == nil {
		return
	}
	m.Toaster.Show(ui.ToastContent{
		Type:        kind,
		Title:       title,
		Description: desc,
		Duration:    3 * time.Second,
	})
}

func (m *AppModel) CanUseBiometric() bool {
	k := m.BiometricKind.Get()
	return k == core.BiometricFingerprint || k == core.BiometricFace
}

func (m *AppModel) BiometricLabel() string {
	if runtime.GOOS == "windows" {
		return "Windows Hello"
	}
	switch m.BiometricKind.Get() {
	case core.BiometricFace:
		return "Face ID"
	case core.BiometricFingerprint:
		return "Touch ID"
	default:
		return "Biometric"
	}
}

func (m *AppModel) UpdatePrefs(fn func(p UserPrefs) UserPrefs) {
	_ = m.Prefs.Update(fn)
}

func (m *AppModel) RefreshBiometricAvailability() {
	m.Scope.BiometricAvailability(func(kind core.BiometricKind) {
		m.BiometricKind.Set(kind)
	})
}

// RefreshBiometricProtection updates whether macOS itself enforces Touch ID
// for the saved biometric key.
func (m *AppModel) RefreshBiometricProtection() {
	check := m.Hooks.BiometricHardwareBound
	accountID := m.Prefs.Get().AccountID
	if check == nil || accountID == "" || !m.Prefs.Get().BiometricEnabled {
		m.BiometricHardware.Set(false)
		return
	}
	go func() {
		bound := check(accountID)
		m.Scope.Post(func() { m.BiometricHardware.Set(bound) })
	}()
}

func (m *AppModel) SetShowTrayIcon(on bool) {
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.ShowTrayIcon = on
		if !on {
			p.HideDockIcon = false
		}
		return p
	})
	if !on && m.Hooks.SetDockVisible != nil {
		m.Hooks.SetDockVisible(true)
	}
	if m.Hooks.SetTrayVisible != nil {
		m.Hooks.SetTrayVisible(on)
	}
}

func clampWidth(v, lo, hi, def float32) float32 {
	if v <= 0 {
		return def
	}
	return min(max(v, lo), hi)
}

// ClampPaneWidths keeps both panes inside their bounds and leaves the detail pane at least MinDetailWidth of total.
func ClampPaneWidths(sidebar, list, total float32) (float32, float32) {
	sidebar = min(max(sidebar, MinSidebarWidth), MaxSidebarWidth)
	list = min(max(list, MinListWidth), MaxListWidth)
	if total <= 0 {
		return sidebar, list
	}
	if over := sidebar + list + MinDetailWidth - total; over > 0 {
		cut := min(over, list-MinListWidth)
		list -= cut
		over -= cut
		sidebar = max(sidebar-over, MinSidebarWidth)
	}
	return sidebar, list
}

func (m *AppModel) PersistPaneWidths() {
	sw, lw := m.SidebarW.Get(), m.ListW.Get()
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.SidebarWidth, p.ListWidth = sw, lw
		return p
	})
}

func (m *AppModel) ReleaseSecureInput() {
	if m.Hooks.ReleaseSecureInput != nil {
		m.Hooks.ReleaseSecureInput(true)
	}
}

var settleSecureInput = func() {}

func (m *AppModel) SyncAccountMetaFromSnapshot() {
	if m.Hooks.DiscoverSnapshot == nil {
		return
	}
	meta := m.Hooks.DiscoverSnapshot(m.Prefs.Get().AccountID)
	if meta == nil {
		return
	}
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.AccountID = meta.AccountID
		if meta.Email != "" {
			p.Email = meta.Email
		}
		if meta.KDFSummary != "" {
			p.KDFSummary = meta.KDFSummary
		}
		return p
	})
	if !meta.LastSyncAt.IsZero() {
		m.LastSync.Set(meta.LastSyncAt)
	}
}

type TwoFactorPrompt struct {
	Providers []api.TwoFactorProvider
	EmailHint string
}

func (p *TwoFactorPrompt) Has(provider api.TwoFactorProvider) bool {
	return p != nil && slices.Contains(p.Providers, provider)
}

func (m *AppModel) loginRequest() (state.LoginRequest, bool) {
	req := state.LoginRequest{
		ServerURL: strings.TrimSpace(m.LoginServer.Get()),
		Email:     strings.TrimSpace(m.LoginEmail.Get()),
	}
	if m.CanReturnToUnlock() {
		// Sign In Again renews the vault on this device: its account only,
		// at its trusted server when one is recorded.
		acct := m.Core.Account()
		if trusted := m.ReSignInServer.Get(); trusted != "" {
			req.ServerURL = trusted
		}
		acct.ServerURL = req.ServerURL
		req.Email, req.SameAccount = acct.Email, &acct
	}
	password := m.LoginPassword.Get()
	if req.ServerURL == "" || req.Email == "" || password == "" {
		return req, false
	}
	req.MasterPassword = []byte(password)
	return req, true
}

func (m *AppModel) Login() {
	if m.LoginBusy.Get() {
		return
	}
	req, ok := m.loginRequest()
	if !ok {
		m.LoginError.Set("Server URL, email, and master password are required.")
		return
	}
	m.submitLogin(req)
}

func (m *AppModel) VerifyTwoFactor() {
	if m.LoginBusy.Get() || m.TwoFactor.Get() == nil {
		return
	}
	code := strings.Join(strings.Fields(m.TwoFactorCode.Get()), "")
	if code == "" {
		m.LoginError.Set("Enter the verification code.")
		return
	}
	req, ok := m.loginRequest()
	if !ok {
		m.CancelTwoFactor()
		return
	}
	req.TwoFactorProvider = m.TwoFactorProvider.Get()
	req.TwoFactorCode = code
	req.RememberDevice = m.TwoFactorRemember.Get()
	m.submitLogin(req)
}

func (m *AppModel) submitLogin(req state.LoginRequest) {
	m.ReleaseSecureInput()
	m.LoginBusy.Set(true)
	m.LoginError.Set("")
	verifying := req.TwoFactorCode != ""
	ctx := state.WithAuthAttempt(context.Background(), m.Core.AuthAttempt())
	gen := m.LockGeneration()

	go func() {
		defer crypto.ZeroBytes(req.MasterPassword)
		err := m.Core.Login(ctx, req)
		m.Scope.Post(func() {
			if gen != m.LockGeneration() {
				return
			}
			m.LoginBusy.Set(false)
			if err != nil {
				m.loginFailed(err, verifying)
				return
			}
			m.finishLogin(req.ServerURL, req.Email)
		})
	}()
}

func (m *AppModel) loginFailed(err error, verifying bool) {
	var tfErr *api.TwoFactorRequiredError
	var apiErr *api.APIError
	switch {
	case verifying && (errors.As(err, &tfErr) || errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest):
		m.TwoFactorCode.Set("")
		m.LoginError.Set("Invalid verification code. Check the code and try again.")
	case errors.As(err, &tfErr):
		m.enterTwoFactor(tfErr.Challenge)
	default:
		m.LoginError.Set(friendlyError(err))
	}
}

func (m *AppModel) enterTwoFactor(ch api.TwoFactorChallenge) {
	prompt := &TwoFactorPrompt{EmailHint: ch.EmailHint()}
	for _, p := range ch.Providers {
		if p == api.TwoFactorAuthenticator || p == api.TwoFactorEmail {
			prompt.Providers = append(prompt.Providers, p)
		}
	}
	if len(prompt.Providers) == 0 {
		names := make([]string, len(ch.Providers))
		for i, p := range ch.Providers {
			names[i] = p.String()
		}
		m.LoginError.Set("This account requires two-step login with " + strings.Join(names, ", ") +
			", which GoVault does not support yet. Enable Authenticator App or Email two-step login in your vault web settings to sign in here.")
		return
	}
	m.TwoFactorProvider.Set(prompt.Providers[0])
	m.TwoFactorCode.Set("")
	m.TwoFactorRemember.Set(false)
	m.TwoFactorNotice.Set("")
	if len(ch.Providers) == 1 && ch.Providers[0] == api.TwoFactorEmail {
		m.TwoFactorNotice.Set(emailSentNotice(prompt.EmailHint))
	}
	m.LoginError.Set("")
	m.TwoFactor.Set(prompt)
}

func (m *AppModel) SelectTwoFactorProvider(p api.TwoFactorProvider) {
	if !m.TwoFactor.Get().Has(p) || m.TwoFactorProvider.Get() == p {
		return
	}
	m.TwoFactorProvider.Set(p)
	m.TwoFactorCode.Set("")
	m.TwoFactorNotice.Set("")
	m.LoginError.Set("")
}

func (m *AppModel) SendTwoFactorEmail() {
	if m.TwoFactorSending.Get() || !m.TwoFactor.Get().Has(api.TwoFactorEmail) {
		return
	}
	req, ok := m.loginRequest()
	if !ok {
		m.CancelTwoFactor()
		return
	}
	hint := m.TwoFactor.Get().EmailHint
	m.TwoFactorSending.Set(true)
	m.LoginError.Set("")
	m.TwoFactorNotice.Set("")
	gen := m.LockGeneration()

	go func() {
		defer crypto.ZeroBytes(req.MasterPassword)
		err := m.Core.SendEmailTwoFactorCode(context.Background(), req)
		m.Scope.Post(func() {
			if gen != m.LockGeneration() {
				return
			}
			m.TwoFactorSending.Set(false)
			if err != nil {
				m.LoginError.Set("Could not send the verification email. " + friendlyError(err))
				return
			}
			m.TwoFactorNotice.Set(emailSentNotice(hint))
		})
	}()
}

func (m *AppModel) CancelTwoFactor() {
	m.TwoFactor.Set(nil)
	m.TwoFactorCode.Set("")
	m.TwoFactorNotice.Set("")
	m.LoginError.Set("")
	m.ReleaseSecureInput()
}

func emailSentNotice(hint string) string {
	if hint == "" {
		return "A verification code was sent to your email."
	}
	return "A verification code was sent to " + hint + "."
}

// SignInAgain shows the sign-in form over a locked vault without removing
// the local copy; signing in replaces the saved sign-in.
func (m *AppModel) SignInAgain() {
	acct := m.Core.Account()
	trusted := m.Core.TrustedServerURL(acct.ID)
	m.ReSignIn.Set(true)
	m.Lock()
	// Only the trusted sign-in record says where to sign in. Without one
	// the user enters the server; the editable snapshot never fills it.
	m.ReSignInServer.Set(trusted)
	m.LoginServer.Set(trusted)
	m.LoginEmail.Set(acct.Email)
	m.LoginError.Set("")
}

// CanReturnToUnlock reports a sign-in form shown over a locked local vault,
// not a first sign-in.
func (m *AppModel) CanReturnToUnlock() bool {
	return m.ReSignIn.Get() && m.LockState.Get() == state.StatusLocked
}

// BackToUnlock leaves the sign-in form for the lock screen, ending a
// sign-in still running; the local vault is untouched.
func (m *AppModel) BackToUnlock() {
	if !m.CanReturnToUnlock() {
		return
	}
	m.Core.RevokeAuthAttempts()
	m.RevokePending()
	m.LoginBusy.Set(false)
	m.LoginPassword.Set("")
	m.LoginError.Set("")
	m.TwoFactor.Set(nil)
	m.TwoFactorCode.Set("")
	m.ReSignIn.Set(false)
	m.ReleaseSecureInput()
}

func (m *AppModel) finishLogin(serverURL, email string) {
	m.ReSignIn.Set(false)
	m.LoginPassword.Set("")
	m.TwoFactor.Set(nil)
	m.TwoFactorCode.Set("")
	m.TwoFactorNotice.Set("")
	// Who just signed in comes from the service, never from settings left
	// by an earlier account.
	acct := m.Core.Account()
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.ServerURL = strings.TrimRight(serverURL, "/")
		p.Email = email
		if acct.ID != "" {
			p.AccountID = acct.ID
		}
		return p
	})
	m.SyncAccountMetaFromSnapshot()
	m.LastSync.Set(time.Now())
	m.SyncState.Set(SyncIdle)
	m.LockState.Set(state.StatusUnlocked)
	m.Route.Set(RouteVault)
	m.RefreshVaultData()
	m.ResetIdleTimer()
	m.ReleaseSecureInput()
}

func (m *AppModel) UnlockWithPassword() {
	if m.LockBusy.Get() {
		return
	}
	password := m.LockPassword.Get()
	if password == "" {
		m.LockError.Set("Enter your master password.")
		return
	}
	m.ReleaseSecureInput()
	m.LockBusy.Set(true)
	m.LockError.Set("")
	pwBytes := []byte(password)
	gen := m.LockGeneration()
	ctx := state.WithAuthAttempt(context.Background(), m.Core.AuthAttempt())

	go func() {
		defer crypto.ZeroBytes(pwBytes)
		err := m.Core.UnlockWithPassword(ctx, pwBytes)
		m.Scope.Post(func() {
			if gen != m.LockGeneration() {
				return
			}
			m.LockBusy.Set(false)
			if err != nil {
				m.LockError.Set(friendlyError(err))
				m.LockPasswordRef.Focus()
				return
			}
			m.finishUnlock()
		})
	}()
}

func (m *AppModel) finishUnlock() {
	m.LockPassword.Set("")
	m.LockAutoFired = false
	m.LockState.Set(state.StatusUnlocked)
	m.RefreshVaultData()
	m.ResetIdleTimer()
	m.ReleaseSecureInput()
	m.SyncNow(true)
}

func (m *AppModel) unlockFailed(msg string) {
	m.LockBusy.Set(false)
	m.LockError.Set(msg)
	m.LockPasswordRef.Focus()
}

func (m *AppModel) UnlockWithBiometric(cx *core.Scope) {
	if !m.CanUseBiometric() || !m.Prefs.Get().BiometricEnabled || m.Hooks.Secrets == nil {
		return
	}
	accountID := m.Prefs.Get().AccountID
	if accountID == "" {
		return
	}
	m.ReleaseSecureInput()
	m.LockBusy.Set(true)
	m.LockError.Set("")

	secrets := m.Hooks.Secrets
	gen := m.LockGeneration()
	ctx := state.WithAuthAttempt(context.Background(), m.Core.AuthAttempt())
	readKey := func() {
		go func() {
			encoded, ok, err := secrets.Get("userkey:" + accountID)
			if errors.Is(err, ErrBiometricCancelled) {
				m.Scope.Post(func() { m.unlockFailed("") })
				return
			}
			if err != nil || !ok || encoded == "" {
				m.Scope.Post(func() { m.unlockFailed("Saved biometric key unavailable. Unlock with master password.") })
				return
			}
			raw, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				m.Scope.Post(func() { m.unlockFailed("Corrupt biometric key. Unlock with master password.") })
				return
			}
			defer crypto.ZeroBytes(raw)
			key, err := crypto.SymmetricKeyFromBytes(raw)
			if err != nil {
				m.Scope.Post(func() { m.unlockFailed("Invalid biometric key. Unlock with master password.") })
				return
			}
			defer key.Zero()

			err = m.Core.UnlockWithUserKey(ctx, key)
			m.Scope.Post(func() {
				if gen != m.LockGeneration() {
					return
				}
				if err != nil {
					m.unlockFailed(friendlyError(err))
					return
				}
				m.LockBusy.Set(false)
				m.finishUnlock()
			})
		}()
	}

	if m.Hooks.BiometricHardwareBound != nil && m.Hooks.BiometricHardwareBound(accountID) {
		readKey()
		return
	}
	cx.AuthenticateBiometric("Unlock GoVault", func(res core.BiometricResult) {
		if res != core.BiometricSuccess {
			msg := ""
			if res != core.BiometricCancelled {
				msg = "Biometric authentication failed. Enter master password."
			}
			m.unlockFailed(msg)
			return
		}
		readKey()
	})
}

func (m *AppModel) ToggleBiometric(cx *core.Scope, enable bool) {
	if m.Hooks.Secrets == nil {
		m.ShowToast(ui.ToastError, "Keychain unavailable", "Cannot access system keychain.")
		return
	}
	if !enable {
		secrets := m.Hooks.Secrets
		go func() {
			err := m.Core.DisableBiometricUnlock(secrets)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastError, "Disable failed", err.Error())
					return
				}
				m.UpdatePrefs(func(p UserPrefs) UserPrefs {
					p.BiometricEnabled = false
					return p
				})
				m.ShowToast(ui.ToastInfo, m.BiometricLabel()+" disabled", "")
			})
		}()
		return
	}

	cx.AuthenticateBiometric("Enable "+m.BiometricLabel()+" for GoVault", func(res core.BiometricResult) {
		if res != core.BiometricSuccess {
			return
		}
		secrets := m.Hooks.Secrets
		go func() {
			err := m.Core.EnableBiometricUnlock(secrets)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastError, "Enable failed", err.Error())
					return
				}
				m.UpdatePrefs(func(p UserPrefs) UserPrefs {
					p.BiometricEnabled = true
					return p
				})
				m.RefreshBiometricProtection()
				m.ShowToast(ui.ToastSuccess, m.BiometricLabel()+" enabled", "You can now unlock GoVault with "+m.BiometricLabel()+".")
			})
		}()
	})
}

func (m *AppModel) Lock() {
	m.RevokePending()
	m.Core.Lock()
	m.clearUnlockedUI()
	m.LockState.Set(m.Core.Status())
}

// ServiceLeftUnlocked runs when the vault service leaves the unlocked state
// on its own, such as a logout the server sent: the same cleanup as a
// local lock, and for a logout the account-scoped settings too.
func (m *AppModel) ServiceLeftUnlocked(st state.LockStatus) {
	if st == state.StatusUnlocked {
		return
	}
	m.RevokePending()
	m.clearUnlockedUI()
	m.LockState.Set(st)
	if st == state.StatusLoggedOut {
		m.forgetAccount()
	}
}

func (m *AppModel) forgetAccount() {
	if f := m.Hooks.Favicons; f != nil {
		_ = f.ClearAccount(m.Prefs.Get().AccountID)
	}
	m.resetFaviconMemory()
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.AccountID = ""
		p.BiometricEnabled = false
		return p
	})
	m.Route.Set(RouteVault)
}

// clearUnlockedUI removes everything the unlocked vault put on screen or in
// memory: drafts, dialogs, revealed secrets, backups and lists.
func (m *AppModel) clearUnlockedUI() {
	m.FolderDialog.Set(FolderModal{})
	m.FolderError.Set("")
	m.FolderBusy.Set(false)
	m.GenResult.Set("")
	m.EditBusy.Set(false)
	m.RepromptBusy.Set(false)
	if m.Hooks.SSHAgent != nil {
		m.Hooks.SSHAgent.Clear()
	}
	m.Reprompt.Set(RepromptModal{})
	m.RepromptPW.Set("")
	m.RepromptError.Set("")
	m.AttachmentBusy.Set("")
	m.TrashBusy.Set(false)
	m.clearBackupState()
	m.clearDedupState()
	if m.Route.Get() == RouteImport || m.Route.Get() == RouteDedup {
		m.Route.Set(RouteVault)
	}
	m.TOTPRevealedID.Set("")
	m.stopTOTP()
	m.idleTimer.Stop()
	// Locking stays quiet: Touch ID is offered again only once the window is
	// reopened or the app starts.
	m.LockAutoFired = true
	m.ActiveCipher.Set(nil)
	m.SelectedID.Set("")
	m.EditMode.Set(false)
	m.EditDraft.Set(nil)
	m.EditDirty.Set(false)
	m.RevealPW.Set(false)
	m.RevealCard.Set(false)
	m.SearchQuery.Set("")
	m.SearchAll.Set(false)
	m.HealthFilter.Set(HealthAll)
	m.clearHistory()
	m.Folders.Set(nil)
	m.Organizations.Set(nil)
	m.Collections.Set(nil)
	m.FilteredItems.Replace(nil)
	m.AllCounts.Set(VaultCounts{ByFolder: map[string]int{}})
	m.Health.Set(health.Report{})
	m.ReleaseSecureInput()
}

func (m *AppModel) LockOnSystemEvent() bool {
	if !m.Prefs.Get().LockOnSleep {
		return false
	}
	if m.LockState.Get() != state.StatusUnlocked {
		// A sign-in or unlock still running must not finish after the
		// sleep, including a biometric prompt answered later.
		m.Core.RevokeAuthAttempts()
		m.RevokePending()
		m.clearAuthInputs()
		return false
	}
	// The UI may show the vault while the unlock that opened it has not
	// reported back yet; nothing it typed or started survives either.
	m.Lock()
	m.clearAuthInputs()
	return true
}

// clearAuthInputs empties every password field and ends every sign-in or
// unlock the UI shows as running.
func (m *AppModel) clearAuthInputs() {
	m.LockBusy.Set(false)
	m.LoginBusy.Set(false)
	m.RepromptBusy.Set(false)
	m.TwoFactorSending.Set(false)
	m.LockPassword.Set("")
	m.LoginPassword.Set("")
	m.RepromptPW.Set("")
	m.TwoFactorCode.Set("")
	m.ReleaseSecureInput()
}

func (m *AppModel) Logout(cx *core.Scope) {
	cx.ShowAlert(core.AlertConfig{
		Title:   "Log out of GoVault?",
		Message: "Your local encrypted vault cache and saved biometric key will be removed from this device.",
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Log Out", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		m.RevokePending()
		m.cancelDedupMerge()
		if m.Hooks.SSHAgent != nil {
			m.Hooks.SSHAgent.Clear()
		}
		secrets := m.Hooks.Secrets
		go func() {
			err := m.Core.Logout(context.Background(), secrets)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastWarning, "Logged out", "Some saved secrets could not be removed: "+err.Error())
				}
				m.Lock()
				m.LockState.Set(state.StatusLoggedOut)
				m.forgetAccount()
			})
		}()
	})
}

func (m *AppModel) SyncNow(silent bool) {
	m.syncNow(silent, true)
}

func (m *AppModel) syncNow(silent, retryDeferred bool) {
	if m.LockState.Get() != state.StatusUnlocked || m.SyncState.Get() == SyncInProgress {
		return
	}
	m.SyncState.Set(SyncInProgress)
	go func() {
		err := m.Core.SyncNow(context.Background())
		m.Scope.Post(func() {
			if m.LockState.Get() != state.StatusUnlocked {
				m.SyncState.Set(SyncIdle)
				return
			}
			if err != nil {
				switch {
				case errors.Is(err, state.ErrSyncDeferred):
					m.SyncState.Set(SyncPending)
					m.RefreshVaultData()
					if retryDeferred {
						gen := m.LockGeneration()
						scheduleSyncRetry(func() {
							m.Scope.Post(func() {
								if m.StillUnlocked(gen) && m.SyncState.Get() == SyncPending {
									m.syncNow(true, false)
								}
							})
						})
					}
				case errors.Is(err, state.ErrSignInRequired):
					m.SyncState.Set(SyncAuthExpired)
					m.LocalOnly.Set(true)
				case errors.Is(err, api.ErrUnauthorized):
					m.SyncState.Set(SyncAuthExpired)
					if !silent {
						m.ShowToast(ui.ToastWarning, "Session expired", "Sign in again to resume syncing.")
					}
				case errors.Is(err, api.ErrNetworkOffline):
					m.SyncState.Set(SyncOffline)
					if !silent {
						m.ShowToast(ui.ToastWarning, "Offline", "Showing cached vault.")
					}
				default:
					m.SyncState.Set(SyncOffline)
					if !silent {
						m.ShowToast(ui.ToastError, "Sync failed", friendlyError(err))
					}
				}
				return
			}
			m.SyncState.Set(SyncIdle)
			m.LastSync.Set(time.Now())
			m.RefreshVaultData()
			if !silent {
				m.ShowToast(ui.ToastSuccess, "Vault synced", "")
			}
		})
	}()
}

func (m *AppModel) RefreshVaultData() {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	m.LocalOnly.Set(m.Core.LocalOnly())
	if f := m.Hooks.Favicons; f != nil {
		f.SetOffline(m.LocalOnly.GetUntracked())
	}
	m.CredentialsNotSaved.Set(m.Core.CredentialsNotSaved())
	folders := m.Core.Folders()
	m.Folders.Set(folders)
	m.Organizations.Set(m.Core.Organizations())
	m.Collections.Set(m.Core.Collections())
	m.recomputeCounts()
	m.recomputeHealth()
	m.recomputeDedup()
	m.RefreshFilteredList()
	m.vaultRev.Set(m.vaultRev.GetUntracked() + 1)

	selID := m.SelectedID.Get()
	if selID != "" {
		if c, err := m.Core.GetCipher(selID); err == nil {
			m.ActiveCipher.Set(c)
		} else {
			m.SelectedID.Set("")
			m.ActiveCipher.Set(nil)
		}
	}
}

func (m *AppModel) recomputeCounts() {
	all := m.Core.Search("", state.SearchFilter{Category: state.FilterAll})
	trash := m.Core.Search("", state.SearchFilter{Category: state.FilterTrash})
	archived := m.Core.Search("", state.SearchFilter{Category: state.FilterArchive})
	counts := VaultCounts{
		All:      len(all),
		Trash:    len(trash),
		Archive:  len(archived),
		ByFolder: make(map[string]int),

		ByCollection: make(map[string]int),
	}
	for _, item := range all {
		for _, id := range item.CollectionIDs {
			counts.ByCollection[id]++
		}
		if item.Favorite {
			counts.Favorites++
		}
		if item.FolderID == nil || *item.FolderID == "" {
			counts.NoFolder++
		} else {
			counts.ByFolder[*item.FolderID]++
		}
		switch item.Type {
		case api.CipherTypeLogin:
			counts.Login++
		case api.CipherTypeCard:
			counts.Card++
		case api.CipherTypeIdentity:
			counts.Identity++
		case api.CipherTypeSecureNote:
			counts.SecureNote++
		case api.CipherTypeSSHKey:
			counts.SSHKey++
		}
	}
	m.AllCounts.Set(counts)
}

func (m *AppModel) recomputeHealth() {
	ciphers := m.Core.AllCiphers()
	for _, c := range ciphers {
		c.HidePassword = c.HidePassword || m.PasswordHidden(c)
	}
	m.Health.Set(health.Analyze(ciphers, time.Now()))
}

// OpenHealthItem shows the flagged item in the vault so it can be reviewed.
func (m *AppModel) OpenHealthItem(cx *core.Scope, id string) {
	m.GuardDirty(cx, func() {
		cx.Batch(func() {
			m.SearchQuery.Set("")
			m.SetSidebarFilter(state.SearchFilter{Category: state.FilterAll})
			m.SelectCipher(cx, id)
		})
	})
}

func (m *AppModel) RefreshFilteredList() {
	if m.LockState.Get() != state.StatusUnlocked {
		m.FilteredItems.Replace(nil)
		return
	}
	m.FilteredItems.Replace(m.Core.Search(m.SearchQuery.Get(), m.EffectiveSearchFilter()))
}

// SearchIsGlobal reports whether a non-empty query searches the whole vault rather than the selected sidebar section.
func (m *AppModel) SearchIsGlobal() bool {
	return m.SearchScoped() && m.SearchAll.Get()
}

// SearchScoped reports whether a query is typed while a section other than
// All Items is selected, so it can search that section or the whole vault.
func (m *AppModel) SearchScoped() bool {
	f := m.SidebarFilter.Get()
	return strings.TrimSpace(m.SearchQuery.Get()) != "" && f.Category != state.FilterTrash && f.Category != state.FilterArchive && !IsAllItemsFilter(f)
}

func IsAllItemsFilter(f state.SearchFilter) bool {
	return f.Category == state.FilterAll && f.FolderID == "" && f.Type == nil && f.CollectionID == "" && f.OrganizationID == ""
}

func (m *AppModel) cipherCollections(c *state.Cipher) []state.Collection {
	if c == nil || len(c.CollectionIDs) == 0 {
		return nil
	}
	var out []state.Collection
	for _, col := range m.Collections.Get() {
		if slices.Contains(c.CollectionIDs, col.ID) {
			out = append(out, col)
		}
	}
	return out
}

func (m *AppModel) OrganizationName(id *string) string {
	if id == nil {
		return ""
	}
	for _, o := range m.Organizations.Get() {
		if o.ID == *id {
			return o.Name
		}
	}
	return ""
}

// CipherReadOnly reports whether the organization only lets the user view c.
func (m *AppModel) CipherReadOnly(c *state.Cipher) bool {
	if c == nil {
		return false
	}
	cols := m.cipherCollections(c)
	return c.ReadOnly || len(cols) > 0 && !slices.ContainsFunc(cols, func(col state.Collection) bool { return !col.ReadOnly })
}

// PasswordHidden reports whether the organization hides the password of c from the user.
func (m *AppModel) PasswordHidden(c *state.Cipher) bool {
	if c == nil {
		return false
	}
	cols := m.cipherCollections(c)
	return c.HidePassword || len(cols) > 0 && !slices.ContainsFunc(cols, func(col state.Collection) bool { return !col.HidePasswords })
}

func (m *AppModel) SSHAgentSocketPath() string {
	if m.Hooks.SSHAgent == nil {
		return ""
	}
	return m.Hooks.SSHAgent.SocketPath()
}

func (m *AppModel) SetSSHAgentEnabled(on bool) {
	m.UpdatePrefs(func(p UserPrefs) UserPrefs {
		p.SSHAgentEnabled = on
		return p
	})
}

func (m *AppModel) CopySSHAuthSock() {
	if path := m.SSHAgentSocketPath(); path != "" {
		m.CopyPlainValue("SSH_AUTH_SOCK", fmt.Sprintf("export SSH_AUTH_SOCK=%q", path))
	}
}

func (m *AppModel) syncSSHAgent() {
	host := m.Hooks.SSHAgent
	if host == nil {
		return
	}
	if !m.Prefs.Get().SSHAgentEnabled {
		host.Stop()
		m.SSHAgentError.Set("")
		return
	}
	if err := host.Start(); err != nil {
		m.SSHAgentError.Set(err.Error())
		return
	}
	m.SSHAgentError.Set("")
	if m.LockState.Get() != state.StatusUnlocked {
		host.Clear()
		return
	}
	host.SetKeys(m.agentKeys())
}

// agentKeys lists the SSH keys the agent may serve: active, viewable and not behind a master password reprompt.
func (m *AppModel) agentKeys() []sshagent.Key {
	t := api.CipherTypeSSHKey
	var keys []sshagent.Key
	for _, item := range m.Core.Search("", state.SearchFilter{Category: state.FilterAll, Type: &t}) {
		c, err := m.Core.GetCipher(item.ID)
		if err != nil || c.SSHKey == nil || c.SSHKey.PrivateKey == "" || c.DeletedDate != nil || c.Reprompt == 1 || m.PasswordHidden(c) {
			continue
		}
		keys = append(keys, sshagent.Key{PrivateKey: c.SSHKey.PrivateKey, Comment: c.Name})
	}
	return keys
}

func (m *AppModel) EffectiveSearchFilter() state.SearchFilter {
	if m.SearchIsGlobal() {
		return state.SearchFilter{Category: state.FilterAll}
	}
	return m.SidebarFilter.Get()
}

func (m *AppModel) SetSearchAll(on bool) {
	m.SearchAll.Set(on)
	m.RefreshFilteredList()
}

func (m *AppModel) SetSearchQuery(q string) {
	m.ResetIdleTimer()
	m.Scope.Batch(func() {
		if strings.TrimSpace(q) != "" && m.Route.Get() != RouteVault {
			m.Route.Set(RouteVault)
		}
		if strings.TrimSpace(q) == "" {
			m.SearchAll.Set(false)
		}
		m.SearchQuery.Set(q)
		m.RefreshFilteredList()
	})
}

func (m *AppModel) SetSidebarFilter(f state.SearchFilter) {
	m.ResetIdleTimer()
	m.Route.Set(RouteVault)
	m.SidebarFilter.Set(f)
	m.SearchAll.Set(false)
	m.RefreshFilteredList()
}

func (m *AppModel) GuardDirty(cx *core.Scope, proceed func()) {
	if !m.EditMode.Get() || !m.EditDirty.Get() {
		proceed()
		return
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   "Discard unsaved changes?",
		Message: "Your edits to this item have not been saved.",
		Actions: []core.AlertAction{
			{Label: "Keep Editing", Role: core.AlertCancel},
			{Label: "Discard", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx == 1 {
			m.EditMode.Set(false)
			m.EditDraft.Set(nil)
			m.EditDirty.Set(false)
			m.EditError.Set("")
			proceed()
		}
	})
}

func (m *AppModel) SelectCipher(cx *core.Scope, id string) {
	m.ResetIdleTimer()
	if id == m.SelectedID.Get() && !m.EditMode.Get() {
		return
	}
	m.GuardDirty(cx, func() {
		m.SelectedID.Set(id)
		m.RevealPW.Set(false)
		m.RevealCard.Set(false)
		m.TOTPRevealedID.Set("")
		if id == "" {
			m.ActiveCipher.Set(nil)
			return
		}
		c, err := m.Core.GetCipher(id)
		if err != nil {
			m.ActiveCipher.Set(nil)
			return
		}
		m.ActiveCipher.Set(c)
	})
}

func (m *AppModel) MoveListSelection(cx *core.Scope, delta int) {
	n := m.FilteredItems.Len()
	if n == 0 {
		return
	}
	cur := m.SelectedID.Get()
	idx := -1
	for i := range n {
		if m.FilteredItems.KeyAt(i) == cur {
			idx = i
			break
		}
	}
	next := idx + delta
	if idx == -1 {
		if delta > 0 {
			next = 0
		} else {
			next = n - 1
		}
	}
	if next < 0 {
		next = 0
	}
	if next >= n {
		next = n - 1
	}
	m.SelectCipher(cx, m.FilteredItems.KeyAt(next))
}

func (m *AppModel) StartCreateCipher(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	m.ResetIdleTimer()
	m.GuardDirty(cx, func() {
		m.Route.Set(RouteVault)
		f := m.SidebarFilter.Get()
		ct := api.CipherTypeLogin
		if f.Type != nil {
			ct = *f.Type
		}
		draft := &EditDraft{
			IsNew:    true,
			Type:     ct,
			FolderID: f.FolderID,
			URIs:     []EditURIDraft{{URI: ""}},
		}
		m.openDraft(draft)
		m.EditDirty.Set(false)
		m.EditError.Set("")
		m.EditMode.Set(true)
	})
}

func (m *AppModel) StartEditCipher(cx *core.Scope) {
	c := m.ActiveCipher.Get()
	if c == nil || c.DeletedDate != nil || m.CipherReadOnly(c) || m.PasswordHidden(c) || m.EditMode.Get() {
		return
	}
	m.ResetIdleTimer()
	m.GateReprompt(cx, c, "edit item", func() {
		if cur := m.ActiveCipher.Get(); cur == nil || cur.ID != c.ID {
			return
		}
		m.openDraft(draftFromCipher(c))
		m.EditDirty.Set(false)
		m.EditError.Set("")
		m.EditMode.Set(true)
	})
}

// openDraft opens d in the editor as a new editing session.
func (m *AppModel) openDraft(d *EditDraft) {
	m.draftSeq++
	d.session = m.draftSeq
	m.EditDraft.Set(d)
}

func (m *AppModel) CancelEdit(cx *core.Scope) {
	m.GuardDirty(cx, func() {
		m.ReleaseSecureInput()
		m.EditMode.Set(false)
		m.EditDraft.Set(nil)
		m.EditDirty.Set(false)
		m.EditError.Set("")
	})
}

func (m *AppModel) MutateDraft(fn func(d *EditDraft)) {
	cur := m.EditDraft.Get()
	// While the draft saves, edits would be lost when the save closes the
	// editor, so none are taken; the editor shows its fields disabled.
	if cur == nil || m.EditBusy.Get() {
		return
	}
	cp := cloneDraft(cur)
	fn(cp)
	m.EditDraft.Set(cp)
	m.EditDirty.Set(true)
	m.ResetIdleTimer()
}

func (m *AppModel) SaveDraft(cx *core.Scope) {
	draft := m.EditDraft.Get()
	if draft == nil || m.EditBusy.Get() {
		return
	}
	if strings.TrimSpace(draft.Name) == "" {
		m.EditError.Set("Name is required.")
		return
	}
	if m.SyncState.Get() == SyncOffline {
		m.EditError.Set("Cannot save while offline.")
		return
	}

	cipher := cipherFromDraft(draft)
	m.ReleaseSecureInput()
	gen := m.LockGeneration()
	session := draft.session
	m.EditBusy.Set(true)
	m.EditError.Set("")

	go func() {
		saved, err := m.Core.SaveCipher(context.Background(), cipher)
		// The server has the item even when its local copy failed: finish
		// the edit with the server item, so Save cannot create it twice.
		var lc *state.LocalCopyError
		localCopyFailed := errors.As(err, &lc)
		if localCopyFailed && saved == nil {
			saved = lc.Cipher
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.EditBusy.Set(false)
			if cur := m.EditDraft.Get(); cur == nil || cur.session != session {
				// The user left this draft; another one may be open now.
				if err == nil || localCopyFailed {
					m.RefreshVaultData()
					m.ShowToast(ui.ToastSuccess, "Item saved", "")
				} else {
					m.ShowToast(ui.ToastError, "Save failed", friendlyError(err))
				}
				return
			}
			if err != nil && !localCopyFailed {
				if errors.Is(err, api.ErrRevisionConflict) {
					cx.ShowAlert(core.AlertConfig{
						Title:   "Item changed on another device",
						Message: "This item was updated elsewhere since your last sync. Reload the latest version to avoid overwriting changes.",
						Actions: []core.AlertAction{
							{Label: "Cancel", Role: core.AlertCancel},
							{Label: "Reload Latest", Role: core.AlertDefault},
						},
						Cancelable: true,
					}, func(idx int) {
						if idx == 1 {
							m.EditMode.Set(false)
							m.EditDraft.Set(nil)
							m.EditDirty.Set(false)
							m.SyncNow(false)
						}
					})
					return
				}
				m.EditError.Set(friendlyError(err))
				return
			}
			m.EditMode.Set(false)
			m.EditDraft.Set(nil)
			m.EditDirty.Set(false)
			m.EditError.Set("")
			m.RefreshVaultData()
			if saved != nil {
				m.SelectedID.Set(saved.ID)
				m.ActiveCipher.Set(saved)
			}
			m.ReleaseSecureInput()
			if localCopyFailed {
				m.ShowLocalCopyWarning("Item saved")
				return
			}
			m.ShowToast(ui.ToastSuccess, "Item saved", "")
		})
	}()
}

// ShowLocalCopyWarning reports a change the server accepted but GoVault
// could not write to its encrypted local copy. It offers a sync, which
// refreshes the copy, and never repeats the change.
func (m *AppModel) ShowLocalCopyWarning(title string) {
	if m.Toaster == nil {
		return
	}
	m.Toaster.Show(ui.ToastContent{
		Type:        ui.ToastWarning,
		Title:       title,
		Description: "Saved on the server, but the copy on this device could not be updated.",
		Action:      "Sync now",
		OnAction:    func() { m.SyncNow(false) },
		Duration:    10 * time.Second,
	})
}

func (m *AppModel) ToggleFavorite() {
	c := m.ActiveCipher.Get()
	if c == nil || m.CipherReadOnly(c) || c.DeletedDate != nil || m.SyncState.Get() == SyncOffline {
		return
	}
	cp := *c
	cp.Favorite = !cp.Favorite
	gen := m.LockGeneration()
	go func() {
		saved, err := m.Core.SaveCipher(context.Background(), &cp)
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			var lc *state.LocalCopyError
			if err != nil && !errors.As(err, &lc) {
				m.ShowToast(ui.ToastError, "Update failed", friendlyError(err))
				return
			}
			m.applyCipherUpdate(saved)
			if lc != nil {
				m.ShowLocalCopyWarning("Favorite updated")
			}
		})
	}()
}

func (m *AppModel) SoftDeleteActive() {
	c := m.ActiveCipher.Get()
	if c == nil || m.SyncState.Get() == SyncOffline || m.CipherReadOnly(c) {
		return
	}
	id := c.ID
	go func() {
		err := m.Core.SoftDeleteCipher(context.Background(), id)
		m.Scope.Post(func() {
			if err != nil {
				m.ShowToast(ui.ToastError, "Move to Trash failed", friendlyError(err))
				return
			}
			m.SelectedID.Set("")
			m.ActiveCipher.Set(nil)
			m.RefreshVaultData()
			m.ShowToast(ui.ToastInfo, "Moved to Trash", "")
		})
	}()
}

// CanFavorite reports whether c may change its favorite: Bitwarden hides
// it on archived items once the account can no longer archive.
func (m *AppModel) CanFavorite(c *state.Cipher) bool {
	return c == nil || c.ArchivedDate == nil || m.Core.CanArchive()
}

// CanArchiveItem reports whether c can go to the Archive now: an item not in
// Trash or the Archive, for an account with Archive (premium).
func (m *AppModel) CanArchiveItem(c *state.Cipher) bool {
	return c != nil && c.DeletedDate == nil && c.ArchivedDate == nil && m.Core.CanArchive() && m.SyncState.Get() != SyncOffline
}

// CanUnarchiveItem reports whether c can leave the Archive. Unlike
// archiving it needs no premium, so items archived before premium ended
// can come back.
func (m *AppModel) CanUnarchiveItem(c *state.Cipher) bool {
	return c != nil && c.DeletedDate == nil && c.ArchivedDate != nil && m.SyncState.Get() != SyncOffline
}

// ArchiveActive moves the selected item to the Archive, or back with
// archive false.
//
// A protected item asks for the master password first, as Bitwarden does
// for both, and the change applies only to the item it was asked for, in
// the session it was asked in.
func (m *AppModel) ArchiveActive(cx *core.Scope, archive bool) {
	c := m.ActiveCipher.Get()
	if (archive && !m.CanArchiveItem(c)) || (!archive && !m.CanUnarchiveItem(c)) {
		return
	}
	id := c.ID
	label := "archive item"
	if !archive {
		label = "unarchive item"
	}
	m.GateReprompt(cx, c, label, func() {
		if cur := m.ActiveCipher.Get(); cur == nil || cur.ID != id {
			return
		}
		m.setArchived(id, archive)
	})
}

func (m *AppModel) setArchived(id string, archive bool) {
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	gen := m.LockGeneration()
	go func() {
		defer cancel()
		var err error
		if archive {
			err = m.Core.ArchiveCipher(ctx, id)
		} else {
			err = m.Core.UnarchiveCipher(ctx, id)
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			var lc *state.LocalCopyError
			if err != nil && !errors.As(err, &lc) {
				title := "Archive failed"
				if !archive {
					title = "Unarchive failed"
				}
				m.ShowToast(ui.ToastError, title, friendlyError(err))
				return
			}
			m.RefreshVaultData()
			title := "Item archived"
			if !archive {
				title = "Item unarchived"
			}
			if lc != nil {
				m.ShowLocalCopyWarning(title)
				return
			}
			m.ShowToast(ui.ToastSuccess, title, "")
		})
	}()
}

func (m *AppModel) RestoreActive() {
	c := m.ActiveCipher.Get()
	if c == nil || m.CipherReadOnly(c) || m.SyncState.Get() == SyncOffline {
		return
	}
	id := c.ID
	go func() {
		err := m.Core.RestoreCipher(context.Background(), id)
		m.Scope.Post(func() {
			if err != nil {
				m.ShowToast(ui.ToastError, "Restore failed", friendlyError(err))
				return
			}
			m.SelectedID.Set("")
			m.ActiveCipher.Set(nil)
			m.RefreshVaultData()
			m.ShowToast(ui.ToastSuccess, "Item restored", "")
		})
	}()
}

func (m *AppModel) HardDeleteActive(cx *core.Scope) {
	c := m.ActiveCipher.Get()
	if c == nil || m.CipherReadOnly(c) || m.SyncState.Get() == SyncOffline {
		return
	}
	id := c.ID
	name := c.Name
	cx.ShowAlert(core.AlertConfig{
		Title:   "Delete permanently?",
		Message: fmt.Sprintf("%q will be permanently deleted and cannot be recovered.", name),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Delete Permanently", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		go func() {
			err := m.Core.HardDeleteCipher(context.Background(), id)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastError, "Delete failed", friendlyError(err))
					return
				}
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
				m.RefreshVaultData()
				m.ShowToast(ui.ToastInfo, "Permanently deleted", "")
			})
		}()
	})
}

func (m *AppModel) OpenNewFolderModal() {
	m.FolderError.Set("")
	m.FolderDialog.Set(FolderModal{Open: true})
}

func (m *AppModel) OpenRenameFolderModal(f state.Folder) {
	m.FolderError.Set("")
	m.FolderDialog.Set(FolderModal{Open: true, FolderID: f.ID, Name: f.Name})
}

func (m *AppModel) SaveFolderModal() {
	dlg := m.FolderDialog.Get()
	name := strings.TrimSpace(dlg.Name)
	if name == "" {
		m.FolderError.Set("Folder name is required.")
		return
	}
	if m.FolderBusy.Get() {
		return
	}
	m.FolderBusy.Set(true)
	m.FolderError.Set("")
	f := &state.Folder{ID: dlg.FolderID, Name: name}
	go func() {
		_, err := m.Core.SaveFolder(context.Background(), f)
		m.Scope.Post(func() {
			m.FolderBusy.Set(false)
			if err != nil {
				m.FolderError.Set(friendlyError(err))
				return
			}
			m.FolderDialog.Set(FolderModal{})
			m.RefreshVaultData()
			m.ShowToast(ui.ToastSuccess, "Folder saved", "")
		})
	}()
}

func (m *AppModel) DeleteFolder(cx *core.Scope, f state.Folder) {
	cx.ShowAlert(core.AlertConfig{
		Title:   "Delete folder?",
		Message: fmt.Sprintf("Items inside %q will be moved to No Folder.", f.Name),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Delete Folder", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		go func() {
			err := m.Core.DeleteFolder(context.Background(), f.ID)
			m.Scope.Post(func() {
				if err != nil {
					m.ShowToast(ui.ToastError, "Delete folder failed", friendlyError(err))
					return
				}
				cur := m.SidebarFilter.Get()
				if cur.FolderID == f.ID {
					m.SidebarFilter.Set(state.SearchFilter{Category: state.FilterAll})
				}
				m.RefreshVaultData()
				m.ShowToast(ui.ToastInfo, "Folder deleted", "")
			})
		}()
	})
}

func (m *AppModel) GateReprompt(cx *core.Scope, cipher *state.Cipher, actionLabel string, allow func()) {
	if cipher == nil || cipher.Reprompt != 1 {
		allow()
		return
	}
	gen := m.LockGeneration()
	onAllow := func() {
		if m.StillUnlocked(gen) {
			allow()
		}
	}
	if m.CanUseBiometric() && m.Prefs.Get().BiometricEnabled {
		cx.AuthenticateBiometric("Verify to "+actionLabel, func(res core.BiometricResult) {
			if res == core.BiometricSuccess {
				onAllow()
			} else if res != core.BiometricCancelled {
				m.openRepromptDialog(actionLabel, onAllow)
			}
		})
		return
	}
	m.openRepromptDialog(actionLabel, onAllow)
}

func (m *AppModel) openRepromptDialog(actionLabel string, onAllow func()) {
	m.RepromptPW.Set("")
	m.RepromptError.Set("")
	m.Reprompt.Set(RepromptModal{
		Open:    true,
		Title:   "Master Password Verification",
		Action:  actionLabel,
		OnAllow: onAllow,
	})
}

func (m *AppModel) CloseReprompt() {
	m.RepromptPW.Set("")
	m.RepromptError.Set("")
	m.Reprompt.Set(RepromptModal{})
	m.ReleaseSecureInput()
}

func (m *AppModel) SubmitReprompt() {
	if m.RepromptBusy.Get() {
		return
	}
	pw := m.RepromptPW.Get()
	if pw == "" {
		m.RepromptError.Set("Enter your master password.")
		return
	}
	if m.Hooks.VerifyMasterPassword == nil {
		m.RepromptError.Set("Master password verification is unavailable.")
		return
	}
	m.ReleaseSecureInput()
	m.RepromptBusy.Set(true)
	m.RepromptError.Set("")
	pwBytes := []byte(pw)
	cb := m.Reprompt.Get().OnAllow
	accountID := m.Core.Account().ID

	go func() {
		defer crypto.ZeroBytes(pwBytes)
		err := m.Hooks.VerifyMasterPassword(accountID, pwBytes)
		m.Scope.Post(func() {
			m.RepromptBusy.Set(false)
			if err != nil {
				m.RepromptError.Set("Incorrect master password.")
				return
			}
			m.RepromptPW.Set("")
			m.Reprompt.Set(RepromptModal{})
			m.ReleaseSecureInput()
			if cb != nil {
				cb()
			}
		})
	}()
}

func (m *AppModel) CopySecretValue(label, secret string) {
	if secret == "" {
		return
	}
	m.ResetIdleTimer()
	secs := m.Prefs.Get().ClipboardClearSeconds
	clearAfter := time.Duration(secs) * time.Second
	var concealed bool
	if m.Hooks.CopySecret != nil {
		var err error
		concealed, err = m.Hooks.CopySecret(secret, clearAfter)
		if err != nil {
			m.ShowToast(ui.ToastError, "Copy failed", err.Error())
			return
		}
	} else {
		m.Scope.SetClipboard(secret)
	}
	desc := ""
	if secs > 0 {
		if concealed {
			desc = fmt.Sprintf("Concealed · clears in %ds", secs)
		} else {
			desc = fmt.Sprintf("Clears in %ds", secs)
		}
	} else if concealed {
		desc = "Concealed from clipboard history"
	}
	m.ShowToast(ui.ToastSuccess, label+" copied", desc)
}

func (m *AppModel) CopyPlainValue(label, text string) {
	if text == "" {
		return
	}
	m.ResetIdleTimer()
	if m.Hooks.CopyPlain != nil {
		m.Hooks.CopyPlain(text)
	} else {
		m.Scope.SetClipboard(text)
	}
	m.ShowToast(ui.ToastInfo, label+" copied", "")
}

func (m *AppModel) RegenerateSecret() {
	p := m.Prefs.Get()
	var out string
	var err error
	if p.GeneratorMode == "passphrase" {
		out, err = gen.GeneratePassphrase(p.PassphraseOpts)
	} else {
		out, err = gen.GeneratePassword(p.PasswordOpts)
	}
	if err != nil {
		m.GenResult.Set("")
		return
	}
	m.GenResult.Set(out)
}

func (m *AppModel) GenerateInlinePassword() string {
	pw, err := gen.GeneratePassword(m.Prefs.Get().PasswordOpts)
	if err != nil {
		pw, _ = gen.GeneratePassword(DefaultUserPrefs().PasswordOpts)
	}
	return pw
}

func draftFromCipher(c *state.Cipher) *EditDraft {
	d := &EditDraft{
		ID:       c.ID,
		IsNew:    false,
		Type:     c.Type,
		Name:     c.Name,
		Favorite: c.Favorite,
		Reprompt: c.Reprompt == 1,
		Notes:    c.Notes,
		Revision: c.RevisionDate,
		Source:   c,
	}
	if c.FolderID != nil {
		d.FolderID = *c.FolderID
	}
	if c.Login != nil {
		d.Username = c.Login.Username
		d.Password = c.Login.Password
		d.TOTP = c.Login.TOTP
		for _, u := range c.Login.URIs {
			orig := u
			d.URIs = append(d.URIs, EditURIDraft{URI: u.URI, orig: &orig})
		}
	}
	if c.Card != nil {
		d.Cardholder = c.Card.CardholderName
		d.Brand = c.Card.Brand
		d.CardNumber = c.Card.Number
		d.ExpMonth = c.Card.ExpMonth
		d.ExpYear = c.Card.ExpYear
		d.CardCode = c.Card.Code
	}
	if c.Identity != nil {
		d.IdentTitle = c.Identity.Title
		d.FirstName = c.Identity.FirstName
		d.MiddleName = c.Identity.MiddleName
		d.LastName = c.Identity.LastName
		d.Company = c.Identity.Company
		d.Email = c.Identity.Email
		d.Phone = c.Identity.Phone
		d.Address1 = c.Identity.Address1
		d.City = c.Identity.City
		d.State = c.Identity.State
		d.PostalCode = c.Identity.PostalCode
		d.Country = c.Identity.Country
		d.IdentUser = c.Identity.Username
		d.SSN = c.Identity.SSN
		d.Passport = c.Identity.PassportNumber
		d.License = c.Identity.LicenseNumber
	}
	if c.SSHKey != nil {
		d.SSHPrivate = c.SSHKey.PrivateKey
		d.SSHPublic = c.SSHKey.PublicKey
		d.SSHFinger = c.SSHKey.KeyFingerprint
	}
	for _, f := range c.Fields {
		orig := f
		d.Fields = append(d.Fields, EditFieldDraft{Name: f.Name, Value: f.Value, Type: f.Type, orig: &orig})
	}
	return d
}

func cloneDraft(d *EditDraft) *EditDraft {
	cp := *d
	cp.URIs = append([]EditURIDraft(nil), d.URIs...)
	cp.Fields = append([]EditFieldDraft(nil), d.Fields...)
	cp.RemovedPasskeys = slices.Clone(d.RemovedPasskeys)
	return &cp
}

// cipherFromDraft turns the editor draft into the cipher to save. It starts
// from the item the editor opened and changes only what the editor shows,
// so everything else the item holds is saved unchanged: passkeys (unless
// the user removed them), URI match settings and checksums, linked fields,
// identity fields the editor does not show, and fields GoVault does not
// model at all.
func cipherFromDraft(d *EditDraft) *state.Cipher {
	var base state.Cipher
	var src *state.Cipher
	if d.Source != nil {
		base = *d.Source
		if d.Source.Type == d.Type {
			src = d.Source
		}
	}
	base.ID = d.ID
	base.Type = d.Type
	base.Name = strings.TrimSpace(d.Name)
	base.Favorite = d.Favorite
	base.Notes = d.Notes
	if d.Reprompt {
		base.Reprompt = 1
	} else {
		base.Reprompt = 0
	}
	if d.FolderID != "" {
		fid := d.FolderID
		base.FolderID = &fid
	} else {
		base.FolderID = nil
	}

	base.Login = nil
	base.SecureNote = nil
	base.Card = nil
	base.Identity = nil
	base.SSHKey = nil

	switch d.Type {
	case api.CipherTypeLogin:
		login := &state.Login{}
		if src != nil && src.Login != nil {
			cp := *src.Login
			login = &cp
		}
		login.Username = d.Username
		login.Password = d.Password
		login.TOTP = strings.TrimSpace(d.TOTP)
		login.URIs = nil
		for _, u := range d.URIs {
			text := strings.TrimSpace(u.URI)
			if u.orig != nil && text == strings.TrimSpace(u.orig.URI) {
				// Unchanged, even when blank: it may carry a match setting
				// or fields GoVault does not show.
				login.URIs = append(login.URIs, *u.orig)
				continue
			}
			if text == "" {
				continue
			}
			nu := state.LoginURI{URI: text}
			if u.orig != nil {
				nu = *u.orig
				nu.URI = text
			}
			login.URIs = append(login.URIs, nu)
		}
		if len(d.RemovedPasskeys) > 0 {
			var kept []state.Fido2Credential
			for i, f := range login.Fido2Credentials {
				if !d.PasskeyRemoved(i) {
					kept = append(kept, f)
				}
			}
			login.Fido2Credentials = kept
		}
		base.Login = login
	case api.CipherTypeSecureNote:
		base.SecureNote = &state.SecureNote{}
		if src != nil && src.SecureNote != nil {
			cp := *src.SecureNote
			base.SecureNote = &cp
		}
	case api.CipherTypeCard:
		card := &state.Card{}
		if src != nil && src.Card != nil {
			cp := *src.Card
			card = &cp
		}
		card.CardholderName = d.Cardholder
		card.Brand = d.Brand
		card.Number = d.CardNumber
		card.ExpMonth = d.ExpMonth
		card.ExpYear = d.ExpYear
		card.Code = d.CardCode
		base.Card = card
	case api.CipherTypeIdentity:
		id := &state.Identity{}
		if src != nil && src.Identity != nil {
			cp := *src.Identity
			id = &cp
		}
		id.Title = d.IdentTitle
		id.FirstName = d.FirstName
		id.MiddleName = d.MiddleName
		id.LastName = d.LastName
		id.Company = d.Company
		id.Email = d.Email
		id.Phone = d.Phone
		id.Address1 = d.Address1
		id.City = d.City
		id.State = d.State
		id.PostalCode = d.PostalCode
		id.Country = d.Country
		id.Username = d.IdentUser
		id.SSN = d.SSN
		id.PassportNumber = d.Passport
		id.LicenseNumber = d.License
		base.Identity = id
	case api.CipherTypeSSHKey:
		priv := strings.TrimSpace(d.SSHPrivate)
		if priv != "" {
			priv += "\n"
		}
		key := &state.SSHKey{}
		if src != nil && src.SSHKey != nil {
			cp := *src.SSHKey
			key = &cp
		}
		key.PrivateKey = priv
		key.PublicKey = strings.TrimSpace(d.SSHPublic)
		key.KeyFingerprint = strings.TrimSpace(d.SSHFinger)
		base.SSHKey = key
	}

	base.Fields = nil
	for _, f := range d.Fields {
		unchanged := f.orig != nil && f.Name == f.orig.Name && f.Value == f.orig.Value && f.Type == f.orig.Type
		if !unchanged && strings.TrimSpace(f.Name) == "" && strings.TrimSpace(f.Value) == "" {
			continue
		}
		nf := state.CustomField{}
		if f.orig != nil {
			nf = *f.orig
			if f.Type != f.orig.Type {
				nf.Shape = nf.Shape.Without("type")
			}
		}
		nf.Name, nf.Value, nf.Type = f.Name, f.Value, f.Type
		base.Fields = append(base.Fields, nf)
	}
	return &base
}

func friendlyError(err error) string {
	switch {
	case errors.Is(err, api.ErrTwoFactorRequired):
		return "Two-step login is required for this account."
	case errors.Is(err, api.ErrUnauthorized):
		return "Invalid email or master password."
	case errors.Is(err, api.ErrNetworkOffline):
		return "Server unreachable. Check your connection and server URL."
	case errors.Is(err, crypto.ErrInvalidMAC):
		return "Incorrect master password."
	case errors.Is(err, state.ErrArchiveUnsupported):
		return "This server does not support Archive. It needs Vaultwarden 1.36 or later."
	case errors.Is(err, state.ErrPremiumRequired):
		return "Archive needs a premium membership."
	case errors.Is(err, state.ErrArchiveNotConfirmed):
		return "The server did not confirm the change. GoVault synced to show where the item is now."
	case errors.Is(err, state.ErrCipherInTrash):
		return "Items in Trash cannot be archived. Restore the item first."
	default:
		return err.Error()
	}
}

// EnsureDeviceID gives the app its device identifier on first launch and
// saves it, so the first sign-in already sends the identifier every later
// launch uses.
func EnsureDeviceID(prefs *core.Persisted[UserPrefs]) UserPrefs {
	p := prefs.Get()
	if p.DeviceID == "" {
		p.DeviceID = newDeviceUUID()
		_ = prefs.Set(p)
	}
	return p
}

func newDeviceUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func FormatTOTPCode(code string) string {
	if len(code) == 6 {
		return code[:3] + " " + code[3:]
	}
	if len(code) == 8 {
		return code[:4] + " " + code[4:]
	}
	return code
}

func CipherTypeLabel(t api.CipherType) string {
	switch t {
	case api.CipherTypeLogin:
		return "Login"
	case api.CipherTypeSecureNote:
		return "Secure Note"
	case api.CipherTypeCard:
		return "Card"
	case api.CipherTypeIdentity:
		return "Identity"
	case api.CipherTypeSSHKey:
		return "SSH Key"
	default:
		return "Item"
	}
}
