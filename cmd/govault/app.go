package main

import (
	"context"
	_ "embed"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/nsgo-dev/nsgo/updater"
	govaultui "github.com/txchen/govault/cmd/govault/ui"
	"github.com/txchen/govault/internal/vaultcore/i18n"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/store"
)

// trayTemplatePNG is the app icon shield and keyhole as a 32x36 template
// image, drawn 18 points tall in the menu bar colors.
//
//go:embed assets/TrayTemplate.png
var trayTemplatePNG []byte

// trayColorPNG is the app icon at 64x64 for the Windows notification area
// and Linux trays, which draw icons as they are, so a black template glyph
// would vanish on a dark taskbar.
//
//go:embed assets/TrayIcon.png
var trayColorPNG []byte

type DesktopShell struct {
	scope     *core.Scope
	dataDir   string
	clipboard *ClipboardAdapter
	favicons  *govaultui.FaviconStore
	sshAgent  *sshAgentHost
	service   *state.Service
	model     *govaultui.AppModel

	mainWin   *desktop.Window
	winTrack  *govaultui.WindowTracker
	trayScope *core.Scope

	rtMu      sync.Mutex
	rtRunning bool
}

func NewDesktopShell(app *core.Scope, demoMode bool) *DesktopShell {
	desktop.SetShutdownMode(app, desktop.ShutdownOnExplicit)
	if demoMode {
		return newDemoShell(app)
	}

	dataDir := ensureDataDir(app)
	secrets := NewBiometricSecretStore(NewSecretStoreAdapter(app.Secrets()), newHardwareKeychain())
	clip := NewClipboardAdapter(app)

	shell := &DesktopShell{
		scope:     app,
		dataDir:   dataDir,
		clipboard: clip,
		sshAgent:  newSSHAgentHost(runtime.GOOS, dataDir),
	}
	if cacheDir := app.CacheDir(); cacheDir != "" {
		shell.favicons = govaultui.NewFaviconStore(govaultui.FaviconStoreConfig{CacheDir: filepath.Join(cacheDir, "icons")})
	}

	tempPrefs := core.NewPersisted(app, govaultui.DefaultPrefsKey, govaultui.DefaultUserPrefs(), core.PersistOptions{Version: 1})
	initialPrefs := govaultui.EnsureDeviceID(tempPrefs)

	meta := DiscoverAccountSnapshot(dataDir, initialPrefs.AccountID)
	accountID := initialPrefs.AccountID
	if meta != nil {
		accountID = meta.AccountID
	}

	svc, err := state.NewService(state.ServiceConfig{
		Store:      store.NewFileStore(dataDir),
		Secrets:    secrets,
		AccountID:  accountID,
		DeviceID:   initialPrefs.DeviceID,
		DeviceName: "GoVault Desktop",
		DeviceType: deviceTypeForOS(),
		OnStatusChange: func(st state.LockStatus) {
			if st != state.StatusUnlocked {
				shell.sshAgent.Clear()
				if m := shell.model; m != nil {
					m.RevokePending()
				}
			}
			app.Post(func() {
				if shell.model == nil {
					return
				}
				if st != state.StatusUnlocked {
					shell.model.ServiceLeftUnlocked(st)
					return
				}
				// A sleep or Back to Unlock may have locked the session
				// again before this callback ran.
				if shell.service.Status() != state.StatusUnlocked {
					return
				}
				shell.model.LockState.Set(st)
				shell.startRealtimeAsync()
			})
		},
		OnVaultUpdated: func() {
			app.Post(func() {
				if shell.model != nil && shell.model.LockState.Get() == state.StatusUnlocked {
					shell.model.RefreshVaultData()
				}
			})
		},
	})
	if err != nil {
		panic(err)
	}
	shell.service = svc

	hooks := shell.platformHooks(secrets)
	hooks.BiometricHardwareBound = secrets.HardwareBound
	hooks.DiscoverSnapshot = func(preferred string) *govaultui.AccountSnapshotMeta {
		return DiscoverAccountSnapshot(dataDir, preferred)
	}
	hooks.VerifyMasterPassword = func(accountID string, password []byte) error {
		return VerifyMasterPasswordOffline(dataDir, accountID, password)
	}

	shell.model = govaultui.NewAppModel(app, svc, hooks)
	if meta != nil {
		shell.model.SyncAccountMetaFromSnapshot()
	}
	shell.finishSetup()
	return shell
}

func (s *DesktopShell) platformHooks(secrets store.SecretStore) govaultui.PlatformHooks {
	app := s.scope
	hooks := govaultui.PlatformHooks{
		Secrets:              secrets,
		CopySecret:           s.clipboard.CopySecret,
		CopyPlain:            s.clipboard.CopyPlain,
		IsClipboardConcealed: s.clipboard.IsConcealed,
		SetLaunchAtLogin: func(on bool) {
			desktop.SetLaunchAtLogin(app, on)
		},
		SetDockVisible: func(on bool) {
			if runtime.GOOS == "darwin" {
				desktop.SetDockVisible(app, on)
			}
		},
		SetTrayVisible:     s.SetTrayVisible,
		ReleaseSecureInput: ReleaseSecureInput,
		SleepLockSupported: sleepLockSupported,
		Favicons:           s.favicons,
		ChooseSavePath:     chooseSavePath,
		DetectSystemLocale: i18n.DetectSystemLocale,
	}
	if s.sshAgent != nil {
		hooks.SSHAgent = s.sshAgent
	}
	return hooks
}

func (s *DesktopShell) finishSetup() {
	app := s.scope
	shell := s
	clip := s.clipboard

	app.Effect(func() {
		shell.model.Locale.Get()
		desktop.SetApplicationMenu(app, applicationMenuLocalized(runtime.GOOS, shell.model.T, func() { updater.Check(app) }))
	})

	p := shell.model.Prefs.Get()
	if runtime.GOOS == "darwin" && p.HideDockIcon && p.ShowTrayIcon {
		desktop.SetDockVisible(app, false)
	}
	shell.SetTrayVisible(p.ShowTrayIcon)

	desktop.OnReopen(app, shell.OpenMainWindow)

	app.Effect(func() {
		if app.Env().Lifecycle() != core.LifecycleActive {
			ReleaseSecureInput(true)
		}
	})

	if stop, err := startSleepLockListener(func() {
		app.Post(func() { shell.model.LockOnSystemEvent() })
	}); err == nil {
		app.Cleanup(stop)
	}

	if stop, err := startMouseNavigation(
		func() { app.Post(shell.model.GoBackFromSystem) },
		func() { app.Post(shell.model.GoForwardFromSystem) },
	); err == nil {
		app.Cleanup(stop)
	}

	app.Cleanup(func() {
		if shell.winTrack != nil {
			shell.winTrack.Flush()
		}
		clip.ClearOnQuit()
		if shell.trayScope != nil {
			shell.trayScope.Dispose()
		}
	})

	if !desktop.LaunchedAtLogin(app) || !p.ShowTrayIcon {
		shell.OpenMainWindow()
	}
}

func (s *DesktopShell) startRealtimeAsync() {
	s.rtMu.Lock()
	if s.rtRunning {
		s.rtMu.Unlock()
		return
	}
	s.rtRunning = true
	s.rtMu.Unlock()

	go func() {
		_ = s.service.StartRealtime(context.Background())
		s.rtMu.Lock()
		s.rtRunning = false
		s.rtMu.Unlock()
	}()
}

func (s *DesktopShell) trayMenu() []desktop.MenuItem {
	unlocked := s.model.LockState.Get() == state.StatusUnlocked
	offline := s.model.SyncState.Get() == govaultui.SyncOffline
	items := []desktop.MenuItem{
		{Label: s.model.T("tray.open"), OnSelect: s.OpenMainWindow},
		{Label: s.model.T("menu.check_updates"), OnSelect: func() { updater.Check(s.scope) }},
		{Separator: true},
		{
			Label:    s.model.T("tray.sync_now"),
			Disabled: !unlocked || offline,
			OnSelect: func() { s.model.SyncNow(false) },
		},
	}
	if unlocked {
		items = append(items, desktop.MenuItem{
			Label:    s.model.T("tray.lock_now"),
			OnSelect: s.model.Lock,
		})
	}
	items = append(items,
		desktop.MenuItem{Separator: true},
		desktop.MenuItem{Label: s.model.T("tray.quit"), OnSelect: s.scope.Quit},
	)
	return items
}

func (s *DesktopShell) OpenMainWindow() {
	if s.mainWin != nil && !s.mainWin.Closed() {
		s.mainWin.Focus()
		return
	}

	frame, width, height, maximize := govaultui.MainWindowPlacement(s.model.Prefs.Get().MainWindow)
	track := govaultui.NewWindowTracker(s.model.SaveMainWindow, s.scope.Post)
	s.winTrack = track
	s.mainWin = desktop.OpenWindow(s.scope, desktop.WindowOptions{
		Title:  "GoVault",
		Key:    "main",
		Width:  width,
		Height: height,
		Frame:  frame,
		Constraints: desktop.WindowConstraints{
			MinWidth:  govaultui.MainWindowMinWidth,
			MinHeight: govaultui.MainWindowMinHeight,
		},
	}, func(cx *core.Scope) core.Node {
		win := desktop.CurrentWindow(cx)
		if runtime.GOOS != "darwin" {
			desktop.SetMenuBar(cx, desktop.MenuBarAutoHide)
		}
		cx.Effect(func() {
			track.Observe(desktop.Frame(cx), desktop.Maximized(cx), desktop.FullScreen(cx))
		})
		if maximize {
			cx.Post(func() {
				if !desktop.Maximized(cx) {
					desktop.ToggleMaximize(cx)
				}
			})
		}
		cx.Effect(func() {
			vis := win.Visible() && !desktop.Minimized(cx)
			s.model.SetMainWindowVisible(vis)
		})
		cx.Effect(func() {
			if cx.Env().Lifecycle() != core.LifecycleActive {
				ReleaseSecureInput(true)
			}
		})
		win.OnClosing(cx, func(ev *desktop.WindowClosing) {
			if s.model.EditMode.Get() && s.model.EditDirty.Get() {
				ev.Cancel()
				s.model.GuardDirty(cx, func() {
					win.Close()
				})
			}
		})
		cx.Cleanup(func() {
			track.Flush()
			s.model.SetMainWindowVisible(false)
		})
		return govaultui.MainWindowView(cx, s.model)
	})
	desktop.SetMainWindow(s.scope, s.mainWin)
}

func (s *DesktopShell) SetTrayVisible(on bool) {
	mode := desktop.ShutdownOnExplicit
	if !on && runtime.GOOS != "darwin" {
		mode = desktop.ShutdownOnLastWindowClose
	}
	desktop.SetShutdownMode(s.scope, mode)
	if on == (s.trayScope != nil) {
		return
	}
	if !on {
		s.trayScope.Dispose()
		s.trayScope = nil
		return
	}
	s.trayScope = s.scope.Child()
	icon, template := trayColorPNG, false
	if runtime.GOOS == "darwin" {
		icon, template = trayTemplatePNG, true
	}
	desktop.NewTray(s.trayScope, desktop.TrayOptions{
		Icon:     icon,
		Template: template,
		Tooltip:  "GoVault",
		OnClick:  s.OpenMainWindow,
		Menu:     s.trayMenu,
	})
}
