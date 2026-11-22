package ui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nsgo-dev/nsgo/core"
	"github.com/nsgo-dev/nsgo/icons/lucide"
	"github.com/nsgo-dev/nsgo/ui"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
	"github.com/txchen/govault/internal/vaultcore/urlcheck"
)

// URLCheckPhase tracks the opt-in website reachability scan lifecycle.
type URLCheckPhase int

const (
	URLCheckIdle URLCheckPhase = iota
	URLCheckScanning
	URLCheckDone
)

const urlCheckPrivacyNotice = "Checks whether login website domains are reachable directly from this device. Only hostnames are contacted; URL paths and vault secrets are never sent. Major sites and local/private addresses are skipped."

// StartURLCheck begins an opt-in website reachability scan for active Login
// items. It is bound to the current unlocked vault session and never starts
// automatically on login, unlock, or sync.
func (m *AppModel) StartURLCheck() {
	if m.LockState.Get() != state.StatusUnlocked || m.URLCheckPhase.Get() == URLCheckScanning {
		return
	}
	m.ResetIdleTimer()

	ctx, sessCancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	gen := m.LockGeneration()

	m.urlCheckMu.Lock()
	if m.urlCheckCancel != nil {
		m.urlCheckCancel()
	}
	m.urlCheckOp++
	op := m.urlCheckOp
	m.urlCheckCancel = sessCancel
	m.urlCheckMu.Unlock()

	ciphers := m.Core.AllCiphers()
	for _, c := range ciphers {
		c.ReadOnly = c.ReadOnly || m.CipherReadOnly(c)
	}

	var opts urlcheck.Options
	if m.urlCheckOpts != nil {
		opts = m.urlCheckOpts()
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = urlcheck.DefaultConcurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = urlcheck.DefaultTimeout
	}
	opts.OnProgress = func(p urlcheck.Progress) {
		if m.LockGeneration() != gen {
			return
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.urlCheckMu.Lock()
			active := m.urlCheckOp == op
			m.urlCheckMu.Unlock()
			if !active || m.URLCheckPhase.Get() != URLCheckScanning {
				return
			}
			m.URLCheckProgress.Set(p)
		})
	}

	m.URLCheckReport.Set(urlcheck.Report{})
	m.URLCheckProgress.Set(urlcheck.Progress{})
	m.URLCheckPhase.Set(URLCheckScanning)

	go func() {
		defer sessCancel()
		report := urlcheck.Scan(ctx, ciphers, opts)
		if m.LockGeneration() != gen {
			return
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.urlCheckMu.Lock()
			active := m.urlCheckOp == op
			if active {
				m.urlCheckCancel = nil
			}
			m.urlCheckMu.Unlock()
			if !active || m.URLCheckPhase.Get() != URLCheckScanning {
				return
			}
			if report.Canceled {
				m.URLCheckProgress.Set(urlcheck.Progress{})
				m.URLCheckReport.Set(urlcheck.Report{})
				m.URLCheckPhase.Set(URLCheckIdle)
				return
			}
			m.URLCheckReport.Set(report)
			m.URLCheckPhase.Set(URLCheckDone)
		})
	}()
}

// CancelURLCheck stops any active website scan and returns to the idle screen.
func (m *AppModel) CancelURLCheck() {
	m.ResetIdleTimer()
	m.cancelURLCheck()
	m.URLCheckProgress.Set(urlcheck.Progress{})
	m.URLCheckReport.Set(urlcheck.Report{})
	m.URLCheckPhase.Set(URLCheckIdle)
}

func (m *AppModel) cancelURLCheck() {
	m.urlCheckMu.Lock()
	m.urlCheckOp++
	cancel := m.urlCheckCancel
	m.urlCheckCancel = nil
	m.urlCheckMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// clearURLCheck cancels any in-flight scan and wipes all cached results on
// lock, logout, or system sleep.
func (m *AppModel) clearURLCheck() {
	m.cancelURLCheck()
	m.URLCheckBusyID.Set("")
	m.URLCheckProgress.Set(urlcheck.Progress{})
	m.URLCheckReport.Set(urlcheck.Report{})
	m.URLCheckPhase.Set(URLCheckIdle)
}

// OpenURLCheckItem jumps from a dead URL result row to the item in the Vault.
func (m *AppModel) OpenURLCheckItem(cx *core.Scope, id string) {
	m.GuardDirty(cx, func() {
		filter := state.SearchFilter{Category: state.FilterAll}
		if c, err := m.Core.GetCipher(id); err == nil && c.ArchivedDate != nil {
			filter = state.SearchFilter{Category: state.FilterArchive}
		}
		cx.Batch(func() {
			m.SearchQuery.Set("")
			m.SetSidebarFilter(filter)
			m.SelectCipher(cx, id)
		})
	})
}

// TrashURLCheckItem moves a dead Login item to Trash when online and writable.
func (m *AppModel) TrashURLCheckItem(id string) {
	if m.LockState.Get() != state.StatusUnlocked || m.SyncState.Get() == SyncOffline || m.LocalOnly.Get() || m.URLCheckBusyID.Get() != "" {
		return
	}
	c, err := m.Core.GetCipher(id)
	if err != nil || c.DeletedDate != nil || m.CipherReadOnly(c) {
		return
	}
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	m.ResetIdleTimer()
	gen := m.LockGeneration()
	m.URLCheckBusyID.Set(id)

	go func() {
		defer cancel()
		err := m.Core.SoftDeleteCipher(ctx, id)
		if m.LockGeneration() != gen {
			return
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.URLCheckBusyID.Set("")
			var lc *state.LocalCopyError
			if err != nil && !errors.As(err, &lc) {
				m.ShowToast(ui.ToastError, "Move to Trash failed", friendlyError(err))
				return
			}
			m.removeURLCheckItem(id)
			if m.SelectedID.Get() == id {
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
			}
			m.RefreshVaultData()
			if lc != nil {
				m.ShowLocalCopyWarning("Moved to Trash")
				return
			}
			m.ShowToast(ui.ToastInfo, "Moved to Trash", "")
		})
	}()
}

func (m *AppModel) removeURLCheckItem(id string) {
	r := m.URLCheckReport.Get()
	if len(r.Dead) == 0 {
		return
	}
	r.Dead = slices.DeleteFunc(slices.Clone(r.Dead), func(it urlcheck.DeadItem) bool {
		return it.CipherID == id
	})
	m.URLCheckReport.Set(r)
}

// pruneURLCheckResults removes items from the current scan report that were
// deleted or trashed elsewhere in the vault, without triggering any network scan.
func (m *AppModel) pruneURLCheckResults() {
	if m.URLCheckPhase.Get() != URLCheckDone {
		return
	}
	r := m.URLCheckReport.Get()
	if len(r.Dead) == 0 {
		return
	}
	changed := false
	kept := make([]urlcheck.DeadItem, 0, len(r.Dead))
	for _, it := range r.Dead {
		c, err := m.Core.GetCipher(it.CipherID)
		if err != nil || c.DeletedDate != nil {
			changed = true
			continue
		}
		ro := c.ReadOnly || m.CipherReadOnly(c)
		if ro != it.ReadOnly || c.Name != it.Name {
			it.ReadOnly = ro
			it.Name = c.Name
			changed = true
		}
		kept = append(kept, it)
	}
	if changed {
		r.Dead = kept
		m.URLCheckReport.Set(r)
	}
}

func urlCheckBadgeVariant(r urlcheck.Reason) ui.BadgeVariant {
	switch r {
	case urlcheck.ReasonDNSNotFound, urlcheck.ReasonRefused, urlcheck.ReasonNotFound, urlcheck.ReasonInvalidURL:
		return ui.BadgeDanger
	case urlcheck.ReasonTimeout, urlcheck.ReasonTLSError, urlcheck.ReasonServerError:
		return ui.BadgeWarn
	default:
		return ui.BadgeNeutral
	}
}

func URLCheckView(cx *core.Scope, m *AppModel) core.Node {
	return core.Scroll{
		TestID: "urlcheck-view",
		Class:  "flex-1 bg-gv-canvas",
		Children: []core.Node{
			core.Dynamic(func(cx *core.Scope) core.Node {
				var body core.Node
				switch m.URLCheckPhase.Get() {
				case URLCheckScanning:
					body = urlCheckScanningView(cx, m)
				case URLCheckDone:
					body = urlCheckResultsView(cx, m)
				default:
					body = urlCheckIdleView(cx, m)
				}
				return core.View{
					Class:    "w-full max-w-[680px] self-center px-7 pt-6 pb-10 gap-5",
					Children: []core.Node{body},
				}
			}),
		},
	}
}

func urlCheckIdleView(cx *core.Scope, m *AppModel) core.Node {
	return card(core.View{
		TestID: "urlcheck-idle",
		Class:  "px-6 py-7 items-center gap-4",
		Children: []core.Node{
			core.View{
				Class: "w-[44px] h-[44px] rounded-[12px] items-center justify-center bg-gv-accent-soft",
				Children: []core.Node{
					icon(lucide.GlobeCheck(), 22, "text-gv-accent"),
				},
			},
			core.View{
				Class: "items-center gap-1.5 max-w-[460px]",
				Children: []core.Node{
					core.Text{
						Class:   "text-[15px] font-semibold text-gv-fg text-center",
						Content: "Website Check",
					},
					core.Text{
						TestID:  "urlcheck-privacy-notice",
						Class:   "text-[12.5px] leading-[18px] text-gv-fg2 text-center",
						Content: urlCheckPrivacyNotice,
					},
				},
			},
			ui.Button{
				TestID:  "urlcheck-scan-btn",
				Text:    "Scan Websites",
				Icon:    lucide.GlobeCheck,
				Variant: ui.ButtonPrimary,
				OnPress: m.StartURLCheck,
			},
		},
	})
}

func urlCheckScanningView(cx *core.Scope, m *AppModel) core.Node {
	return card(core.View{
		TestID: "urlcheck-scanning",
		Class:  "px-6 py-6 gap-4",
		Children: []core.Node{
			core.View{
				Class: "flex-row items-center gap-3",
				Children: []core.Node{
					icon(lucide.GlobeCheck(), 18, "text-gv-accent"),
					core.View{
						Class: "flex-1 gap-[2px]",
						Children: []core.Node{
							core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: "Scanning Websites…"},
							core.Text{
								TestID: "urlcheck-progress-text",
								Class:  "text-[12px] text-gv-fg2 tabular-nums",
								ContentFunc: func() string {
									p := m.URLCheckProgress.Get()
									if p.Total <= 0 {
										return "Preparing domain list…"
									}
									if p.DeadCount > 0 {
										return fmt.Sprintf("%d / %d domains checked · %d unreachable", p.Checked, p.Total, p.DeadCount)
									}
									return fmt.Sprintf("%d / %d domains checked", p.Checked, p.Total)
								},
							},
						},
					},
					ui.Button{
						TestID:  "urlcheck-cancel-btn",
						Text:    "Cancel",
						Variant: ui.ButtonSecondary,
						Size:    ui.SizeSmall,
						OnPress: m.CancelURLCheck,
					},
				},
			},
			ui.Progress{
				TestID: "urlcheck-progress-bar",
				Label:  "Website scan progress",
				Value: func() float32 {
					p := m.URLCheckProgress.Get()
					if p.Total <= 0 {
						return 0
					}
					return float32(p.Checked) * 100 / float32(p.Total)
				},
				Indeterminate: func() bool {
					return m.URLCheckProgress.Get().Total <= 0
				},
			},
			core.Text{
				Class:   "text-[11.5px] text-gv-fg3",
				Content: "Only hostnames are contacted directly from this device. Major sites and local/private addresses are skipped.",
			},
		},
	})
}

func urlCheckResultsView(cx *core.Scope, m *AppModel) core.Node {
	r := m.URLCheckReport.Get()
	offline := func() bool { return m.SyncState.Get() == SyncOffline || m.LocalOnly.Get() }

	summary := fmt.Sprintf("Checked %d domain(s) · %d major and %d local/private skipped", r.CheckedTargets, r.SkippedWhitelisted, r.SkippedPrivate)
	if len(r.Dead) > 0 {
		summary = fmt.Sprintf("%d unreachable item(s) · %s", len(r.Dead), summary)
	}

	header := core.View{
		TestID: "urlcheck-results-header",
		Class:  "flex-row items-center justify-between gap-3",
		Children: []core.Node{
			core.Text{
				TestID:  "urlcheck-summary",
				Class:   "flex-1 text-[12px] text-gv-fg2",
				Content: summary,
			},
			ui.Button{
				TestID:  "urlcheck-rescan-btn",
				Text:    "Scan Again",
				Icon:    lucide.RefreshCw,
				Variant: ui.ButtonSecondary,
				Size:    ui.SizeSmall,
				OnPress: m.StartURLCheck,
			},
		},
	}

	blocks := []core.Node{header}
	if len(r.Dead) == 0 {
		blocks = append(blocks, card(core.View{
			TestID: "urlcheck-all-clear",
			Class:  "flex-row items-center gap-3 px-4 py-4",
			Children: []core.Node{
				icon(lucide.CircleCheck(), 22, "text-gv-success"),
				core.View{
					Class: "flex-1 gap-[2px]",
					Children: []core.Node{
						core.Text{Class: "text-[14px] font-semibold text-gv-fg", Content: "All websites reachable"},
						core.Text{Class: "text-[12px] text-gv-fg2", Content: "No unreachable login domains were found."},
					},
				},
			},
		}))
	} else {
		rows := make([]core.Node, 0, len(r.Dead))
		for _, item := range r.Dead {
			it := item
			name := strings.TrimSpace(it.Name)
			if name == "" {
				name = "Untitled"
			}
			sub := it.Domain
			if it.Username != "" {
				sub = it.Domain + " · " + it.Username
			}
			rows = append(rows, core.View{
				TestID: "urlcheck-item",
				Class:  "flex-row items-center gap-2 ps-3.5 pe-3 py-2 min-h-[52px]",
				Children: []core.Node{
					core.View{
						TestID:  "urlcheck-open-" + it.CipherID,
						Role:    core.RoleButton,
						Label:   "Open " + name,
						Class:   "flex-1 flex-row items-center gap-3 py-0.5 rounded-[6px] active:bg-gv-fill overflow-hidden",
						OnPress: func(core.PressEvent) { m.OpenURLCheckItem(cx, it.CipherID) },
						Children: []core.Node{
							itemEmblem(name, api.CipherTypeLogin, "", 28),
							core.View{
								Class: "flex-1 gap-[2px] overflow-hidden",
								Children: []core.Node{
									core.Text{MaxLines: 1, Class: "text-[13.5px] font-medium text-gv-fg", Content: name},
									core.Text{MaxLines: 1, Class: "text-[11.5px] text-gv-fg3", Content: sub},
								},
							},
							core.View{
								TestID: "urlcheck-badge-" + it.CipherID,
								Children: []core.Node{
									ui.Badge{
										Text:    it.ReasonLabel(),
										Variant: urlCheckBadgeVariant(it.Reason),
									},
								},
							},
						},
					},
					ui.Button{
						TestID:   "urlcheck-trash-" + it.CipherID,
						Text:     "Move to Trash",
						Icon:     lucide.Trash,
						Variant:  ui.ButtonGhost,
						Size:     ui.SizeSmall,
						Tint:     func() core.Color { return themeColor(cx, "gv-danger") },
						Busy:     func() bool { return m.URLCheckBusyID.Get() == it.CipherID },
						Disabled: func() bool { return offline() || it.ReadOnly || m.URLCheckBusyID.Get() != "" },
						OnPress:  func() { m.TrashURLCheckItem(it.CipherID) },
					},
				},
			})
		}
		blocks = append(blocks, section("Unreachable Websites", card(rows...)))
	}
	blocks = append(blocks, core.Text{
		Class:   "px-1 text-[11.5px] text-gv-fg3",
		Content: "Click an item to review or update its website in your vault.",
	})

	return core.View{
		TestID:   "urlcheck-results",
		Class:    "gap-4",
		Children: blocks,
	}
}
