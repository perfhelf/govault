package ui

import (
	"github.com/nsgo-dev/nsgo/core"
	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/state"
)

type HealthCategory string

const (
	HealthAll         HealthCategory = ""
	HealthReused      HealthCategory = "reused"
	HealthWeak        HealthCategory = "weak"
	HealthEmpty       HealthCategory = "empty"
	HealthStale       HealthCategory = "stale"
	HealthCards       HealthCategory = "cards"
	HealthUnsecured   HealthCategory = "unsecured"
	HealthMissingURI  HealthCategory = "missing-uri"
	HealthMissingName HealthCategory = "missing-name"
	HealthUnreadable  HealthCategory = "unreadable"
)

// NavState is one place the user visited, as Back and Forward restore it.
type NavState struct {
	Route        MainRoute
	Filter       state.SearchFilter
	SelectedID   string
	HealthFilter HealthCategory
}

const maxNavHistory = 100

type navHistory struct {
	back, forward []NavState
	current       NavState
}

func filterEqual(a, b state.SearchFilter) bool {
	if a.Category != b.Category || a.FolderID != b.FolderID || a.OrganizationID != b.OrganizationID || a.CollectionID != b.CollectionID {
		return false
	}
	if (a.Type == nil) != (b.Type == nil) {
		return false
	}
	return a.Type == nil || *a.Type == *b.Type
}

func (a NavState) equal(b NavState) bool {
	return a.Route == b.Route && a.SelectedID == b.SelectedID && a.HealthFilter == b.HealthFilter && filterEqual(a.Filter, b.Filter)
}

func cloneFilter(f state.SearchFilter) state.SearchFilter {
	if f.Type != nil {
		t := api.CipherType(*f.Type)
		f.Type = &t
	}
	return f
}

func (m *AppModel) navState() NavState {
	return NavState{
		Route:        m.Route.Get(),
		Filter:       cloneFilter(m.SidebarFilter.Get()),
		SelectedID:   m.SelectedID.Get(),
		HealthFilter: m.HealthFilter.Get(),
	}
}

// setupNavigation records every change of place in the unlocked vault. A
// batch of changes, such as opening an item from Vault Health, is one step.
func (m *AppModel) setupNavigation() {
	m.Scope.Effect(func() {
		cur := m.navState()
		if m.LockState.Get() != state.StatusUnlocked {
			m.Scope.Untrack(m.clearHistory)
			return
		}
		m.Scope.Untrack(func() {
			if cur.equal(m.nav.current) {
				return
			}
			m.nav.back = append(m.nav.back, m.nav.current)
			if len(m.nav.back) > maxNavHistory {
				m.nav.back = m.nav.back[len(m.nav.back)-maxNavHistory:]
			}
			m.nav.forward = nil
			m.nav.current = cur
			m.updateNavSignals()
		})
	})
}

func (m *AppModel) updateNavSignals() {
	m.CanGoBack.Set(len(m.nav.back) > 0)
	m.CanGoForward.Set(len(m.nav.forward) > 0)
}

func (m *AppModel) clearHistory() {
	m.nav = navHistory{current: NavState{Filter: state.SearchFilter{Category: state.FilterAll}}}
	m.updateNavSignals()
}

// SetMainWindowVisible tracks whether the main window is on screen. Showing a
// locked vault again lets Touch ID prompt automatically once more.
func (m *AppModel) SetMainWindowVisible(visible bool) {
	if visible && !m.MainWinVisible.GetUntracked() && m.LockState.GetUntracked() == state.StatusLocked {
		m.LockAutoFired = false
	}
	m.MainWinVisible.Set(visible)
}

func (m *AppModel) GoBack(cx *core.Scope) { m.navigate(cx, -1) }

func (m *AppModel) GoForward(cx *core.Scope) { m.navigate(cx, 1) }

// GoBackFromSystem and GoForwardFromSystem serve mouse side buttons, which
// arrive outside any window scope.
func (m *AppModel) GoBackFromSystem()    { m.navigate(m.navScope(), -1) }
func (m *AppModel) GoForwardFromSystem() { m.navigate(m.navScope(), 1) }

func (m *AppModel) navScope() *core.Scope {
	if m.windowScope != nil {
		return m.windowScope
	}
	return m.Scope
}

func (m *AppModel) navigate(cx *core.Scope, dir int) {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	if (dir < 0 && len(m.nav.back) == 0) || (dir > 0 && len(m.nav.forward) == 0) {
		return
	}
	m.GuardDirty(cx, func() {
		var target NavState
		if dir < 0 {
			target = m.nav.back[len(m.nav.back)-1]
			m.nav.back = m.nav.back[:len(m.nav.back)-1]
			m.nav.forward = append(m.nav.forward, m.nav.current)
		} else {
			target = m.nav.forward[len(m.nav.forward)-1]
			m.nav.forward = m.nav.forward[:len(m.nav.forward)-1]
			m.nav.back = append(m.nav.back, m.nav.current)
		}
		m.ResetIdleTimer()
		cx.Batch(func() {
			m.Route.Set(target.Route)
			m.SidebarFilter.Set(cloneFilter(target.Filter))
			m.HealthFilter.Set(target.HealthFilter)
			m.SearchQuery.Set("")
			m.SearchAll.Set(false)
			m.RefreshFilteredList()
			m.SelectCipher(cx, target.SelectedID)
			m.nav.current = core.Untracked(cx, m.navState)
		})
		m.updateNavSignals()
	})
}
