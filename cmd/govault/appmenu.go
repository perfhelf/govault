package main

import (
	"github.com/nsgo-dev/nsgo/desktop"
	"github.com/txchen/govault/internal/vaultcore/i18n"
)

// applicationMenu is the menu bar for goos. Check for Updates does not depend
// on the vault, so it works while logged out or locked and without the
// tray icon.
//
// On macOS it keeps the standard app, Edit and Window menus and their
// system shortcuts. The edit roles have no handlers of their own, so they go
// down the responder chain exactly as NSGo's default menu does. Elsewhere the
// window draws the menu bar itself; it stays hidden until Alt (see
// OpenMainWindow), so it only offers the app items.
func applicationMenu(goos string, checkUpdates func()) []desktop.MenuItem {
	return applicationMenuLocalized(goos, nil, checkUpdates)
}

func applicationMenuLocalized(goos string, tr func(string) string, checkUpdates func()) []desktop.MenuItem {
	if tr == nil {
		tr = i18n.NewCatalog(i18n.DefaultLocale).T
	}
	update := desktop.MenuItem{Label: tr("menu.check_updates"), OnSelect: checkUpdates}
	if goos != "darwin" {
		return []desktop.MenuItem{{Label: "GoVault", Items: []desktop.MenuItem{
			update,
			{Separator: true},
			{Role: desktop.MenuQuit},
		}}}
	}
	return []desktop.MenuItem{
		{Label: "GoVault", Items: []desktop.MenuItem{
			{Role: desktop.MenuAbout},
			{Separator: true},
			update,
			{Separator: true},
			{Role: desktop.MenuHide},
			{Role: desktop.MenuHideOthers},
			{Role: desktop.MenuShowAll},
			{Separator: true},
			{Role: desktop.MenuQuit},
		}},
		{Label: tr("menu.edit"), Items: []desktop.MenuItem{
			{Role: desktop.MenuUndo},
			{Role: desktop.MenuRedo},
			{Separator: true},
			{Role: desktop.MenuCut},
			{Role: desktop.MenuCopy},
			{Role: desktop.MenuPaste},
			{Role: desktop.MenuSelectAll},
		}},
		{Label: tr("menu.window"), Role: desktop.MenuWindowMenu, Items: []desktop.MenuItem{
			{Role: desktop.MenuMinimize},
			{Role: desktop.MenuZoom},
			{Separator: true},
			{Role: desktop.MenuClose},
		}},
	}
}
