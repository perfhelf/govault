# GoVault Upstream PR Roadmap (`txchen/govault`)

This document inventories the 7 feature and localization branches prepared on top of `master` (`277686dc4ae62e571dd18359720670d9f1f76060`), their recommended upstream submission sequence, security and privacy invariants, architectural fit, and the unified `integration/all` branch that combines and cross-polishes all of them.

---

## Merge & Submission Dependency Graph

```text
master (277686dc4ae62e571dd18359720670d9f1f76060)
├── 1. pr/apikey-login (6546fff905d9fded5b733a7b258909ca2b24f6b6)
│      └── 2. pr/login-profile (6facb85e4dc6563a995ae967a6826f146dd80e5d)
├── 3. pr/batch-ops (784719b2e10ed788e1d1aa070987f3c5cae891a6)       [independent]
├── 4. pr/health-plus (fbc043deeb22caf71d91e57da23c5e4edfc5446f)     [independent]
├── 5. pr/dedup (e39d51f2b9826aadca40da5270047e16fbeb37f4)           [independent]
├── 6. pr/url-check (821d863c8eac9e9cbb8cacb7b4ecfc62ed31755c)       [independent]
└── 7. pr/i18n (1ab4ef0e87094d8be6cb9577a667443c80915987)            [submit last or rebase to cover 1–6]

integration/all
└── Merges 1 → 2 → 3 → 4 → 5 → 6 → 7 + cross-PR 6-language parity, RTL completion, and Dead URLs × Batch Ops wiring
```

### Recommended Submission Order

1. **`pr/apikey-login`** (`base: master`) — submit first; `pr/login-profile` stacks on its API-key auth mode.
2. **`pr/login-profile`** (`base: pr/apikey-login` while unmerged, then rebase onto `master`) — stacked because `.gvprofile` optionally stores API-key credentials alongside password auth metadata.
3. **`pr/batch-ops`**, **`pr/health-plus`**, **`pr/dedup`**, **`pr/url-check`** (`base: master`) — functionally independent of each other and can be reviewed or merged in parallel in any order (minor merge touchpoints exist only in shared navigation/dialog/model wiring).
4. **`pr/i18n`** (`base: master` for core localization, or rebased after 1–6) — landing feature PRs first (or following `integration/all`) avoids untranslated strings on newly added views; when submitted independently against `master`, follow-up locale keys cleanly track feature additions.

---

## Branch Inventory

### 1. `pr/apikey-login`
- **Commit:** `6546fff905d9fded5b733a7b258909ca2b24f6b6`
- **Base:** `master` (`277686dc4ae62e571dd18359720670d9f1f76060`) · **Submission order:** `#1`
- **Suggested Upstream PR Title:** `feat(govault): support Personal API Key sign-in`
- **Suggested Upstream PR Description:** Adds Bitwarden/Vaultwarden Personal API Key authentication (`grant_type=client_credentials`) alongside password-based sign-in so accounts with external 2FA or strict API workflows can authenticate with `client_id` / `client_secret` while continuing to derive and verify vault encryption keys locally from the user's Master Password.
- **Scope & Files (11 files):**
  - `internal/vaultcore/api/`: `client.go`, `types.go`, `client_test.go`
  - `internal/vaultcore/state/`: `service.go`, `types.go`, `apikey_test.go`
  - `cmd/govault/ui/`: `login.go`, `model.go`, `app_test.go`, `apikey_login_test.go`
  - `cmd/govault/demo/demo.go`
- **Verified Security & Privacy Invariants:**
  - Server token exchange uses `client_credentials` (`scope=api offline_access`) and never sends the user's Master Password or PBKDF2/Argon2id auth hash to `/identity/connect/token`.
  - Master Password remains strictly local: `TokenResponse.KDFConfig()` supplies Argon2id/PBKDF2 parameters (falling back to `/api/accounts/prelogin` when omitted) for local key derivation and verification against synced `Profile.Key`.
  - Client Secret input is concealed and never persisted in plaintext or exposed in error messages.
  - Non-HTTPS server URLs trigger explicit insecure-connection warnings before submission.
- **Why It Fits `txchen/govault`:** Keeps HTTP protocol details and session token handling inside `internal/vaultcore/api` and `internal/vaultcore/state` (zero GUI/CGO dependencies), preserving the strict separation between `vaultcore` and `cmd/govault/ui`.

---

### 2. `pr/login-profile`
- **Commit:** `6facb85e4dc6563a995ae967a6826f146dd80e5d`
- **Base:** `pr/apikey-login` (`6546fff905d9fded5b733a7b258909ca2b24f6b6`) · **Submission order:** `#2`
- **Suggested Upstream PR Title:** `feat(govault): support encrypted .gvprofile login profiles`
- **Suggested Upstream PR Description:** Introduces encrypted, portable `.gvprofile` login profile containers for importing/exporting server URL, email, and optional Personal API Key credentials via drag-and-drop or file picker, accelerating multi-device or self-hosted server onboarding without ever storing Master Passwords.
- **Scope & Files (beyond `pr/apikey-login`, 9 touched files including 2 new packages/files):**
  - `internal/vaultcore/loginprofile/`: `profile.go`, `profile_test.go`
  - `cmd/govault/ui/`: `loginprofile.go`, `login_profile_test.go`, `attachments.go`, `login.go`, `mainview.go`, `model.go`, `settings.go`
- **Verified Security & Privacy Invariants:**
  - Format `"govault-login-profile"` v1 uses AES-GCM with bound AAD (`"govault-login-profile-v1"`), random salt/nonce, and Argon2id `DefaultKDF` (3 iterations, 64 MiB, parallelism 4) or PBKDF2-SHA256, enforcing a minimum 8-rune passphrase and 64 KiB file size cap (`MaxFileSize`).
  - `Profile` struct contains zero Master Password field, and JSON decoding rejects unknown fields strictly (`DisallowUnknownFields`).
  - Locked-vault unlock/drop checks reject profiles whose `ServerURL` or `Email` does not match the active locked session.
  - Exported profiles are saved with owner-only (`0600`) file permissions.
- **Why It Fits `txchen/govault`:** Follows GoVault's zero-plaintext-on-disk philosophy by isolating all cryptographic container encoding/decoding in `internal/vaultcore/loginprofile`, keeping `cmd/govault/ui` responsible only for modal prompts and signal bindings.

---

### 3. `pr/batch-ops`
- **Commit:** `784719b2e10ed788e1d1aa070987f3c5cae891a6`
- **Base:** `master` (`277686dc4ae62e571dd18359720670d9f1f76060`) · **Submission order:** `#3`
- **Suggested Upstream PR Title:** `feat(govault): add multi-select and bulk vault operations`
- **Suggested Upstream PR Description:** Adds multi-select mode to the vault item list and Trash view along with an inline action bar supporting bulk Move to Folder, Move to Trash, Restore (original or chosen folder), and strict permanent Delete.
- **Scope & Files (15 files):**
  - `internal/vaultcore/api/`: `client.go`, `bulk_test.go`
  - `internal/vaultcore/state/`: `service.go`, `search.go`, `types.go`, `bulk_test.go`, `service_test.go`
  - `cmd/govault/ui/`: `batch.go`, `batch_test.go`, `vault.go`, `mainview.go`, `model.go`, `nav.go`, `app_test.go`
  - `cmd/govault/demo/demo.go`
- **Verified Security & Privacy Invariants:**
  - Read-only organization items (`SummaryReadOnly` / `CipherReadOnly`) cannot be checked in UI, are skipped by `Select All`, and are rejected by service-layer `Bulk*` methods.
  - Mutations are disabled in both UI and state service when `Offline` or `LocalOnly`.
  - Bulk Move to Trash and Permanent Delete require explicit confirmation alerts (destructive alert framing for non-recoverable permanent delete).
  - Server-success / local-snapshot-write failures surface explicit `LocalCopyError` warnings; selection clears cleanly on lock, logout, route change, filter switch, and `Escape`.
- **Why It Fits `txchen/govault`:** Mirrors GoVault's existing single-item service mutation path (`ensureOnlineMutable` + atomic encrypted snapshot save + optimistic signal refresh) with zero extra dependencies or SQLite state.

---

### 4. `pr/health-plus`
- **Commit:** `fbc043deeb22caf71d91e57da23c5e4edfc5446f`
- **Base:** `master` (`277686dc4ae62e571dd18359720670d9f1f76060`) · **Submission order:** `#4`
- **Suggested Upstream PR Title:** `feat(govault): expand local vault health checks and weighted health score`
- **Suggested Upstream PR Description:** Expands Vault Health with a weighted 0–100 `Vault Health Score` (Strong / Fair / Needs Attention / At Risk), risk-tier breakdown, and 9 actionable inspection tiles covering weak/reused/stale (>1y)/empty passwords, expiring cards, unsecured HTTP logins, missing titles/URIs, and undecryptable items.
- **Scope & Files (6 files):**
  - `internal/vaultcore/health/`: `health.go`, `health_test.go`
  - `cmd/govault/ui/`: `health.go`, `health_test.go`, `model.go`, `nav.go`
- **Verified Security & Privacy Invariants:**
  - **100% local on-device evaluation:** `internal/vaultcore/health` never performs network requests (no HIBP queries or telemetry) and never writes findings to disk.
  - Properly excludes trashed and archived items from active hygiene scoring while surfacing undecryptable personal ciphers read-only with clear server remediation instructions.
- **Why It Fits `txchen/govault`:** Keeps all security heuristics and scoring arithmetic in pure, unit-tested `internal/vaultcore/health`, enabling fast reactive recalculation on unlock/edit with zero UI-thread stalling.

---

### 5. `pr/dedup`
- **Commit:** `e39d51f2b9826aadca40da5270047e16fbeb37f4`
- **Base:** `master` (`277686dc4ae62e571dd18359720670d9f1f76060`) · **Submission order:** `#5`
- **Suggested Upstream PR Title:** `feat(govault): add smart duplicate login detection and safe merge`
- **Suggested Upstream PR Description:** Adds a local duplicate analyzer and review UI (`Duplicates`) that groups Exact and Same-Site duplicate logins, lets users pick which item to keep, optionally simplifies URIs to base domains, merges supplemental fields without data loss, and moves redundant entries safely to Trash.
- **Scope & Files (10 files):**
  - `internal/vaultcore/dedup/`: `analyze.go`, `plan.go`, `uri.go`, `dedup_test.go`
  - `cmd/govault/ui/`: `dedup.go`, `dedup_test.go`, `mainview.go`, `model.go`, `nav.go`, `vault.go`
- **Verified Security & Privacy Invariants:**
  - Detection (`Analyze`) and plan generation run strictly in-memory on device with zero network calls.
  - Never touches read-only organization items or `HidePassword` items (groups are visibly blocked and non-selectable).
  - Separates clean `Path A · Pure Delete` from `Path B · Merge`, highlights differing fields (and explicitly warns when usernames differ in Same-Site groups), preserves passkeys, attachments, TOTP, custom fields, Favorite, and Reprompt flags, and gates Master-Password-protected merges behind reprompt verification.
  - Redundant items move to Trash (30-day server recovery), never hard-deleted, with cancel support and `LocalCopyError` surfacing.
- **Why It Fits `txchen/govault`:** Pure-Go planner (`internal/vaultcore/dedup`) produces explicit, testable mutation plans executed via standard `vaultcore/state` cipher APIs, keeping destructive edge cases auditable outside UI code.

---

### 6. `pr/url-check`
- **Commit:** `821d863c8eac9e9cbb8cacb7b4ecfc62ed31755c`
- **Base:** `master` (`277686dc4ae62e571dd18359720670d9f1f76060`) · **Submission order:** `#6`
- **Suggested Upstream PR Title:** `feat(govault): add opt-in local website reachability scanner`
- **Suggested Upstream PR Description:** Adds an explicit opt-in `Website Check` tool that probes whether active Login website domains remain reachable from the user's device, flags dead/invalid entries (`DNS not found`, `Connection refused`, `HTTP 4xx/5xx`, `TLS error`, `Timeout`, `Invalid URL`), lets users jump straight to edit them, or move them to Trash.
- **Scope & Files (8 files):**
  - `internal/vaultcore/urlcheck/`: `urlcheck.go`, `whitelist.go`, `urlcheck_test.go`
  - `cmd/govault/ui/`: `urlcheck.go`, `urlcheck_test.go`, `mainview.go`, `model.go`, `vault.go`
- **Verified Security & Privacy Invariants:**
  - **Strictly opt-in:** Never starts automatically on sign-in, unlock, sync, or timers.
  - **Origin-only probing:** Sends requests exclusively to `scheme://host[:port]/`, stripping all URL paths, queries, fragments, credentials, and cookies; vault secrets never leave the device.
  - Skips well-known major domains (`whitelist.go` `majorDomains`) and private/loopback/local addresses; bounds probes with `MaxProbeBodyBytes` (1 KiB), `DefaultMaxRedirects` (5), `DefaultTimeout` (5s), and bounded concurrency (`8`).
  - Cancels active probes via session `context.Context` and wipes cached results immediately on lock, logout, sleep, or `Escape`.
- **Why It Fits `txchen/govault`:** Implements bounded stdlib `net/http` probing in `internal/vaultcore/urlcheck` (zero CGO, cross-platform macOS/Linux/Windows) wired into `AppModel` lock-generation and `SessionContext` guards.

---

### 7. `pr/i18n`
- **Commits:** `f96b413145dd4a20a39fe577a667443c80915987` + `1ab4ef0e87094d8be6cb9577a667443c80915987`
- **Base:** `master` (`277686dc4ae62e571dd18359720670d9f1f76060`) · **Submission order:** `#7`
- **Suggested Upstream PR Title:** `feat(govault): add 6-language localization and RTL layout support`
- **Suggested Upstream PR Description:** Introduces embedded translations for English (`en`), Simplified Chinese (`zh-CN`), French (`fr`), German (`de`), Spanish (`es`), and Arabic (`ar`) with system locale auto-detection, live runtime switching across main window/tray/app menu, and full RTL layout mirroring for Arabic.
- **Scope & Files (32 files):**
  - `internal/vaultcore/i18n/`: `i18n.go`, `detect.go`, `detect_other.go`, `detect_windows.go`, `i18n_test.go`, `locales/{en,zh-CN,fr,de,es,ar}.json`
  - `cmd/govault/`: `app.go`, `appmenu.go`, `appmenu_test.go`
  - `cmd/govault/ui/`: `i18n.go`, `i18n_test.go`, plus localization & logical CSS updates across `attachments.go`, `editor.go`, `favicons.go`, `generator.go`, `health.go`, `import.go`, `lock.go`, `login.go`, `mainview.go`, `model.go`, `passkey.go`, `settings.go`, `theme.go`, `trash_clone.go`, `twofactor.go`, `vault.go`
- **Verified Security & Privacy Invariants:**
  - Uses Go `embed.FS` JSON catalogs with zero external files/network calls and zero CGO dependencies (`internal/vaultcore/i18n`).
  - Enforces strict build-time test parity: all 6 locale JSON files must contain identical key sets and identical ordered `fmt` format verbs (`TestAllLocalesParseAndMatchEnglishKeysAndFormatVerbs`), plus static code check guaranteeing every UI `T`/`Tf` key exists in `en.json` (`TestAllReferencedI18nKeysExist`).
  - Uses logical Tailwind directional utilities (`ps-`, `pe-`, `ms-`, `me-`, `start-`, `end-`, `text-start`, `text-end`), `rtlSVG`/`rtlIcon` chevron mirroring, and loop-free auto-locale updates (`1ab4ef0`).
- **Why It Fits `txchen/govault`:** Keeps locale loading and POSIX/BCP-47 detection strictly inside `internal/vaultcore/i18n`, allowing `cmd/govault/ui` to reactively re-render labels, menus, dates, and RTL layout direction with zero restart required.

---

## Unified Branch: `integration/all`

- **Base:** Exact sequential merge of `pr/apikey-login` → `pr/login-profile` → `pr/batch-ops` → `pr/health-plus` → `pr/dedup` → `pr/url-check` → `pr/i18n` onto `master` (`277686dc4ae62e571dd18359720670d9f1f76060`).
- **Cross-PR Integration Polish Applied:**
  1. **Unified Error & Helper Routing:** Consolidated all PR error mapping into localized `m.friendlyError` (`cmd/govault/ui/i18n.go`), preserved all PR `Effect` / `Lock` / `Logout` / `RefreshVaultData` lifecycle hooks (`model.go`), and preserved Archive sidebar item count badge alongside all new tool badges (`vault.go`).
  2. **100% 6-Language Parity & RTL Completion Across New PRs:** Externalized every user-facing string across `pr/apikey-login`, `pr/login-profile`, `pr/batch-ops`, `pr/health-plus`, `pr/dedup`, and `pr/url-check` into all 6 locale files (`en`, `zh-CN`, `fr`, `de`, `es`, `ar` — `804` keys each, exact key and format-verb parity), wired `m.T`/`m.Tf`, converted the last physical directional padding (`dedup.go` `pl-4 pr-3` → `ps-4 pe-3`) and directional icon (`dedup.go` `ChevronRight` → `rtlSVG`), and added `TestI18nNewPRSurfacesLocalizedAndRTL`.
  3. **Dead URLs × Batch Ops Integration:** Added multi-select checkboxes (`urlcheck-check-*`), `Select All` / `Clear` toolbar (`urlcheck-batch-bar`), bulk **Move to Folder…** via the shared `batch-folder-dialog` (`BatchFolderURLCheckMove`), and bulk **Move to Trash** with destructive confirmation directly in `URLCheckView`. Preserves `Offline`, `LocalOnly`, and `ReadOnly` guards, prunes trashed/edited rows from `URLCheckReport.Dead`, clears selection cleanly on `Escape`, route switch, rescan, lock, and logout, and is verified end-to-end by `TestURLCheckBatchMoveToFolderAndTrashAndGuards`.
