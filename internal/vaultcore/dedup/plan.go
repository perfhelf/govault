package dedup

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/state"
)

type PlanOptions struct {
	SimplifyURLs bool
}

type GroupSelection struct {
	Group         Group
	KeepCipherID  string
	ItemIDs       []string
	TitleOverride string
}

type OpMode int

const (
	OpPureDelete OpMode = iota
	OpInPlace
	OpCreateThenDelete
)

type PlanGroup struct {
	GroupID        string
	Label          string
	Mode           OpMode
	KeepID         string
	MergedCipher   *state.Cipher
	DeleteIDs      []string
	HasPasskeys    bool
	HasAttachments bool
}

type PlanError struct {
	GroupID string
	Label   string
	Reason  string
}

type Plan struct {
	Groups []PlanGroup
	Errors []PlanError
}

// BuildPlan constructs an execution plan from selected duplicate groups.
//
// Safety invariants:
//   - Groups containing ReadOnly or HidePassword items are refused.
//   - Items with differing OrganizationID are never merged.
//   - Attachments are never orphaned: if the keep item holds attachments and
//     no removed item holds attachments, Path B uses an in-place SaveCipher
//     update on the keep item. If any removed item has attachments, the group
//     is refused so no attachment is ever soft-deleted.
//   - All other Path B merges (including passkey-holding merges) use strict
//     Create-Then-Delete with ID == "" while preserving Key, SealedKeyID,
//     ProvenSealed, Extra, Login.Fido2Credentials, OrganizationID, and
//     CollectionIDs.
//   - Every deletion is a soft-delete (Trash, 30-day recovery).
func BuildPlan(selections []GroupSelection, opts PlanOptions) Plan {
	var plan Plan

	for _, sel := range selections {
		g := sel.Group
		items := selectGroupItems(g.Items, sel.ItemIDs)
		if len(items) < 2 {
			if len(sel.ItemIDs) > 0 {
				plan.Errors = append(plan.Errors, PlanError{
					GroupID: g.ID,
					Label:   g.Label,
					Reason:  "Select at least 2 items to merge",
				})
			}
			continue
		}

		if g.BlockedReason != "" {
			plan.Errors = append(plan.Errors, PlanError{
				GroupID: g.ID,
				Label:   g.Label,
				Reason:  g.BlockedReason,
			})
			continue
		}
		if reason := validateItemsSafety(items); reason != "" {
			plan.Errors = append(plan.Errors, PlanError{
				GroupID: g.ID,
				Label:   g.Label,
				Reason:  reason,
			})
			continue
		}

		sorted := SortByQuality(items)
		keepItem := sorted[0]
		if sel.KeepCipherID != "" {
			found := false
			for _, it := range sorted {
				if it.ID == sel.KeepCipherID {
					keepItem = it
					found = true
					break
				}
			}
			if !found {
				plan.Errors = append(plan.Errors, PlanError{
					GroupID: g.ID,
					Label:   g.Label,
					Reason:  fmt.Sprintf("Keep item %q not found in group", sel.KeepCipherID),
				})
				continue
			}
		}

		var removeItems []*state.Cipher
		var removeIDs []string
		var allIDs []string
		for _, it := range sorted {
			allIDs = append(allIDs, it.ID)
			if it.ID != keepItem.ID {
				removeItems = append(removeItems, it)
				removeIDs = append(removeIDs, it.ID)
			}
		}
		if len(removeItems) == 0 {
			continue
		}

		// Protect attachments: never soft-delete an item that carries attachments.
		removeHasAttachments := slices.ContainsFunc(removeItems, func(c *state.Cipher) bool {
			return len(c.Attachments) > 0
		})
		if removeHasAttachments {
			reason := "Cannot delete an item with attachments; keep the attachment-bearing item instead"
			if len(keepItem.Attachments) > 0 {
				reason = "Multiple items have attachments; merge skipped to avoid losing attachments"
			}
			plan.Errors = append(plan.Errors, PlanError{
				GroupID: g.ID,
				Label:   g.Label,
				Reason:  reason,
			})
			continue
		}

		keepHasAttachments := len(keepItem.Attachments) > 0
		pureDelete, _ := analyzeGroupDiffs(sorted)
		override := strings.TrimSpace(sel.TitleOverride)
		titleChanged := override != "" && override != strings.TrimSpace(keepItem.Name)

		if pureDelete && !titleChanged && !keepHasAttachments {
			plan.Groups = append(plan.Groups, PlanGroup{
				GroupID:        g.ID,
				Label:          g.Label,
				Mode:           OpPureDelete,
				KeepID:         keepItem.ID,
				DeleteIDs:      removeIDs,
				HasPasskeys:    passkeyCount(keepItem) > 0,
				HasAttachments: false,
			})
			continue
		}

		merged, err := buildMergedCipher(keepItem, removeItems, override, opts)
		if err != nil {
			plan.Errors = append(plan.Errors, PlanError{
				GroupID: g.ID,
				Label:   g.Label,
				Reason:  err.Error(),
			})
			continue
		}

		if keepHasAttachments {
			// In-place update on the attachment-bearing keep item preserves
			// its server-side attachments, then soft-deletes duplicates.
			plan.Groups = append(plan.Groups, PlanGroup{
				GroupID:        g.ID,
				Label:          g.Label,
				Mode:           OpInPlace,
				KeepID:         keepItem.ID,
				MergedCipher:   merged,
				DeleteIDs:      removeIDs,
				HasPasskeys:    passkeyCount(merged) > 0,
				HasAttachments: true,
			})
			continue
		}

		// Path B (standard and passkey-holding merges): Create-Then-Delete.
		clearForCreate(merged)
		plan.Groups = append(plan.Groups, PlanGroup{
			GroupID:        g.ID,
			Label:          g.Label,
			Mode:           OpCreateThenDelete,
			MergedCipher:   merged,
			DeleteIDs:      allIDs,
			HasPasskeys:    passkeyCount(merged) > 0,
			HasAttachments: false,
		})
	}

	return plan
}

func selectGroupItems(all []*state.Cipher, subsetIDs []string) []*state.Cipher {
	if len(subsetIDs) == 0 {
		return slices.Clone(all)
	}
	want := map[string]bool{}
	for _, id := range subsetIDs {
		want[id] = true
	}
	var out []*state.Cipher
	for _, c := range all {
		if c != nil && want[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

func validateItemsSafety(items []*state.Cipher) string {
	org := orgBucket(items[0])
	for _, c := range items {
		if c == nil || c.Type != api.CipherTypeLogin || c.Login == nil {
			return "Group contains a non-login or invalid item"
		}
		if c.ReadOnly {
			return "Contains a read-only organization item"
		}
		if c.HidePassword {
			return "Contains an item whose password is hidden by your organization"
		}
		if orgBucket(c) != org {
			return "Cannot merge items across different organizations"
		}
	}
	return ""
}

func buildMergedCipher(keepItem *state.Cipher, removeItems []*state.Cipher, titleOverride string, opts PlanOptions) (*state.Cipher, error) {
	allItems := make([]*state.Cipher, 0, 1+len(removeItems))
	allItems = append(allItems, keepItem)
	allItems = append(allItems, removeItems...)

	merged := cloneCipher(keepItem)
	if merged.Login == nil {
		merged.Login = &state.Login{}
	}

	// Passkeys & key-binding verification across items.
	adoptedKeyID, err := mergePasskeys(merged, keepItem, removeItems)
	if err != nil {
		return nil, err
	}

	// 1. Smart Title Selection + Notes preservation.
	var names []string
	for _, it := range allItems {
		if t := strings.TrimSpace(it.Name); t != "" {
			names = append(names, t)
		}
	}
	var chosenTitle string
	var discardedTitles []string
	if titleOverride != "" {
		chosenTitle = titleOverride
		seen := map[string]bool{titleOverride: true}
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				discardedTitles = append(discardedTitles, n)
			}
		}
	} else {
		chosenTitle, discardedTitles = ChooseBestTitle(names)
	}
	if chosenTitle == "" {
		chosenTitle = "Untitled"
	}
	merged.Name = chosenTitle

	// 2. Notes: longest + append discarded titles.
	bestNotes := keepItem.Notes
	for _, it := range removeItems {
		if len(it.Notes) > len(bestNotes) {
			bestNotes = it.Notes
		}
	}
	if len(discardedTitles) > 0 {
		suffix := "Previous titles before merge: " + strings.Join(discardedTitles, ", ")
		if bestNotes != "" {
			bestNotes += "\n" + suffix
		} else {
			bestNotes = suffix
		}
	}
	merged.Notes = bestNotes

	// 3. Username & Password: from keepItem, falling back to non-empty from others
	// (supports passkey-only item merging with a password-bearing item).
	if merged.Login.Username == "" {
		for _, it := range removeItems {
			if it.Login != nil && it.Login.Username != "" {
				merged.Login.Username = it.Login.Username
				break
			}
		}
	}
	if merged.Login.Password == "" {
		for _, it := range removeItems {
			if it.Login != nil && it.Login.Password != "" {
				merged.Login.Password = it.Login.Password
				if merged.Login.PasswordRevisionDate == nil {
					merged.Login.PasswordRevisionDate = cloneTimePtr(it.Login.PasswordRevisionDate)
				}
				break
			}
		}
	}

	// 4. TOTP: first non-empty starting with keepItem.
	if strings.TrimSpace(merged.Login.TOTP) == "" {
		for _, it := range removeItems {
			if it.Login != nil && strings.TrimSpace(it.Login.TOTP) != "" {
				merged.Login.TOTP = strings.TrimSpace(it.Login.TOTP)
				break
			}
		}
	} else {
		merged.Login.TOTP = strings.TrimSpace(merged.Login.TOTP)
	}

	// 5. URIs: union of unique URIs (with opt-in SimplifyURLs).
	seenURI := map[string]bool{}
	var mergedURIs []state.LoginURI
	for _, it := range allItems {
		if it.Login == nil {
			continue
		}
		sameKey := it.SealedKeyID == merged.SealedKeyID
		for _, u := range it.Login.URIs {
			raw := strings.TrimSpace(u.URI)
			if raw == "" {
				continue
			}
			target := raw
			if opts.SimplifyURLs {
				target = SimplifyURL(raw)
			}
			if target == "" || seenURI[target] {
				continue
			}
			seenURI[target] = true
			nu := cloneLoginURI(u)
			nu.URI = target
			if !sameKey {
				// Foreign-key checksums and sealed URI extras cannot be sent
				// under merged's key; clear them so state.Service recomputes.
				nu.Checksum = nil
				nu.ChecksumOf = ""
				nu.Extra = nil
			}
			mergedURIs = append(mergedURIs, nu)
		}
	}
	merged.Login.URIs = mergedURIs

	// 6. Custom Fields: union by name.
	seenFields := map[string]bool{}
	var mergedFields []state.CustomField
	for _, it := range allItems {
		sameKey := it.SealedKeyID == merged.SealedKeyID
		for _, f := range it.Fields {
			if f.Name != "" && seenFields[f.Name] {
				continue
			}
			if f.Name != "" {
				seenFields[f.Name] = true
			}
			nf := cloneCustomField(f)
			if !sameKey {
				nf.Extra = nil
			}
			mergedFields = append(mergedFields, nf)
		}
	}
	merged.Fields = mergedFields

	// 7. Favorite & Reprompt: OR of all items.
	fav := false
	reprompt := 0
	for _, it := range allItems {
		if it.Favorite {
			fav = true
		}
		if it.Reprompt != 0 {
			reprompt = 1
		}
	}
	merged.Favorite = fav
	merged.Reprompt = reprompt

	// 8. FolderID: keep from keepItem.
	merged.FolderID = cloneStringPtr(keepItem.FolderID)

	// 9. OrganizationID & CollectionIDs.
	merged.OrganizationID = cloneStringPtr(keepItem.OrganizationID)
	seenCols := map[string]bool{}
	var mergedCols []string
	for _, it := range allItems {
		for _, colID := range it.CollectionIDs {
			if colID == "" || seenCols[colID] {
				continue
			}
			seenCols[colID] = true
			mergedCols = append(mergedCols, colID)
		}
	}
	merged.CollectionIDs = mergedCols

	// 10. PasswordHistory: deduplicated union across all items.
	merged.PasswordHistory = collectPasswordHistory(allItems, merged.SealedKeyID)

	_ = adoptedKeyID
	return merged, nil
}

func mergePasskeys(merged, keepItem *state.Cipher, removeItems []*state.Cipher) (string, error) {
	seen := map[string]bool{}
	var out []state.Fido2Credential
	for _, f := range keepItem.Login.Fido2Credentials {
		k := passkeyIdentity(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, cloneFido2(f))
	}

	var adoptedKeyFrom *state.Cipher
	for _, other := range removeItems {
		if other.Login == nil || len(other.Login.Fido2Credentials) == 0 {
			continue
		}
		for _, f := range other.Login.Fido2Credentials {
			k := passkeyIdentity(f)
			if seen[k] {
				continue
			}
			if len(f.Sealed) > 0 && other.SealedKeyID != keepItem.SealedKeyID {
				// A passkey sealed with another per-cipher key cannot be saved
				// under keepItem's key unless we safely adopt that key carrier.
				canAdopt := len(keepItem.Login.Fido2Credentials) == 0 &&
					len(keepItem.Attachments) == 0 &&
					len(keepItem.Extra) == 0 &&
					(keepItem.Login == nil || len(keepItem.Login.Extra) == 0) &&
					len(keepItem.ProvenSealed) == 0 &&
					(adoptedKeyFrom == nil || adoptedKeyFrom.SealedKeyID == other.SealedKeyID)
				if !canAdopt {
					return "", errors.New("cannot combine passkeys sealed under different cipher keys; keep the passkey item instead")
				}
				adoptedKeyFrom = other
			}
			seen[k] = true
			out = append(out, cloneFido2(f))
		}
	}

	adoptedKeyID := ""
	if adoptedKeyFrom != nil {
		merged.Key = cloneStringPtr(adoptedKeyFrom.Key)
		merged.SealedKeyID = adoptedKeyFrom.SealedKeyID
		merged.ProvenSealed = maps.Clone(adoptedKeyFrom.ProvenSealed)
		adoptedKeyID = adoptedKeyFrom.SealedKeyID
	}
	merged.Login.Fido2Credentials = out
	return adoptedKeyID, nil
}

func clearForCreate(c *state.Cipher) {
	c.ID = ""
	c.RevisionDate = nil
	c.CreationDate = nil
	c.DeletedDate = nil
	c.ArchivedDate = nil
	c.Data = nil
	c.EncryptedFor = nil
	c.EncryptedByKeyID = nil
	c.ReadOnly = false
	c.HidePassword = false
	c.Attachments = nil
}

func collectPasswordHistory(items []*state.Cipher, targetSealedKeyID string) []state.PasswordHistoryEntry {
	seen := map[[32]byte]bool{}
	var out []state.PasswordHistoryEntry
	for _, it := range items {
		sameKey := it.SealedKeyID == targetSealedKeyID
		for _, h := range it.PasswordHistory {
			digest := historyDigest(h.Password, h.LastUsedDate)
			if seen[digest] {
				continue
			}
			seen[digest] = true
			var extra map[string]json.RawMessage
			if sameKey {
				extra = cloneExtra(h.Extra)
			}
			out = append(out, state.PasswordHistoryEntry{
				Password:     h.Password,
				LastUsedDate: h.LastUsedDate,
				Extra:        extra,
				Shape:        cloneShape(h.Shape),
			})
		}
	}
	return out
}

func historyDigest(password string, ts time.Time) [32]byte {
	var nanoBuf [8]byte
	binary.BigEndian.PutUint64(nanoBuf[:], uint64(ts.UTC().UnixNano()))
	buf := make([]byte, 0, len(password)+len(nanoBuf))
	defer crypto.ZeroBytes(buf[:cap(buf)])
	buf = append(buf, password...)
	buf = append(buf, nanoBuf[:]...)
	return sha256.Sum256(buf)
}

type Progress struct {
	CompletedGroups int
	TotalGroups     int
	CompletedOps    int
	TotalOps        int
	Percent         float32
	CurrentGroup    string
	Phase           string
}

type GroupResult struct {
	GroupID      string
	Label        string
	Mode         OpMode
	CreatedID    string
	UpdatedID    string
	DeletedIDs   []string
	Skipped      bool
	Err          error
	LocalCopyErr error
}

type ExecuteReport struct {
	TotalGroups     int
	SucceededGroups int
	FailedGroups    int
	CreatedCount    int
	UpdatedCount    int
	DeletedCount    int
	Cancelled       bool
	Results         []GroupResult
	LocalCopyErr    error
	Err             error
}

// ExecutePlan applies plan against svc, honoring ctx.Done() and enforcing
// Create-Then-Delete / in-place attachment safety so originals are never
// soft-deleted if SaveCipher fails.
func ExecutePlan(ctx context.Context, svc state.VaultService, plan Plan, onProgress func(Progress)) ExecuteReport {
	var report ExecuteReport
	report.TotalGroups = len(plan.Groups) + len(plan.Errors)

	var errs, localErrs []error
	for _, pe := range plan.Errors {
		err := errors.New(pe.Reason)
		report.FailedGroups++
		report.Results = append(report.Results, GroupResult{
			GroupID: pe.GroupID,
			Label:   pe.Label,
			Skipped: true,
			Err:     err,
		})
		errs = append(errs, fmt.Errorf("%s: %w", pe.Label, err))
	}

	if svc == nil {
		err := errors.New("dedup: vault service is unavailable")
		for _, g := range plan.Groups {
			report.FailedGroups++
			report.Results = append(report.Results, GroupResult{GroupID: g.GroupID, Label: g.Label, Mode: g.Mode, Err: err})
		}
		report.Err = errors.Join(append(errs, err)...)
		return report
	}

	totalOps := 0
	for _, g := range plan.Groups {
		if g.Mode != OpPureDelete {
			totalOps++
		}
		totalOps += len(g.DeleteIDs)
	}
	completedOps := 0
	completedGroups := 0

	emit := func(label, phase string) {
		if onProgress == nil {
			return
		}
		var pct float32
		if totalOps > 0 {
			pct = float32(completedOps) * 100 / float32(totalOps)
		} else if phase == "done" {
			pct = 100
		}
		onProgress(Progress{
			CompletedGroups: completedGroups,
			TotalGroups:     len(plan.Groups),
			CompletedOps:    completedOps,
			TotalOps:        totalOps,
			Percent:         pct,
			CurrentGroup:    label,
			Phase:           phase,
		})
	}

	for _, g := range plan.Groups {
		if err := ctx.Err(); err != nil {
			report.Cancelled = true
			errs = append(errs, err)
			break
		}

		res := GroupResult{
			GroupID: g.GroupID,
			Label:   g.Label,
			Mode:    g.Mode,
		}

		switch g.Mode {
		case OpCreateThenDelete:
			emit(g.Label, "creating")
			saved, err := svc.SaveCipher(ctx, g.MergedCipher)
			completedOps++
			createdID, lcErr, realErr := classifySaveResult(saved, err)
			if lcErr != nil {
				res.LocalCopyErr = lcErr
				localErrs = append(localErrs, fmt.Errorf("%s: %w", g.Label, lcErr))
			}
			if realErr != nil || createdID == "" {
				if realErr == nil {
					realErr = errors.New("dedup: created item has empty ID")
				}
				// Abort group without deleting any originals.
				res.Err = realErr
				report.FailedGroups++
				report.Results = append(report.Results, res)
				errs = append(errs, fmt.Errorf("%s: %w", g.Label, realErr))
				completedOps += len(g.DeleteIDs)
				completedGroups++
				emit(g.Label, "failed")
				continue
			}
			res.CreatedID = createdID
			report.CreatedCount++

		case OpInPlace:
			emit(g.Label, "updating")
			saved, err := svc.SaveCipher(ctx, g.MergedCipher)
			completedOps++
			updatedID, lcErr, realErr := classifySaveResult(saved, err)
			if lcErr != nil {
				res.LocalCopyErr = lcErr
				localErrs = append(localErrs, fmt.Errorf("%s: %w", g.Label, lcErr))
			}
			if realErr != nil {
				// Abort group without deleting any originals.
				res.Err = realErr
				report.FailedGroups++
				report.Results = append(report.Results, res)
				errs = append(errs, fmt.Errorf("%s: %w", g.Label, realErr))
				completedOps += len(g.DeleteIDs)
				completedGroups++
				emit(g.Label, "failed")
				continue
			}
			if updatedID == "" {
				updatedID = g.KeepID
			}
			res.UpdatedID = updatedID
			report.UpdatedCount++
		}

		var delErrs []error
		for _, id := range g.DeleteIDs {
			if err := ctx.Err(); err != nil {
				report.Cancelled = true
				delErrs = append(delErrs, err)
				break
			}
			emit(g.Label, "deleting")
			err := svc.SoftDeleteCipher(ctx, id)
			completedOps++
			if lc := (*state.LocalCopyError)(nil); errors.As(err, &lc) {
				localErrs = append(localErrs, fmt.Errorf("%s (%s): %w", g.Label, id, lc))
				res.DeletedIDs = append(res.DeletedIDs, id)
				report.DeletedCount++
				continue
			}
			if err != nil {
				delErrs = append(delErrs, fmt.Errorf("%s: %w", id, err))
				continue
			}
			res.DeletedIDs = append(res.DeletedIDs, id)
			report.DeletedCount++
		}

		if len(delErrs) > 0 {
			res.Err = errors.Join(delErrs...)
			report.FailedGroups++
			errs = append(errs, fmt.Errorf("%s: %w", g.Label, res.Err))
		} else {
			report.SucceededGroups++
		}
		report.Results = append(report.Results, res)
		completedGroups++
		emit(g.Label, "group_done")
		if report.Cancelled {
			break
		}
	}

	if !report.Cancelled {
		emit("", "done")
	}
	report.LocalCopyErr = errors.Join(localErrs...)
	report.Err = errors.Join(errs...)
	return report
}

func classifySaveResult(saved *state.Cipher, err error) (id string, localCopyErr, realErr error) {
	var lc *state.LocalCopyError
	if errors.As(err, &lc) {
		if saved != nil && saved.ID != "" {
			id = saved.ID
		} else if lc.Cipher != nil {
			id = lc.Cipher.ID
		}
		return id, err, nil
	}
	if err != nil {
		return "", nil, err
	}
	if saved != nil {
		id = saved.ID
	}
	return id, nil, nil
}

func cloneCipher(c *state.Cipher) *state.Cipher {
	if c == nil {
		return nil
	}
	cp := *c
	cp.FolderID = cloneStringPtr(c.FolderID)
	cp.OrganizationID = cloneStringPtr(c.OrganizationID)
	cp.Key = cloneStringPtr(c.Key)
	cp.RevisionDate = cloneTimePtr(c.RevisionDate)
	cp.CreationDate = cloneTimePtr(c.CreationDate)
	cp.DeletedDate = cloneTimePtr(c.DeletedDate)
	cp.ArchivedDate = cloneTimePtr(c.ArchivedDate)
	cp.EncryptedFor = cloneStringPtr(c.EncryptedFor)
	cp.EncryptedByKeyID = cloneStringPtr(c.EncryptedByKeyID)
	cp.Data = slices.Clone(c.Data)
	cp.Extra = cloneExtra(c.Extra)
	cp.ProvenSealed = maps.Clone(c.ProvenSealed)
	cp.CollectionIDs = slices.Clone(c.CollectionIDs)

	if c.Login != nil {
		l := *c.Login
		l.PasswordRevisionDate = cloneTimePtr(c.Login.PasswordRevisionDate)
		l.Extra = cloneExtra(c.Login.Extra)
		l.Shape = cloneShape(c.Login.Shape)
		if len(c.Login.URIs) > 0 {
			l.URIs = make([]state.LoginURI, len(c.Login.URIs))
			for i, u := range c.Login.URIs {
				l.URIs[i] = cloneLoginURI(u)
			}
		} else {
			l.URIs = nil
		}
		if len(c.Login.Fido2Credentials) > 0 {
			l.Fido2Credentials = make([]state.Fido2Credential, len(c.Login.Fido2Credentials))
			for i, f := range c.Login.Fido2Credentials {
				l.Fido2Credentials[i] = cloneFido2(f)
			}
		} else {
			l.Fido2Credentials = nil
		}
		cp.Login = &l
	}
	if len(c.Fields) > 0 {
		cp.Fields = make([]state.CustomField, len(c.Fields))
		for i, f := range c.Fields {
			cp.Fields[i] = cloneCustomField(f)
		}
	} else {
		cp.Fields = nil
	}
	if len(c.PasswordHistory) > 0 {
		cp.PasswordHistory = make([]state.PasswordHistoryEntry, len(c.PasswordHistory))
		for i, h := range c.PasswordHistory {
			cp.PasswordHistory[i] = state.PasswordHistoryEntry{
				Password:     h.Password,
				LastUsedDate: h.LastUsedDate,
				Extra:        cloneExtra(h.Extra),
				Shape:        cloneShape(h.Shape),
			}
		}
	} else {
		cp.PasswordHistory = nil
	}
	if len(c.Attachments) > 0 {
		cp.Attachments = make([]state.Attachment, len(c.Attachments))
		for i, a := range c.Attachments {
			a.Key = cloneStringPtr(a.Key)
			a.Extra = cloneExtra(a.Extra)
			cp.Attachments[i] = a
		}
	} else {
		cp.Attachments = nil
	}
	return &cp
}

func cloneLoginURI(u state.LoginURI) state.LoginURI {
	u.Match = cloneIntPtr(u.Match)
	u.Checksum = cloneStringPtr(u.Checksum)
	u.Extra = cloneExtra(u.Extra)
	u.Shape = cloneShape(u.Shape)
	return u
}

func cloneCustomField(f state.CustomField) state.CustomField {
	f.LinkedID = cloneIntPtr(f.LinkedID)
	f.Extra = cloneExtra(f.Extra)
	f.Shape = cloneShape(f.Shape)
	return f
}

func cloneFido2(f state.Fido2Credential) state.Fido2Credential {
	f.Sealed = slices.Clone(f.Sealed)
	f.Unreadable = slices.Clone(f.Unreadable)
	return f
}

func cloneStringPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneTimePtr(p *time.Time) *time.Time {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneExtra(m map[string]json.RawMessage) map[string]json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}

func cloneShape(s api.Shape) api.Shape {
	if len(s) == 0 {
		return nil
	}
	out := make(api.Shape, len(s))
	for k, p := range s {
		p.Raw = slices.Clone(p.Raw)
		p.Zero = slices.Clone(p.Zero)
		out[k] = p
	}
	return out
}
