package state

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/api"
	"github.com/txchen/govault/internal/vaultcore/crypto"
	"github.com/txchen/govault/internal/vaultcore/store"
)

type bulkServerRecorder struct {
	mu           sync.Mutex
	calls        []string
	sentIDs      [][]string
	sentFolders  []*string
	failOnPath   string
	failMethod   string
	failStatus   int
	beforeCommit func(r *http.Request)
}

func attachBulkHandler(env *vaultTestEnv) *bulkServerRecorder {
	rec := &bulkServerRecorder{}
	env.bulkHandler = func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/delete",
			r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/move",
			r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/restore",
			r.Method == http.MethodDelete && r.URL.Path == "/api/ciphers/delete":
		default:
			return false
		}

		raw, _ := io.ReadAll(r.Body)
		var body struct {
			IDs      []string `json:"ids"`
			FolderID *string  `json:"folderId"`
		}
		_ = json.Unmarshal(raw, &body)

		rec.mu.Lock()
		rec.calls = append(rec.calls, r.Method+" "+r.URL.Path)
		rec.sentIDs = append(rec.sentIDs, body.IDs)
		rec.sentFolders = append(rec.sentFolders, cloneStringPtr(body.FolderID))
		failPath, failMethod, failStatus, hook := rec.failOnPath, rec.failMethod, rec.failStatus, rec.beforeCommit
		rec.mu.Unlock()

		if hook != nil {
			hook(r)
		}
		if failPath == r.URL.Path && (failMethod == "" || failMethod == r.Method) {
			if failStatus == 0 {
				failStatus = http.StatusInternalServerError
			}
			w.WriteHeader(failStatus)
			return true
		}

		env.mu.Lock()
		now := time.Now().UTC()
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/delete":
			for _, id := range body.IDs {
				if c, ok := env.ciphers[id]; ok {
					ts := now
					c.DeletedDate = &ts
					env.ciphers[id] = c
				}
			}
		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/move":
			for _, id := range body.IDs {
				if c, ok := env.ciphers[id]; ok {
					c.FolderID = cloneStringPtr(body.FolderID)
					env.ciphers[id] = c
				}
			}
		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/restore":
			for _, id := range body.IDs {
				if c, ok := env.ciphers[id]; ok {
					c.DeletedDate = nil
					env.ciphers[id] = c
				}
			}
		case r.Method == http.MethodDelete && r.URL.Path == "/api/ciphers/delete":
			for _, id := range body.IDs {
				delete(env.ciphers, id)
			}
		}
		env.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return true
	}
	return rec
}

func seedBulkCipher(t *testing.T, env *vaultTestEnv, id, name string, folderID *string, deleted *time.Time, edit *bool) {
	t.Helper()
	encName, err := crypto.EncryptString(name, env.userKey)
	if err != nil {
		t.Fatal(err)
	}
	rev := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	env.ciphers[id] = api.EncryptedCipher{
		ID:           id,
		Type:         api.CipherTypeSecureNote,
		FolderID:     cloneStringPtr(folderID),
		Name:         encName,
		RevisionDate: &rev,
		DeletedDate:  cloneTimePtr(deleted),
		Edit:         edit,
		SecureNote:   &api.EncryptedSecureNote{Type: 0},
	}
}

func TestService_BulkLifecycleAndSnapshotPersistence(t *testing.T) {
	env := newVaultTestEnv(t)
	rec := attachBulkHandler(env)
	f2Name, _ := crypto.EncryptString("Personal", env.userKey)
	f2 := "f-personal"
	env.folders[f2] = api.EncryptedFolder{ID: f2, Name: f2Name}
	work := "f-work"
	seedBulkCipher(t, env, "c-2", "Note Two", &work, nil, nil)
	seedBulkCipher(t, env, "c-3", "Note Three", nil, nil, nil)

	svc := loggedInTestService(t, env)
	ctx := context.Background()

	// Duplicate IDs are deduplicated preserving order.
	if err := svc.BulkMoveFolder(ctx, []string{"c-1", "c-1", "c-3"}, &f2); err != nil {
		t.Fatalf("BulkMoveFolder: %v", err)
	}
	rec.mu.Lock()
	if len(rec.sentIDs) != 1 || !slices.Equal(rec.sentIDs[0], []string{"c-1", "c-3"}) {
		rec.mu.Unlock()
		t.Fatalf("deduplicated IDs sent = %v", rec.sentIDs)
	}
	if rec.sentFolders[0] == nil || *rec.sentFolders[0] != f2 {
		rec.mu.Unlock()
		t.Fatalf("folder sent = %v, want %q", rec.sentFolders[0], f2)
	}
	rec.mu.Unlock()

	if err := svc.BulkSoftDelete(ctx, []string{"c-2", "c-3"}); err != nil {
		t.Fatalf("BulkSoftDelete: %v", err)
	}

	relockOffline(t, svc, env)
	if c1, _ := svc.GetCipher("c-1"); c1.FolderID == nil || *c1.FolderID != f2 {
		t.Fatalf("c-1 folder after relock = %v, want %q", c1.FolderID, f2)
	}
	if c2, _ := svc.GetCipher("c-2"); c2.DeletedDate == nil {
		t.Fatal("c-2 not soft-deleted in snapshot")
	}
	if c3, _ := svc.GetCipher("c-3"); c3.DeletedDate == nil || c3.FolderID == nil || *c3.FolderID != f2 {
		t.Fatalf("c-3 after relock = %+v", c3)
	}
}

func TestService_BulkRestoreAndHardDeletePersistToSnapshot(t *testing.T) {
	env := newVaultTestEnv(t)
	rec := attachBulkHandler(env)
	f2Name, _ := crypto.EncryptString("Personal", env.userKey)
	f2 := "f-personal"
	work := "f-work"
	env.folders[f2] = api.EncryptedFolder{ID: f2, Name: f2Name}
	deleted := time.Now().UTC().Add(-time.Hour)
	seedBulkCipher(t, env, "c-tr1", "Trash One", &work, &deleted, nil)
	seedBulkCipher(t, env, "c-tr2", "Trash Two", &work, &deleted, nil)
	seedBulkCipher(t, env, "c-tr3", "Trash Three", &work, &deleted, nil)

	svc := loggedInTestService(t, env)
	ctx := context.Background()

	// 1) Restore keeping original folder (targetFolderID == nil) does NOT call BulkMoveCiphers.
	if err := svc.BulkRestore(ctx, []string{"c-tr1"}, nil); err != nil {
		t.Fatalf("BulkRestore(nil): %v", err)
	}
	if c, _ := svc.GetCipher("c-tr1"); c.DeletedDate != nil || c.FolderID == nil || *c.FolderID != work {
		t.Fatalf("c-tr1 after restore(nil) = %+v", c)
	}

	// 2) Restore to No Folder (targetFolderID == ptr("")): calls restore then move(null).
	empty := ""
	if err := svc.BulkRestore(ctx, []string{"c-tr2"}, &empty); err != nil {
		t.Fatalf("BulkRestore(empty): %v", err)
	}
	if c, _ := svc.GetCipher("c-tr2"); c.DeletedDate != nil || c.FolderID != nil {
		t.Fatalf("c-tr2 after restore(\"\") = %+v", c)
	}

	// 3) Restore to chosen folder: calls restore then move(f-personal).
	if err := svc.BulkRestore(ctx, []string{"c-tr3"}, &f2); err != nil {
		t.Fatalf("BulkRestore(f-personal): %v", err)
	}

	// 4) Hard delete multiple items.
	if err := svc.BulkHardDelete(ctx, []string{"c-trash", "c-tr1"}); err != nil {
		t.Fatalf("BulkHardDelete: %v", err)
	}

	rec.mu.Lock()
	wantCalls := []string{
		"PUT /api/ciphers/restore",
		"PUT /api/ciphers/restore",
		"PUT /api/ciphers/move",
		"PUT /api/ciphers/restore",
		"PUT /api/ciphers/move",
		"DELETE /api/ciphers/delete",
	}
	gotCalls := slices.Clone(rec.calls)
	rec.mu.Unlock()
	if !slices.Equal(gotCalls, wantCalls) {
		t.Fatalf("calls = %v, want %v", gotCalls, wantCalls)
	}

	relockOffline(t, svc, env)
	if _, err := svc.GetCipher("c-trash"); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("c-trash still present after hard delete: %v", err)
	}
	if _, err := svc.GetCipher("c-tr1"); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("c-tr1 still present after hard delete: %v", err)
	}
	if c, _ := svc.GetCipher("c-tr2"); c.DeletedDate != nil || c.FolderID != nil {
		t.Fatalf("c-tr2 after relock = %+v", c)
	}
	if c, _ := svc.GetCipher("c-tr3"); c.DeletedDate != nil || c.FolderID == nil || *c.FolderID != f2 {
		t.Fatalf("c-tr3 after relock = %+v", c)
	}
}

func TestService_BulkValidationGuardsBeforeServerCalls(t *testing.T) {
	env := newVaultTestEnv(t)
	rec := attachBulkHandler(env)
	no := false
	seedBulkCipher(t, env, "c-ro", "ReadOnly", nil, nil, &no)
	seedBulkCipher(t, env, "c-col-ro", "Col ReadOnly", nil, nil, nil)
	colCipher := env.ciphers["c-col-ro"]
	colCipher.CollectionIDs = []string{"col-ro"}
	env.ciphers["c-col-ro"] = colCipher

	fileStore := store.NewFileStore(t.TempDir())
	secrets := newMemSecretStore()
	svc, err := NewService(ServiceConfig{Store: fileStore, Secrets: secrets, HTTPClient: env.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := svc.Login(ctx, LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	svc.mu.Lock()
	svc.collections["col-ro"] = Collection{ID: "col-ro", Name: "RO", ReadOnly: true}
	svc.mu.Unlock()

	// Search reports ReadOnly accurately for both item-level and collection-level read-only.
	roCount := 0
	for _, s := range svc.Search("", SearchFilter{}) {
		if (s.ID == "c-ro" || s.ID == "c-col-ro") != s.ReadOnly {
			t.Fatalf("summary ReadOnly wrong for %s: %+v", s.ID, s)
		}
		if s.ReadOnly {
			roCount++
		}
	}
	if roCount != 2 {
		t.Fatalf("roCount = %d, want 2", roCount)
	}

	// Empty slice is a no-op with zero server calls.
	if err := svc.BulkSoftDelete(ctx, nil); err != nil {
		t.Fatalf("empty BulkSoftDelete = %v", err)
	}
	// Empty ID string, missing ID, read-only item, read-only collection, missing folder all fail preflight.
	if err := svc.BulkSoftDelete(ctx, []string{"c-1", ""}); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("empty id = %v, want ErrCipherNotFound", err)
	}
	if err := svc.BulkHardDelete(ctx, []string{"c-1", "missing"}); !errors.Is(err, ErrCipherNotFound) {
		t.Fatalf("missing id = %v, want ErrCipherNotFound", err)
	}
	if err := svc.BulkSoftDelete(ctx, []string{"c-1", "c-ro"}); !errors.Is(err, ErrReadOnlyCipher) {
		t.Fatalf("read-only item = %v, want ErrReadOnlyCipher", err)
	}
	if err := svc.BulkMoveFolder(ctx, []string{"c-1", "c-col-ro"}, nil); !errors.Is(err, ErrReadOnlyCipher) {
		t.Fatalf("read-only collection item = %v, want ErrReadOnlyCipher", err)
	}
	missingFolder := "f-missing"
	if err := svc.BulkMoveFolder(ctx, []string{"c-1"}, &missingFolder); !errors.Is(err, ErrFolderNotFound) {
		t.Fatalf("missing folder = %v, want ErrFolderNotFound", err)
	}
	if err := svc.BulkRestore(ctx, []string{"c-trash"}, &missingFolder); !errors.Is(err, ErrFolderNotFound) {
		t.Fatalf("restore missing folder = %v, want ErrFolderNotFound", err)
	}

	// SessionContext bound to old session fails with ErrLocked.
	sessCtx, cancel, err := svc.SessionContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	// Locked rejects.
	svc.Lock()
	if err := svc.BulkSoftDelete(ctx, []string{"c-1"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("while locked = %v, want ErrLocked", err)
	}

	// LocalOnly rejects with ErrSignInRequired (remove refresh token then unlock offline).
	_ = secrets.Delete(refreshTokenKeyPrefix + "acct-1")
	if err := svc.UnlockWithPassword(ctx, env.password); err != nil {
		t.Fatal(err)
	}
	if !svc.LocalOnly() {
		t.Fatal("expected LocalOnly session")
	}
	if err := svc.BulkSoftDelete(ctx, []string{"c-1"}); !errors.Is(err, ErrSignInRequired) {
		t.Fatalf("while localOnly = %v, want ErrSignInRequired", err)
	}

	// Re-login and verify stale SessionContext is rejected with ErrLocked.
	if err := svc.Login(ctx, LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}
	if err := svc.BulkMoveFolder(sessCtx, []string{"c-1"}, nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("stale SessionContext = %v, want ErrLocked", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 0 {
		t.Fatalf("rejected operations reached server: %v", rec.calls)
	}
}

func TestService_BulkLocalCopyErrorAndPartialRestoreMoveFailure(t *testing.T) {
	env := newVaultTestEnv(t)
	rec := attachBulkHandler(env)
	work := "f-work"
	deleted := time.Now().UTC().Add(-time.Hour)
	seedBulkCipher(t, env, "c-tr", "Trash Item", &work, &deleted, nil)

	fs := &flakyStore{Store: store.NewFileStore(t.TempDir())}
	svc, err := NewService(ServiceConfig{Store: fs, Secrets: newMemSecretStore(), HTTPClient: env.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := svc.Login(ctx, LoginRequest{ServerURL: env.server.URL, Email: env.email, MasterPassword: env.password}); err != nil {
		t.Fatal(err)
	}

	// Snapshot write failure after server success returns LocalCopyError and updates memory.
	fs.fail = true
	err = svc.BulkMoveFolder(ctx, []string{"c-1"}, nil)
	var lc *LocalCopyError
	if !errors.As(err, &lc) || !errors.Is(err, ErrSnapshotNotUpdated) {
		t.Fatalf("BulkMoveFolder on disk error = %v, want *LocalCopyError", err)
	}
	if c, _ := svc.GetCipher("c-1"); c.FolderID != nil {
		t.Fatalf("memory not updated on LocalCopyError: folder=%v", c.FolderID)
	}
	fs.fail = false

	// BulkRestore where restore succeeds and move fails still commits the restore locally.
	rec.mu.Lock()
	rec.failOnPath = "/api/ciphers/move"
	rec.failMethod = http.MethodPut
	rec.failStatus = http.StatusBadRequest
	rec.mu.Unlock()

	err = svc.BulkRestore(ctx, []string{"c-tr"}, &work)
	if err == nil {
		t.Fatal("expected move error from BulkRestore")
	}
	if c, _ := svc.GetCipher("c-tr"); c.DeletedDate != nil {
		t.Fatal("restore was not committed locally even though server restored the item")
	}
	relockOffline(t, svc, env)
	if c, _ := svc.GetCipher("c-tr"); c.DeletedDate != nil {
		t.Fatal("restore was not saved to snapshot on partial move failure")
	}
}

func TestService_BulkCommitBumpsSnapSeqOverConcurrentSync(t *testing.T) {
	env := newVaultTestEnv(t)
	_ = attachBulkHandler(env)
	svc := loggedInTestService(t, env)
	ctx := context.Background()

	// Another device renames folder while sync starts; bulk move runs before sync commits.
	env.mu.Lock()
	f := env.folders["f-work"]
	f.Name = mustEncString(t, "Work (renamed)", env.userKey)
	env.folders["f-work"] = f
	env.syncStarted, env.syncGate, env.syncStale = make(chan struct{}), make(chan struct{}), true
	started, gate := env.syncStarted, env.syncGate
	env.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- svc.forceSync(ctx) }()
	<-started
	env.mu.Lock()
	env.syncStarted, env.syncGate, env.syncStale = nil, nil, false
	env.mu.Unlock()

	if err := svc.BulkMoveFolder(ctx, []string{"c-1"}, nil); err != nil {
		t.Fatalf("BulkMoveFolder during sync: %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("forceSync: %v", err)
	}
	if c, _ := svc.GetCipher("c-1"); c.FolderID != nil {
		t.Fatalf("stale sync overwrote bulk folder move: folder=%v", c.FolderID)
	}
	relockOffline(t, svc, env)
	if c, _ := svc.GetCipher("c-1"); c.FolderID != nil {
		t.Fatalf("stale sync overwrote snapshot folder move: folder=%v", c.FolderID)
	}
}

func TestService_LockDuringBulkCallRefusesCommit(t *testing.T) {
	env := newVaultTestEnv(t)
	rec := attachBulkHandler(env)
	svc := loggedInTestService(t, env)

	rec.mu.Lock()
	rec.beforeCommit = func(*http.Request) {
		svc.Lock()
	}
	rec.mu.Unlock()

	err := svc.BulkSoftDelete(context.Background(), []string{"c-1"})
	if !errors.Is(err, ErrLocked) && !errors.Is(err, context.Canceled) {
		t.Fatalf("BulkSoftDelete locked mid-flight = %v, want ErrLocked or context.Canceled", err)
	}
	if svc.Status() != StatusLocked {
		t.Fatalf("status = %v, want StatusLocked", svc.Status())
	}
	if err := svc.UnlockWithPassword(context.Background(), env.password); err != nil {
		t.Fatalf("re-unlock: %v", err)
	}
	if c, err := svc.GetCipher("c-1"); err != nil || c.DeletedDate != nil {
		t.Fatalf("c-1 snapshot mutated after mid-flight lock: %+v, %v", c, err)
	}
}
