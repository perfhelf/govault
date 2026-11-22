package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestBulkCipherEndpoints(t *testing.T) {
	type seenReq struct {
		method string
		path   string
		auth   string
		ctype  string
		body   string
	}
	var seen []seenReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		seen = append(seen, seenReq{
			method: r.Method,
			path:   r.URL.Path,
			auth:   r.Header.Get("Authorization"),
			ctype:  r.Header.Get("Content-Type"),
			body:   string(raw),
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()
	ids := []string{"c-1", "c-2"}
	folderID := "f-work"
	emptyFolder := ""

	if err := c.BulkSoftDeleteCiphers(ctx, "tok-1", ids); err != nil {
		t.Fatalf("BulkSoftDeleteCiphers: %v", err)
	}
	if err := c.BulkMoveCiphers(ctx, "tok-1", ids, &folderID); err != nil {
		t.Fatalf("BulkMoveCiphers(folder): %v", err)
	}
	if err := c.BulkMoveCiphers(ctx, "tok-1", ids, nil); err != nil {
		t.Fatalf("BulkMoveCiphers(nil): %v", err)
	}
	if err := c.BulkMoveCiphers(ctx, "tok-1", nil, &emptyFolder); err != nil {
		t.Fatalf("BulkMoveCiphers(empty): %v", err)
	}
	if err := c.BulkRestoreCiphers(ctx, "tok-1", ids); err != nil {
		t.Fatalf("BulkRestoreCiphers: %v", err)
	}
	if err := c.BulkHardDeleteCiphers(ctx, "tok-1", ids); err != nil {
		t.Fatalf("BulkHardDeleteCiphers: %v", err)
	}

	want := []seenReq{
		{http.MethodPut, "/api/ciphers/delete", "Bearer tok-1", "application/json", `{"ids":["c-1","c-2"]}`},
		{http.MethodPut, "/api/ciphers/move", "Bearer tok-1", "application/json", `{"ids":["c-1","c-2"],"folderId":"f-work"}`},
		{http.MethodPut, "/api/ciphers/move", "Bearer tok-1", "application/json", `{"ids":["c-1","c-2"],"folderId":null}`},
		{http.MethodPut, "/api/ciphers/move", "Bearer tok-1", "application/json", `{"ids":[],"folderId":null}`},
		{http.MethodPut, "/api/ciphers/restore", "Bearer tok-1", "application/json", `{"ids":["c-1","c-2"]}`},
		{http.MethodDelete, "/api/ciphers/delete", "Bearer tok-1", "application/json", `{"ids":["c-1","c-2"]}`},
	}
	if !slices.Equal(seen, want) {
		t.Fatalf("requests mismatch:\n got: %+v\nwant: %+v", seen, want)
	}
}

func TestBulkCipherErrorsAndRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer expired":
			w.WriteHeader(http.StatusUnauthorized)
		case "Bearer not-found":
			w.WriteHeader(http.StatusNotFound)
		case "Bearer bad-req":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"Cipher doesn't exist"}`))
		case "Bearer conflict":
			w.WriteHeader(http.StatusConflict)
		case "Bearer valid":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := c.BulkSoftDeleteCiphers(ctx, "expired", []string{"c-1"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("401 = %v, want ErrUnauthorized", err)
	}
	if err := c.BulkHardDeleteCiphers(ctx, "not-found", []string{"c-1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 = %v, want ErrNotFound", err)
	}
	if err := c.BulkMoveCiphers(ctx, "bad-req", []string{"c-1"}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("400 missing = %v, want ErrNotFound", err)
	}
	if err := c.BulkRestoreCiphers(ctx, "conflict", []string{"c-1"}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("409 = %v, want ErrRevisionConflict", err)
	}

	_, err = DoWithRefresh(ctx, "expired", func(context.Context) (string, error) {
		return "valid", nil
	}, func(tok string) (struct{}, error) {
		return struct{}{}, c.BulkSoftDeleteCiphers(ctx, tok, []string{"c-1"})
	})
	if err != nil {
		t.Fatalf("DoWithRefresh = %v", err)
	}
}
