package gateway

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ai-relay/ai-relay/internal/v2/lifecycle"
)

func TestNewLifecycleHTTPHandlerBindsOptInControllerScopes(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, token := issueTestController(t, s, "chatgpt", lifecycle.ScopeProjectWrite, lifecycle.ScopeProjectRead)
	handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"Project"}}}`)
	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewReader(body))
	req.TLS = directTLSStateForTest(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"isError":false`)) {
		t.Fatalf("lifecycle response = %d %s", response.Code, response.Body.String())
	}
	if _, err := store.Project("p"); err != nil {
		t.Fatalf("project was not created through authenticated handoff: %v", err)
	}

	caseInsensitive := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)))
	caseInsensitive.TLS = directTLSStateForTest(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	caseInsensitive.Header.Set("Authorization", "bEaReR "+token)
	caseInsensitive.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, caseInsensitive)
	if response.Code != http.StatusOK {
		t.Fatalf("case-insensitive bearer status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestNewLifecycleHTTPHandlerDoesNotGrantLegacyScopes(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, token := issueTestController(t, s, "chatgpt", scopeSubmit)
	handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"Project"}}}`))
	req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("legacy-only controller status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if _, err := store.Project("p"); err == nil {
		t.Fatal("legacy-only controller gained lifecycle authority")
	}
}

func TestNewLifecycleHTTPHandlerRejectsOversizedPersistedScopeClaims(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const token = "oversized-controller-token"
	s.mu.Lock()
	s.controllers["oversized-controller"] = &ControllerRecord{
		ID:        "oversized-controller",
		Kind:      controllerChatGPT,
		TokenHash: hashControllerToken(token),
		Scopes:    make([]string, len(allowedControllerScopes())+1),
	}
	s.mu.Unlock()

	handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"Project"}}}`))
	req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("oversized persisted scope claim status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if _, err := store.Project("p"); err == nil {
		t.Fatal("oversized persisted scope claim reached lifecycle mutation")
	}
}

func TestNewLifecycleHTTPHandlerRejectsMalformedPersistedScopeClaims(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, tc := range []struct {
		name   string
		scopes []string
	}{
		{name: "unknown mixed with valid", scopes: []string{lifecycle.ScopeProjectWrite, "lifecycle.project.admin"}},
		{name: "duplicate valid", scopes: []string{lifecycle.ScopeProjectWrite, lifecycle.ScopeProjectWrite}},
		{name: "oversized", scopes: []string{strings.Repeat("x", maxControllerScopeBytes+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const token = "malformed-controller-token"
			s.mu.Lock()
			s.controllers[tc.name] = &ControllerRecord{
				ID:        tc.name,
				Kind:      controllerChatGPT,
				TokenHash: hashControllerToken(token),
				Scopes:    tc.scopes,
			}
			s.mu.Unlock()

			handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
			if err != nil {
				t.Fatal(err)
			}
			projectID := "p-" + strings.ReplaceAll(tc.name, " ", "-")
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"` + projectID + `","name":"Project"}}}`
			req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewBufferString(body))
			req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("malformed persisted scope status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
			if _, err := store.Project(projectID); err == nil {
				t.Fatal("malformed persisted scope claim reached lifecycle mutation")
			}
		})
	}

}

func TestNewLifecycleHTTPHandlerFailsClosedForNilPersistedController(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	s.mu.Lock()
	s.controllers["malformed-null-controller"] = nil
	s.mu.Unlock()

	handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"Project"}}}`))
	req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	req.Header.Set("Authorization", "Bearer malformed-token")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("nil persisted controller panicked during authentication: %v", recovered)
		}
	}()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("nil persisted controller status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if _, err := store.Project("p"); err == nil {
		t.Fatal("nil persisted controller reached lifecycle mutation")
	}
}

func TestMalformedPersistedControllerTokenHashFailsClosed(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const (
		controllerID = "malformed-token-hash-controller"
		token        = "malformed-token-hash"
	)
	s.mu.Lock()
	s.controllers[controllerID] = &ControllerRecord{
		ID:        controllerID,
		Kind:      controllerChatGPT,
		TokenHash: strings.Repeat("a", maxControllerTokenHashBytes+1),
		Scopes:    []string{lifecycle.ScopeProjectRead},
	}
	s.mu.Unlock()

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	if got := s.controllerFromRequest(request); got != nil {
		t.Fatalf("malformed persisted token hash authenticated as %#v", got)
	}

	listing := httptest.NewRecorder()
	adminRequest := httptest.NewRequest(http.MethodGet, "/v1/controllers", nil)
	adminRequest.Header.Set("Authorization", "Bearer "+s.adminToken)
	s.controllersHandler(listing, adminRequest)
	if listing.Code != http.StatusOK {
		t.Fatalf("malformed token hash listing status = %d, want %d", listing.Code, http.StatusOK)
	}
	var listed []*ControllerRecord
	if err := json.Unmarshal(listing.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode malformed token hash listing: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("malformed token hash listing = %#v, want empty", listed)
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/controllers/"+controllerID, nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+s.adminToken)
	deleted := httptest.NewRecorder()
	s.controllersHandler(deleted, deleteRequest)
	if deleted.Code != http.StatusNotFound {
		t.Fatalf("malformed token hash delete status = %d, want %d", deleted.Code, http.StatusNotFound)
	}
	s.mu.Lock()
	remaining := s.controllers[controllerID]
	s.mu.Unlock()
	if remaining == nil || remaining.Revoked {
		t.Fatalf("malformed token hash was mutated by delete: %#v", remaining)
	}
}

func TestMalformedPersistedControllerScopesFailClosedAcrossGatewayPaths(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		scopes []string
	}{
		{name: "unknown", scopes: []string{"lifecycle.controller.admin"}},
		{name: "duplicate", scopes: []string{scopeRead, scopeRead}},
		{name: "overlong", scopes: []string{strings.Repeat("x", maxControllerScopeBytes+1)}},
		{name: "oversized", scopes: make([]string, len(allowedControllerScopes())+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "malformed-scopes-" + tc.name
			const token = "malformed-scopes-token"
			s.mu.Lock()
			s.controllers[id] = &ControllerRecord{
				ID:        id,
				Kind:      controllerChatGPT,
				TokenHash: hashControllerToken(token),
				Scopes:    tc.scopes,
			}
			s.mu.Unlock()

			request := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			if got := s.controllerFromRequest(request); got != nil {
				t.Fatalf("malformed scope claim authenticated as %#v", got)
			}

			listing := httptest.NewRecorder()
			adminRequest := httptest.NewRequest(http.MethodGet, "/v1/controllers", nil)
			adminRequest.Header.Set("Authorization", "Bearer "+s.adminToken)
			s.controllersHandler(listing, adminRequest)
			if listing.Code != http.StatusOK {
				t.Fatalf("listing status = %d, want %d", listing.Code, http.StatusOK)
			}
			var listed []*ControllerRecord
			if err := json.Unmarshal(listing.Body.Bytes(), &listed); err != nil {
				t.Fatalf("decode listing: %v", err)
			}
			for _, record := range listed {
				if record != nil && record.ID == id {
					t.Fatalf("malformed scope claim was listed: %#v", record)
				}
			}

			deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/controllers/"+id, nil)
			deleteRequest.Header.Set("Authorization", "Bearer "+s.adminToken)
			deleted := httptest.NewRecorder()
			s.controllersHandler(deleted, deleteRequest)
			if deleted.Code != http.StatusNotFound {
				t.Fatalf("delete status = %d, want %d", deleted.Code, http.StatusNotFound)
			}
		})
	}
}

func TestMalformedPersistedControllerIdentityFailsClosedAcrossGatewayPaths(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		id   string
	}{
		{name: "oversized", id: strings.Repeat("x", maxControllerIDBytes+1)},
		{name: "path separator", id: "controller/child"},
		{name: "control", id: "controller\x00id"},
		{name: "invalid utf8", id: string([]byte{'c', 'o', 'n', 't', 'r', 'o', 'l', 'l', 'e', 'r', 0xff})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const token = "malformed-controller-id-token"
			s.mu.Lock()
			s.controllers[tc.id] = &ControllerRecord{
				ID:        tc.id,
				Kind:      controllerChatGPT,
				TokenHash: hashControllerToken(token),
				Scopes:    []string{lifecycle.ScopeProjectWrite},
			}
			s.mu.Unlock()

			request := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			if got := s.controllerFromRequest(request); got != nil {
				t.Fatalf("malformed controller ID authenticated as %#v", got)
			}

			listing := httptest.NewRecorder()
			adminRequest := httptest.NewRequest(http.MethodGet, "/v1/controllers", nil)
			adminRequest.Header.Set("Authorization", "Bearer "+s.adminToken)
			s.controllersHandler(listing, adminRequest)
			if listing.Code != http.StatusOK {
				t.Fatalf("listing status = %d, want %d", listing.Code, http.StatusOK)
			}
			if strings.Contains(listing.Body.String(), tc.id) {
				t.Fatal("malformed controller identity was exposed in listing")
			}

			deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/controllers/invalid", nil)
			deleteRequest.URL.Path = "/v1/controllers/" + tc.id
			deleteRequest.Header.Set("Authorization", "Bearer "+s.adminToken)
			deleted := httptest.NewRecorder()
			s.controllersHandler(deleted, deleteRequest)
			if deleted.Code != http.StatusNotFound {
				t.Fatalf("delete status = %d, want %d", deleted.Code, http.StatusNotFound)
			}
			s.mu.Lock()
			remaining := s.controllers[tc.id]
			s.mu.Unlock()
			if remaining == nil || remaining.Revoked {
				t.Fatalf("malformed controller identity was mutated by delete: %#v", remaining)
			}
		})
	}
}

func TestControllerListingSkipsNilPersistedController(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	validID, _ := issueTestController(t, s, "chatgpt", lifecycle.ScopeProjectRead)
	s.mu.Lock()
	s.controllers["malformed-null-controller"] = nil
	s.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/v1/controllers", nil)
	req.Header.Set("Authorization", "Bearer "+s.adminToken)
	response := httptest.NewRecorder()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("nil persisted controller panicked during listing: %v", recovered)
		}
	}()
	s.controllersHandler(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("controller listing status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var listed []*ControllerRecord
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode controller listing: %v", err)
	}
	if len(listed) != 1 || listed[0] == nil || listed[0].ID != validID {
		t.Fatalf("controller listing = %#v, want only valid controller %q", listed, validID)
	}
}

func TestPersistedControllerIdentityMismatchFailsClosed(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const token = "mismatched-controller-token"
	s.mu.Lock()
	s.controllers["map-owner"] = &ControllerRecord{
		ID:        "embedded-other-owner",
		Kind:      controllerChatGPT,
		TokenHash: hashControllerToken(token),
		Scopes:    []string{lifecycle.ScopeProjectWrite},
	}
	s.mu.Unlock()

	handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"Project"}}}`))
	req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched persisted identity status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if _, err := store.Project("p"); err == nil {
		t.Fatal("mismatched persisted identity reached lifecycle mutation")
	}

	listing := httptest.NewRecorder()
	adminRequest := httptest.NewRequest(http.MethodGet, "/v1/controllers", nil)
	adminRequest.Header.Set("Authorization", "Bearer "+s.adminToken)
	s.controllersHandler(listing, adminRequest)
	if listing.Code != http.StatusOK {
		t.Fatalf("mismatched persisted identity listing status = %d, want %d", listing.Code, http.StatusOK)
	}
	var listed []*ControllerRecord
	if err := json.Unmarshal(listing.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode controller listing: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("mismatched persisted identity listing = %#v, want empty", listed)
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/controllers/map-owner", nil)
	deleteRequest.Header.Set("Authorization", "Bearer "+s.adminToken)
	deleteResponse := httptest.NewRecorder()
	s.controllersHandler(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNotFound {
		t.Fatalf("mismatched persisted identity delete status = %d, want %d", deleteResponse.Code, http.StatusNotFound)
	}
	s.mu.Lock()
	remaining := s.controllers["map-owner"]
	s.mu.Unlock()
	if remaining == nil || remaining.Revoked {
		t.Fatalf("mismatched persisted identity was mutated by delete: %#v", remaining)
	}
}

func TestDuplicatePersistedControllerCredentialFailsClosed(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const token = "duplicate-controller-token"
	s.mu.Lock()
	for _, id := range []string{"controller-a", "controller-b"} {
		s.controllers[id] = &ControllerRecord{
			ID:        id,
			Kind:      controllerChatGPT,
			TokenHash: hashControllerToken(token),
			Scopes:    []string{lifecycle.ScopeProjectWrite},
		}
	}
	s.mu.Unlock()

	handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"Project"}}}`))
	req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate persisted credential status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if _, err := store.Project("p"); err == nil {
		t.Fatal("ambiguous persisted credential reached lifecycle mutation")
	}
}

func TestPersistedControllerCredentialCollidingWithLegacyTokenFailsClosed(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, token := issueTestController(t, s, "chatgpt", lifecycle.ScopeProjectWrite)
	s.mu.Lock()
	s.mcpToken = token
	s.mu.Unlock()

	handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"collision-project","name":"Project"}}}`))
	req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("legacy/persisted credential collision status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if _, err := store.Project("collision-project"); err == nil {
		t.Fatal("ambiguous legacy/persisted credential reached lifecycle mutation")
	}
}

func TestControllerAuthenticationUsesStableScopeSnapshot(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, token := issueTestController(t, s, "chatgpt", lifecycle.ScopeProjectWrite, lifecycle.ScopeProjectRead)
	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	snapshot := s.controllerFromRequest(req)
	if snapshot == nil || snapshot.ID != id {
		t.Fatalf("controller snapshot = %#v, want controller %q", snapshot, id)
	}

	s.mu.Lock()
	s.controllers[id].Scopes[0] = "lifecycle.tampered"
	s.mu.Unlock()
	if got, want := snapshot.Scopes[0], lifecycle.ScopeProjectWrite; got != want {
		t.Fatalf("authenticated scope snapshot changed to %q, want %q", got, want)
	}

	ambiguous := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", nil)
	ambiguous.Header = http.Header{
		"Authorization": []string{"Bearer " + token},
		"authorization": []string{},
	}
	if got := s.controllerFromRequest(ambiguous); got != nil {
		t.Fatalf("zero-entry case-variant authorization was accepted: %#v", got)
	}
}

func TestControllerAuthenticationFailsClosedForNilServer(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", nil)
	request.Header.Set("Authorization", "Bearer ignored")

	var server *Server
	if got := server.controllerFromRequest(request); got != nil {
		t.Fatalf("nil server authentication snapshot = %#v, want nil", got)
	}
}

func TestNewLifecycleHTTPHandlerRejectsAmbiguousOrOversizedAuthorization(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := openTestLifecycleStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, token := issueTestController(t, s, "chatgpt", lifecycle.ScopeProjectWrite)
	handler, err := s.NewLifecycleHTTPHandler(store, lifecycle.RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"Project"}}}`)

	for _, tc := range []struct {
		name       string
		values     []string
		wantStatus int
	}{
		{name: "duplicate authorization", values: []string{"Bearer " + token, "Bearer " + token}, wantStatus: http.StatusBadRequest},
		{name: "oversized authorization", values: []string{"Bearer " + strings.Repeat("a", maxControllerAuthorizationBytes)}, wantStatus: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewReader(body))
			req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
			for _, value := range tc.values {
				req.Header.Add("Authorization", value)
			}
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tc.wantStatus {
				t.Fatalf("authorization status = %d, want %d", response.Code, tc.wantStatus)
			}
			if _, err := store.Project("p"); err == nil {
				t.Fatal("ambiguous or oversized authorization reached lifecycle mutation")
			}
		})
	}

	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/v2/lifecycle", bytes.NewReader(body))
	req.TLS = directTLSStateForTest(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	req.Header = http.Header{
		"Authorization": []string{"Bearer " + token},
		"authorization": []string{"Bearer " + token},
		"Content-Type":  []string{"application/json"},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("differently cased duplicate authorization status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if _, err := store.Project("p"); err == nil {
		t.Fatal("differently cased duplicate authorization reached lifecycle mutation")
	}
}

func directTLSStateForTest(version, cipherSuite uint16) *tls.ConnectionState {
	state := &tls.ConnectionState{
		Version:                    version,
		HandshakeComplete:          true,
		CipherSuite:                cipherSuite,
		NegotiatedProtocolIsMutual: true,
	}
	if version == tls.VersionTLS12 {
		state.TLSUnique = bytes.Repeat([]byte{1}, 12)
	}
	return state
}

func openTestLifecycleStore(t *testing.T) (*lifecycle.Store, error) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		return nil, err
	}
	return lifecycle.Open(root)
}

func TestControllersRejectDuplicateScopesAndAcceptLifecycleScopes(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		scopes []string
		want   int
	}{
		{name: "lifecycle scope", scopes: []string{lifecycle.ScopeTaskRead}, want: http.StatusOK},
		{name: "duplicate", scopes: []string{lifecycle.ScopeTaskRead, lifecycle.ScopeTaskRead}, want: http.StatusBadRequest},
		{name: "oversized claim", scopes: make([]string, len(allowedControllerScopes())+1), want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			beforeControllers := 0
			if tc.name == "oversized claim" {
				s.mu.Lock()
				beforeControllers = len(s.controllers)
				s.mu.Unlock()
			}
			body, err := json.Marshal(map[string]any{"kind": "chatgpt", "scopes": tc.scopes})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/controllers", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+s.adminToken)
			response := httptest.NewRecorder()
			s.controllersHandler(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", response.Code, tc.want, response.Body.String())
			}
			if tc.name == "oversized claim" {
				s.mu.Lock()
				controllerCount := len(s.controllers)
				s.mu.Unlock()
				if controllerCount != beforeControllers {
					t.Fatalf("oversized claim changed persisted controller count from %d to %d", beforeControllers, controllerCount)
				}
			}
		})
	}
}

func TestControllerIssueRollsBackOnPersistFailure(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.state = filepath.Join(t.TempDir(), "missing-parent", "state")

	body := []byte(`{"kind":"chatgpt","scopes":["lifecycle.project.read"]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/controllers", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-admin")
	response := httptest.NewRecorder()
	s.controllersHandler(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("issue status = %d, want %d: %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.controllers) != 0 {
		t.Fatalf("failed issue left %d in-memory controllers", len(s.controllers))
	}
}

func TestControllerRevokeAuditsKindFromLockedSnapshot(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := issueTestController(t, s, "gemini", lifecycle.ScopeProjectRead)

	request := httptest.NewRequest(http.MethodDelete, "/v1/controllers/"+id, nil)
	request.Header.Set("Authorization", "Bearer test-admin")
	response := httptest.NewRecorder()
	s.controllersHandler(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}

	auditBytes, err := os.ReadFile(filepath.Join(s.state, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(auditBytes, []byte(`"action":"controller.revoke"`)) ||
		!bytes.Contains(auditBytes, []byte(`"kind":"gemini"`)) {
		t.Fatalf("revoke audit = %s, want locked controller kind", auditBytes)
	}
}

func TestControllerRevokeRollsBackOnPersistFailure(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, token := issueTestController(t, s, "chatgpt")
	s.state = filepath.Join(t.TempDir(), "missing-parent", "state")

	req := httptest.NewRequest(http.MethodDelete, "/v1/controllers/"+id, nil)
	req.Header.Set("Authorization", "Bearer test-admin")
	response := httptest.NewRecorder()
	s.controllersHandler(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("revoke status = %d, want %d: %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
	s.mu.Lock()
	revoked := s.controllers[id].Revoked
	s.mu.Unlock()
	if revoked {
		t.Fatal("failed revoke left the controller revoked in memory")
	}
	if status, _ := controllerMCP(s, token, "health", nil); status != http.StatusOK {
		t.Fatalf("controller remained unusable after failed revoke: status %d", status)
	}
}
