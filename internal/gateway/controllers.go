package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ai-relay/ai-relay/internal/audit"
	"github.com/ai-relay/ai-relay/internal/security"
	"github.com/ai-relay/ai-relay/internal/v2/lifecycle"
)

const (
	controllerChatGPT = "chatgpt"
	controllerGemini  = "gemini"
	controllerGrok    = "grok"
	scopeRead         = "job.read"
	scopeSubmit       = "job.submit"
	scopeControl      = "job.control"
	scopeConfidence   = "confidence.evaluate"
	// Issued controller tokens are much smaller than this bound. Keep the
	// authenticated lookup bounded before hashing attacker-controlled header
	// data, while leaving room for private deployments with longer opaque
	// bearer values.
	maxControllerAuthorizationBytes = 4096
	// Authentication callers accept exactly one matching header value. Keeping
	// only the first two values is enough to distinguish valid input from any
	// duplicate while bounding malformed direct Header maps before the caller's
	// single-value check.
	maxAuthorizationHeaderValues = 2
	// Direct library callers can construct an arbitrarily large Header map.
	// Keep the case-insensitive authentication scan bounded before either the
	// controller or admin token is compared.
	maxAuthorizationHeaderFields     = 256
	maxAuthorizationHeaderEntries    = 1024
	maxAuthorizationHeaderNameBytes  = 256
	maxAuthorizationHeaderValueBytes = 16 << 10
	maxAuthorizationHeaderTotalBytes = 64 << 10
	// Controller hashes are produced by hashControllerToken as lowercase
	// SHA-256 hex. Keep persisted local state on that canonical representation
	// before authentication compares it.
	maxControllerTokenHashBytes = sha256.Size * 2
	// Controller IDs become lifecycle principal IDs and management-route path
	// components. Keep persisted local state on the same bounded identity shape
	// before it is listed, authenticated, or used by the v2 handoff.
	maxControllerIDBytes = 128
)

type ControllerRecord struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	TokenHash string   `json:"-"`
	Scopes    []string `json:"scopes"`
	Revoked   bool     `json:"revoked"`
	Created   int64    `json:"created"`
}

func hashControllerToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func defaultControllerScopes() []string {
	// New capabilities are opt-in so legacy and default controller credentials
	// do not silently gain authority during an upgrade.
	return []string{scopeRead, scopeSubmit, scopeControl}
}

func allowedControllerScopes() map[string]bool {
	return map[string]bool{
		scopeRead:                   true,
		scopeSubmit:                 true,
		scopeControl:                true,
		scopeConfidence:             true,
		lifecycle.ScopeProjectRead:  true,
		lifecycle.ScopeProjectWrite: true,
		lifecycle.ScopeTaskRead:     true,
		lifecycle.ScopeTaskWrite:    true,
		lifecycle.ScopeTaskLease:    true,
		lifecycle.ScopeTaskRecover:  true,
	}
}

func validControllerKind(kind string) bool {
	return kind == controllerChatGPT || kind == controllerGemini || kind == controllerGrok
}

func hasScope(c *ControllerRecord, want string) bool {
	if c == nil || c.Revoked {
		return false
	}
	for _, scope := range c.Scopes {
		if scope == want {
			return true
		}
	}
	return false
}

// validPersistedController rejects local controller records whose embedded
// identity no longer matches the map key that owns them. The map key is the
// durable ownership boundary; accepting a mismatched record could authenticate
// one token as a different principal or advertise a misleading identity.
func validPersistedController(id string, c *ControllerRecord) bool {
	return c != nil && validControllerID(id) && c.ID == id && validControllerKind(c.Kind) && validControllerTokenHash(c.TokenHash) && validPersistedControllerScopes(c.Scopes)
}

func validControllerID(value string) bool {
	if value == "" || len(value) > maxControllerIDBytes || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/?#") || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

func validControllerTokenHash(value string) bool {
	if len(value) != maxControllerTokenHashBytes {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')) {
			return false
		}
	}
	return true
}

// validPersistedControllerScopes applies the same vocabulary, size, and
// duplicate rules to local state that controller issuance applies to request
// input. Every gateway path shares this check so malformed claims cannot be
// authenticated for a legacy operation and only rejected later by v2.
func validPersistedControllerScopes(scopes []string) bool {
	allowed := allowedControllerScopes()
	if len(scopes) > len(allowed) {
		return false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if len(scope) > maxControllerScopeBytes || !allowed[scope] {
			return false
		}
		if _, duplicate := seen[scope]; duplicate {
			return false
		}
		seen[scope] = struct{}{}
	}
	return true
}

// cloneControllerRecord returns an immutable handoff snapshot. The gateway
// lock protects the map and record while it is held, but the scope slice is a
// separately allocated reference; retaining it after unlocking would let a
// later local-state update change the authenticated lifecycle principal.
func cloneControllerRecord(c *ControllerRecord) *ControllerRecord {
	if c == nil {
		return nil
	}
	copy := *c
	copy.Scopes = append([]string(nil), c.Scopes...)
	return &copy
}

func (s *Server) controllerFromRequest(r *http.Request) *ControllerRecord {
	if s == nil || r == nil {
		return nil
	}
	authValues := headerValuesCaseInsensitive(r.Header, "Authorization")
	if len(authValues) != 1 || len(authValues[0]) > maxControllerAuthorizationBytes {
		return nil
	}
	token, ok := parseBearerAuthorization(authValues[0])
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var matched *ControllerRecord
	for id, c := range s.controllers {
		// Persisted controller state is local input. A malformed JSON null
		// entry must not turn an authentication lookup into a process panic.
		if !validPersistedController(id, c) {
			continue
		}
		if security.ConstantTimeEqual(c.TokenHash, hashControllerToken(token)) && !c.Revoked {
			// A token must identify exactly one controller. Do not let map
			// iteration order choose an owner when corrupted or manually
			// repaired local state contains duplicate credentials.
			if matched != nil {
				return nil
			}
			matched = cloneControllerRecord(c)
		}
	}
	if matched != nil {
		// The legacy MCP token is a second durable identity. A credential that
		// matches both it and a persisted controller must not silently select
		// one owner based on precedence; reject the identity collision.
		if s.mcpToken != "" && security.ConstantTimeEqual(s.mcpToken, token) {
			return nil
		}
		return matched
	}
	// Existing deployments keep working: the old MCP token is attributed to
	// ChatGPT, never to a name supplied by the caller.
	if s.mcpToken != "" && security.ConstantTimeEqual(s.mcpToken, token) {
		return &ControllerRecord{ID: controllerChatGPT, Kind: controllerChatGPT, Scopes: defaultControllerScopes()}
	}
	return nil
}

// parseBearerAuthorization accepts the HTTP authentication scheme without
// making its casing significant. The credential remains bounded by the
// caller, and the existing whitespace/token rules stay unchanged.
func parseBearerAuthorization(value string) (string, bool) {
	const prefix = "Bearer "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(value[len(prefix):])
	return token, token != ""
}

// headerValuesCaseInsensitive preserves HTTP's case-insensitive field-name
// semantics for direct library callers whose Header map may contain both
// canonical and non-canonical keys. Authentication must see every matching
// value so duplicate fields fail closed instead of being reduced to the first
// canonical map entry. Only two values are retained because callers accept a
// singleton and reject any duplicate.
func headerValuesCaseInsensitive(header http.Header, name string) []string {
	if len(header) > maxAuthorizationHeaderFields {
		return nil
	}
	remainingBytes := maxAuthorizationHeaderTotalBytes
	var values []string
	for key, entries := range header {
		if len(key) == 0 || len(key) > maxAuthorizationHeaderNameBytes || len(key) > remainingBytes {
			return nil
		}
		remainingBytes -= len(key)
		if len(entries) > maxAuthorizationHeaderEntries {
			return nil
		}
		for _, entry := range entries {
			if len(entry) > maxAuthorizationHeaderValueBytes || len(entry) > remainingBytes {
				return nil
			}
			remainingBytes -= len(entry)
		}
		if strings.EqualFold(key, name) {
			// A direct caller can represent a present field with zero values.
			// Preserve that malformed presence as one empty value so a valid
			// value under another case-variant key cannot become an accepted
			// singleton through omission of the empty entry.
			if len(entries) == 0 {
				if len(values) >= maxAuthorizationHeaderValues {
					return values
				}
				values = append(values, "")
				continue
			}
			remaining := maxAuthorizationHeaderValues - len(values)
			if remaining <= 0 {
				return values
			}
			if len(entries) > remaining {
				values = append(values, entries[:remaining]...)
				return values
			}
			values = append(values, entries...)
		}
	}
	return values
}

func (s *Server) controllersHandler(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == "POST" {
		var req struct {
			Kind   string   `json:"kind"`
			Scopes []string `json:"scopes"`
		}
		if jsonDecode(r, &req) != nil || !validControllerKind(req.Kind) {
			http.Error(w, "kind must be chatgpt, gemini, or grok", http.StatusBadRequest)
			return
		}
		if len(req.Scopes) == 0 {
			req.Scopes = defaultControllerScopes()
		}
		allowed := allowedControllerScopes()
		// Bound the persisted claim before allocating a map sized from
		// caller-controlled input. The lifecycle handoff applies the same
		// vocabulary bound when it revalidates an authenticated snapshot.
		if len(req.Scopes) > len(allowed) {
			http.Error(w, "too many scopes", http.StatusBadRequest)
			return
		}
		seen := make(map[string]struct{}, len(req.Scopes))
		for _, scope := range req.Scopes {
			if !allowed[scope] {
				http.Error(w, "invalid scope", http.StatusBadRequest)
				return
			}
			if _, duplicate := seen[scope]; duplicate {
				http.Error(w, "duplicate scope", http.StatusBadRequest)
				return
			}
			seen[scope] = struct{}{}
		}
		token, err := security.Token(32)
		if err != nil {
			http.Error(w, "token generation failed", http.StatusInternalServerError)
			return
		}
		id, err := security.Token(12)
		if err != nil {
			http.Error(w, "id generation failed", http.StatusInternalServerError)
			return
		}
		c := &ControllerRecord{ID: id, Kind: req.Kind, TokenHash: hashControllerToken(token), Scopes: req.Scopes, Created: time.Now().Unix()}
		s.mu.Lock()
		if _, exists := s.controllers[id]; exists {
			s.mu.Unlock()
			http.Error(w, "persist failed", http.StatusInternalServerError)
			return
		}
		s.controllers[id] = c
		err = s.saveStateLocked()
		if err != nil {
			delete(s.controllers, id)
		}
		s.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", http.StatusInternalServerError)
			return
		}
		_ = s.audit.Write(audit.Event{Action: "controller.issue", Detail: map[string]any{"id": id, "kind": req.Kind, "scopes": req.Scopes}})
		write(w, map[string]any{"id": id, "kind": req.Kind, "scopes": req.Scopes, "token": token})
		return
	}
	if r.Method == "GET" {
		s.mu.Lock()
		defer s.mu.Unlock()
		out := make([]*ControllerRecord, 0, len(s.controllers))
		for id, c := range s.controllers {
			// Persisted controller state is local input. Omit malformed null
			// entries from the administrative listing instead of panicking while
			// copying a record; authentication applies the same fail-closed rule.
			if !validPersistedController(id, c) {
				continue
			}
			out = append(out, cloneControllerRecord(c))
		}
		write(w, out)
		return
	}
	if r.Method == "DELETE" {
		id := strings.TrimPrefix(r.URL.Path, "/v1/controllers/")
		if !validControllerID(id) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.mu.Lock()
		c := s.controllers[id]
		// A controller map entry is local persisted state. Do not revoke or
		// audit a record whose embedded identity or kind no longer matches the
		// map key; malformed state must fail closed on every management path.
		if !validPersistedController(id, c) {
			s.mu.Unlock()
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		previousRevoked := c.Revoked
		// Keep audit evidence independent of the mutable controller record once
		// the gateway lock is released. A later state update must not race with
		// or rewrite the kind recorded for this revocation.
		auditKind := c.Kind
		c.Revoked = true
		if err := s.saveStateLocked(); err != nil {
			c.Revoked = previousRevoked
			s.mu.Unlock()
			http.Error(w, "persist failed", http.StatusInternalServerError)
			return
		}
		s.mu.Unlock()
		_ = s.audit.Write(audit.Event{Action: "controller.revoke", Detail: map[string]any{"id": id, "kind": auditKind}})
		write(w, map[string]any{"revoked": id})
		return
	}
	http.Error(w, "method", http.StatusMethodNotAllowed)
}

func jsonDecode(r *http.Request, v any) error { return decodeRequest(r, v) }
