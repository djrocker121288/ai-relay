package gateway

import (
	"errors"
	"net/http"

	"github.com/ai-relay/ai-relay/internal/v2/lifecycle"
)

const maxControllerScopeBytes = 256

// NewLifecycleHTTPHandler creates the reviewed handoff from an authenticated
// gateway controller to the additive v2 lifecycle HTTP boundary. It does not
// register a route, open a listener, terminate TLS, or alter the legacy
// gateway. Callers must supply a lifecycle store and a verifier for the
// deployment's completed HTTPS boundary.
func (s *Server) NewLifecycleHTTPHandler(store *lifecycle.Store, secure lifecycle.SecureTransportVerifier) (http.Handler, error) {
	if s == nil {
		return nil, errors.New("gateway server is required")
	}
	return lifecycle.NewMCPHTTPHandler(store, func(r *http.Request) (lifecycle.Principal, error) {
		controller := s.controllerFromRequest(r)
		if controller == nil {
			return lifecycle.Principal{}, errors.New("controller authentication failed")
		}
		scopes, err := lifecycleScopes(controller)
		if err != nil {
			return lifecycle.Principal{}, errors.New("controller scopes are invalid")
		}
		return lifecycle.Principal{
			ID:     controller.ID,
			Scopes: scopes,
		}, nil
	}, secure)
}

func lifecycleScopes(controller *ControllerRecord) ([]string, error) {
	if controller == nil {
		return nil, errors.New("controller is required")
	}
	if !validPersistedControllerScopes(controller.Scopes) {
		return nil, errors.New("controller scopes are invalid")
	}
	lifecycleKnown := map[string]struct{}{
		lifecycle.ScopeProjectRead:  {},
		lifecycle.ScopeProjectWrite: {},
		lifecycle.ScopeTaskRead:     {},
		lifecycle.ScopeTaskWrite:    {},
		lifecycle.ScopeTaskLease:    {},
		lifecycle.ScopeTaskRecover:  {},
	}
	scopes := make([]string, 0, len(controller.Scopes))
	for _, scope := range controller.Scopes {
		if _, ok := lifecycleKnown[scope]; ok {
			scopes = append(scopes, scope)
		}
	}
	return scopes, nil
}
