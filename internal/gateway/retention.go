package gateway

import "time"

const maxRememberedNonces = 100000

// acceptNonceLocked bounds ephemeral replay state without evicting live nonces:
// saturation fails closed, preserving replay protection. Call while holding mu.
func (s *Server) acceptNonceLocked(device, nonce string, now time.Time) bool {
	if nonce == "" || len(nonce) > 256 {
		return false
	}
	if s.nonceSweep.IsZero() || now.Sub(s.nonceSweep) >= time.Minute || len(s.nonces) >= maxRememberedNonces {
		for key, expires := range s.nonces {
			if !expires.After(now) {
				delete(s.nonces, key)
			}
		}
		s.nonceSweep = now
	}
	key := device + ":" + nonce
	if expires, exists := s.nonces[key]; exists && expires.After(now) {
		return false
	}
	if len(s.nonces) >= maxRememberedNonces {
		return false
	}
	s.nonces[key] = now.Add(10 * time.Minute)
	return true
}

func (s *Server) pruneEnrollLocked(now time.Time) {
	for token, expires := range s.enroll {
		if !expires.After(now) {
			delete(s.enroll, token)
		}
	}
}
