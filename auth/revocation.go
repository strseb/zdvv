package auth

import (
	"sync"
)

// RevocationService manages token revocation
type RevocationService struct {
	revokedTokens map[string]struct{}
	mu            sync.RWMutex
}

// NewRevocationService creates a new revocation service
func NewRevocationService() *RevocationService {
	return &RevocationService{
		revokedTokens: make(map[string]struct{}),
	}
}

// Revoke adds a token ID to the revocation list
func (s *RevocationService) Revoke(jti string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedTokens[jti] = struct{}{}
}

// IsRevoked checks if a token ID has been revoked
func (s *RevocationService) IsRevoked(jti string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, revoked := s.revokedTokens[jti]
	return revoked
}

// GetRevokedList returns a copy of the revoked tokens list
func (s *RevocationService) GetRevokedList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	revokedList := make([]string, 0, len(s.revokedTokens))
	for jti := range s.revokedTokens {
		revokedList = append(revokedList, jti)
	}

	return revokedList
}
