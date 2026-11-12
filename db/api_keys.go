package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// APIKeyPrefix distinguishes machine API keys from signed admin JWTs.
	APIKeyPrefix = "artex_ak_"

	ScopeTasksCreate     = "tasks:create"
	ScopeTasksRead       = "tasks:read"
	ScopeTasksControl    = "tasks:control"
	ScopeFindingsRead    = "findings:read"
	ScopeChatWrite       = "chat:write"
	ScopeInterceptDecide = "intercept:decide"
)

// AllAPIKeyScopes lists all assignable machine API key scopes in canonical order.
var AllAPIKeyScopes = []string{
	ScopeTasksCreate,
	ScopeTasksRead,
	ScopeTasksControl,
	ScopeFindingsRead,
	ScopeChatWrite,
	ScopeInterceptDecide,
}

var validAPIKeyScopes = func() map[string]bool {
	m := make(map[string]bool, len(AllAPIKeyScopes))
	for _, s := range AllAPIKeyScopes {
		m[s] = true
	}
	return m
}()

var (
	ErrAPIKeyInvalidName  = errors.New("api key name is required (max 128 characters)")
	ErrAPIKeyInvalidScope = errors.New("invalid or empty api key scopes")
	ErrAPIKeyUnauthorized = errors.New("api key is invalid, expired, or revoked")
)

// APIKey is a scoped machine credential stored hashed in PostgreSQL.
type APIKey struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// IsAPIKeyFormat reports whether raw carries the ARTEX machine key prefix.
func IsAPIKeyFormat(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), APIKeyPrefix)
}

// HashAPIKey returns the SHA-256 hex digest persisted for raw.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

// NormalizeAPIKeyScopes validates and deduplicates requested scopes.
func NormalizeAPIKeyScopes(scopes []string) ([]string, error) {
	seen := make(map[string]bool, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, raw := range scopes {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !validAPIKeyScopes[s] {
			return nil, fmt.Errorf("%w: unknown scope %q", ErrAPIKeyInvalidScope, s)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: at least one scope is required", ErrAPIKeyInvalidScope)
	}
	return out, nil
}

// CreateAPIKey mints a new scoped machine API key and stores only its SHA-256 hash.
// The raw secret is returned once to the caller and cannot be recovered later.
func (d *DB) CreateAPIKey(name string, scopes []string, expiresAt *time.Time) (*APIKey, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 128 {
		return nil, "", ErrAPIKeyInvalidName
	}
	normScopes, err := NormalizeAPIKeyScopes(scopes)
	if err != nil {
		return nil, "", err
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return nil, "", fmt.Errorf("generate api key: %w", err)
	}
	rawSecret := APIKeyPrefix + hex.EncodeToString(buf)
	keyPrefix := rawSecret[:len(APIKeyPrefix)+8]
	keyHash := HashAPIKey(rawSecret)
	scopesJSON, _ := json.Marshal(normScopes)

	var k APIKey
	var rawScopes []byte
	err = d.QueryRow(`
INSERT INTO api_keys(name, key_prefix, key_hash, scopes, expires_at)
VALUES ($1, $2, $3, $4::jsonb, $5)
RETURNING id, name, key_prefix, scopes, created_at, last_used_at, expires_at, revoked_at`,
		name, keyPrefix, keyHash, string(scopesJSON), expiresAt).
		Scan(&k.ID, &k.Name, &k.KeyPrefix, &rawScopes, &k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt)
	if err != nil {
		return nil, "", err
	}
	_ = json.Unmarshal(rawScopes, &k.Scopes)
	return &k, rawSecret, nil
}

// ListAPIKeys returns all API keys newest first without exposing hashes.
func (d *DB) ListAPIKeys() ([]APIKey, error) {
	rows, err := d.Query(`
SELECT id, name, key_prefix, scopes, created_at, last_used_at, expires_at, revoked_at
FROM api_keys
ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		var rawScopes []byte
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &rawScopes, &k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rawScopes, &k.Scopes)
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey marks an active API key as revoked.
func (d *DB) RevokeAPIKey(id int64) (bool, error) {
	res, err := d.Exec(`UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// AuthenticateAPIKey verifies raw against active non-expired keys and updates last_used_at.
func (d *DB) AuthenticateAPIKey(raw string, now time.Time) (*APIKey, error) {
	if !IsAPIKeyFormat(raw) {
		return nil, ErrAPIKeyUnauthorized
	}
	hash := HashAPIKey(raw)
	var k APIKey
	var rawScopes []byte
	err := d.QueryRow(`
SELECT id, name, key_prefix, scopes, created_at, last_used_at, expires_at, revoked_at
FROM api_keys
WHERE key_hash = $1`, hash).
		Scan(&k.ID, &k.Name, &k.KeyPrefix, &rawScopes, &k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt)
	if err == sql.ErrNoRows {
		return nil, ErrAPIKeyUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if k.RevokedAt != nil {
		return nil, ErrAPIKeyUnauthorized
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
		return nil, ErrAPIKeyUnauthorized
	}
	_ = json.Unmarshal(rawScopes, &k.Scopes)
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) >= time.Minute {
		_, _ = d.Exec(`UPDATE api_keys SET last_used_at=$2 WHERE id=$1`, k.ID, now)
	}
	return &k, nil
}
