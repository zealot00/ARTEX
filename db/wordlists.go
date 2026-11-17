package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	WordlistKindUsername = "username"
	WordlistKindPassword = "password"
	WordlistKindUserpass = "userpass"
)

var (
	ErrWordlistInvalidName = errors.New("wordlist name is required (max 128 characters, no slashes)")
	ErrWordlistInvalidKind = errors.New("wordlist kind must be one of: username, password, userpass")
	ErrWordlistNotFound    = errors.New("wordlist not found")
)

// WordlistMeta stores metadata for an encrypted wordlist. Plaintext entries are never persisted in PostgreSQL.
type WordlistMeta struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Description string    `json:"description"`
	EntryCount  int       `json:"entry_count"`
	SHA256      string    `json:"sha256"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NormalizeWordlistName validates and trims a wordlist name.
func NormalizeWordlistName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || utf8.RuneCountInString(name) > 128 || strings.ContainsAny(name, "/\\") {
		return "", ErrWordlistInvalidName
	}
	return name, nil
}

// NormalizeWordlistKind validates and normalizes a wordlist kind.
func NormalizeWordlistKind(raw string) (string, error) {
	k := strings.ToLower(strings.TrimSpace(raw))
	switch k {
	case WordlistKindUsername, WordlistKindPassword, WordlistKindUserpass:
		return k, nil
	default:
		return "", ErrWordlistInvalidKind
	}
}

// UpsertWordlistMeta creates or updates a wordlist metadata record by unique name.
// Returns created=true when a new row was inserted.
func (d *DB) UpsertWordlistMeta(name, kind, description, createdBy string) (meta *WordlistMeta, created bool, err error) {
	name, err = NormalizeWordlistName(name)
	if err != nil {
		return nil, false, err
	}
	kind, err = NormalizeWordlistKind(kind)
	if err != nil {
		return nil, false, err
	}
	description = strings.TrimSpace(description)
	createdBy = strings.TrimSpace(createdBy)

	var m WordlistMeta
	var isInsert bool
	err = d.QueryRow(`
INSERT INTO wordlists(name, kind, description, created_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (name) DO UPDATE
  SET kind = EXCLUDED.kind,
      description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE wordlists.description END
RETURNING id, name, kind, description, entry_count, sha256, created_by, created_at, updated_at, (xmax = 0)`,
		name, kind, description, createdBy).
		Scan(&m.ID, &m.Name, &m.Kind, &m.Description, &m.EntryCount, &m.SHA256, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt, &isInsert)
	if err != nil {
		return nil, false, err
	}
	return &m, isInsert, nil
}

// UpdateWordlistStats records the encrypted entry count and plaintext SHA-256 after Vault.Save succeeds.
func (d *DB) UpdateWordlistStats(id int64, entryCount int, sha256Hex string) (*WordlistMeta, error) {
	var m WordlistMeta
	err := d.QueryRow(`
UPDATE wordlists
SET entry_count = $2, sha256 = $3
WHERE id = $1
RETURNING id, name, kind, description, entry_count, sha256, created_by, created_at, updated_at`,
		id, entryCount, sha256Hex).
		Scan(&m.ID, &m.Name, &m.Kind, &m.Description, &m.EntryCount, &m.SHA256, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrWordlistNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListWordlists returns wordlist metadata sorted by kind and name, optionally filtered by kind.
func (d *DB) ListWordlists(kind string) ([]WordlistMeta, error) {
	kind = strings.TrimSpace(kind)
	var err error
	if kind != "" {
		kind, err = NormalizeWordlistKind(kind)
		if err != nil {
			return nil, err
		}
	}
	rows, err := d.Query(`
SELECT id, name, kind, description, entry_count, sha256, created_by, created_at, updated_at
FROM wordlists
WHERE ($1 = '' OR kind = $1)
ORDER BY kind ASC, name ASC`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WordlistMeta{}
	for rows.Next() {
		var m WordlistMeta
		if err := rows.Scan(&m.ID, &m.Name, &m.Kind, &m.Description, &m.EntryCount, &m.SHA256, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ResolveWordlist looks up a wordlist by numeric ID or exact name.
func (d *DB) ResolveWordlist(ref string) (*WordlistMeta, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("%w: empty reference", ErrWordlistNotFound)
	}
	var m WordlistMeta
	var err error
	if id, parseErr := strconv.ParseInt(ref, 10, 64); parseErr == nil && id > 0 {
		err = d.QueryRow(`
SELECT id, name, kind, description, entry_count, sha256, created_by, created_at, updated_at
FROM wordlists WHERE id = $1`, id).
			Scan(&m.ID, &m.Name, &m.Kind, &m.Description, &m.EntryCount, &m.SHA256, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt)
	} else {
		err = d.QueryRow(`
SELECT id, name, kind, description, entry_count, sha256, created_by, created_at, updated_at
FROM wordlists WHERE name = $1`, ref).
			Scan(&m.ID, &m.Name, &m.Kind, &m.Description, &m.EntryCount, &m.SHA256, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrWordlistNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// DeleteWordlistMeta removes a wordlist metadata row by ID.
func (d *DB) DeleteWordlistMeta(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM wordlists WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
