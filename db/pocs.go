package db

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	PocKindNucleiYAML   = "nuclei_yaml"
	PocKindPythonScript = "python_script"
)

var (
	ErrPocInvalidName     = errors.New("poc name is required (max 128 characters, no slashes)")
	ErrPocInvalidKind     = errors.New("poc kind must be one of: nuclei_yaml, python_script")
	ErrPocInvalidSeverity = errors.New("poc severity must be one of: info, low, medium, high, critical")
	ErrPocEmptyContent    = errors.New("poc content must not be empty")
	ErrPocNotFound        = errors.New("poc not found")
)

// PocRecord stores an enterprise custom PoC template or verification script.
type PocRecord struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	Severity        string    `json:"severity"`
	CVE             string    `json:"cve"`
	Tags            string    `json:"tags"`
	Description     string    `json:"description"`
	Content         string    `json:"content,omitempty"`
	ExploitGuidance string    `json:"exploit_guidance,omitempty"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// UpsertPocInput holds validated fields for creating or updating a PoC record.
type UpsertPocInput struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Severity        string `json:"severity"`
	CVE             string `json:"cve"`
	Tags            string `json:"tags"`
	Description     string `json:"description"`
	Content         string `json:"content"`
	ExploitGuidance string `json:"exploit_guidance"`
	CreatedBy       string `json:"created_by"`
}

func normalizePocName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || utf8.RuneCountInString(name) > 128 || strings.ContainsAny(name, "/\\") {
		return "", ErrPocInvalidName
	}
	return name, nil
}

func normalizePocKind(raw string) (string, error) {
	k := strings.ToLower(strings.TrimSpace(raw))
	switch k {
	case PocKindNucleiYAML, PocKindPythonScript:
		return k, nil
	default:
		return "", ErrPocInvalidKind
	}
}

func normalizePocSeverity(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "medium", nil
	}
	switch s {
	case "info", "low", "medium", "high", "critical":
		return s, nil
	default:
		return "", ErrPocInvalidSeverity
	}
}

func normalizePocTags(raw string) string {
	parts := strings.Split(raw, ",")
	seen := make(map[string]bool, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.ToLower(strings.TrimSpace(p))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return strings.Join(out, ",")
}

// UpsertPoc creates or updates an enterprise PoC by unique name.
func (d *DB) UpsertPoc(in UpsertPocInput) (rec *PocRecord, created bool, err error) {
	name, err := normalizePocName(in.Name)
	if err != nil {
		return nil, false, err
	}
	kind, err := normalizePocKind(in.Kind)
	if err != nil {
		return nil, false, err
	}
	sev, err := normalizePocSeverity(in.Severity)
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(in.Content) == "" {
		return nil, false, ErrPocEmptyContent
	}
	cve := strings.ToUpper(strings.TrimSpace(in.CVE))
	tags := normalizePocTags(in.Tags)
	desc := strings.TrimSpace(in.Description)
	guidance := strings.TrimSpace(in.ExploitGuidance)
	createdBy := strings.TrimSpace(in.CreatedBy)

	var p PocRecord
	var isInsert bool
	err = d.QueryRow(`
INSERT INTO pocs(name, kind, severity, cve, tags, description, content, exploit_guidance, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (name) DO UPDATE
  SET kind             = EXCLUDED.kind,
      severity         = EXCLUDED.severity,
      cve              = EXCLUDED.cve,
      tags             = EXCLUDED.tags,
      description      = EXCLUDED.description,
      content          = EXCLUDED.content,
      exploit_guidance = EXCLUDED.exploit_guidance
RETURNING id, name, kind, severity, cve, tags, description, content, exploit_guidance, created_by, created_at, updated_at, (xmax = 0)`,
		name, kind, sev, cve, tags, desc, in.Content, guidance, createdBy).
		Scan(&p.ID, &p.Name, &p.Kind, &p.Severity, &p.CVE, &p.Tags, &p.Description, &p.Content, &p.ExploitGuidance, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &isInsert)
	if err != nil {
		return nil, false, err
	}
	return &p, isInsert, nil
}

// SearchPocs returns PoC metadata matching optional query, kind, and tag filters.
func (d *DB) SearchPocs(query, kind, tag string, limit int) ([]PocRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	q := strings.ToLower(strings.TrimSpace(query))
	k := strings.ToLower(strings.TrimSpace(kind))
	tg := strings.ToLower(strings.TrimSpace(tag))

	rows, err := d.Query(`
SELECT id, name, kind, severity, cve, tags, description, exploit_guidance, created_by, created_at, updated_at
FROM pocs
WHERE ($1 = '' OR kind = $1)
  AND ($2 = '' OR strpos(',' || tags || ',', ',' || $2 || ',') > 0)
  AND ($3 = '' OR lower(name) LIKE '%' || $3 || '%' OR lower(cve) LIKE '%' || $3 || '%' OR lower(tags) LIKE '%' || $3 || '%' OR lower(description) LIKE '%' || $3 || '%')
ORDER BY id DESC
LIMIT $4`, k, tg, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PocRecord
	for rows.Next() {
		var p PocRecord
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.Severity, &p.CVE, &p.Tags, &p.Description, &p.ExploitGuidance, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPocByRef fetches a PoC (including full content) by numeric id or exact name.
func (d *DB) GetPocByRef(ref string) (*PocRecord, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, ErrPocNotFound
	}
	var p PocRecord
	var row *sql.Row
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil && id > 0 {
		row = d.QueryRow(`
SELECT id, name, kind, severity, cve, tags, description, content, exploit_guidance, created_by, created_at, updated_at
FROM pocs WHERE id = $1`, id)
	} else {
		row = d.QueryRow(`
SELECT id, name, kind, severity, cve, tags, description, content, exploit_guidance, created_by, created_at, updated_at
FROM pocs WHERE name = $1`, ref)
	}
	err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.Severity, &p.CVE, &p.Tags, &p.Description, &p.Content, &p.ExploitGuidance, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPocNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// DeletePoc removes a PoC record by id.
func (d *DB) DeletePoc(id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM pocs WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
