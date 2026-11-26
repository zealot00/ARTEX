package db

import (
	"regexp"
	"strings"
	"testing"
)

// TestSchemaRollingUpdateIdempotencyGuard statically audits db/schema.sql so
// future commits cannot reintroduce destructive or ACCESS-EXCLUSIVE-lock-heavy
// non-idempotent DDL (such as unconditional DROP TRIGGER / DROP CONSTRAINT /
// CREATE TABLE without IF NOT EXISTS) that breaks zero-downtime rolling updates.
func TestSchemaRollingUpdateIdempotencyGuard(t *testing.T) {
	lines := strings.Split(schemaSQL, "\n")

	reCreateTable := regexp.MustCompile(`(?i)^\s*CREATE\s+TABLE\s+`)
	reCreateTableSafe := regexp.MustCompile(`(?i)^\s*CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+`)
	reCreateIndex := regexp.MustCompile(`(?i)^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+`)
	reCreateIndexSafe := regexp.MustCompile(`(?i)^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+`)
	reTopLevelDropTrigger := regexp.MustCompile(`(?i)^\s*DROP\s+TRIGGER\b`)
	reTopLevelCreateTrigger := regexp.MustCompile(`(?i)^\s*CREATE\s+TRIGGER\b`)
	reTopLevelDropConstraint := regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+\S+\s+DROP\s+CONSTRAINT\b`)

	for i, line := range lines {
		ln := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		if reCreateTable.MatchString(line) && !reCreateTableSafe.MatchString(line) {
			t.Errorf("db/schema.sql:%d: CREATE TABLE must use IF NOT EXISTS: %s", ln, trimmed)
		}
		if reCreateIndex.MatchString(line) && !reCreateIndexSafe.MatchString(line) {
			t.Errorf("db/schema.sql:%d: CREATE INDEX must use IF NOT EXISTS: %s", ln, trimmed)
		}
		if reTopLevelDropTrigger.MatchString(line) {
			t.Errorf("db/schema.sql:%d: unconditional DROP TRIGGER acquires ACCESS EXCLUSIVE lock on every restart; use ensure_trigger(): %s", ln, trimmed)
		}
		if reTopLevelCreateTrigger.MatchString(line) {
			t.Errorf("db/schema.sql:%d: top-level CREATE TRIGGER is not idempotent; use ensure_trigger(): %s", ln, trimmed)
		}
		if reTopLevelDropConstraint.MatchString(line) {
			t.Errorf("db/schema.sql:%d: unconditional top-level DROP CONSTRAINT locks/re-scans table on every restart; use ensure_check_constraint() or DO $$ guard: %s", ln, trimmed)
		}
	}

	if !strings.Contains(schemaSQL, "CREATE TABLE IF NOT EXISTS schema_migrations") {
		t.Error("db/schema.sql must define schema_migrations table for rolling-update checksum tracking")
	}
	if len(schemaChecksum()) != 64 {
		t.Fatalf("expected 64-char sha256 schemaChecksum, got %q", schemaChecksum())
	}
}
