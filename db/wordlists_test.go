package db

import (
	"errors"
	"testing"
)

func TestNormalizeWordlistInputs(t *testing.T) {
	if _, err := NormalizeWordlistName(""); !errors.Is(err, ErrWordlistInvalidName) {
		t.Fatalf("empty name: got %v, want %v", err, ErrWordlistInvalidName)
	}
	if _, err := NormalizeWordlistName("bad/name"); !errors.Is(err, ErrWordlistInvalidName) {
		t.Fatalf("slash name: got %v, want %v", err, ErrWordlistInvalidName)
	}
	gotName, err := NormalizeWordlistName("  corp-top100  ")
	if err != nil || gotName != "corp-top100" {
		t.Fatalf("valid name: got %q, %v", gotName, err)
	}
	for _, k := range []string{"username", "PASSWORD", " UserPass "} {
		if _, err := NormalizeWordlistKind(k); err != nil {
			t.Fatalf("kind %q should be valid: %v", k, err)
		}
	}
	if _, err := NormalizeWordlistKind("other"); !errors.Is(err, ErrWordlistInvalidKind) {
		t.Fatalf("invalid kind: got %v, want %v", err, ErrWordlistInvalidKind)
	}
}
