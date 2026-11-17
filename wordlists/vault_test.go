package wordlists

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultEncryptsAtRestAndMasksMatches(t *testing.T) {
	keyDir := t.TempDir()
	v, err := NewVault(keyDir)
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}

	secrets := []string{"SuperSecretPass!2026", "Winter@Corp99"}
	sum, count, err := v.Save(7, secrets)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if sum == "" || count != 2 {
		t.Fatalf("unexpected sum=%q count=%d", sum, count)
	}

	// Verify ciphertext on disk never contains plaintext passwords.
	rawDisk, err := os.ReadFile(filepath.Join(keyDir, vaultSubdir, "7.enc"))
	if err != nil {
		t.Fatalf("read .enc: %v", err)
	}
	for _, s := range secrets {
		if bytes.Contains(rawDisk, []byte(s)) {
			t.Fatalf("plaintext secret %q found on disk in encrypted blob", s)
		}
	}

	// Materialize into ephemeral temp file and verify contents match.
	tmpDir := t.TempDir()
	tmpPath, n, err := v.MaterializeTemp(7, tmpDir, "pass")
	if err != nil {
		t.Fatalf("MaterializeTemp: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 entries, got %d", n)
	}
	gotTmp, _ := os.ReadFile(tmpPath)
	if !strings.Contains(string(gotTmp), "SuperSecretPass!2026") {
		t.Fatalf("materialized file missing expected entry")
	}

	// ParseHydraMatches must redact passwords before returning to the model.
	hydraOut := "[22][ssh] host: 10.10.1.5   login: opsadmin   password: SuperSecretPass!2026\n"
	matches := ParseHydraMatches(hydraOut)
	if len(matches) != 1 || matches[0].Username != "opsadmin" {
		t.Fatalf("unexpected matches: %+v", matches)
	}
	if strings.Contains(matches[0].MaskedPassword, "SuperSecretPass") {
		t.Fatalf("password was not masked: %q", matches[0].MaskedPassword)
	}
}

func TestLoadDecryptedSliceAndParseNxcMatches(t *testing.T) {
	v, err := NewVault(t.TempDir())
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if _, _, err := v.Save(9, []string{"Spring2026!", "Summer2026!", "Autumn2026!"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	slice, total, err := v.LoadDecryptedSlice(9, 1, 1)
	if err != nil || total != 3 || len(slice) != 1 || slice[0] != "Summer2026!" {
		t.Fatalf("LoadDecryptedSlice(1,1) = %v, total=%d, err=%v", slice, total, err)
	}

	nxcOut := "SMB         10.10.0.10      445    DC01             [+] CORP\\alice:Summer2026! (Pwn3d!)\n" +
		"SMB         10.10.0.10      445    DC01             [-] CORP\\bob:WrongPass\n"
	matches := ParseNxcMatches(nxcOut)
	if len(matches) != 1 || matches[0].Username != `CORP\alice` {
		t.Fatalf("unexpected nxc matches: %+v", matches)
	}
	if strings.Contains(matches[0].MaskedPassword, "Summer2026") {
		t.Fatalf("nxc password was not masked: %q", matches[0].MaskedPassword)
	}
}
