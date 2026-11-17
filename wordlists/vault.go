// Package wordlists provides an AES-256-GCM encrypted local vault for
// credential-audit dictionaries so plaintext passwords are encrypted at rest
// outside the agent workspace and remain invisible to LLM contexts.
package wordlists

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	keyFilename    = "wordlist.key"
	maxEntries     = 50000
	maxEntryRunes  = 512
	vaultSubdir    = "wordlists"
	nonceSizeBytes = 12
)

var (
	ErrEmptyWordlist = errors.New("wordlist must contain at least one non-empty entry")
	ErrTooManyItems  = errors.New("wordlist exceeds maximum allowed entries")
)

// Vault manages AES-256-GCM encrypted wordlist files inside keyDir/wordlists.
type Vault struct {
	dir string
	key []byte // 32 bytes AES-256
}

// NewVault initializes the encrypted wordlist vault inside keyDir (never dataDir).
func NewVault(keyDir string) (*Vault, error) {
	if strings.TrimSpace(keyDir) == "" {
		return nil, fmt.Errorf("wordlists: keyDir is required")
	}
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create wordlist key dir: %w", err)
	}
	dir := filepath.Join(keyDir, vaultSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create wordlist vault dir: %w", err)
	}
	key, err := loadOrCreateKey(filepath.Join(keyDir, keyFilename))
	if err != nil {
		return nil, err
	}
	return &Vault{dir: dir, key: key}, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		decoded, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("invalid wordlist key at %s", path)
		}
		return decoded, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read wordlist key: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate wordlist key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("write wordlist key: %w", err)
	}
	_, werr := f.WriteString(hex.EncodeToString(key) + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(path)
		if werr != nil {
			return nil, werr
		}
		return nil, cerr
	}
	return key, nil
}

// NormalizeEntries trims line endings, drops blank lines, and deduplicates preserving order.
func NormalizeEntries(entries []string) ([]string, error) {
	seen := make(map[string]bool, len(entries))
	out := make([]string, 0, len(entries))
	for _, raw := range entries {
		s := strings.TrimRight(raw, "\r\n")
		if strings.TrimSpace(s) == "" {
			continue
		}
		if utf8.RuneCountInString(s) > maxEntryRunes {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) > maxEntries {
			return nil, fmt.Errorf("%w (%d)", ErrTooManyItems, maxEntries)
		}
	}
	if len(out) == 0 {
		return nil, ErrEmptyWordlist
	}
	return out, nil
}

// Save encrypts entries with AES-256-GCM and writes them atomically to <id>.enc.
func (v *Vault) Save(id int64, entries []string) (sha256Hex string, count int, err error) {
	norm, err := NormalizeEntries(entries)
	if err != nil {
		return "", 0, err
	}
	plaintext := []byte(strings.Join(norm, "\n") + "\n")
	sum := sha256.Sum256(plaintext)
	sha256Hex = hex.EncodeToString(sum[:])

	block, err := aes.NewCipher(v.key)
	if err != nil {
		return "", 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", 0, err
	}
	nonce := make([]byte, nonceSizeBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", 0, err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)

	dst := v.blobPath(id)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", 0, err
	}
	return sha256Hex, len(norm), nil
}

// LoadDecrypted decrypts and returns the wordlist entries in memory.
func (v *Vault) LoadDecrypted(id int64) ([]string, error) {
	raw, err := os.ReadFile(v.blobPath(id))
	if err != nil {
		return nil, err
	}
	if len(raw) < nonceSizeBytes {
		return nil, fmt.Errorf("corrupt encrypted wordlist #%d", id)
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, raw[:nonceSizeBytes], raw[nonceSizeBytes:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt wordlist #%d: %w", id, err)
	}
	return NormalizeEntries(strings.Split(string(plaintext), "\n"))
}

// LoadDecryptedSlice decrypts wordlist entries and returns a bounded slice [offset, offset+limit).
func (v *Vault) LoadDecryptedSlice(id int64, offset, limit int) ([]string, int, error) {
	all, err := v.LoadDecrypted(id)
	if err != nil {
		return nil, 0, err
	}
	total := len(all)
	if offset < 0 {
		offset = 0
	}
	if offset >= total || limit <= 0 {
		return nil, total, nil
	}
	end := min(offset+limit, total)
	out := make([]string, end-offset)
	copy(out, all[offset:end])
	return out, total, nil
}

// MaterializeTemp writes decrypted entries into an ephemeral 0600 file in dir
// for immediate consumption by a local CLI tool (caller must RemoveAll(dir)).
func (v *Vault) MaterializeTemp(id int64, dir, prefix string) (path string, count int, err error) {
	entries, err := v.LoadDecrypted(id)
	if err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(dir, prefix+"-*.txt")
	if err != nil {
		return "", 0, err
	}
	path = f.Name()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		_ = os.Remove(path)
		return "", 0, err
	}
	_, werr := f.WriteString(strings.Join(entries, "\n") + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(path)
		if werr != nil {
			return "", 0, werr
		}
		return "", 0, cerr
	}
	return path, len(entries), nil
}

// Delete removes the encrypted blob for id if present.
func (v *Vault) Delete(id int64) error {
	err := os.Remove(v.blobPath(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (v *Vault) blobPath(id int64) string {
	return filepath.Join(v.dir, fmt.Sprintf("%d.enc", id))
}

// MaskSecret redacts a password so plaintext credentials never enter LLM contexts.
func MaskSecret(secret string) string {
	r := []rune(secret)
	n := len(r)
	if n == 0 {
		return "(empty)"
	}
	if n <= 3 {
		return fmt.Sprintf("*** (len=%d)", n)
	}
	return fmt.Sprintf("%c%s%c (len=%d)", r[0], strings.Repeat("*", min(n-2, 8)), r[n-1], n)
}

// MaskedMatch is a model-safe credential-audit match with the password redacted.
type MaskedMatch struct {
	Username       string `json:"username"`
	MaskedPassword string `json:"masked_password"`
}

var hydraMatchRE = regexp.MustCompile(`(?m)^\[\d+\]\[[^\]]+\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(.+?)\s*$`)

// ParseHydraMatches extracts matched accounts from hydra output and redacts passwords.
func ParseHydraMatches(output string) []MaskedMatch {
	matches := hydraMatchRE.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]MaskedMatch, 0, len(matches))
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		out = append(out, MaskedMatch{
			Username:       strings.TrimSpace(m[1]),
			MaskedPassword: MaskSecret(strings.TrimSpace(m[2])),
		})
	}
	return out
}

var nxcMatchRE = regexp.MustCompile(`(?m)\[\+\]\s+([^\s:]+):(\S+)`)

// ParseNxcMatches extracts matched accounts from netexec/nxc [+] output lines and redacts passwords.
func ParseNxcMatches(output string) []MaskedMatch {
	matches := nxcMatchRE.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]MaskedMatch, 0, len(matches))
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		out = append(out, MaskedMatch{
			Username:       strings.TrimSpace(m[1]),
			MaskedPassword: MaskSecret(strings.TrimSpace(m[2])),
		})
	}
	return out
}
