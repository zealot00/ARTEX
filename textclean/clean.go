package textclean

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	xunicode "golang.org/x/text/encoding/unicode"
)

const (
	maxDecompressBytes = 4 * 1024 * 1024 // 4 MiB safety cap against zip/gzip bombs
)

var (
	// Matches CSI sequences (\x1b[...), OSC sequences (\x1b]...\x07 or \x1b\\), and 2-byte ESC codes.
	reANSI = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])`)
	// Matches charset=... in Content-Type headers or HTML <meta> tags.
	reHeaderCharset = regexp.MustCompile(`(?i)\bcharset\s*=\s*["']?([a-z0-9._-]+)["']?`)
	reMetaCharset   = regexp.MustCompile(`(?i)<meta[^>]+charset\s*=\s*["']?\s*([a-z0-9._-]+)`)
)

// CleanBytes decompresses (if needed), decodes non-UTF-8 charsets (GBK/GB18030/Big5/ShiftJIS/UTF-16/etc.),
// strips ANSI escape sequences and NUL/control noise, and summarizes opaque binary payloads so tool outputs,
// HTTP traffic bodies, and remote session logs never produce garbled mojibake or break UTF-8 storage.
func CleanBytes(raw []byte, contentTypeHint, contentEncodingHint string) string {
	s, _ := DecodeBytes(raw, contentTypeHint, contentEncodingHint)
	return s
}

// DecodeBytes returns the cleaned UTF-8 text and the detected/applied charset label.
func DecodeBytes(raw []byte, contentTypeHint, contentEncodingHint string) (string, string) {
	if len(raw) == 0 {
		return "", "utf-8"
	}

	// 1. Auto-decompress if Content-Encoding indicates compression or gzip magic is present.
	data := maybeDecompress(raw, contentEncodingHint)

	// 2. Reject obvious binary formats (images, archives, PDF, ELF, PE, etc.) before charset heuristics.
	if label, isBin := detectBinaryMagic(data, contentTypeHint); isBin {
		return formatBinarySummary(data, label), "binary"
	}

	// 3. Handle explicit BOMs (UTF-8, UTF-16LE, UTF-16BE — common in Windows PowerShell/cmd output).
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return sanitizeText(string(data[3:])), "utf-8-bom"
	}
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		if dec, err := xunicode.UTF16(xunicode.LittleEndian, xunicode.ExpectBOM).NewDecoder().Bytes(data); err == nil {
			return sanitizeText(string(dec)), "utf-16le"
		}
	}
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		if dec, err := xunicode.UTF16(xunicode.BigEndian, xunicode.ExpectBOM).NewDecoder().Bytes(data); err == nil {
			return sanitizeText(string(dec)), "utf-16be"
		}
	}
	// BOM-less UTF-16LE heuristic (e.g. Windows wmic / PowerShell piped output: ASCII interleaved with 0x00).
	if looksLikeUTF16LE(data) {
		if dec, err := xunicode.UTF16(xunicode.LittleEndian, xunicode.IgnoreBOM).NewDecoder().Bytes(data); err == nil {
			return sanitizeText(string(dec)), "utf-16le"
		}
	}

	// 4. Explicit charset hint from HTTP Content-Type header or HTML <meta> tag.
	charset := extractCharset(contentTypeHint)
	if charset == "" {
		charset = extractMetaCharset(data)
	}
	if charset != "" && !isUTF8Label(charset) {
		if enc := lookupEncoding(charset); enc != nil {
			if dec, err := enc.NewDecoder().Bytes(data); err == nil && utf8.Valid(dec) {
				return sanitizeText(string(dec)), strings.ToLower(charset)
			}
		}
	}

	// 5. Already valid UTF-8? Keep it as-is (after ANSI/control cleanup).
	if utf8.Valid(data) {
		cleaned := sanitizeText(string(data))
		if looksMostlyBinaryText(cleaned) {
			return formatBinarySummary(data, "opaque"), "binary"
		}
		return cleaned, "utf-8"
	}

	// 6. Invalid UTF-8 bytes: try chardet first, then GB18030 (superset of GBK/GB2312), then Windows-1252.
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if res, err := chardet.NewTextDetector().DetectBest(sample); err == nil && res != nil && res.Confidence >= 45 {
		if enc := lookupEncoding(res.Charset); enc != nil {
			if dec, derr := enc.NewDecoder().Bytes(data); derr == nil && utf8.Valid(dec) && replacementRatio(string(dec)) < 0.05 {
				return sanitizeText(string(dec)), strings.ToLower(res.Charset)
			}
		}
	}

	// GB18030 fallback: covers Chinese Windows cmd/PowerShell/NetExec/legacy OA systems even on short strings
	// where statistical chardet confidence is low.
	if dec, err := simplifiedchinese.GB18030.NewDecoder().Bytes(data); err == nil && utf8.Valid(dec) {
		s := sanitizeText(string(dec))
		if replacementRatio(s) < 0.05 && !looksMostlyBinaryText(s) {
			return s, "gb18030"
		}
	}

	// Last resort: check if opaque binary, otherwise losslessly coerce to valid UTF-8.
	if rawBinaryRatio(data) > 0.30 {
		return formatBinarySummary(data, "opaque"), "binary"
	}
	return sanitizeText(strings.ToValidUTF8(string(data), "?")), "utf-8-coerced"
}

// CleanText strips ANSI escape codes, NUL bytes, and stray control characters from an existing string,
// and repairs non-UTF-8 byte sequences (such as raw GBK/GB18030 bytes stored inside a Go string).
func CleanText(s string) string {
	if s == "" {
		return ""
	}
	if !utf8.ValidString(s) {
		return CleanBytes([]byte(s), "", "")
	}
	return sanitizeText(s)
}

func sanitizeText(s string) string {
	if s == "" {
		return ""
	}
	// Strip ANSI escape sequences (colors, cursor movement, terminal title).
	if strings.ContainsRune(s, '\x1b') {
		s = reANSI.ReplaceAllString(s, "")
	}
	// Normalize CRLF -> LF and strip NUL + stray non-printable control chars (keep \n, \t).
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == '\r':
			// Convert standalone CR to LF if not followed by LF.
			if i < len(s) && s[i] == '\n' {
				continue
			}
			b.WriteByte('\n')
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == 0 || (r < 0x20) || r == 0x7f:
			// Drop NUL and non-printable ASCII control bytes (PostgreSQL rejects \x00 in text/jsonb).
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func maybeDecompress(raw []byte, contentEncodingHint string) []byte {
	ce := strings.ToLower(strings.TrimSpace(contentEncodingHint))
	if strings.Contains(ce, "gzip") || (len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b) {
		if gr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
			defer gr.Close()
			if out, rerr := io.ReadAll(io.LimitReader(gr, maxDecompressBytes)); rerr == nil && len(out) > 0 {
				return out
			}
		}
	}
	if strings.Contains(ce, "br") {
		br := brotli.NewReader(bytes.NewReader(raw))
		if out, rerr := io.ReadAll(io.LimitReader(br, maxDecompressBytes)); rerr == nil && len(out) > 0 {
			return out
		}
	}
	if strings.Contains(ce, "deflate") {
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			defer zr.Close()
			if out, rerr := io.ReadAll(io.LimitReader(zr, maxDecompressBytes)); rerr == nil && len(out) > 0 {
				return out
			}
		}
	}
	return raw
}

func extractCharset(ct string) string {
	m := reHeaderCharset.FindStringSubmatch(ct)
	if len(m) >= 2 {
		return strings.ToLower(strings.TrimSpace(m[1]))
	}
	return ""
}

func extractMetaCharset(raw []byte) string {
	n := len(raw)
	if n > 2048 {
		n = 2048
	}
	m := reMetaCharset.FindSubmatch(raw[:n])
	if len(m) >= 2 {
		return strings.ToLower(strings.TrimSpace(string(m[1])))
	}
	return ""
}

func isUTF8Label(label string) bool {
	l := strings.ToLower(strings.TrimSpace(label))
	return l == "utf-8" || l == "utf8" || l == "us-ascii" || l == "ascii"
}

func lookupEncoding(label string) encoding.Encoding {
	l := strings.ToLower(strings.TrimSpace(label))
	switch l {
	case "gbk", "gb2312", "gb-2312", "gb_2312", "gb_2312-80", "gb18030", "gb-18030", "cp936", "ms936", "x-gbk", "hz-gb-2312":
		return simplifiedchinese.GB18030
	case "big5", "big-5", "cp950":
		return traditionalchinese.Big5
	case "shift_jis", "shift-jis", "sjis", "cp932":
		return japanese.ShiftJIS
	case "euc-jp":
		return japanese.EUCJP
	case "euc-kr", "cp949":
		return korean.EUCKR
	case "windows-1252", "cp1252", "iso-8859-1", "latin1", "latin-1":
		return charmap.Windows1252
	case "utf-16le", "utf16le":
		return xunicode.UTF16(xunicode.LittleEndian, xunicode.IgnoreBOM)
	case "utf-16be", "utf16be":
		return xunicode.UTF16(xunicode.BigEndian, xunicode.IgnoreBOM)
	}
	if enc, err := htmlindex.Get(l); err == nil {
		return enc
	}
	return nil
}

func looksLikeUTF16LE(data []byte) bool {
	if len(data) < 8 || len(data)%2 != 0 {
		return false
	}
	n := len(data)
	if n > 256 {
		n = 256
	}
	evenASCII, oddZero := 0, 0
	pairs := n / 2
	for i := 0; i+1 < n; i += 2 {
		if data[i] >= 0x09 && data[i] <= 0x7e {
			evenASCII++
		}
		if data[i+1] == 0x00 {
			oddZero++
		}
	}
	return pairs >= 4 && oddZero*10 >= pairs*8 && evenASCII*10 >= pairs*7
}

func detectBinaryMagic(data []byte, contentTypeHint string) (string, bool) {
	ct := strings.ToLower(strings.TrimSpace(contentTypeHint))
	for _, prefix := range []string{"image/", "audio/", "video/", "font/", "application/pdf", "application/zip", "application/octet-stream", "application/wasm"} {
		if strings.HasPrefix(ct, prefix) {
			return prefix, true
		}
	}
	if len(data) >= 4 {
		switch {
		case bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G'}):
			return "png", true
		case bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}):
			return "jpeg", true
		case bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")):
			return "gif", true
		case bytes.HasPrefix(data, []byte("%PDF-")):
			return "pdf", true
		case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}):
			return "elf", true
		case bytes.HasPrefix(data, []byte{'P', 'K', 0x03, 0x04}):
			return "zip", true
		case bytes.HasPrefix(data, []byte{0x00, 'a', 's', 'm'}):
			return "wasm", true
		}
	}
	return "", false
}

func formatBinarySummary(data []byte, label string) string {
	n := len(data)
	previewLen := n
	if previewLen > 8 {
		previewLen = 8
	}
	return fmt.Sprintf("[binary payload: %s, %d bytes, magic=%s]", label, n, hex.EncodeToString(data[:previewLen]))
}

func replacementRatio(s string) float64 {
	if s == "" {
		return 0
	}
	total, repl := 0, 0
	for _, r := range s {
		total++
		if r == unicode.ReplacementChar {
			repl++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(repl) / float64(total)
}

func rawBinaryRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	n := len(data)
	if n > 4096 {
		n = 4096
	}
	bad := 0
	for _, b := range data[:n] {
		if b == 0 || (b < 0x09) || (b >= 0x0e && b < 0x20) {
			bad++
		}
	}
	return float64(bad) / float64(n)
}

func looksMostlyBinaryText(s string) bool {
	if len(s) < 64 {
		return false
	}
	total, repl := 0, 0
	for _, r := range s {
		total++
		if r == unicode.ReplacementChar {
			repl++
		}
		if total >= 1024 {
			break
		}
	}
	return total > 0 && float64(repl)/float64(total) > 0.25
}
