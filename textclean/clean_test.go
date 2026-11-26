package textclean

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/unicode"
)

func TestDecodeGBKAndGB18030(t *testing.T) {
	want := "系统管理后台 - 用户名或密码错误"
	gbkBytes, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(want))
	if err != nil {
		t.Fatal(err)
	}

	// 1. With explicit Content-Type charset=gbk
	got, cs := DecodeBytes(gbkBytes, "text/html; charset=gbk", "")
	if got != want || cs != "gbk" {
		t.Fatalf("explicit gbk failed: got=%q cs=%q want=%q", got, cs, want)
	}

	// 2. Without Content-Type hint (e.g., Windows cmd/SSH output)
	got2, _ := DecodeBytes(gbkBytes, "", "")
	if got2 != want {
		t.Fatalf("auto-detect gbk failed: got=%q want=%q", got2, want)
	}

	// 3. CleanText repairs raw GBK bytes stored inside a Go string
	if got3 := CleanText(string(gbkBytes)); got3 != want {
		t.Fatalf("CleanText gbk repair failed: got=%q want=%q", got3, want)
	}
}

func TestDecodeGzipHTMLMetaGB2312(t *testing.T) {
	html := `<html><head><meta charset="gb2312"><title>企业内部门户</title></head><body>欢迎登录</body></html>`
	gbBytes, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(html))
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(gbBytes)
	_ = w.Close()

	got, cs := DecodeBytes(gz.Bytes(), "text/html", "gzip")
	if !strings.Contains(got, "企业内部门户") || !strings.Contains(got, "欢迎登录") {
		t.Fatalf("gzip+gb2312 decode failed: cs=%q got=%q", cs, got)
	}
}

func TestDecodeUTF16LEAndStripANSIAndNUL(t *testing.T) {
	u16, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().Bytes([]byte("Windows IP Configuration\r\nIPv4 Address: 10.10.2.5"))
	if err != nil {
		t.Fatal(err)
	}
	got, cs := DecodeBytes(u16, "", "")
	if !strings.Contains(got, "IPv4 Address: 10.10.2.5") || cs != "utf-16le" {
		t.Fatalf("utf-16le decode failed: cs=%q got=%q", cs, got)
	}

	ansi := "\x1b[32m[+]\x1b[0m SMB 10.10.1.5:445\x00\x07 OK\r\n"
	cleaned := CleanText(ansi)
	if cleaned != "[+] SMB 10.10.1.5:445 OK\n" {
		t.Fatalf("ANSI/NUL clean failed: got=%q", cleaned)
	}
}

func TestBinaryPayloadSummary(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d}
	got, cs := DecodeBytes(png, "image/png", "")
	if cs != "binary" || !strings.Contains(got, "[binary payload:") {
		t.Fatalf("expected binary summary, got cs=%q text=%q", cs, got)
	}
}
