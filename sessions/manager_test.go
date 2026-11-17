package sessions

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestPTYSessionPersistsStateAcrossExecAndClosesWithTask(t *testing.T) {
	mgr := NewManager()
	defer mgr.CloseAll()

	info, _, err := mgr.Open(context.Background(), OpenRequest{
		TaskID: "42",
		Name:   "local-pivot",
		Kind:   KindPTY,
	})
	if err != nil {
		t.Fatalf("Open PTY: %v", err)
	}
	if info.Status != StatusOpen || info.PID <= 0 {
		t.Fatalf("unexpected PTY info: %+v", info)
	}

	tmpDir := t.TempDir()
	res, err := mgr.Exec(context.Background(), "42", info.ID, "cd "+tmpDir, 10)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("cd failed: res=%+v err=%v", res, err)
	}

	res, err = mgr.Exec(context.Background(), "42", info.ID, "pwd", 10)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("pwd failed: res=%+v err=%v", res, err)
	}
	if !strings.Contains(res.Output, tmpDir) {
		t.Fatalf("expected pwd to persist %q, got %q", tmpDir, res.Output)
	}

	if closed := mgr.CloseTask("42"); closed != 1 {
		t.Fatalf("CloseTask closed %d, want 1", closed)
	}
	if _, err := mgr.Exec(context.Background(), "42", info.ID, "echo nope", 5); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed after CloseTask, got %v", err)
	}
}

func startTestSSHServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "pivot" && string(pass) == "secret123" {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh: %v", err)
	}

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					switch newChan.ChannelType() {
					case "session":
						ch, requests, err := newChan.Accept()
						if err != nil {
							continue
						}
						go func(in <-chan *ssh.Request) {
							for req := range in {
								if req.Type == "exec" && len(req.Payload) >= 4 {
									l := binary.BigEndian.Uint32(req.Payload[:4])
									cmd := string(req.Payload[4 : 4+l])
									_ = req.Reply(true, nil)
									_, _ = io.WriteString(ch, "exec:"+cmd)
									_ = ch.CloseWrite()
									_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
									_ = ch.Close()
									return
								}
								_ = req.Reply(false, nil)
							}
						}(requests)
					case "direct-tcpip":
						var d struct {
							DestAddr string
							DestPort uint32
							OrigAddr string
							OrigPort uint32
						}
						if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
							_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
							continue
						}
						targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", d.DestAddr, d.DestPort), 3*time.Second)
						if err != nil {
							_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
							continue
						}
						ch, reqs, err := newChan.Accept()
						if err != nil {
							_ = targetConn.Close()
							continue
						}
						go ssh.DiscardRequests(reqs)
						go func() {
							_, _ = io.Copy(ch, targetConn)
							_ = ch.Close()
						}()
						go func() {
							_, _ = io.Copy(targetConn, ch)
							_ = targetConn.Close()
						}()
					default:
						_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
					}
				}
			}(nConn)
		}
	}()

	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestSSHSessionMultiHopJumpAndSOCKS5(t *testing.T) {
	sshAddr, closeSSH := startTestSSHServer(t)
	defer closeSSH()

	// Local echo target reachable only through SSH direct-tcpip.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(sshAddr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	mgr := NewManager()
	defer mgr.CloseAll()

	// 1. Open jump SSH session with auto-assigned SOCKS5 port.
	jumpInfo, _, err := mgr.Open(context.Background(), OpenRequest{
		TaskID:    "99",
		Name:      "hop-1",
		Kind:      KindSSH,
		Target:    host,
		Port:      port,
		Username:  "pivot",
		Password:  "secret123",
		SocksPort: -1,
	})
	if err != nil {
		t.Fatalf("Open jump SSH: %v", err)
	}
	if jumpInfo.SocksAddr == "" {
		t.Fatalf("expected SOCKS5 address to be assigned")
	}

	// Verify Exec works on SSH session.
	res, err := mgr.Exec(context.Background(), "99", jumpInfo.ID, "id", 10)
	if err != nil || res.ExitCode != 0 || res.Output != "exec:id" {
		t.Fatalf("SSH Exec got res=%+v err=%v", res, err)
	}

	// 2. Open second-hop SSH session chained through jump_session_id.
	hop2Info, _, err := mgr.Open(context.Background(), OpenRequest{
		TaskID:        "99",
		Name:          "hop-2",
		Kind:          KindSSH,
		Target:        host,
		Port:          port,
		Username:      "pivot",
		Password:      "secret123",
		JumpSessionID: jumpInfo.ID,
	})
	if err != nil {
		t.Fatalf("Open hop-2 SSH via jump_session_id: %v", err)
	}
	res2, err := mgr.Exec(context.Background(), "99", hop2Info.ID, "hostname", 10)
	if err != nil || res2.Output != "exec:hostname" {
		t.Fatalf("hop-2 Exec got res=%+v err=%v", res2, err)
	}

	// 3. Verify SOCKS5 tunnel forwards traffic to echoLn.
	socksConn, err := net.DialTimeout("tcp", jumpInfo.SocksAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks5 %s: %v", jumpInfo.SocksAddr, err)
	}
	defer socksConn.Close()
	_, _ = socksConn.Write([]byte{0x05, 0x01, 0x00})
	var authRep [2]byte
	if _, err := io.ReadFull(socksConn, authRep[:]); err != nil || authRep[1] != 0x00 {
		t.Fatalf("socks5 auth failed: %v %v", authRep, err)
	}
	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	var echoPort uint16
	_, _ = fmt.Sscanf(echoPortStr, "%d", &echoPort)
	ip4 := net.ParseIP(echoHost).To4()
	req := []byte{0x05, 0x01, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], byte(echoPort >> 8), byte(echoPort)}
	_, _ = socksConn.Write(req)
	var connRep [10]byte
	if _, err := io.ReadFull(socksConn, connRep[:]); err != nil || connRep[1] != 0x00 {
		t.Fatalf("socks5 connect failed: %v %v", connRep, err)
	}
	_, _ = socksConn.Write([]byte("ping-pivot"))
	buf := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, buf); err != nil || string(buf) != "ping-pivot" {
		t.Fatalf("socks5 echo failed: %q err=%v", string(buf), err)
	}
}
