package sessions

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/textclean"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

const (
	KindPTY    = "pty"
	KindSSH    = "ssh"
	KindTunnel = "tunnel"

	StatusOpen   = "open"
	StatusClosed = "closed"
	StatusError  = "error"

	defaultMaxSessions     = 8
	prodSafeMaxSessions    = 4
	ringBufferLimitBytes   = 64 * 1024
	defaultExecTimeoutSecs = 30
	maxExecTimeoutSecs     = 180
)

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionClosed       = errors.New("session is closed")
	ErrSessionLimitReached = errors.New("maximum concurrent sessions reached for task")
	ErrInvalidSessionKind  = errors.New("session kind must be one of: pty, ssh, tunnel")
)

// SessionInfo is the model- and operator-safe metadata snapshot for a persistent session.
// Plaintext credentials are never stored in or returned by SessionInfo.
type SessionInfo struct {
	ID            string    `json:"id"`
	TaskID        string    `json:"task_id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Status        string    `json:"status"`
	Target        string    `json:"target,omitempty"`
	Port          int       `json:"port,omitempty"`
	Username      string    `json:"username,omitempty"`
	JumpSessionID string    `json:"jump_session_id,omitempty"`
	SocksAddr     string    `json:"socks_addr,omitempty"`
	PID           int       `json:"pid,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	LastActiveAt  time.Time `json:"last_active_at"`
}

// OpenRequest describes how to open a persistent depth session.
type OpenRequest struct {
	TaskID        string
	Name          string
	Kind          string
	Target        string
	Port          int
	Username      string
	Password      string // never echoed
	PrivateKeyPEM []byte // never echoed
	JumpSessionID string
	SocksPort     int      // >0 or -1 for auto ephemeral port on 127.0.0.1
	Command       []string // for pty/tunnel
	WorkDir       string
	ProdSafeMode  bool
}

// ExecResult holds the deterministic output of a command sent to a persistent session.
type ExecResult struct {
	SessionID string `json:"session_id"`
	Output    string `json:"output"`
	ExitCode  int    `json:"exit_code"`
	TimedOut  bool   `json:"timed_out,omitempty"`
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type ringBuf struct {
	mu  sync.Mutex
	buf []byte
}

func (r *ringBuf) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > ringBufferLimitBytes {
		r.buf = append([]byte(nil), r.buf[len(r.buf)-ringBufferLimitBytes:]...)
	}
	return len(p), nil
}

func (r *ringBuf) Snapshot() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.buf)
}

func (r *ringBuf) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}

func (r *ringBuf) SliceFrom(offset int) (string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if offset < 0 {
		offset = 0
	}
	if offset >= len(r.buf) {
		return "", len(r.buf)
	}
	return string(r.buf[offset:]), len(r.buf)
}

type session struct {
	mu            sync.Mutex
	info          SessionInfo
	cmd           *exec.Cmd
	ptyFile       *os.File
	sshClient     *ssh.Client
	socksListener net.Listener
	output        ringBuf
	done          chan struct{}
	closeOnce     sync.Once
}

// Manager maintains persistent interactive/pivot sessions scoped to tasks.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

// NewManager creates an empty persistent session manager.
func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*session)}
}

func newSessionID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "sess-" + hex.EncodeToString(b)
}

// Open starts a persistent pty, ssh, or tunnel session bound to req.TaskID.
func (m *Manager) Open(ctx context.Context, req OpenRequest) (*SessionInfo, string, error) {
	req.TaskID = strings.TrimSpace(req.TaskID)
	req.Kind = strings.ToLower(strings.TrimSpace(req.Kind))
	req.Name = strings.TrimSpace(req.Name)
	req.Target = strings.TrimSpace(req.Target)
	req.Username = strings.TrimSpace(req.Username)
	req.JumpSessionID = strings.TrimSpace(req.JumpSessionID)

	if req.TaskID == "" {
		return nil, "", errors.New("task_id is required")
	}
	switch req.Kind {
	case KindPTY, KindSSH, KindTunnel:
	default:
		return nil, "", ErrInvalidSessionKind
	}

	limit := defaultMaxSessions
	if req.ProdSafeMode {
		limit = prodSafeMaxSessions
	}
	if m.countOpenForTask(req.TaskID) >= limit {
		return nil, "", fmt.Errorf("%w (%d)", ErrSessionLimitReached, limit)
	}

	now := time.Now().UTC()
	id := newSessionID()
	if req.Name == "" {
		req.Name = fmt.Sprintf("%s-%s", req.Kind, id[len(id)-4:])
	}

	s := &session{
		info: SessionInfo{
			ID:            id,
			TaskID:        req.TaskID,
			Name:          req.Name,
			Kind:          req.Kind,
			Status:        StatusOpen,
			Target:        req.Target,
			Port:          req.Port,
			Username:      req.Username,
			JumpSessionID: req.JumpSessionID,
			CreatedAt:     now,
			LastActiveAt:  now,
		},
		done: make(chan struct{}),
	}

	var err error
	switch req.Kind {
	case KindPTY:
		err = m.startPTY(s, req)
	case KindSSH:
		err = m.startSSH(ctx, s, req)
	case KindTunnel:
		err = m.startTunnel(s, req)
	}
	if err != nil {
		s.terminate("open failed: " + err.Error())
		return nil, "", err
	}

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()

	if req.Kind == KindPTY {
		time.Sleep(150 * time.Millisecond)
	}
	infoCopy := s.snapshot()
	return &infoCopy, s.output.Snapshot(), nil
}

func (m *Manager) countOpenForTask(taskID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, s := range m.sessions {
		if s.info.TaskID == taskID && s.snapshot().Status == StatusOpen {
			n++
		}
	}
	return n
}

func (m *Manager) startPTY(s *session, req OpenRequest) error {
	argv := req.Command
	if len(argv) == 0 {
		argv = []string{"/bin/sh"}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("start pty: %w", err)
	}
	s.cmd = cmd
	s.ptyFile = ptmx
	s.info.PID = cmd.Process.Pid

	go func() {
		_, _ = io.Copy(&s.output, ptmx)
	}()
	go func() {
		err := cmd.Wait()
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		s.markClosed(msg)
	}()
	return nil
}

func (m *Manager) startTunnel(s *session, req OpenRequest) error {
	if len(req.Command) == 0 {
		return errors.New("tunnel session requires command")
	}
	cmd := exec.Command(req.Command[0], req.Command[1:]...)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	cmd.Stdout = &s.output
	cmd.Stderr = &s.output
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tunnel: %w", err)
	}
	s.cmd = cmd
	s.info.PID = cmd.Process.Pid
	if req.SocksPort > 0 {
		s.info.SocksAddr = fmt.Sprintf("127.0.0.1:%d", req.SocksPort)
	}
	go func() {
		err := cmd.Wait()
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		s.markClosed(msg)
	}()
	return nil
}

func (m *Manager) startSSH(ctx context.Context, s *session, req OpenRequest) error {
	if req.Target == "" {
		return errors.New("ssh session requires target")
	}
	if req.Username == "" {
		return errors.New("ssh session requires username")
	}
	port := req.Port
	if port <= 0 {
		port = 22
	}
	s.info.Port = port

	var auths []ssh.AuthMethod
	if len(req.PrivateKeyPEM) > 0 {
		signer, err := ssh.ParsePrivateKey(req.PrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("parse ssh private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if req.Password != "" {
		pw := req.Password
		auths = append(auths, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			ans := make([]string, len(questions))
			for i := range questions {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	if len(auths) == 0 {
		return errors.New("ssh session requires password or private key")
	}

	cfg := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // internal pentest targets rarely share known_hosts
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(req.Target, strconv.Itoa(port))
	var rawConn net.Conn
	var err error
	if req.JumpSessionID != "" {
		parent, ok := m.get(req.TaskID, req.JumpSessionID)
		if !ok {
			return fmt.Errorf("jump_session_id %q not found", req.JumpSessionID)
		}
		parent.mu.Lock()
		pClient := parent.sshClient
		parent.mu.Unlock()
		if pClient == nil || parent.snapshot().Status != StatusOpen {
			return fmt.Errorf("jump_session_id %q is not an open ssh session", req.JumpSessionID)
		}
		rawConn, err = pClient.Dial("tcp", addr)
	} else {
		dialer := net.Dialer{Timeout: 15 * time.Second}
		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial ssh %s: %w", addr, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(rawConn, addr, cfg)
	if err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	client := ssh.NewClient(c, chans, reqs)
	s.sshClient = client

	if req.SocksPort != 0 {
		bindPort := req.SocksPort
		if bindPort < 0 {
			bindPort = 0
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bindPort))
		if err != nil {
			_ = client.Close()
			return fmt.Errorf("listen socks5: %w", err)
		}
		s.socksListener = ln
		s.info.SocksAddr = ln.Addr().String()
		go serveSOCKS5(ln, client)
	}

	go func() {
		err := client.Wait()
		msg := ""
		if err != nil && !errors.Is(err, io.EOF) {
			msg = err.Error()
		}
		s.markClosed(msg)
	}()
	return nil
}

// Exec runs a command on an open persistent session and returns deterministic output.
func (m *Manager) Exec(ctx context.Context, taskID, sessionID, command string, timeoutSecs int) (*ExecResult, error) {
	s, ok := m.get(taskID, sessionID)
	if !ok {
		return nil, ErrSessionNotFound
	}
	if s.snapshot().Status != StatusOpen {
		return nil, ErrSessionClosed
	}
	if timeoutSecs <= 0 {
		timeoutSecs = defaultExecTimeoutSecs
	}
	if timeoutSecs > maxExecTimeoutSecs {
		timeoutSecs = maxExecTimeoutSecs
	}

	s.mu.Lock()
	s.info.LastActiveAt = time.Now().UTC()
	kind := s.info.Kind
	client := s.sshClient
	ptmx := s.ptyFile
	s.mu.Unlock()

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	switch kind {
	case KindSSH:
		if client == nil {
			return nil, ErrSessionClosed
		}
		sess, err := client.NewSession()
		if err != nil {
			return nil, fmt.Errorf("new ssh channel: %w", err)
		}
		defer sess.Close()
		var outBuf syncBuffer
		sess.Stdout = &outBuf
		sess.Stderr = &outBuf

		errCh := make(chan error, 1)
		go func() {
			errCh <- sess.Run(command)
		}()

		select {
		case <-runCtx.Done():
			_ = sess.Signal(ssh.SIGTERM)
			_ = sess.Close()
			return &ExecResult{
				SessionID: sessionID,
				Output:    textclean.CleanText(outBuf.String()),
				ExitCode:  -1,
				TimedOut:  true,
			}, nil
		case runErr := <-errCh:
			exitCode := 0
			if runErr != nil {
				var ee *ssh.ExitError
				if errors.As(runErr, &ee) {
					exitCode = ee.ExitStatus()
				} else {
					exitCode = -1
				}
			}
			cleanOut := textclean.CleanText(outBuf.String())
			_, _ = s.output.Write([]byte(fmt.Sprintf("$ %s\n%s\n", command, cleanOut)))
			return &ExecResult{
				SessionID: sessionID,
				Output:    cleanOut,
				ExitCode:  exitCode,
			}, nil
		}

	case KindPTY:
		if ptmx == nil {
			return nil, ErrSessionClosed
		}
		startOffset := s.output.Len()
		tokenBytes := make([]byte, 4)
		_, _ = rand.Read(tokenBytes)
		tokenHex := hex.EncodeToString(tokenBytes)
		sentinel := "__ARTEX_DONE_" + tokenHex + "__"
		line := fmt.Sprintf("%s; printf '\\n%%s%%s:%%d\\n' '__ARTEX_DONE_' '%s__' $?\n", command, tokenHex)
		if _, err := io.WriteString(ptmx, line); err != nil {
			return nil, fmt.Errorf("write pty: %w", err)
		}
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			chunk, _ := s.output.SliceFrom(startOffset)
			if idx := strings.Index(chunk, sentinel+":"); idx >= 0 {
				rest := chunk[idx+len(sentinel)+1:]
				if nl := strings.IndexAny(rest, "\r\n"); nl >= 0 {
					codeStr := strings.TrimSpace(rest[:nl])
					exitCode, _ := strconv.Atoi(codeStr)
					cleanOut := strings.TrimSpace(textclean.CleanText(chunk[:idx]))
					return &ExecResult{
						SessionID: sessionID,
						Output:    cleanOut,
						ExitCode:  exitCode,
					}, nil
				}
			}
			select {
			case <-runCtx.Done():
				chunk, _ := s.output.SliceFrom(startOffset)
				return &ExecResult{
					SessionID: sessionID,
					Output:    chunk,
					ExitCode:  -1,
					TimedOut:  true,
				}, nil
			case <-ticker.C:
			}
		}

	case KindTunnel:
		return &ExecResult{
			SessionID: sessionID,
			Output:    s.output.Snapshot(),
			ExitCode:  0,
		}, nil
	default:
		return nil, ErrInvalidSessionKind
	}
}

// List returns all sessions belonging to taskID.
func (m *Manager) List(taskID string) []SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SessionInfo, 0)
	for _, s := range m.sessions {
		if s.info.TaskID == taskID {
			out = append(out, s.snapshot())
		}
	}
	return out
}

// Close terminates a single session belonging to taskID.
func (m *Manager) Close(taskID, sessionID string) (bool, error) {
	s, ok := m.get(taskID, sessionID)
	if !ok {
		return false, ErrSessionNotFound
	}
	s.terminate("")
	return true, nil
}

// CloseTask terminates all open sessions belonging to taskID.
func (m *Manager) CloseTask(taskID string) int {
	m.mu.RLock()
	var targets []*session
	for _, s := range m.sessions {
		if s.info.TaskID == taskID {
			targets = append(targets, s)
		}
	}
	m.mu.RUnlock()
	closed := 0
	for _, s := range targets {
		if s.snapshot().Status == StatusOpen {
			closed++
		}
		s.terminate("")
	}
	return closed
}

// CloseAll terminates every active session in the manager.
func (m *Manager) CloseAll() {
	m.mu.RLock()
	targets := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		targets = append(targets, s)
	}
	m.mu.RUnlock()
	for _, s := range targets {
		s.terminate("")
	}
}

func (m *Manager) get(taskID, sessionID string) (*session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[strings.TrimSpace(sessionID)]
	if !ok || s.info.TaskID != strings.TrimSpace(taskID) {
		return nil, false
	}
	return s, true
}

func (s *session) snapshot() SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

func (s *session) markClosed(errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.info.Status == StatusClosed {
		return
	}
	if errMsg != "" {
		s.info.Status = StatusError
		s.info.LastError = errMsg
	} else {
		s.info.Status = StatusClosed
	}
	if s.socksListener != nil {
		_ = s.socksListener.Close()
		s.socksListener = nil
	}
}

func (s *session) terminate(errMsg string) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.socksListener != nil {
			_ = s.socksListener.Close()
			s.socksListener = nil
		}
		if s.sshClient != nil {
			_ = s.sshClient.Close()
			s.sshClient = nil
		}
		if s.ptyFile != nil {
			_ = s.ptyFile.Close()
			s.ptyFile = nil
		}
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		if errMsg != "" {
			s.info.Status = StatusError
			s.info.LastError = errMsg
		} else {
			s.info.Status = StatusClosed
		}
		s.mu.Unlock()
		close(s.done)
	})
}

// serveSOCKS5 implements RFC 1928 CONNECT over an ssh.Client dialer.
func serveSOCKS5(ln net.Listener, client *ssh.Client) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSOCKS5Conn(conn, client)
	}
}

func handleSOCKS5Conn(conn net.Conn, client *ssh.Client) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no-auth
		return
	}

	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 0x03: // Domain
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		dom := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, dom); err != nil {
			return
		}
		host = string(dom)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	dst := net.JoinHostPort(host, strconv.Itoa(int(port)))

	remote, err := client.Dial("tcp", dst)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	_ = conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, conn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, remote)
	}()
	wg.Wait()
}
