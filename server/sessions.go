package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/sessions"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) listTaskSessions(w http.ResponseWriter, r *http.Request) {
	if s.sessMgr == nil {
		writeJSON(w, 200, map[string]any{"sessions": []sessions.SessionInfo{}})
		return
	}
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	writeJSON(w, 200, map[string]any{"sessions": s.sessMgr.List(t.ID)})
}

func (s *Server) closeTaskSession(w http.ResponseWriter, r *http.Request) {
	if s.sessMgr == nil {
		writeErr(w, 503, "session manager unavailable")
		return
	}
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	sid := strings.TrimSpace(r.PathValue("sid"))
	closed, err := s.sessMgr.Close(t.ID, sid)
	if err != nil {
		if errors.Is(err, sessions.ErrSessionNotFound) {
			writeErr(w, 404, "session not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"closed": closed, "session_id": sid})
}

func (s *Server) sessionTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolDepthSessionOpen(),
		s.toolDepthSessionExec(),
		s.toolDepthSessionList(),
		s.toolDepthSessionClose(),
	}
}

func (s *Server) seedSessionTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "planner", "main", "auto", "pentest"})
	for _, t := range s.sessionTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[sessions] seed tool %s: %v", t.Name(), err)
		}
	}
}

func (s *Server) toolDepthSessionOpen() actool.CoreTool {
	return wrTool(
		"depth_session_open",
		"Open a task-scoped persistent interactive/pivot session (kind: 'pty', 'ssh', or 'tunnel'). Supports multi-hop SSH pivoting via jump_session_id, built-in local SOCKS5 proxy via socks_port, and automatic cleanup when the task ends. Enforces electronic fence and lateral_gate.",
		objSchema(map[string]any{
			"task_id":         strParam("Task ID (numeric string)"),
			"name":            strParam("Short human-readable label (e.g. 'dmz-jump', 'k8s-pod-shell')"),
			"kind":            strParam("Session kind: pty, ssh, or tunnel"),
			"target":          strParam("Remote target IP or hostname (required for ssh)"),
			"port":            map[string]any{"type": "integer", "description": "Remote SSH port (default 22)"},
			"username":        strParam("SSH username"),
			"password":        strParam("SSH password (optional if ssh_key_path or credential_id is given)"),
			"credential_id":   map[string]any{"type": "integer", "description": "Optional task_credentials ID to resolve username/password server-side"},
			"ssh_key_path":    strParam("Optional path to SSH private key file"),
			"jump_session_id": strParam("Optional existing open 'ssh' session ID to pivot through (multi-hop)"),
			"socks_port":      map[string]any{"type": "integer", "description": "For ssh: 0=none, -1=auto ephemeral 127.0.0.1 SOCKS5 port, >0=specific port"},
			"command":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Argv for pty or tunnel session (e.g. ['/bin/sh'] or ['chisel','client',...])"},
		}, "task_id", "kind"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.sessMgr == nil {
				return actool.Errorf("session manager unavailable"), nil
			}
			var p struct {
				TaskID        string   `json:"task_id"`
				Name          string   `json:"name"`
				Kind          string   `json:"kind"`
				Target        string   `json:"target"`
				Port          int      `json:"port"`
				Username      string   `json:"username"`
				Password      string   `json:"password"`
				CredentialID  int64    `json:"credential_id"`
				SSHKeyPath    string   `json:"ssh_key_path"`
				JumpSessionID string   `json:"jump_session_id"`
				SocksPort     int      `json:"socks_port"`
				Command       []string `json:"command"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf(fmt.Sprintf("task %q not found", p.TaskID)), nil
			}

			kind := strings.ToLower(strings.TrimSpace(p.Kind))
			cmdStr := strings.Join(p.Command, " ")
			if t.LateralGate && !t.LateralApproved {
				if kind == sessions.KindSSH || kind == sessions.KindTunnel {
					return actool.Errorf("lateral gate is active: approve lateral movement via POST /api/tasks/{id}/lateral/approve before opening remote ssh/tunnel sessions"), nil
				}
				if reason, blocked := guard.CheckLateralCommand(cmdStr); blocked {
					return actool.Errorf("lateral gate blocked session command: " + reason), nil
				}
			}

			if t.Guard != nil {
				probeCmd := cmdStr
				if strings.TrimSpace(p.Target) != "" {
					probeCmd = strings.TrimSpace(probeCmd + " " + p.Target)
				}
				if probeCmd != "" {
					probeInput, _ := json.Marshal(map[string]string{"command": probeCmd})
					if blocked, reason := t.Guard.CheckFence("Bash", probeInput); blocked {
						return actool.Errorf("electronic fence blocked session_open: " + reason), nil
					}
				}
			}

			var keyPEM []byte
			if kp := strings.TrimSpace(p.SSHKeyPath); kp != "" {
				b, err := os.ReadFile(kp)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("read ssh_key_path: %v", err)), nil
				}
				keyPEM = b
			}
			if p.CredentialID > 0 && s.m != nil && s.m.pg != nil {
				tid, _ := strconv.ParseInt(t.ID, 10, 64)
				creds, err := s.m.pg.TaskCredentials(tid)
				if err == nil {
					for _, c := range creds {
						if c.ID == p.CredentialID {
							if p.Username == "" {
								p.Username = c.Username
							}
							if p.Password == "" {
								p.Password = c.Password
							}
							break
						}
					}
				}
			}

			info, banner, err := s.sessMgr.Open(ctx, sessions.OpenRequest{
				TaskID:        t.ID,
				Name:          p.Name,
				Kind:          kind,
				Target:        p.Target,
				Port:          p.Port,
				Username:      p.Username,
				Password:      p.Password,
				PrivateKeyPEM: keyPEM,
				JumpSessionID: p.JumpSessionID,
				SocksPort:     p.SocksPort,
				Command:       p.Command,
				ProdSafeMode:  t.ProdSafeMode,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"session": info,
				"banner":  banner,
			})
		},
	)
}

func (s *Server) toolDepthSessionExec() actool.CoreTool {
	return wrTool(
		"depth_session_exec",
		"Execute a command inside an open persistent session (pty or ssh) and wait for deterministic output + exit_code.",
		objSchema(map[string]any{
			"task_id":         strParam("Task ID (numeric string)"),
			"session_id":      strParam("Session ID returned by depth_session_open"),
			"command":         strParam("Shell command to execute in the persistent session"),
			"timeout_seconds": map[string]any{"type": "integer", "description": "Command timeout in seconds (default 30, max 180)"},
		}, "task_id", "session_id", "command"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.sessMgr == nil {
				return actool.Errorf("session manager unavailable"), nil
			}
			var p struct {
				TaskID         string `json:"task_id"`
				SessionID      string `json:"session_id"`
				Command        string `json:"command"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf(fmt.Sprintf("task %q not found", p.TaskID)), nil
			}
			if t.Guard != nil && strings.TrimSpace(p.Command) != "" {
				probeInput, _ := json.Marshal(map[string]string{"command": p.Command})
				if blocked, reason := t.Guard.CheckFence("Bash", probeInput); blocked {
					return actool.Errorf("electronic fence blocked session_exec: " + reason), nil
				}
			}
			res, err := s.sessMgr.Exec(ctx, t.ID, p.SessionID, p.Command, p.TimeoutSeconds)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(res)
		},
	)
}

func (s *Server) toolDepthSessionList() actool.CoreTool {
	return roTool(
		"depth_session_list",
		"List all persistent interactive/pivot sessions (id, name, kind, target, socks_addr, status, pid) for a task.",
		objSchema(map[string]any{
			"task_id": strParam("Task ID (numeric string)"),
		}, "task_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.sessMgr == nil {
				return actool.Errorf("session manager unavailable"), nil
			}
			var p struct {
				TaskID string `json:"task_id"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf(fmt.Sprintf("task %q not found", p.TaskID)), nil
			}
			return jsonResult(map[string]any{"sessions": s.sessMgr.List(t.ID)})
		},
	)
}

func (s *Server) toolDepthSessionClose() actool.CoreTool {
	return wrTool(
		"depth_session_close",
		"Close and clean up a persistent session or pivot tunnel (frees SOCKS5 ports and terminates remote/PTY processes).",
		objSchema(map[string]any{
			"task_id":    strParam("Task ID (numeric string)"),
			"session_id": strParam("Session ID to close"),
		}, "task_id", "session_id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.sessMgr == nil {
				return actool.Errorf("session manager unavailable"), nil
			}
			var p struct {
				TaskID    string `json:"task_id"`
				SessionID string `json:"session_id"`
			}
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t == nil {
				return actool.Errorf(fmt.Sprintf("task %q not found", p.TaskID)), nil
			}
			closed, err := s.sessMgr.Close(t.ID, p.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"closed": closed, "session_id": p.SessionID})
		},
	)
}
