package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/wordlists"
	actool "github.com/Autumn-27/norma/tool"
)

var allowedHydraServices = map[string]bool{
	"ssh":             true,
	"ftp":             true,
	"smb":             true,
	"rdp":             true,
	"mysql":           true,
	"postgres":        true,
	"mssql":           true,
	"redis":           true,
	"telnet":          true,
	"vnc":             true,
	"snmp":            true,
	"ldap2":           true,
	"ldap3":           true,
	"http-get":        true,
	"https-get":       true,
	"http-post-form":  true,
	"https-post-form": true,
	"imap":            true,
	"pop3":            true,
	"smtp":            true,
}

func (s *Server) listWordlists(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminJWT(w, r) {
		return
	}
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	items, err := s.m.pg.ListWordlists(kind)
	if err != nil {
		if errors.Is(err, db.ErrWordlistInvalidKind) {
			writeErr(w, 400, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"wordlists": items})
}

func (s *Server) createWordlist(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminJWT(w, r) {
		return
	}
	if s.m == nil || s.m.pg == nil || s.wlVault == nil {
		writeErr(w, 503, "wordlist vault unavailable")
		return
	}
	var req struct {
		Name        string   `json:"name"`
		Kind        string   `json:"kind"`
		Description string   `json:"description"`
		Entries     []string `json:"entries"`
		Content     string   `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON payload")
		return
	}

	rawEntries := req.Entries
	if len(rawEntries) == 0 && strings.TrimSpace(req.Content) != "" {
		rawEntries = strings.Split(req.Content, "\n")
	}
	normEntries, err := wordlists.NormalizeEntries(rawEntries)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	meta, created, err := s.m.pg.UpsertWordlistMeta(req.Name, req.Kind, req.Description, s.approver(r))
	if err != nil {
		if errors.Is(err, db.ErrWordlistInvalidName) || errors.Is(err, db.ErrWordlistInvalidKind) {
			writeErr(w, 400, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}

	sha256Hex, count, err := s.wlVault.Save(meta.ID, normEntries)
	if err != nil {
		if created {
			_, _ = s.m.pg.DeleteWordlistMeta(meta.ID)
		}
		writeErr(w, 500, fmt.Sprintf("encrypt wordlist: %v", err))
		return
	}
	updated, err := s.m.pg.UpdateWordlistStats(meta.ID, count, sha256Hex)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, map[string]any{"wordlist": updated})
}

func (s *Server) deleteWordlist(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminJWT(w, r) {
		return
	}
	if s.m == nil || s.m.pg == nil || s.wlVault == nil {
		writeErr(w, 503, "wordlist vault unavailable")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid wordlist id")
		return
	}
	deleted, err := s.m.pg.DeleteWordlistMeta(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !deleted {
		writeErr(w, 404, "wordlist not found")
		return
	}
	if err := s.wlVault.Delete(id); err != nil {
		log.Printf("[wordlists] delete encrypted file id=%d: %v", id, err)
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": id})
}

func (s *Server) wordlistTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolListWordlists(),
		s.toolRunCredentialAudit(),
		s.toolRunPasswordSpray(),
	}
}

func (s *Server) seedWordlistTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "planner", "main", "auto", "pentest"})
	for _, t := range s.wordlistTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[wordlists] seed tool %s: %v", t.Name(), err)
		}
	}
}

func (s *Server) toolListWordlists() actool.CoreTool {
	return roTool(
		"list_wordlists",
		"List available encrypted wordlists (metadata only: id, name, kind, entry_count, sha256). Plaintext entries are encrypted at rest and never exposed to the model; pass the wordlist id or name to run_credential_audit.",
		objSchema(map[string]any{
			"kind": strParam("Optional filter: username, password, or userpass"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("database unavailable"), nil
			}
			var p struct {
				Kind string `json:"kind"`
			}
			if len(in) > 0 {
				if err := json.Unmarshal(in, &p); err != nil {
					return actool.Errorf(err.Error()), nil
				}
			}
			items, err := s.m.pg.ListWordlists(p.Kind)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"wordlists": items})
		},
	)
}

type credentialAuditRequest struct {
	TaskID       string `json:"task_id"`
	Target       string `json:"target"`
	Service      string `json:"service"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	UserList     string `json:"user_list"`
	PassList     string `json:"pass_list"`
	UserpassList string `json:"userpass_list"`
	Threads      int    `json:"threads"`
	StopOnFirst  *bool  `json:"stop_on_first"`
}

func isValidAuditTarget(target string) bool {
	if target == "" || len(target) > 255 {
		return false
	}
	return !strings.ContainsAny(target, " \t\r\n;|&$`<>\"'\\")
}

func validateAndNormalizeAuditRequest(p *credentialAuditRequest, prodSafe bool) error {
	p.TaskID = strings.TrimSpace(p.TaskID)
	p.Target = strings.TrimSpace(p.Target)
	p.Service = strings.ToLower(strings.TrimSpace(p.Service))
	p.Username = strings.TrimSpace(p.Username)
	p.UserList = strings.TrimSpace(p.UserList)
	p.PassList = strings.TrimSpace(p.PassList)
	p.UserpassList = strings.TrimSpace(p.UserpassList)

	if !isValidAuditTarget(p.Target) {
		return errors.New("invalid target host or IP")
	}
	if !allowedHydraServices[p.Service] {
		return fmt.Errorf("unsupported service %q; allowed: ssh, ftp, smb, rdp, mysql, postgres, mssql, redis, telnet, vnc, snmp, ldap2, ldap3, http-get, https-get, http-post-form, https-post-form, imap, pop3, smtp", p.Service)
	}
	if p.Port < 0 || p.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if p.UserpassList != "" {
		if p.Username != "" || p.UserList != "" || p.PassList != "" {
			return errors.New("userpass_list cannot be combined with username, user_list, or pass_list")
		}
	} else {
		if p.PassList == "" {
			return errors.New("pass_list is required when userpass_list is not set")
		}
		if (p.Username == "" && p.UserList == "") || (p.Username != "" && p.UserList != "") {
			return errors.New("provide exactly one of username or user_list")
		}
	}
	if p.Threads <= 0 {
		p.Threads = 4
	}
	if p.Threads > 16 {
		p.Threads = 16
	}
	if prodSafe && p.Threads > 4 {
		p.Threads = 4
	}
	return nil
}

func buildHydraArgs(p credentialAuditRequest, userFile, passFile, userpassFile string) []string {
	args := []string{"-I", "-t", strconv.Itoa(p.Threads)}
	if p.Port > 0 {
		args = append(args, "-s", strconv.Itoa(p.Port))
	}
	stopOnFirst := true
	if p.StopOnFirst != nil {
		stopOnFirst = *p.StopOnFirst
	}
	if stopOnFirst {
		args = append(args, "-f")
	}
	if userpassFile != "" {
		args = append(args, "-C", userpassFile)
	} else {
		if p.Username != "" {
			args = append(args, "-l", p.Username)
		} else {
			args = append(args, "-L", userFile)
		}
		args = append(args, "-P", passFile)
	}
	args = append(args, p.Target, p.Service)
	return args
}

func (s *Server) toolRunCredentialAudit() actool.CoreTool {
	return wrTool(
		"run_credential_audit",
		"Run a bounded, electronic-fence-checked credential audit against a target service using encrypted server-side wordlists (never exposing plaintext passwords to the model). Matched passwords are masked in the returned JSON.",
		objSchema(map[string]any{
			"task_id":       strParam("Task ID (numeric string)"),
			"target":        strParam("Target IP address or hostname"),
			"service":       strParam("Service protocol (e.g. ssh, ftp, smb, rdp, mysql, postgres, mssql, redis, snmp, ldap2, ldap3)"),
			"port":          map[string]any{"type": "integer", "description": "Optional non-default TCP/UDP port"},
			"username":      strParam("Single username to test (mutually exclusive with user_list)"),
			"user_list":     strParam("Encrypted wordlist ID or name of kind 'username'"),
			"pass_list":     strParam("Encrypted wordlist ID or name of kind 'password'"),
			"userpass_list": strParam("Encrypted wordlist ID or name of kind 'userpass' (user:pass pairs)"),
			"threads":       map[string]any{"type": "integer", "description": "Concurrency threads (default 4, max 16; capped at 4 in prod_safe_mode)"},
			"stop_on_first": map[string]any{"type": "boolean", "description": "Stop on first valid credential found (default true)"},
		}, "task_id", "target", "service"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil || s.wlVault == nil {
				return actool.Errorf("wordlist vault or database unavailable"), nil
			}
			var p credentialAuditRequest
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}

			var prodSafe bool
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			if t != nil {
				prodSafe = t.ProdSafeMode
			}
			if err := validateAndNormalizeAuditRequest(&p, prodSafe); err != nil {
				return actool.Errorf(err.Error()), nil
			}

			if t != nil && t.Guard != nil {
				probeInput, _ := json.Marshal(map[string]string{
					"command": fmt.Sprintf("hydra %s://%s", p.Service, p.Target),
				})
				if blocked, reason := t.Guard.CheckFence("Bash", probeInput); blocked {
					return actool.Errorf(fmt.Sprintf("electronic fence blocked credential audit: %s", reason)), nil
				}
			}

			tmpDir, err := os.MkdirTemp("", "artex-credaudit-*")
			if err != nil {
				return actool.Errorf(fmt.Sprintf("create temp dir: %v", err)), nil
			}
			defer os.RemoveAll(tmpDir)

			var userFile, passFile, userpassFile string
			if p.UserpassList != "" {
				meta, err := s.m.pg.ResolveWordlist(p.UserpassList)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("resolve userpass_list %q: %v", p.UserpassList, err)), nil
				}
				if meta.Kind != db.WordlistKindUserpass {
					return actool.Errorf(fmt.Sprintf("wordlist %q has kind %q, expected %q", meta.Name, meta.Kind, db.WordlistKindUserpass)), nil
				}
				userpassFile, _, err = s.wlVault.MaterializeTemp(meta.ID, tmpDir, "userpass")
				if err != nil {
					return actool.Errorf(fmt.Sprintf("decrypt userpass_list: %v", err)), nil
				}
			} else {
				if p.UserList != "" {
					uMeta, err := s.m.pg.ResolveWordlist(p.UserList)
					if err != nil {
						return actool.Errorf(fmt.Sprintf("resolve user_list %q: %v", p.UserList, err)), nil
					}
					if uMeta.Kind != db.WordlistKindUsername {
						return actool.Errorf(fmt.Sprintf("wordlist %q has kind %q, expected %q", uMeta.Name, uMeta.Kind, db.WordlistKindUsername)), nil
					}
					userFile, _, err = s.wlVault.MaterializeTemp(uMeta.ID, tmpDir, "users")
					if err != nil {
						return actool.Errorf(fmt.Sprintf("decrypt user_list: %v", err)), nil
					}
				}
				pMeta, err := s.m.pg.ResolveWordlist(p.PassList)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("resolve pass_list %q: %v", p.PassList, err)), nil
				}
				if pMeta.Kind != db.WordlistKindPassword {
					return actool.Errorf(fmt.Sprintf("wordlist %q has kind %q, expected %q", pMeta.Name, pMeta.Kind, db.WordlistKindPassword)), nil
				}
				passFile, _, err = s.wlVault.MaterializeTemp(pMeta.ID, tmpDir, "passes")
				if err != nil {
					return actool.Errorf(fmt.Sprintf("decrypt pass_list: %v", err)), nil
				}
			}

			hydraBin, err := exec.LookPath("hydra")
			if err != nil {
				return actool.Errorf("hydra binary not found in PATH"), nil
			}
			args := buildHydraArgs(p, userFile, passFile, userpassFile)
			return executeHydraAudit(ctx, hydraBin, args, p, prodSafe)
		},
	)
}

func executeHydraAudit(ctx context.Context, hydraBin string, args []string, p credentialAuditRequest, prodSafe bool) (actool.Result, error) {
	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, hydraBin, args...)
	outBytes, runErr := cmd.CombinedOutput()
	matches := wordlists.ParseHydraMatches(string(outBytes))

	exitCode := 0
	statusNote := "completed"
	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			statusNote = "timeout_60s"
			exitCode = -1
		} else {
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
			statusNote = "finished_with_exit_code"
		}
	}

	return jsonResult(map[string]any{
		"target":         p.Target,
		"service":        p.Service,
		"port":           p.Port,
		"prod_safe_mode": prodSafe,
		"threads":        p.Threads,
		"status":         statusNote,
		"exit_code":      exitCode,
		"match_count":    len(matches),
		"matches":        matches,
	})
}

var allowedSprayProtocols = map[string]bool{
	"smb":   true,
	"ldap":  true,
	"winrm": true,
	"ssh":   true,
	"rdp":   true,
	"mssql": true,
	"wmi":   true,
}

type passwordSprayRequest struct {
	TaskID       string `json:"task_id"`
	Target       string `json:"target"`
	Protocol     string `json:"protocol"`
	Domain       string `json:"domain"`
	Username     string `json:"username"`
	UserList     string `json:"user_list"`
	PassList     string `json:"pass_list"`
	StartOffset  int    `json:"start_offset"`
	MaxPasswords int    `json:"max_passwords"`
	DelaySeconds int    `json:"delay_seconds"`
}

func validateAndNormalizeSprayRequest(p *passwordSprayRequest, prodSafe bool) error {
	p.TaskID = strings.TrimSpace(p.TaskID)
	p.Target = strings.TrimSpace(p.Target)
	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	p.Domain = strings.TrimSpace(p.Domain)
	p.Username = strings.TrimSpace(p.Username)
	p.UserList = strings.TrimSpace(p.UserList)
	p.PassList = strings.TrimSpace(p.PassList)

	if !isValidAuditTarget(p.Target) {
		return errors.New("invalid target host, IP, or CIDR")
	}
	if !allowedSprayProtocols[p.Protocol] {
		return fmt.Errorf("unsupported spray protocol %q; allowed: smb, ldap, winrm, ssh, rdp, mssql, wmi", p.Protocol)
	}
	if p.Domain != "" && strings.ContainsAny(p.Domain, " \t\r\n;|&$`<>\"'\\") {
		return errors.New("invalid domain")
	}
	if p.PassList == "" {
		return errors.New("pass_list is required")
	}
	if (p.Username == "" && p.UserList == "") || (p.Username != "" && p.UserList != "") {
		return errors.New("provide exactly one of username or user_list")
	}
	if p.StartOffset < 0 {
		p.StartOffset = 0
	}
	if p.MaxPasswords <= 0 {
		p.MaxPasswords = 1
	}
	if p.MaxPasswords > 3 {
		p.MaxPasswords = 3
	}
	if prodSafe && p.MaxPasswords > 1 {
		p.MaxPasswords = 1
	}
	if p.DelaySeconds < 1 {
		p.DelaySeconds = 1
	}
	if prodSafe && p.DelaySeconds < 2 {
		p.DelaySeconds = 2
	}
	if p.DelaySeconds > 30 {
		p.DelaySeconds = 30
	}
	return nil
}

func (s *Server) toolRunPasswordSpray() actool.CoreTool {
	return wrTool(
		"run_password_spray",
		"Run a lockout-safe, low-rate password spray using netexec (nxc) and encrypted server-side wordlists. Sprays at most 3 passwords per call (capped at 1 in prod_safe_mode) with inter-round delay, enforces electronic fence and lateral_gate, and masks all matched passwords.",
		objSchema(map[string]any{
			"task_id":       strParam("Task ID (numeric string)"),
			"target":        strParam("Target IP, hostname, or CIDR inside the authorized electronic fence"),
			"protocol":      strParam("Protocol: smb, ldap, winrm, ssh, rdp, mssql, or wmi"),
			"domain":        strParam("Optional AD domain name (e.g. CORP)"),
			"username":      strParam("Single username to test (mutually exclusive with user_list)"),
			"user_list":     strParam("Encrypted wordlist ID or name of kind 'username'"),
			"pass_list":     strParam("Encrypted wordlist ID or name of kind 'password'"),
			"start_offset":  map[string]any{"type": "integer", "description": "0-based index into pass_list (default 0)"},
			"max_passwords": map[string]any{"type": "integer", "description": "Passwords to spray in this call (default 1, max 3; capped at 1 in prod_safe_mode)"},
			"delay_seconds": map[string]any{"type": "integer", "description": "Delay in seconds between password rounds (default 1; min 2 in prod_safe_mode)"},
		}, "task_id", "target", "protocol", "pass_list"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil || s.wlVault == nil {
				return actool.Errorf("wordlist vault or database unavailable"), nil
			}
			var p passwordSprayRequest
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t := s.m.ResolveTask(strings.TrimSpace(p.TaskID))
			prodSafe := t != nil && t.ProdSafeMode
			if err := validateAndNormalizeSprayRequest(&p, prodSafe); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t != nil && t.LateralGate && !t.LateralApproved {
				return actool.Errorf("lateral gate is active: approve lateral movement via POST /api/tasks/{id}/lateral/approve before running password spray"), nil
			}
			if t != nil && t.Guard != nil {
				probeInput, _ := json.Marshal(map[string]string{
					"command": fmt.Sprintf("nxc %s %s", p.Protocol, p.Target),
				})
				if blocked, reason := t.Guard.CheckFence("Bash", probeInput); blocked {
					return actool.Errorf(fmt.Sprintf("electronic fence blocked password spray: %s", reason)), nil
				}
			}

			tmpDir, err := os.MkdirTemp("", "artex-spray-*")
			if err != nil {
				return actool.Errorf(fmt.Sprintf("create temp dir: %v", err)), nil
			}
			defer os.RemoveAll(tmpDir)

			userArg := p.Username
			if p.UserList != "" {
				uMeta, err := s.m.pg.ResolveWordlist(p.UserList)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("resolve user_list %q: %v", p.UserList, err)), nil
				}
				if uMeta.Kind != db.WordlistKindUsername {
					return actool.Errorf(fmt.Sprintf("wordlist %q has kind %q, expected %q", uMeta.Name, uMeta.Kind, db.WordlistKindUsername)), nil
				}
				userArg, _, err = s.wlVault.MaterializeTemp(uMeta.ID, tmpDir, "users")
				if err != nil {
					return actool.Errorf(fmt.Sprintf("decrypt user_list: %v", err)), nil
				}
			}

			pMeta, err := s.m.pg.ResolveWordlist(p.PassList)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("resolve pass_list %q: %v", p.PassList, err)), nil
			}
			if pMeta.Kind != db.WordlistKindPassword {
				return actool.Errorf(fmt.Sprintf("wordlist %q has kind %q, expected %q", pMeta.Name, pMeta.Kind, db.WordlistKindPassword)), nil
			}
			passes, totalPasses, err := s.wlVault.LoadDecryptedSlice(pMeta.ID, p.StartOffset, p.MaxPasswords)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("decrypt pass_list: %v", err)), nil
			}

			nxcBin, err := exec.LookPath("nxc")
			if err != nil {
				nxcBin, err = exec.LookPath("netexec")
				if err != nil {
					return actool.Errorf("netexec (nxc) binary not found in PATH"), nil
				}
			}
			return executeNxcSpray(ctx, nxcBin, p, userArg, passes, totalPasses, prodSafe)
		},
	)
}

func executeNxcSpray(ctx context.Context, nxcBin string, p passwordSprayRequest, userArg string, passes []string, totalPasses int, prodSafe bool) (actool.Result, error) {
	allMatches := []wordlists.MaskedMatch{}
	for idx, secret := range passes {
		if idx > 0 {
			select {
			case <-ctx.Done():
				return actool.Errorf(ctx.Err().Error()), nil
			case <-time.After(time.Duration(p.DelaySeconds) * time.Second):
			}
		}
		args := []string{p.Protocol, p.Target, "-u", userArg, "-p", secret, "--continue-on-success", "--no-bruteforce"}
		if p.Domain != "" {
			args = append(args, "-d", p.Domain)
		}
		runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		cmd := exec.CommandContext(runCtx, nxcBin, args...)
		outBytes, _ := cmd.CombinedOutput()
		cancel()
		if m := wordlists.ParseNxcMatches(string(outBytes)); len(m) > 0 {
			allMatches = append(allMatches, m...)
		}
	}
	return jsonResult(map[string]any{
		"target":          p.Target,
		"protocol":        p.Protocol,
		"domain":          p.Domain,
		"prod_safe_mode":  prodSafe,
		"start_offset":    p.StartOffset,
		"sprayed_count":   len(passes),
		"total_passwords": totalPasses,
		"next_offset":     p.StartOffset + len(passes),
		"delay_seconds":   p.DelaySeconds,
		"match_count":     len(allMatches),
		"matches":         allMatches,
	})
}
