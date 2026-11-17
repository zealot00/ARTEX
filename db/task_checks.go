package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ComplianceProfileMLPS = "mlps"

	CheckStatusPending = "pending"
	CheckStatusPassed  = "passed"
	CheckStatusFailed  = "failed"
	CheckStatusNA      = "na"
	CheckStatusBlocked = "blocked"
)

var (
	ErrInvalidCheckCode   = errors.New("invalid compliance check_code")
	ErrInvalidCheckStatus = errors.New("check status must be pending, passed, failed, na, or blocked")
)

// TaskCheckTemplate describes one baseline compliance control item.
type TaskCheckTemplate struct {
	Code   string `json:"check_code"`
	Domain string `json:"domain"`
	Title  string `json:"title"`
}

// TaskCheck is one persisted compliance check item for a task (supporting
// both positive findings and negative "tested and passed" compliance records).
type TaskCheck struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	CheckCode string    `json:"check_code"`
	Domain    string    `json:"domain"`
	Title     string    `json:"title"`
	Status    string    `json:"status"`
	Target    string    `json:"target,omitempty"`
	Evidence  string    `json:"evidence,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	FindingID *int64    `json:"finding_id,omitempty"`
	TestedBy  string    `json:"tested_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TaskCheckSummary aggregates checklist progress for reporting and polling.
type TaskCheckSummary struct {
	Total   int `json:"total"`
	Pending int `json:"pending"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	NA      int `json:"na"`
	Blocked int `json:"blocked"`
}

// MLPSBaselineChecks returns the 12 standard MLPS 2.0 penetration testing domains.
func MLPSBaselineChecks() []TaskCheckTemplate {
	return []TaskCheckTemplate{
		{Code: "NET-TLS", Domain: "安全通信网络", Title: "传输加密与 TLS 协议/弱密码套件/证书安全性检查"},
		{Code: "NET-BOUNDARY", Domain: "安全区域边界", Title: "网络边界暴露面与区域隔离穿透有效性验证"},
		{Code: "AUTH-WEAKPWD", Domain: "安全计算环境-身份鉴别", Title: "系统/中间件/数据库/Web 弱口令与默认口令审计"},
		{Code: "AUTH-SESSION", Domain: "安全计算环境-会话认证", Title: "会话固定、Cookie 属性、登出失效、锁定策略与重放防护"},
		{Code: "AUTH-ACCESS", Domain: "安全计算环境-访问控制", Title: "垂直越权与水平越权（IDOR/未授权强制浏览）验证"},
		{Code: "WEB-INJECTION", Domain: "应用安全-注入漏洞", Title: "SQL 注入、命令注入、SSTI、XXE 等注入类漏洞验证"},
		{Code: "WEB-XSS-CSRF", Domain: "应用安全-客户端与传输", Title: "XSS、CSRF、SSRF、任意文件上传/下载与路径遍历验证"},
		{Code: "APP-API", Domain: "应用安全-接口与逻辑", Title: "API 未授权访问、文档/监控端点暴露、敏感信息泄漏与业务绕过"},
		{Code: "SVC-UNAUTH", Domain: "安全计算环境-服务暴露", Title: "高危端口与中间件/数据库未授权访问（Redis/SMB/ES/Actuator 等）"},
		{Code: "AD-DIR", Domain: "安全计算环境-目录与域控", Title: "LDAP/Kerberos 域环境匿名绑定、传输签名与目录权限基线检查"},
		{Code: "WIN-SVC", Domain: "安全计算环境-Windows与打印服务", Title: "SMB/Samba 签名与共享权限、WinRM/RDP 暴露面及打印服务（IPP/Spooler）合规检查"},
		{Code: "SEC-PROD-SAFE", Domain: "测试过程合规", Title: "生产安全基线核查（低并发限速、无 DoS/无破坏性操作）"},
	}
}

var mlpsTemplateByCode = func() map[string]TaskCheckTemplate {
	all := MLPSBaselineChecks()
	m := make(map[string]TaskCheckTemplate, len(all))
	for _, t := range all {
		m[t.Code] = t
	}
	return m
}()

// NormalizeCheckStatus validates a check status value.
func NormalizeCheckStatus(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case CheckStatusPending, CheckStatusPassed, CheckStatusFailed, CheckStatusNA, CheckStatusBlocked:
		return s, nil
	default:
		return "", ErrInvalidCheckStatus
	}
}

// SummarizeTaskChecks computes per-status counts over checks.
func SummarizeTaskChecks(checks []TaskCheck) TaskCheckSummary {
	var sum TaskCheckSummary
	sum.Total = len(checks)
	for _, c := range checks {
		switch c.Status {
		case CheckStatusPassed:
			sum.Passed++
		case CheckStatusFailed:
			sum.Failed++
		case CheckStatusNA:
			sum.NA++
		case CheckStatusBlocked:
			sum.Blocked++
		default:
			sum.Pending++
		}
	}
	return sum
}

func seedTaskChecksTx(tx *sql.Tx, taskID int64, profile string) error {
	if strings.ToLower(strings.TrimSpace(profile)) != ComplianceProfileMLPS {
		return nil
	}
	for _, tpl := range MLPSBaselineChecks() {
		if _, err := tx.Exec(`
INSERT INTO task_checks(task_id, check_code, domain, title, status, target)
VALUES ($1, $2, $3, $4, 'pending', '')
ON CONFLICT (task_id, check_code, target) DO NOTHING`,
			taskID, tpl.Code, tpl.Domain, tpl.Title); err != nil {
			return err
		}
	}
	return nil
}

// TaskCheckInput specifies an upsert to task_checks.
type TaskCheckInput struct {
	CheckCode string
	Domain    string
	Title     string
	Status    string
	Target    string
	Evidence  string
	Notes     string
	FindingID *int64
	TestedBy  string
}

// ListTaskChecks returns all compliance check rows for taskID ordered by ID.
func (d *DB) ListTaskChecks(taskID int64) ([]TaskCheck, error) {
	rows, err := d.Query(`
SELECT id, task_id, check_code, domain, title, status, target, evidence, notes, finding_id, tested_by, created_at, updated_at
FROM task_checks
WHERE task_id = $1
ORDER BY id ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskCheck{}
	for rows.Next() {
		var c TaskCheck
		if err := rows.Scan(&c.ID, &c.TaskID, &c.CheckCode, &c.Domain, &c.Title, &c.Status, &c.Target, &c.Evidence, &c.Notes, &c.FindingID, &c.TestedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpsertTaskCheckResult records or updates a compliance check verdict for (task, check_code, target).
func (d *DB) UpsertTaskCheckResult(taskID int64, in TaskCheckInput) (*TaskCheck, error) {
	code := strings.ToUpper(strings.TrimSpace(in.CheckCode))
	if code == "" || len(code) > 64 {
		return nil, fmt.Errorf("%w: empty or too long", ErrInvalidCheckCode)
	}
	status, err := NormalizeCheckStatus(in.Status)
	if err != nil {
		return nil, err
	}
	domain := strings.TrimSpace(in.Domain)
	title := strings.TrimSpace(in.Title)
	if tpl, ok := mlpsTemplateByCode[code]; ok {
		if domain == "" {
			domain = tpl.Domain
		}
		if title == "" {
			title = tpl.Title
		}
	}
	if domain == "" {
		domain = "自定义检查项"
	}
	if title == "" {
		title = code
	}
	target := strings.TrimSpace(in.Target)
	evidence := strings.TrimSpace(in.Evidence)
	notes := strings.TrimSpace(in.Notes)
	testedBy := strings.TrimSpace(in.TestedBy)

	// When a target-specific verdict is recorded for a seeded baseline code,
	// drop the initial un-targeted 'pending' placeholder row if one exists.
	if target != "" {
		_, _ = d.Exec(`DELETE FROM task_checks WHERE task_id=$1 AND check_code=$2 AND target='' AND status='pending'`, taskID, code)
	}

	var c TaskCheck
	err = d.QueryRow(`
INSERT INTO task_checks(task_id, check_code, domain, title, status, target, evidence, notes, finding_id, tested_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (task_id, check_code, target) DO UPDATE
SET domain     = EXCLUDED.domain,
    title      = EXCLUDED.title,
    status     = EXCLUDED.status,
    evidence   = CASE WHEN EXCLUDED.evidence <> '' THEN EXCLUDED.evidence ELSE task_checks.evidence END,
    notes      = CASE WHEN EXCLUDED.notes <> '' THEN EXCLUDED.notes ELSE task_checks.notes END,
    finding_id = COALESCE(EXCLUDED.finding_id, task_checks.finding_id),
    tested_by  = CASE WHEN EXCLUDED.tested_by <> '' THEN EXCLUDED.tested_by ELSE task_checks.tested_by END,
    updated_at = now()
RETURNING id, task_id, check_code, domain, title, status, target, evidence, notes, finding_id, tested_by, created_at, updated_at`,
		taskID, code, domain, title, status, target, evidence, notes, in.FindingID, testedBy).
		Scan(&c.ID, &c.TaskID, &c.CheckCode, &c.Domain, &c.Title, &c.Status, &c.Target, &c.Evidence, &c.Notes, &c.FindingID, &c.TestedBy, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
