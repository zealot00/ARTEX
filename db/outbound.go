package db

import (
	"strings"
	"time"
)

// OutboundLog records aggregated external network connections observed during a task
// so security teams can account for legitimate outbound traffic in upper-layer NDR/SOC audits.
type OutboundLog struct {
	ID         int64     `json:"id"`
	TaskID     int64     `json:"task_id"`
	Source     string    `json:"source"`
	Protocol   string    `json:"protocol"`
	TargetHost string    `json:"target_host"`
	TargetPort int       `json:"target_port"`
	Method     string    `json:"method"`
	URLPreview string    `json:"url_preview"`
	Purpose    string    `json:"purpose"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	HitCount   int       `json:"hit_count"`
}

// RecordOutboundInput holds one observed outbound connection event.
type RecordOutboundInput struct {
	TaskID     int64
	Source     string
	Protocol   string
	TargetHost string
	TargetPort int
	Method     string
	URLPreview string
	Purpose    string
}

// RecordOutboundLog inserts or aggregates an outbound connection log for task_id.
func (d *DB) RecordOutboundLog(in RecordOutboundInput) error {
	if d == nil || in.TaskID <= 0 {
		return nil
	}
	host := strings.ToLower(strings.TrimSpace(in.TargetHost))
	if host == "" {
		return nil
	}
	src := strings.ToLower(strings.TrimSpace(in.Source))
	if src == "" {
		src = "proxy"
	}
	proto := strings.ToLower(strings.TrimSpace(in.Protocol))
	if proto == "" {
		proto = "http"
	}
	port := in.TargetPort
	if port < 0 || port > 65535 {
		port = 0
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	preview := strings.TrimSpace(in.URLPreview)
	if len(preview) > 256 {
		preview = preview[:256]
	}
	purpose := strings.TrimSpace(in.Purpose)

	_, err := d.Exec(`
INSERT INTO task_outbound_logs(task_id, source, protocol, target_host, target_port, method, url_preview, purpose)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (task_id, source, protocol, target_host, target_port) DO UPDATE
  SET hit_count   = task_outbound_logs.hit_count + 1,
      last_seen   = now(),
      method      = CASE WHEN EXCLUDED.method <> '' THEN EXCLUDED.method ELSE task_outbound_logs.method END,
      url_preview = CASE WHEN EXCLUDED.url_preview <> '' THEN EXCLUDED.url_preview ELSE task_outbound_logs.url_preview END,
      purpose     = CASE WHEN EXCLUDED.purpose <> '' THEN EXCLUDED.purpose ELSE task_outbound_logs.purpose END`,
		in.TaskID, src, proto, host, port, method, preview, purpose)
	return err
}

// ListTaskOutboundLogs returns aggregated outbound connection logs for taskID ordered by most recent.
func (d *DB) ListTaskOutboundLogs(taskID int64) ([]OutboundLog, error) {
	if d == nil || taskID <= 0 {
		return nil, nil
	}
	rows, err := d.Query(`
SELECT id, task_id, source, protocol, target_host, target_port, method, url_preview, purpose, first_seen, last_seen, hit_count
FROM task_outbound_logs
WHERE task_id = $1
ORDER BY last_seen DESC, id DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []OutboundLog
	for rows.Next() {
		var l OutboundLog
		if err := rows.Scan(&l.ID, &l.TaskID, &l.Source, &l.Protocol, &l.TargetHost, &l.TargetPort, &l.Method, &l.URLPreview, &l.Purpose, &l.FirstSeen, &l.LastSeen, &l.HitCount); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
