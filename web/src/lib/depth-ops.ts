export function parseLineEntries(raw: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      out.push(trimmed);
    }
  }
  return out;
}

export function formatRulesText(rules: string[] | undefined): string {
  return (rules ?? []).join("\n");
}

export function summarizeChecksProgress(checks: Array<{ status: string }>): {
  total: number;
  completed: number;
  passed: number;
  failed: number;
  percent: number;
} {
  const total = checks.length;
  let passed = 0;
  let failed = 0;
  let completed = 0;
  for (const c of checks) {
    if (c.status === "passed") {
      passed += 1;
      completed += 1;
    } else if (c.status === "failed") {
      failed += 1;
      completed += 1;
    } else if (c.status === "na") {
      completed += 1;
    }
  }
  const percent = total > 0 ? Math.round((completed / total) * 100) : 0;
  return { total, completed, passed, failed, percent };
}

export function formatSessionEndpoint(sess: {
  kind: string;
  target?: string;
  port?: number;
  socks_addr?: string;
}): string {
  const host = sess.target ? (sess.port ? `${sess.target}:${sess.port}` : sess.target) : "local";
  if (sess.socks_addr) {
    return `${host} (SOCKS5 ${sess.socks_addr})`;
  }
  return host;
}
