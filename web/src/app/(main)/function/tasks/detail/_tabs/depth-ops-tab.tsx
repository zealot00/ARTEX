"use client";

import * as React from "react";

import {
  CheckCircle2Icon,
  DownloadIcon,
  RefreshCwIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  TerminalIcon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { formatRulesText, formatSessionEndpoint, parseLineEntries, summarizeChecksProgress } from "@/lib/depth-ops";
import type { DepthSessionInfo, Task, TaskCheckRow } from "@/lib/types";

export function DepthOpsTab({
  taskId,
  task,
  onTaskUpdated,
}: {
  taskId: string;
  task: Task;
  onTaskUpdated: () => void;
}) {
  const [fenceEnabled, setFenceEnabled] = React.useState(!!task.fence_enabled);
  const [fenceRulesText, setFenceRulesText] = React.useState(formatRulesText(task.fence_rules));
  const [savingFence, setSavingFence] = React.useState(false);

  const [sessions, setSessions] = React.useState<DepthSessionInfo[]>([]);
  const [loadingSessions, setLoadingSessions] = React.useState(true);

  const [checks, setChecks] = React.useState<TaskCheckRow[]>([]);
  const [loadingChecks, setLoadingChecks] = React.useState(true);

  const [lateralNote, setLateralNote] = React.useState("");
  const [approvingLateral, setApprovingLateral] = React.useState(false);

  const loadAll = React.useCallback(async () => {
    setLoadingSessions(true);
    setLoadingChecks(true);
    try {
      const [fenceCfg, sessList, checksRes] = await Promise.all([
        api.taskFence(taskId).catch(() => null),
        api.taskDepthSessions(taskId).catch(() => []),
        api.taskChecks(taskId).catch(() => ({ checks: [], summary: null })),
      ]);
      if (fenceCfg) {
        setFenceEnabled(fenceCfg.fence_enabled);
        setFenceRulesText(formatRulesText(fenceCfg.fence_rules));
      }
      setSessions(sessList);
      setChecks(checksRes.checks ?? []);
    } finally {
      setLoadingSessions(false);
      setLoadingChecks(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleSaveFence = async () => {
    setSavingFence(true);
    try {
      const rules = parseLineEntries(fenceRulesText);
      const updated = await api.updateTaskFence(taskId, fenceEnabled, rules);
      setFenceEnabled(updated.fence_enabled);
      setFenceRulesText(formatRulesText(updated.fence_rules));
      toast.success("Electronic fence updated");
      onTaskUpdated();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to update electronic fence");
    } finally {
      setSavingFence(false);
    }
  };

  const handleApproveLateral = async () => {
    setApprovingLateral(true);
    try {
      await api.approveTaskLateral(taskId, lateralNote.trim());
      toast.success("Lateral movement approved and task resumed");
      setLateralNote("");
      onTaskUpdated();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to approve lateral movement");
    } finally {
      setApprovingLateral(false);
    }
  };

  const handleCloseSession = async (sid: string) => {
    try {
      await api.closeTaskDepthSession(taskId, sid);
      toast.success(`Closed session ${sid}`);
      await loadAll();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to close session");
    }
  };

  const progress = summarizeChecksProgress(checks);

  return (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Electronic Fence */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-base">
              <span className="flex items-center gap-2">
                <ShieldCheckIcon className="size-4" />
                Electronic Fence (Scope Geofence)
              </span>
              <Switch checked={fenceEnabled} onCheckedChange={setFenceEnabled} />
            </CardTitle>
            <CardDescription>
              Fail-closed boundary enforced across Planner, Workers, MainAgent, credential audits, and HTTP 30x redirects.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="fence-rules" className="text-xs">
                Authorized Rules (CIDR, IP, domain, *.domain, or URL prefix — one per line)
              </Label>
              <Textarea
                id="fence-rules"
                rows={4}
                className="font-mono text-xs"
                placeholder={"10.10.0.0/16\n*.corp.local\nhttps://portal.corp.local:8443"}
                value={fenceRulesText}
                onChange={(e) => setFenceRulesText(e.target.value)}
              />
            </div>
            <Button size="sm" onClick={handleSaveFence} disabled={savingFence}>
              {savingFence ? "Saving..." : "Save Electronic Fence"}
            </Button>
          </CardContent>
        </Card>

        {/* Lateral Gate & Safety */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlertIcon className="size-4" />
              Lateral Gate & Safety Controls
            </CardTitle>
            <CardDescription>
              Controls foothold-gated pivoting (<code>proxychains4</code>, <code>chisel</code>, <code>impacket</code>,{" "}
              <code>nxc</code>, <code>depth_session_open</code>).
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex flex-wrap gap-2">
              <Badge variant={task.prod_safe_mode ? "default" : "outline"}>
                prod_safe_mode: {task.prod_safe_mode ? "ON" : "OFF"}
              </Badge>
              <Badge variant={task.lateral_gate ? "secondary" : "outline"}>
                lateral_gate: {task.lateral_gate ? "ON" : "OFF"}
              </Badge>
              <Badge variant={task.lateral_approved ? "default" : "outline"}>
                lateral_approved: {task.lateral_approved ? "YES" : "NO"}
              </Badge>
            </div>
            {task.parked_reason && (
              <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs">
                Parked reason: <span className="font-mono">{task.parked_reason}</span>
              </div>
            )}
            {task.lateral_gate && !task.lateral_approved && (
              <div className="space-y-2 border-t pt-3">
                <Input
                  placeholder="Approval note (optional)"
                  value={lateralNote}
                  onChange={(e) => setLateralNote(e.target.value)}
                />
                <Button size="sm" onClick={handleApproveLateral} disabled={approvingLateral}>
                  <CheckCircle2Icon className="mr-1.5 size-3.5" />
                  {approvingLateral ? "Approving..." : "Approve Lateral Movement & Resume"}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Persistent Depth Sessions & Pivot Tunnels */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <TerminalIcon className="size-4" />
              Persistent Depth Sessions & Pivot Tunnels
            </CardTitle>
            <CardDescription>
              Task-scoped interactive PTYs, multi-hop SSH jumps, SOCKS5 proxies, and tunnels (auto-cleaned on task completion).
            </CardDescription>
          </div>
          <Button size="sm" variant="outline" onClick={() => void loadAll()}>
            <RefreshCwIcon className="mr-1.5 size-3.5" />
            Refresh
          </Button>
        </CardHeader>
        <CardContent>
          {loadingSessions ? (
            <p className="text-xs text-muted-foreground">Loading sessions...</p>
          ) : sessions.length === 0 ? (
            <p className="text-xs text-muted-foreground">No persistent depth sessions recorded for this task.</p>
          ) : (
            <div className="space-y-2">
              {sessions.map((s) => (
                <div key={s.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border px-3 py-2 text-xs">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold">{s.id}</span>
                      <Badge variant="outline">{s.kind}</Badge>
                      <Badge variant={s.status === "open" ? "default" : "secondary"}>{s.status}</Badge>
                      <span className="font-medium">{s.name}</span>
                    </div>
                    <div className="font-mono text-[11px] text-muted-foreground">
                      {formatSessionEndpoint(s)}
                      {s.username ? ` • user=${s.username}` : ""}
                      {s.jump_session_id ? ` • via=${s.jump_session_id}` : ""}
                      {s.pid ? ` • pid=${s.pid}` : ""}
                    </div>
                  </div>
                  {s.status === "open" && (
                    <Button size="sm" variant="destructive" onClick={() => void handleCloseSession(s.id)}>
                      <XCircleIcon className="mr-1 size-3.5" />
                      Close
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* MLPS 2.0 Compliance Checks */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base">
              Compliance Checklist ({progress.completed}/{progress.total} • {progress.percent}%)
            </CardTitle>
            <CardDescription>
              Positive findings and negative-evidence verification across MLPS 2.0 / AD / Windows / Network domains.
            </CardDescription>
          </div>
          <Button size="sm" variant="outline" asChild>
            <a href={`/api/tasks/${encodeURIComponent(taskId)}/report/mlps`} target="_blank" rel="noreferrer">
              <DownloadIcon className="mr-1.5 size-3.5" />
              Export MLPS Report
            </a>
          </Button>
        </CardHeader>
        <CardContent>
          {loadingChecks ? (
            <p className="text-xs text-muted-foreground">Loading checks...</p>
          ) : checks.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No compliance checklist seeded for this task (set <code>compliance_profile: &quot;mlps&quot;</code> at creation).
            </p>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {checks.map((c) => (
                <div key={c.id} className="rounded-md border px-3 py-2 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-semibold">{c.check_code}</span>
                    <Badge
                      variant={
                        c.status === "passed" ? "default" : c.status === "failed" ? "destructive" : "secondary"
                      }
                    >
                      {c.status}
                    </Badge>
                  </div>
                  <p className="mt-1 font-medium">{c.title}</p>
                  <p className="text-muted-foreground">{c.domain}</p>
                  {c.evidence && <p className="mt-1 line-clamp-2 font-mono text-[11px] text-muted-foreground">{c.evidence}</p>}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
