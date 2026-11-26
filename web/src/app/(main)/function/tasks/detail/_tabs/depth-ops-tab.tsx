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
import { useI18n } from "@/lib/i18n/provider";
import type {
  BlackboardEntry,
  BlackboardKind,
  DepthSessionInfo,
  OutboundLog,
  ProxyHeaderRule,
  ResourceLease,
  SolverStateRecord,
  Task,
  TaskCheckRow,
} from "@/lib/types";

export function DepthOpsTab({
  taskId,
  task,
  onTaskUpdated,
}: {
  taskId: string;
  task: Task;
  onTaskUpdated: () => void;
}) {
  const { t } = useI18n();
  const [fenceEnabled, setFenceEnabled] = React.useState(!!task.fence_enabled);
  const [fenceRulesText, setFenceRulesText] = React.useState(formatRulesText(task.fence_rules));
  const [savingFence, setSavingFence] = React.useState(false);

  const [sessions, setSessions] = React.useState<DepthSessionInfo[]>([]);
  const [loadingSessions, setLoadingSessions] = React.useState(true);

  const [checks, setChecks] = React.useState<TaskCheckRow[]>([]);
  const [loadingChecks, setLoadingChecks] = React.useState(true);

  const [outboundLogs, setOutboundLogs] = React.useState<OutboundLog[]>([]);
  const [loadingOutbound, setLoadingOutbound] = React.useState(true);

  const [proxyRules, setProxyRules] = React.useState<ProxyHeaderRule[]>([]);
  const [proxyHost, setProxyHost] = React.useState("");
  const [proxyHeaderName, setProxyHeaderName] = React.useState("Authorization");
  const [proxyHeaderValue, setProxyHeaderValue] = React.useState("");
  const [proxyOverwrite, setProxyOverwrite] = React.useState(true);
  const [savingProxyHeaders, setSavingProxyHeaders] = React.useState(false);

  const [lateralNote, setLateralNote] = React.useState("");
  const [approvingLateral, setApprovingLateral] = React.useState(false);

  const [solverState, setSolverState] = React.useState<SolverStateRecord | null>(null);
  const [blackboard, setBlackboard] = React.useState<BlackboardEntry[]>([]);
  const [leases, setLeases] = React.useState<ResourceLease[]>([]);
  const [escalatingSolver, setEscalatingSolver] = React.useState(false);
  const [bbKind, setBbKind] = React.useState<BlackboardKind>("hypothesis");
  const [bbTarget, setBbTarget] = React.useState("");
  const [bbTopic, setBbTopic] = React.useState("");
  const [bbPrecondition, setBbPrecondition] = React.useState("");
  const [postingBB, setPostingBB] = React.useState(false);

  const loadAll = React.useCallback(async () => {
    setLoadingSessions(true);
    setLoadingChecks(true);
    setLoadingOutbound(true);
    try {
      const [fenceCfg, sessList, checksRes, outList, phRules, solverSnap] = await Promise.all([
        api.taskFence(taskId).catch(() => null),
        api.taskDepthSessions(taskId).catch(() => []),
        api.taskChecks(taskId).catch(() => ({ checks: [], summary: null })),
        api.taskOutboundLogs(taskId).catch(() => []),
        api.taskProxyHeaders(taskId).catch(() => []),
        api.taskSolver(taskId).catch(() => null),
      ]);
      if (fenceCfg) {
        setFenceEnabled(fenceCfg.fence_enabled);
        setFenceRulesText(formatRulesText(fenceCfg.fence_rules));
      }
      setSessions(sessList);
      setChecks(checksRes.checks ?? []);
      setOutboundLogs(outList);
      setProxyRules(phRules);
      if (solverSnap) {
        setSolverState(solverSnap.solver);
        setBlackboard(solverSnap.blackboard ?? []);
        setLeases(solverSnap.leases ?? []);
      }
    } finally {
      setLoadingSessions(false);
      setLoadingChecks(false);
      setLoadingOutbound(false);
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
      toast.success(t("depth.fence.savedToast"));
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
      toast.success(t("depth.lateral.approvedToast"));
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
      toast.success(t("depth.sessions.closedToast", { id: sid }));
      await loadAll();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to close session");
    }
  };

  const handleSaveProxyHeader = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!proxyHost.trim() || !proxyHeaderName.trim() || !proxyHeaderValue.trim()) return;
    setSavingProxyHeaders(true);
    try {
      await api.updateTaskProxyHeaders(
        taskId,
        [
          {
            host: proxyHost.trim(),
            headers: { [proxyHeaderName.trim()]: proxyHeaderValue },
            overwrite: proxyOverwrite,
          },
        ],
        true,
      );
      toast.success(t("depth.proxyHeaders.savedToast"));
      setProxyHeaderValue("");
      await loadAll();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save proxy header rule");
    } finally {
      setSavingProxyHeaders(false);
    }
  };

  const handleClearProxyHeaders = async () => {
    setSavingProxyHeaders(true);
    try {
      await api.updateTaskProxyHeaders(taskId, []);
      toast.success(t("depth.proxyHeaders.clearedToast"));
      await loadAll();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to clear proxy header rules");
    } finally {
      setSavingProxyHeaders(false);
    }
  };

  const handleEscalateSolver = async (nextTier: number) => {
    setEscalatingSolver(true);
    try {
      const res = await api.escalateTaskSolver(taskId, nextTier, "operator manual escalation");
      setSolverState(res.solver);
      toast.success(t("depth.solver.escalatedToast", { tier: nextTier }));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("depth.solver.escalateFailed"));
    } finally {
      setEscalatingSolver(false);
    }
  };

  const handlePostBlackboard = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bbTopic.trim()) return;
    setPostingBB(true);
    try {
      await api.postTaskBlackboard(taskId, {
        kind: bbKind,
        target: bbTarget.trim(),
        topic: bbTopic.trim(),
        precondition_tag: bbPrecondition.trim(),
      });
      toast.success(t("depth.solver.postedToast"));
      setBbTopic("");
      setBbTarget("");
      setBbPrecondition("");
      await loadAll();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("depth.solver.postFailed"));
    } finally {
      setPostingBB(false);
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
                {t("depth.fence.title")}
              </span>
              <Switch checked={fenceEnabled} onCheckedChange={setFenceEnabled} />
            </CardTitle>
            <CardDescription>{t("depth.fence.desc")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="fence-rules" className="text-xs">
                {t("depth.fence.rulesLabel")}
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
              {savingFence ? t("common.saving") : t("depth.fence.saveBtn")}
            </Button>
          </CardContent>
        </Card>

        {/* Lateral Gate & Safety */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlertIcon className="size-4" />
              {t("depth.lateral.title")}
            </CardTitle>
            <CardDescription>{t("depth.lateral.desc")}</CardDescription>
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
                {t("depth.lateral.parkedReason", { reason: task.parked_reason })}
              </div>
            )}
            {task.lateral_gate && !task.lateral_approved && (
              <div className="space-y-2 border-t pt-3">
                <Input
                  placeholder={t("depth.lateral.notePlaceholder")}
                  value={lateralNote}
                  onChange={(e) => setLateralNote(e.target.value)}
                />
                <Button size="sm" onClick={handleApproveLateral} disabled={approvingLateral}>
                  <CheckCircle2Icon className="mr-1.5 size-3.5" />
                  {approvingLateral ? t("depth.lateral.approvingBtn") : t("depth.lateral.approveBtn")}
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
              {t("depth.sessions.title")}
            </CardTitle>
            <CardDescription>{t("depth.sessions.desc")}</CardDescription>
          </div>
          <Button size="sm" variant="outline" onClick={() => void loadAll()}>
            <RefreshCwIcon className="mr-1.5 size-3.5" />
            {t("common.refresh")}
          </Button>
        </CardHeader>
        <CardContent>
          {loadingSessions ? (
            <p className="text-xs text-muted-foreground">{t("common.loading")}</p>
          ) : sessions.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("depth.sessions.empty")}</p>
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
                      {t("common.close")}
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
              {t("depth.checks.title", {
                completed: progress.completed,
                total: progress.total,
                percent: progress.percent,
              })}
            </CardTitle>
            <CardDescription>{t("depth.checks.desc")}</CardDescription>
          </div>
          <Button size="sm" variant="outline" asChild>
            <a href={`/api/tasks/${encodeURIComponent(taskId)}/report/mlps`} target="_blank" rel="noreferrer">
              <DownloadIcon className="mr-1.5 size-3.5" />
              {t("depth.checks.exportBtn")}
            </a>
          </Button>
        </CardHeader>
        <CardContent>
          {loadingChecks ? (
            <p className="text-xs text-muted-foreground">{t("common.loading")}</p>
          ) : checks.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("depth.checks.empty")}</p>
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
      {/* Host-Scoped Proxy Auth Header Injection */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base">{t("depth.proxyHeaders.title")}</CardTitle>
            <CardDescription>{t("depth.proxyHeaders.desc")}</CardDescription>
          </div>
          {proxyRules.length > 0 && (
            <Button size="sm" variant="outline" onClick={() => void handleClearProxyHeaders()} disabled={savingProxyHeaders}>
              {t("depth.proxyHeaders.clearBtn")}
            </Button>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={handleSaveProxyHeader} className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1">
              <Label className="text-xs">{t("depth.proxyHeaders.hostLabel")}</Label>
              <Input
                value={proxyHost}
                onChange={(e) => setProxyHost(e.target.value)}
                placeholder={t("depth.proxyHeaders.hostPlaceholder")}
                required
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t("depth.proxyHeaders.headerNameLabel")}</Label>
              <Input
                value={proxyHeaderName}
                onChange={(e) => setProxyHeaderName(e.target.value)}
                placeholder="Authorization / Cookie"
                required
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t("depth.proxyHeaders.headerValueLabel")}</Label>
              <Input
                type="password"
                value={proxyHeaderValue}
                onChange={(e) => setProxyHeaderValue(e.target.value)}
                placeholder="Bearer ... / sid=..."
                required
              />
            </div>
            <div className="flex items-center gap-2 sm:col-span-2">
              <Switch checked={proxyOverwrite} onCheckedChange={setProxyOverwrite} />
              <Label className="text-xs">{t("depth.proxyHeaders.overwriteLabel")}</Label>
            </div>
            <div className="flex justify-end">
              <Button type="submit" size="sm" disabled={savingProxyHeaders}>
                {savingProxyHeaders ? t("common.saving") : t("depth.proxyHeaders.saveBtn")}
              </Button>
            </div>
          </form>

          {proxyRules.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("depth.proxyHeaders.empty")}</p>
          ) : (
            <div className="space-y-2">
              {proxyRules.map((r, idx) => (
                <div key={`${r.host}-${idx}`} className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono font-semibold">{r.host}</span>
                    <Badge variant="outline">
                      {r.overwrite ? t("depth.proxyHeaders.modeOverwrite") : t("depth.proxyHeaders.modeDefault")}
                    </Badge>
                    {Object.entries(r.headers).map(([hk, hv]) => (
                      <Badge key={hk} variant="secondary" className="font-mono">
                        {hk}: {hv}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Focused Persistent Solver (L1–L5) & Shared Uncertainty Blackboard */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base">{t("depth.solver.title")}</CardTitle>
            <CardDescription>{t("depth.solver.desc")}</CardDescription>
          </div>
          {solverState && solverState.current_tier < 5 && (
            <Button
              size="sm"
              variant="outline"
              disabled={escalatingSolver}
              onClick={() => void handleEscalateSolver(solverState.current_tier + 1)}
            >
              {t("depth.solver.escalateBtn", { tier: solverState.current_tier + 1 })}
            </Button>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {([1, 2, 3, 4, 5] as const).map((tier) => {
              const active = (solverState?.current_tier ?? 1) >= tier;
              const isCurrent = (solverState?.current_tier ?? 1) === tier;
              const tierKey = `depth.solver.tier.${tier}` as
                | "depth.solver.tier.1"
                | "depth.solver.tier.2"
                | "depth.solver.tier.3"
                | "depth.solver.tier.4"
                | "depth.solver.tier.5";
              return (
                <Badge key={tier} variant={isCurrent ? "default" : active ? "secondary" : "outline"} className="font-mono">
                  {t(tierKey)}
                </Badge>
              );
            })}
          </div>

          {leases.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-xs font-medium">{t("depth.solver.leasesTitle", { count: leases.length })}</p>
              <div className="flex flex-wrap gap-2">
                {leases.map((l) => (
                  <Badge key={`${l.resource_key}-${l.holder}`} variant="outline" className="font-mono text-[11px]">
                    {l.resource_key} ({l.mode} · {l.holder})
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="space-y-1.5">
            <p className="text-xs font-medium">
              {t("depth.solver.prunedTitle", { count: solverState?.pruned_mechanisms?.length ?? 0 })}
            </p>
            {!solverState?.pruned_mechanisms?.length ? (
              <p className="text-xs text-muted-foreground">{t("depth.solver.prunedEmpty")}</p>
            ) : (
              <div className="space-y-1.5">
                {solverState.pruned_mechanisms.map((pm, idx) => (
                  <div key={`${pm.target}-${pm.mechanism}-${idx}`} className="rounded-md border px-3 py-1.5 text-xs">
                    <span className="font-mono font-semibold">{pm.mechanism}</span> @{" "}
                    <span className="font-mono text-muted-foreground">{pm.target}</span> (L{pm.tier}) — {pm.reason}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-2 border-t pt-3">
            <p className="text-xs font-medium">{t("depth.solver.blackboardTitle", { count: blackboard.length })}</p>
            <form onSubmit={handlePostBlackboard} className="grid gap-2 sm:grid-cols-4">
              <select
                aria-label={t("depth.solver.kindLabel")}
                className="h-9 rounded-md border bg-background px-2 text-xs"
                value={bbKind}
                onChange={(e) => setBbKind(e.target.value as BlackboardKind)}
              >
                <option value="hypothesis">{t("depth.solver.kind.hypothesis")}</option>
                <option value="anomaly">{t("depth.solver.kind.anomaly")}</option>
                <option value="precondition_need">{t("depth.solver.kind.precondition_need")}</option>
                <option value="deferred_endpoint">{t("depth.solver.kind.deferred_endpoint")}</option>
                <option value="env_constraint">{t("depth.solver.kind.env_constraint")}</option>
              </select>
              <Input
                value={bbTarget}
                onChange={(e) => setBbTarget(e.target.value)}
                placeholder={t("depth.solver.targetLabel")}
              />
              <Input
                value={bbTopic}
                onChange={(e) => setBbTopic(e.target.value)}
                placeholder={t("depth.solver.topicPlaceholder")}
                required
              />
              <div className="flex gap-2">
                <Input
                  value={bbPrecondition}
                  onChange={(e) => setBbPrecondition(e.target.value)}
                  placeholder={t("depth.solver.preconditionPlaceholder")}
                />
                <Button type="submit" size="sm" disabled={postingBB}>
                  {t("depth.solver.postBtn")}
                </Button>
              </div>
            </form>

            {blackboard.length === 0 ? (
              <p className="text-xs text-muted-foreground">{t("depth.solver.blackboardEmpty")}</p>
            ) : (
              <div className="space-y-1.5">
                {blackboard.map((e) => (
                  <div key={e.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs">
                    <div className="space-y-0.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {e.kind}
                        </Badge>
                        <Badge
                          variant={e.epistemic_state === "quarantined" ? "destructive" : "secondary"}
                          className="font-mono text-[10px]"
                        >
                          {e.epistemic_state}
                        </Badge>
                        {e.precondition_tag && (
                          <Badge variant="outline" className="font-mono text-[10px]">
                            need:{e.precondition_tag}
                          </Badge>
                        )}
                        <span className="font-medium">{e.topic}</span>
                      </div>
                      {e.target && <p className="font-mono text-[11px] text-muted-foreground">{e.target}</p>}
                    </div>
                    <span className="font-mono text-[11px] text-muted-foreground">{e.author}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Outbound / External Connections Audit */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base">{t("depth.outbound.title", { count: outboundLogs.length })}</CardTitle>
            <CardDescription>{t("depth.outbound.desc")}</CardDescription>
          </div>
          <Button size="sm" variant="outline" onClick={() => void loadAll()} disabled={loadingOutbound}>
            <RefreshCwIcon className="mr-1.5 size-3.5" />
            {t("common.refresh")}
          </Button>
        </CardHeader>
        <CardContent>
          {loadingOutbound ? (
            <p className="text-xs text-muted-foreground">{t("common.loading")}</p>
          ) : outboundLogs.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("depth.outbound.empty")}</p>
          ) : (
            <div className="space-y-2">
              {outboundLogs.map((o) => (
                <div key={o.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold">
                        {o.target_host}:{o.target_port}
                      </span>
                      <Badge variant="outline">{o.protocol}</Badge>
                      <Badge variant="secondary">{o.source}</Badge>
                      <Badge variant="secondary">×{o.hit_count}</Badge>
                    </div>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      {o.purpose}
                      {o.url_preview ? ` • ${o.url_preview}` : ""}
                    </p>
                  </div>
                  <span className="font-mono text-[11px] text-muted-foreground">{o.last_seen}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
