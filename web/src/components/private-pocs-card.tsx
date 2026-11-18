"use client";

import * as React from "react";

import { BugIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { useI18n } from "@/lib/i18n/provider";
import type { PocKind, PocRecord, PocSeverity } from "@/lib/types";

export function PrivatePocsCard() {
  const { t } = useI18n();
  const [items, setItems] = React.useState<PocRecord[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [query, setQuery] = React.useState("");

  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState<PocKind>("nuclei_yaml");
  const [severity, setSeverity] = React.useState<PocSeverity>("high");
  const [cve, setCve] = React.useState("");
  const [tags, setTags] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [guidance, setGuidance] = React.useState("");
  const [content, setContent] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.pocs(query.trim() || undefined);
      setItems(list);
    } catch {
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [query]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !content.trim()) return;
    setSaving(true);
    try {
      await api.upsertPoc({
        name: name.trim(),
        kind,
        severity,
        cve: cve.trim(),
        tags: tags.trim(),
        description: description.trim(),
        exploit_guidance: guidance.trim(),
        content,
      });
      toast.success(t("pocs.savedToast", { name: name.trim() }));
      setName("");
      setCve("");
      setTags("");
      setDescription("");
      setGuidance("");
      setContent("");
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save PoC");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await api.deletePoc(id);
      toast.success(t("pocs.deletedToast", { id }));
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete PoC");
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <BugIcon className="size-4 text-primary" />
            {t("pocs.title")}
          </CardTitle>
          <CardDescription>{t("pocs.desc")}</CardDescription>
        </div>
        <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
          <RefreshCwIcon className="mr-1.5 size-3.5" />
          {t("common.refresh")}
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={handleSave} className="space-y-3 rounded-md border p-3">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1">
              <Label className="text-xs">{t("pocs.nameLabel")}</Label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t("pocs.namePlaceholder")}
                required
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t("pocs.kindLabel")}</Label>
              <select
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
                value={kind}
                onChange={(e) => setKind(e.target.value as PocKind)}
              >
                <option value="nuclei_yaml">{t("pocs.kindNuclei")}</option>
                <option value="python_script">{t("pocs.kindPython")}</option>
              </select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t("pocs.severityLabel")}</Label>
              <select
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as PocSeverity)}
              >
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
                <option value="info">info</option>
              </select>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">{t("pocs.cveLabel")}</Label>
              <Input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2025-XXXX" />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t("pocs.tagsLabel")}</Label>
              <Input
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder={t("pocs.tagsPlaceholder")}
              />
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">{t("pocs.descLabel")}</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t("pocs.guidanceLabel")}</Label>
              <Input value={guidance} onChange={(e) => setGuidance(e.target.value)} />
            </div>
          </div>

          <div className="space-y-1">
            <Label className="text-xs">{t("pocs.contentLabel")}</Label>
            <Textarea
              rows={5}
              className="font-mono text-xs"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              required
            />
          </div>

          <Button type="submit" size="sm" disabled={saving}>
            <PlusIcon className="mr-1.5 size-3.5" />
            {saving ? t("pocs.savingBtn") : t("pocs.saveBtn")}
          </Button>
        </form>

        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("pocs.searchPlaceholder")}
          className="max-w-sm"
        />

        {loading ? (
          <p className="text-xs text-muted-foreground">{t("common.loading")}</p>
        ) : items.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t("pocs.empty")}</p>
        ) : (
          <div className="space-y-2">
            {items.map((p) => (
              <div
                key={p.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs"
              >
                <div className="space-y-0.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono font-semibold">{p.name}</span>
                    <Badge variant="outline">{p.kind}</Badge>
                    <Badge variant={p.severity === "critical" || p.severity === "high" ? "destructive" : "secondary"}>
                      {p.severity}
                    </Badge>
                    {p.cve && <Badge variant="secondary">{p.cve}</Badge>}
                    {p.tags && <span className="text-muted-foreground">[{p.tags}]</span>}
                  </div>
                  {p.description && <p className="text-muted-foreground">{p.description}</p>}
                </div>
                <Button size="icon" variant="ghost" onClick={() => void handleDelete(p.id)}>
                  <Trash2Icon className="size-3.5 text-destructive" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
