"use client";

import * as React from "react";

import { KeyRoundIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { useI18n } from "@/lib/i18n/provider";
import type { WordlistKind, WordlistMeta } from "@/lib/types";

export function WordlistsVaultCard() {
  const { t } = useI18n();
  const [items, setItems] = React.useState<WordlistMeta[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState<WordlistKind>("password");
  const [description, setDescription] = React.useState("");
  const [content, setContent] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.wordlists();
      setItems(list);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to load encrypted wordlists");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const handleSave = async () => {
    const trimmedName = name.trim();
    if (!trimmedName) {
      toast.error(t("wordlists.errName"));
      return;
    }
    if (!content.trim()) {
      toast.error(t("wordlists.errContent"));
      return;
    }
    setSaving(true);
    try {
      await api.createWordlist({
        name: trimmedName,
        kind,
        description: description.trim(),
        content,
      });
      toast.success(t("wordlists.savedToast", { name: trimmedName }));
      setName("");
      setDescription("");
      setContent("");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to save encrypted wordlist");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (w: WordlistMeta) => {
    try {
      await api.deleteWordlist(w.id);
      toast.success(t("wordlists.deletedToast", { name: w.name }));
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to delete wordlist");
    }
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRoundIcon className="size-4" />
          {t("wordlists.title")}
        </CardTitle>
        <CardDescription>{t("wordlists.desc")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor="wl-name" className="text-xs">
              {t("wordlists.nameLabel")}
            </Label>
            <Input
              id="wl-name"
              placeholder="corp-seasonal-passwords"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="wl-kind" className="text-xs">
              {t("wordlists.kindLabel")}
            </Label>
            <Select value={kind} onValueChange={(v) => setKind(v as WordlistKind)}>
              <SelectTrigger id="wl-kind">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="password">password</SelectItem>
                <SelectItem value="username">username</SelectItem>
                <SelectItem value="userpass">userpass (user:pass)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="space-y-1">
          <Label htmlFor="wl-desc" className="text-xs">
            {t("wordlists.descLabel")}
          </Label>
          <Input
            id="wl-desc"
            placeholder="Curated internal spray dictionary"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        <div className="space-y-1">
          <Label htmlFor="wl-content" className="text-xs">
            {t("wordlists.entriesLabel")}
          </Label>
          <Textarea
            id="wl-content"
            rows={4}
            className="font-mono text-xs"
            placeholder={"Spring2026!\nWelcome@123"}
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />
        </div>

        <Button size="sm" onClick={handleSave} disabled={saving}>
          <PlusIcon className="mr-1.5 size-3.5" />
          {saving ? t("wordlists.savingBtn") : t("wordlists.saveBtn")}
        </Button>

        <div className="space-y-2 border-t pt-3">
          <div className="text-xs font-medium text-muted-foreground">
            {t("wordlists.storedCount", { count: loading ? "..." : items.length })}
          </div>
          {items.length === 0 && !loading ? (
            <p className="text-xs text-muted-foreground">{t("wordlists.empty")}</p>
          ) : (
            <div className="space-y-2">
              {items.map((w) => (
                <div key={w.id} className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs">
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-mono font-medium">{w.name}</span>
                      <Badge variant="outline" className="text-[10px]">
                        {w.kind}
                      </Badge>
                      <span className="text-muted-foreground">
                        {t("wordlists.entriesCount", { count: w.entry_count })}
                      </span>
                    </div>
                    {w.description && <p className="truncate text-muted-foreground">{w.description}</p>}
                    <p className="truncate font-mono text-[10px] text-muted-foreground">sha256:{w.sha256.slice(0, 16)}…</p>
                  </div>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="size-7 shrink-0 text-destructive hover:text-destructive"
                    onClick={() => void handleDelete(w)}
                    aria-label={`Delete ${w.name}`}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
