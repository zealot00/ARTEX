export type Locale = "zh-CN" | "en";

export const DEFAULT_LOCALE: Locale = "zh-CN";
export const LOCALE_STORAGE_KEY = "artex.locale";

export function normalizeLocale(raw?: string | null): Locale {
  if (!raw) return DEFAULT_LOCALE;
  const s = raw.trim().toLowerCase();
  if (s.startsWith("en")) return "en";
  if (s.startsWith("zh")) return "zh-CN";
  return DEFAULT_LOCALE;
}

export function translateFrom(
  messages: Record<Locale, Record<string, string>>,
  locale: Locale,
  key: string,
  vars?: Record<string, string | number>,
): string {
  const dict = messages[locale] ?? messages[DEFAULT_LOCALE];
  let text = dict[key] ?? messages.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      text = text.replaceAll(`{${k}}`, String(v));
    }
  }
  return text;
}

export function formatLocaleDate(locale: Locale, input: string | number | Date): string {
  const d = input instanceof Date ? input : new Date(input);
  if (Number.isNaN(d.getTime())) return String(input);
  return d.toLocaleString(locale === "zh-CN" ? "zh-CN" : "en-US");
}
