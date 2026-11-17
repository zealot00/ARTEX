"use client";

import * as React from "react";

import { DEFAULT_LOCALE, LOCALE_STORAGE_KEY, type Locale, normalizeLocale, translateFrom } from "./core";
import { MESSAGES, type TranslationKey } from "./messages";

interface I18nContextValue {
  locale: Locale;
  setLocale: (next: Locale) => void;
  t: (key: TranslationKey, vars?: Record<string, string | number>) => string;
}

const I18nContext = React.createContext<I18nContextValue>({
  locale: DEFAULT_LOCALE,
  setLocale: () => {},
  t: (key, vars) => translateFrom(MESSAGES, DEFAULT_LOCALE, key, vars),
});

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = React.useState<Locale>(DEFAULT_LOCALE);

  React.useEffect(() => {
    try {
      const saved = window.localStorage.getItem(LOCALE_STORAGE_KEY);
      const resolved = saved ? normalizeLocale(saved) : normalizeLocale(window.navigator.language);
      setLocaleState(resolved);
      document.documentElement.lang = resolved;
    } catch {
      document.documentElement.lang = DEFAULT_LOCALE;
    }
  }, []);

  const setLocale = React.useCallback((next: Locale) => {
    setLocaleState(next);
    try {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, next);
      document.documentElement.lang = next;
    } catch {
      // ignore storage errors in restricted environments
    }
  }, []);

  const t = React.useCallback(
    (key: TranslationKey, vars?: Record<string, string | number>) => translateFrom(MESSAGES, locale, key, vars),
    [locale],
  );

  const value = React.useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  return React.useContext(I18nContext);
}
