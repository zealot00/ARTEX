import { redirect } from "next/navigation";

import { DEFAULT_LOCALE, translateFrom } from "@/lib/i18n/core";
import { MESSAGES } from "@/lib/i18n/messages";

export default function Home() {
  redirect("/function/tasks");
  return <>{translateFrom(MESSAGES, DEFAULT_LOCALE, "common.comingSoon")}</>;
}
