"use client";

import { ApprovalRecords } from "@/components/approval-records";
import { useI18n } from "@/lib/i18n/provider";

export default function ApprovalsPage() {
  const { t } = useI18n();
  return (
    <div className="flex min-w-0 flex-1 flex-col p-4 sm:p-6" aria-label={t("approvals.title")}>
      <ApprovalRecords />
    </div>
  );
}
