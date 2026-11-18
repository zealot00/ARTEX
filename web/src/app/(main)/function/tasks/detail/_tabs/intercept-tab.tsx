"use client";

import { ApprovalRecords } from "@/components/approval-records";
import { useI18n } from "@/lib/i18n/provider";

export function InterceptTab({ taskId }: { taskId: string }) {
  const { t } = useI18n();
  return (
    <div aria-label={t("tasks.detail.tab.intercept")}>
      <ApprovalRecords key={taskId} taskId={taskId} />
    </div>
  );
}
