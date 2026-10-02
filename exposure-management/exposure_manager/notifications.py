from __future__ import annotations

import os

from .integrations import send_slack, send_webhook


class NotificationService:
    def __init__(self, manager, platform) -> None:
        self.manager = manager
        self.platform = platform

    def configured(self) -> dict:
        return {
            "enabled": bool(self.platform.get_setting("notifications_enabled", False)),
            "min_risk": int(self.platform.get_setting("notification_min_risk", 70)),
            "slack": bool(os.environ.get("EXPOSURE_SLACK_WEBHOOK")),
            "webhook": bool(os.environ.get("EXPOSURE_WEBHOOK_URL")),
        }

    def notify_scan(self, summary: dict) -> dict:
        config = self.configured()
        if not config["enabled"]:
            return {"sent": 0, "skipped": "notifications disabled"}

        scan_id = summary.get("scan_id")
        findings = [
            item
            for item in self.manager.db.list_findings(min_risk=config["min_risk"], limit=5000)
            if item.get("last_scan_id") == scan_id and item.get("status") in {"open", "in_progress"}
        ]
        if not findings:
            return {"sent": 0, "skipped": "no matching active findings"}

        title = (
            f"Exposure scan: {summary.get('source', 'scanner')} / "
            f"{summary.get('scope', 'default')}"
        )
        sent = 0
        errors: list[str] = []

        slack_url = os.environ.get("EXPOSURE_SLACK_WEBHOOK")
        if slack_url:
            try:
                send_slack(slack_url, title=title, findings=findings)
                sent += 1
            except Exception as error:
                errors.append(f"Slack: {error}")

        webhook_url = os.environ.get("EXPOSURE_WEBHOOK_URL")
        if webhook_url:
            try:
                send_webhook(
                    webhook_url,
                    {
                        "event": "scan_completed",
                        "summary": summary,
                        "findings": findings[:100],
                    },
                    bearer_token=os.environ.get("EXPOSURE_WEBHOOK_TOKEN"),
                )
                sent += 1
            except Exception as error:
                errors.append(f"Webhook: {error}")

        return {
            "sent": sent,
            "finding_count": len(findings),
            "errors": errors,
            "skipped": "no webhook configured" if not sent and not errors else "",
        }
