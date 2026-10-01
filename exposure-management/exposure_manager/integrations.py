from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request


def finding_ticket_payload(finding: dict) -> dict:
    description = (
        f"Asset: {finding.get('asset_key', '')}\n"
        f"Risk: {finding.get('risk_score', 0)} ({finding.get('risk_band', '')})\n"
        f"Severity: {finding.get('severity', '')}\n"
        f"Source: {finding.get('source', '')}\n"
        f"External ID: {finding.get('external_id') or '-'}\n\n"
        f"{finding.get('description') or 'No description provided.'}\n\n"
        f"Remediation:\n{finding.get('remediation') or 'Review and remediate the finding.'}"
    )
    return {
        "summary": f"[{finding.get('risk_band', 'risk').upper()}] {finding.get('title', 'Security finding')}",
        "description": description,
        "labels": ["exposure-management", str(finding.get("source") or "security")],
    }


def _post_json(url: str, payload: dict, headers: dict[str, str] | None = None, timeout: int = 15) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request_headers = {"Content-Type": "application/json", "User-Agent": "ExposureManagement/0.2"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, data=body, headers=request_headers, method="POST")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read().decode("utf-8", errors="replace")
            if not data.strip():
                return {"status": response.status}
            try:
                parsed = json.loads(data)
            except json.JSONDecodeError:
                return {"status": response.status, "body": data}
            if isinstance(parsed, dict):
                parsed.setdefault("status", response.status)
                return parsed
            return {"status": response.status, "body": parsed}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {error.code}: {detail[:500]}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"request failed: {error.reason}") from error


def send_slack(webhook_url: str, *, title: str, findings: list[dict]) -> dict:
    lines = [f"*{title}*"]
    for item in findings[:10]:
        lines.append(
            f"• Risk {item.get('risk_score', 0)} — {item.get('asset_key', 'unknown')} — {item.get('title', '')}"
        )
    if len(findings) > 10:
        lines.append(f"…and {len(findings) - 10} more")
    return _post_json(webhook_url, {"text": "\n".join(lines)})


def send_webhook(url: str, payload: dict, *, bearer_token: str | None = None) -> dict:
    headers = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return _post_json(url, payload, headers=headers)


def create_jira_issue(
    *,
    base_url: str,
    project_key: str,
    email: str,
    api_token: str,
    finding: dict,
    issue_type: str = "Task",
) -> dict:
    ticket = finding_ticket_payload(finding)
    auth = base64.b64encode(f"{email}:{api_token}".encode("utf-8")).decode("ascii")
    url = base_url.rstrip("/") + "/rest/api/3/issue"
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": ticket["summary"],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": ticket["description"]}],
                    }
                ],
            },
            "issuetype": {"name": issue_type},
            "labels": ticket["labels"],
        }
    }
    return _post_json(
        url,
        payload,
        headers={
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        },
    )
