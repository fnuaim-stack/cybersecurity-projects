from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from .models import NormalizedFinding
from .scoring import normalize_severity


def _float(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int(value) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value).split("/")[0])
    except (TypeError, ValueError):
        return None


def _bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "known", "available"}


def _first(mapping: dict, *names, default=""):
    lower = {str(key).lower(): value for key, value in mapping.items()}
    for name in names:
        value = lower.get(name.lower())
        if value not in (None, ""):
            return value
    return default


def _target_parts(value: str) -> tuple[str, str, str, int | None]:
    text = (value or "").strip()
    if not text:
        return "unknown", "", "", None

    if "://" in text:
        parsed = urlparse(text)
        hostname = parsed.hostname or text
        port = parsed.port
        return hostname, "", hostname, port

    cleaned = text.split("/")[0].strip()
    if ":" in cleaned and cleaned.count(":") == 1:
        host, maybe_port = cleaned.rsplit(":", 1)
        if maybe_port.isdigit():
            return host, "", host, int(maybe_port)

    return cleaned, "", cleaned, None


def detect_format(path: str | Path) -> str:
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".nessus":
        return "nessus"
    if suffix == ".xml":
        return "nmap"
    if suffix == ".sarif":
        return "sarif"

    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            header = [cell.strip().lower() for cell in next(reader, [])]
        if any(value in header for value in ("nvt name", "nvt oid", "cvss")) and any(
            value in header for value in ("ip", "hostname")
        ):
            return "openvas-csv"
        return "generic"

    if suffix in {".jsonl", ".ndjson"}:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    break
                if isinstance(item, dict) and ("template-id" in item or "templateID" in item):
                    return "nuclei"
                break
        return "generic"

    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            if "Results" in data:
                return "trivy"
            if "runs" in data and str(data.get("version", "")).startswith("2."):
                return "sarif"
            if "template-id" in data or "templateID" in data:
                return "nuclei"
            if isinstance(data.get("site"), list):
                return "zap"
            results = data.get("results")
            if isinstance(results, list) and results and isinstance(results[0], dict) and "check_id" in results[0]:
                return "semgrep"
        return "generic"

    return "generic"


def load_findings(path: str | Path, fmt: str = "auto") -> tuple[str, list[NormalizedFinding]]:
    path = Path(path)
    selected = detect_format(path) if fmt == "auto" else fmt

    loaders = {
        "nuclei": load_nuclei,
        "trivy": load_trivy,
        "nmap": load_nmap,
        "nessus": load_nessus,
        "openvas-csv": load_openvas_csv,
        "sarif": load_sarif,
        "zap": load_zap,
        "semgrep": load_semgrep,
        "generic": load_generic,
    }
    if selected not in loaders:
        raise ValueError(f"unsupported format: {selected}")

    return selected, loaders[selected](path)


def load_nuclei(path: Path) -> list[NormalizedFinding]:
    items = []
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        raw_items = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        raw_items = parsed if isinstance(parsed, list) else [parsed]

    for item in raw_items:
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        target = item.get("host") or item.get("matched-at") or item.get("ip") or "unknown"
        asset, _, hostname, parsed_port = _target_parts(str(target))
        address = str(item.get("ip") or "")
        port = _int(item.get("port")) or parsed_port

        external_id = str(item.get("template-id") or item.get("templateID") or "")
        cves = classification.get("cve-id") or classification.get("cve_id") or []
        if isinstance(cves, str):
            cves = [cves]

        metadata = {
            "matcher_name": item.get("matcher-name"),
            "type": item.get("type"),
            "matched_at": item.get("matched-at"),
            "cves": cves,
            "cwe": classification.get("cwe-id") or classification.get("cwe_id"),
            "template_url": item.get("template-url"),
        }

        items.append(
            NormalizedFinding(
                asset=asset,
                title=str(info.get("name") or external_id or "Nuclei finding"),
                severity=normalize_severity(str(info.get("severity") or "info")),
                external_id=external_id,
                description=str(info.get("description") or ""),
                remediation=str(info.get("remediation") or ""),
                address=address,
                hostname=hostname,
                port=port,
                protocol=str(item.get("type") or ""),
                service="",
                cvss=_float(classification.get("cvss-score") or classification.get("cvss_score")),
                exploit_available=_bool(classification.get("exploit-available")),
                known_exploited=_bool(classification.get("known-exploited")),
                metadata=metadata,
            )
        )
    return items


def load_trivy(path: Path) -> list[NormalizedFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    results = data.get("Results", []) if isinstance(data, dict) else []
    items: list[NormalizedFinding] = []

    for result in results:
        target = str(result.get("Target") or "unknown")
        vulnerabilities = result.get("Vulnerabilities") or []
        for vuln in vulnerabilities:
            cvss = None
            cvss_map = vuln.get("CVSS") or {}
            if isinstance(cvss_map, dict):
                values = []
                for provider in cvss_map.values():
                    if isinstance(provider, dict):
                        score = _float(provider.get("V3Score") or provider.get("V2Score"))
                        if score is not None:
                            values.append(score)
                if values:
                    cvss = max(values)

            vuln_id = str(vuln.get("VulnerabilityID") or "")
            pkg = str(vuln.get("PkgName") or "")
            fixed = str(vuln.get("FixedVersion") or "")
            remediation = f"Upgrade {pkg} to {fixed}." if pkg and fixed else ""

            items.append(
                NormalizedFinding(
                    asset=target,
                    title=str(vuln.get("Title") or vuln_id or "Trivy finding"),
                    severity=normalize_severity(str(vuln.get("Severity") or "info")),
                    external_id=vuln_id,
                    description=str(vuln.get("Description") or ""),
                    remediation=remediation,
                    cvss=cvss,
                    metadata={
                        "package": pkg,
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": fixed,
                        "primary_url": vuln.get("PrimaryURL"),
                        "target_class": result.get("Class"),
                        "target_type": result.get("Type"),
                    },
                )
            )
    return items


def load_nmap(path: Path) -> list[NormalizedFinding]:
    root = ET.parse(path).getroot()
    items: list[NormalizedFinding] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue

        addresses = [node.attrib for node in host.findall("address")]
        ipv4 = next((item.get("addr", "") for item in addresses if item.get("addrtype") == "ipv4"), "")
        ipv6 = next((item.get("addr", "") for item in addresses if item.get("addrtype") == "ipv6"), "")
        address = ipv4 or ipv6 or next((item.get("addr", "") for item in addresses), "")

        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            first_hostname = hostnames.find("hostname")
            if first_hostname is not None:
                hostname = first_hostname.attrib.get("name", "")

        asset = hostname or address or "unknown"

        ports_node = host.find("ports")
        if ports_node is None:
            continue

        for port_node in ports_node.findall("port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            port = _int(port_node.attrib.get("portid"))
            protocol = port_node.attrib.get("protocol", "")
            service_node = port_node.find("service")
            service = service_node.attrib.get("name", "") if service_node is not None else ""
            product = service_node.attrib.get("product", "") if service_node is not None else ""
            version = service_node.attrib.get("version", "") if service_node is not None else ""
            service_text = " ".join(value for value in (product, version) if value).strip()

            items.append(
                NormalizedFinding(
                    asset=asset,
                    title=f"Open service: {port}/{protocol} {service}".strip(),
                    severity="info",
                    external_id=f"nmap:{port}/{protocol}",
                    description="An open network service was observed during the Nmap scan.",
                    remediation="Confirm the service is required, patched, and restricted to the networks that need it.",
                    address=address,
                    hostname=hostname,
                    port=port,
                    protocol=protocol,
                    service=service,
                    metadata={"product": product, "version": version, "service_detail": service_text},
                )
            )
    return items


def load_openvas_csv(path: Path) -> list[NormalizedFinding]:
    items: list[NormalizedFinding] = []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            ip = str(_first(row, "IP", "Host", "host ip"))
            hostname = str(_first(row, "Hostname", "DNS", "Host Name"))
            asset = hostname or ip or "unknown"
            title = str(_first(row, "NVT Name", "Name", "Vulnerability", "Title", default="OpenVAS finding"))
            external_id = str(_first(row, "NVT OID", "OID", "CVE", "CVEs"))
            severity = str(_first(row, "Severity", "Threat", default="info"))
            cvss = _float(_first(row, "CVSS", "CVSS Base", "CVSS Score"))
            port_text = str(_first(row, "Port", "Port/Protocol"))
            port = _int(port_text)
            protocol = port_text.split("/")[-1] if "/" in port_text else ""

            items.append(
                NormalizedFinding(
                    asset=asset,
                    title=title,
                    severity=normalize_severity(severity),
                    external_id=external_id,
                    description=str(_first(row, "Summary", "Description", "Specific Result")),
                    remediation=str(_first(row, "Solution", "Remediation")),
                    address=ip,
                    hostname=hostname,
                    port=port,
                    protocol=protocol,
                    cvss=cvss,
                    metadata={
                        "qod": _first(row, "QoD", "Quality of Detection"),
                        "cves": _first(row, "CVEs", "CVE"),
                    },
                )
            )
    return items


def load_sarif(path: Path) -> list[NormalizedFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items: list[NormalizedFinding] = []

    for run in data.get("runs", []):
        rules = {}
        driver = ((run.get("tool") or {}).get("driver") or {})
        for rule in driver.get("rules", []) or []:
            rule_id = str(rule.get("id") or "")
            if rule_id:
                rules[rule_id] = rule

        for result in run.get("results", []) or []:
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id, {})
            message = (result.get("message") or {}).get("text") or ""
            locations = result.get("locations") or []
            uri = "repository"
            if locations:
                physical = (locations[0].get("physicalLocation") or {})
                uri = ((physical.get("artifactLocation") or {}).get("uri") or "repository")

            level = str(result.get("level") or "warning").lower()
            severity = {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "medium")
            help_text = ((rule.get("help") or {}).get("text") or (rule.get("fullDescription") or {}).get("text") or "")

            items.append(
                NormalizedFinding(
                    asset=str(uri),
                    title=str((rule.get("shortDescription") or {}).get("text") or rule_id or "SARIF finding"),
                    severity=severity,
                    external_id=rule_id,
                    description=str(message),
                    remediation=str(help_text),
                    metadata={
                        "tool": driver.get("name"),
                        "rule_index": result.get("ruleIndex"),
                    },
                )
            )
    return items


def load_nessus(path: Path) -> list[NormalizedFinding]:
    root = ET.parse(path).getroot()
    items: list[NormalizedFinding] = []
    severity_map = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}

    for host in root.findall(".//ReportHost"):
        props = {}
        properties = host.find("HostProperties")
        if properties is not None:
            for tag in properties.findall("tag"):
                name = tag.attrib.get("name", "")
                if name:
                    props[name] = tag.text or ""

        hostname = props.get("host-fqdn") or props.get("hostname") or host.attrib.get("name", "")
        address = props.get("host-ip") or host.attrib.get("name", "")
        asset = hostname or address or "unknown"

        for node in host.findall("ReportItem"):
            plugin_id = str(node.attrib.get("pluginID") or "")
            severity = severity_map.get(str(node.attrib.get("severity") or "0"), "info")
            port = _int(node.attrib.get("port"))
            protocol = str(node.attrib.get("protocol") or "")
            service = str(node.attrib.get("svc_name") or "")
            cves = [part.strip().upper() for part in str(node.findtext("cve") or "").split(",") if part.strip()]

            items.append(
                NormalizedFinding(
                    asset=asset,
                    title=str(node.attrib.get("pluginName") or f"Nessus plugin {plugin_id}"),
                    severity=severity,
                    external_id=plugin_id,
                    description=str(node.findtext("synopsis") or node.findtext("description") or ""),
                    remediation=str(node.findtext("solution") or ""),
                    address=address,
                    hostname=hostname,
                    port=port,
                    protocol=protocol,
                    service=service,
                    cvss=_float(node.findtext("cvss3_base_score") or node.findtext("cvss_base_score")),
                    exploit_available=_bool(node.findtext("exploit_available")),
                    metadata={
                        "plugin_family": node.attrib.get("pluginFamily"),
                        "cves": cves,
                        "risk_factor": node.findtext("risk_factor"),
                        "plugin_output": node.findtext("plugin_output"),
                    },
                )
            )
    return items


def load_zap(path: Path) -> list[NormalizedFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    sites = data.get("site") or []
    items: list[NormalizedFinding] = []
    severity_map = {"0": "info", "1": "low", "2": "medium", "3": "high"}

    for site in sites:
        site_name = str(site.get("@name") or site.get("name") or "unknown")
        parsed = urlparse(site_name) if "://" in site_name else None
        hostname = parsed.hostname if parsed else site_name
        port = parsed.port if parsed else None

        for alert in site.get("alerts") or []:
            riskcode = str(alert.get("riskcode") or alert.get("risk") or "0").split()[0]
            instances = alert.get("instances") or []
            first_uri = ""
            if instances and isinstance(instances[0], dict):
                first_uri = str(instances[0].get("uri") or "")
            target = first_uri or site_name
            asset, _, instance_host, instance_port = _target_parts(target)

            items.append(
                NormalizedFinding(
                    asset=asset,
                    title=str(alert.get("alert") or alert.get("name") or "ZAP alert"),
                    severity=severity_map.get(riskcode, "medium"),
                    external_id=str(alert.get("pluginid") or alert.get("alertRef") or ""),
                    description=str(alert.get("desc") or alert.get("description") or ""),
                    remediation=str(alert.get("solution") or ""),
                    hostname=instance_host or hostname or "",
                    port=instance_port or port,
                    protocol="http",
                    service="web",
                    metadata={
                        "confidence": alert.get("confidence"),
                        "cweid": alert.get("cweid"),
                        "wascid": alert.get("wascid"),
                        "reference": alert.get("reference"),
                        "instances": instances[:20],
                    },
                )
            )
    return items


def load_semgrep(path: Path) -> list[NormalizedFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items: list[NormalizedFinding] = []
    severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

    for result in data.get("results") or []:
        extra = result.get("extra") or {}
        check_id = str(result.get("check_id") or "")
        path_value = str(result.get("path") or "repository")
        message = str(extra.get("message") or "")
        severity = severity_map.get(str(extra.get("severity") or "WARNING").upper(), "medium")
        start = result.get("start") or {}
        end = result.get("end") or {}

        items.append(
            NormalizedFinding(
                asset=path_value,
                title=check_id or message or "Semgrep finding",
                severity=severity,
                external_id=check_id,
                description=message,
                remediation=str(extra.get("fix") or ""),
                metadata={
                    "path": path_value,
                    "start_line": start.get("line"),
                    "end_line": end.get("line"),
                    "metadata": extra.get("metadata") or {},
                    "metavars": extra.get("metavars") or {},
                },
            )
        )
    return items


def load_generic(path: Path) -> list[NormalizedFinding]:
    suffix = path.suffix.lower()

    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            raw_items = list(csv.DictReader(handle))
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
        stripped = text.strip()
        if not stripped:
            raw_items = []
        elif suffix in {".jsonl", ".ndjson"}:
            raw_items = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            data = json.loads(text)
            if isinstance(data, list):
                raw_items = data
            elif isinstance(data, dict) and isinstance(data.get("findings"), list):
                raw_items = data["findings"]
            elif isinstance(data, dict):
                raw_items = [data]
            else:
                raise ValueError("generic input must contain objects")

    items: list[NormalizedFinding] = []
    for row in raw_items:
        if not isinstance(row, dict):
            continue

        asset = str(_first(row, "asset", "host", "hostname", "ip", "target", default="unknown"))
        hostname = str(_first(row, "hostname", "host name"))
        address = str(_first(row, "ip", "address"))
        title = str(_first(row, "title", "name", "finding", "vulnerability", default="Imported finding"))

        items.append(
            NormalizedFinding(
                asset=asset,
                title=title,
                severity=normalize_severity(str(_first(row, "severity", "risk", default="info"))),
                external_id=str(_first(row, "external_id", "id", "cve", "cve_id", "plugin_id")),
                description=str(_first(row, "description", "summary", "details")),
                remediation=str(_first(row, "remediation", "solution", "fix")),
                address=address,
                hostname=hostname,
                port=_int(_first(row, "port")),
                protocol=str(_first(row, "protocol")),
                service=str(_first(row, "service")),
                cvss=_float(_first(row, "cvss", "cvss_score", "score")),
                exploit_available=_bool(_first(row, "exploit_available", "exploit")),
                known_exploited=_bool(_first(row, "known_exploited", "kev")),
                metadata={"raw": row},
            )
        )
    return items
