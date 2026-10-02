from __future__ import annotations

import hmac
import json
import os
import tempfile
import threading
import webbrowser
from pathlib import Path

from flask import Flask, Response, flash, redirect, render_template, request, url_for

from exposure_manager.active_scans import ScannerService
from exposure_manager.analytics import build_analytics
from exposure_manager.campaigns import CampaignManager
from exposure_manager.intel import enrich_findings, enrich_findings_online
from exposure_manager.scheduler import ScanScheduler
from exposure_manager.models import VALID_STATUSES
from exposure_manager.reporting import to_csv, to_json, to_markdown
from exposure_manager.service import ExposureManager


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = Path.home() / ".exposure-management" / "exposure.db"
FORMATS = [
    "auto",
    "nuclei",
    "trivy",
    "nmap",
    "nessus",
    "openvas-csv",
    "sarif",
    "zap",
    "semgrep",
    "generic",
]


def create_app(
    database_path: str | Path | None = None,
    *,
    start_scheduler: bool | None = None,
) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.secret_key = os.environ.get("EXPOSURE_SECRET_KEY", "local-exposure-management-ui")

    db_path = Path(
        database_path
        or os.environ.get("EXPOSURE_DB")
        or DEFAULT_DB
    )
    manager = ExposureManager(db_path)
    campaigns = CampaignManager(manager.db)
    scanner = ScannerService(manager)
    platform = manager.platform
    scheduler = ScanScheduler(scanner, platform)
    should_start_scheduler = bool(start_scheduler) and os.environ.get("EXPOSURE_DISABLE_SCHEDULER") != "1"
    if should_start_scheduler:
        scheduler.start()

    app.config["MANAGER"] = manager
    app.config["CAMPAIGNS"] = campaigns
    app.config["SCANNER"] = scanner
    app.config["PLATFORM"] = platform
    app.config["SCHEDULER"] = scheduler
    app.config["DATABASE_PATH"] = str(db_path)

    @app.context_processor
    def shared_template_data():
        return {
            "valid_statuses": sorted(VALID_STATUSES),
            "formats": FORMATS,
            "database_path": app.config["DATABASE_PATH"],
        }

    @app.get("/")
    def dashboard():
        summary = manager.summary()
        analytics = build_analytics(manager.db)
        queue = manager.remediation_queue(8)
        scans = manager.db.list_scans(8)
        scan_jobs = [scanner.store.get(item["id"]) for item in scanner.store.list(8)]
        return render_template(
            "dashboard.html",
            page="dashboard",
            summary=summary,
            analytics=analytics,
            queue=queue,
            scans=scans,
            scan_jobs=scan_jobs,
        )

    @app.route("/scan", methods=["GET", "POST"])
    def scan_page():
        if request.method == "POST":
            if request.form.get("authorized") != "on":
                flash("Confirm that you are authorized to scan the target.", "error")
                return redirect(url_for("scan_page"))

            port_mode = request.form.get("port_mode", "quick")
            ports = request.form.get("custom_ports", "").strip() if port_mode == "custom" else port_mode
            try:
                job = scanner.start(
                    provider=request.form.get("provider", ""),
                    target=request.form.get("target", ""),
                    scope=request.form.get("scope", "default"),
                    ports=ports,
                    partial=request.form.get("partial") == "on",
                )
                return redirect(url_for("scan_job", job_id=job["id"]))
            except Exception as error:
                flash(f"Could not start scan: {error}", "error")
                return redirect(url_for("scan_page"))

        return render_template(
            "scan.html",
            page="scan",
            providers=scanner.providers(),
            jobs=scanner.store.list(30),
        )

    @app.get("/scan/jobs/<job_id>")
    def scan_job(job_id: str):
        try:
            job = scanner.store.get(job_id)
        except KeyError:
            flash("Scan job not found.", "error")
            return redirect(url_for("scan_page"))
        return render_template(
            "scan_job.html",
            page="scan",
            job=job,
        )

    @app.get("/api/scan/jobs/<job_id>")
    def scan_job_api(job_id: str):
        try:
            job = scanner.store.get(job_id)
        except KeyError:
            return {"error": "not found"}, 404
        return {
            "id": job["id"],
            "provider": job["provider"],
            "target": job["target"],
            "status": job["status"],
            "progress": job["progress"],
            "result_count": job["result_count"],
            "log_text": job["log_text"],
            "error": job["error"],
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "import_summary": job["import_summary"],
        }

    @app.post("/scan/jobs/<job_id>/cancel")
    def scan_cancel(job_id: str):
        try:
            scanner.cancel(job_id)
            flash("Cancellation requested.", "success")
        except Exception as error:
            flash(f"Could not cancel scan: {error}", "error")
        return redirect(url_for("scan_job", job_id=job_id))

    @app.route("/import", methods=["GET", "POST"])
    def import_scan():
        if request.method == "GET":
            return render_template("import.html", page="import")

        upload = request.files.get("scan_file")
        if not upload or not upload.filename:
            flash("Choose a scanner result file first.", "error")
            return redirect(url_for("import_scan"))

        suffix = Path(upload.filename).suffix
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
                temp_path = Path(handle.name)
                upload.save(handle)

            result = manager.import_scan(
                temp_path,
                fmt=request.form.get("format", "auto"),
                source=request.form.get("source") or None,
                scope=request.form.get("scope", "default").strip() or "default",
                verification_misses=max(1, int(request.form.get("verify_misses", "2"))),
                verify_missing=request.form.get("partial") != "on",
            )
            flash(
                f"Imported {result['imported']} findings. "
                f"{result['created']} new, {result['updated']} updated.",
                "success",
            )
            return redirect(url_for("findings"))
        except Exception as error:
            flash(f"Import failed: {error}", "error")
            return redirect(url_for("import_scan"))
        finally:
            if temp_path:
                temp_path.unlink(missing_ok=True)

    @app.get("/findings")
    def findings():
        filters = {
            "status": request.args.get("status") or None,
            "severity": request.args.get("severity") or None,
            "source": request.args.get("source") or None,
            "owner": request.args.get("owner") or None,
        }
        query = request.args.get("q", "").strip()
        min_risk_raw = request.args.get("min_risk", "").strip()
        min_risk = int(min_risk_raw) if min_risk_raw.isdigit() else None
        page_number = max(1, int(request.args.get("page", "1") or "1"))
        page_size = 100
        rows = manager.db.list_findings(
            status=filters["status"],
            severity=filters["severity"],
            source=filters["source"],
            owner=filters["owner"],
            min_risk=min_risk,
            query=query or None,
            limit=page_size + 1,
            offset=(page_number - 1) * page_size,
        )
        has_next = len(rows) > page_size
        rows = rows[:page_size]
        return render_template(
            "findings.html",
            page="findings",
            findings=rows,
            filters=filters,
            min_risk=min_risk_raw,
            query=query,
            page_number=page_number,
            has_next=has_next,
        )

    @app.get("/findings/<int:finding_id>")
    def finding_detail(finding_id: int):
        try:
            finding = manager.export_finding(finding_id)
        except KeyError:
            flash("Finding not found.", "error")
            return redirect(url_for("findings"))
        return render_template(
            "finding.html",
            page="findings",
            finding=finding,
            notes=platform.notes(finding_id),
        )

    @app.post("/findings/<int:finding_id>/update")
    def finding_update(finding_id: int):
        status = request.form.get("status") or None
        owner = request.form.get("owner")
        try:
            manager.set_finding(finding_id, status=status, owner=owner)
            flash("Finding updated.", "success")
        except Exception as error:
            flash(f"Could not update finding: {error}", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id))

    @app.post("/findings/<int:finding_id>/accept-risk")
    def finding_accept_risk(finding_id: int):
        try:
            manager.accept_risk(
                finding_id,
                request.form.get("until", ""),
                request.form.get("reason", ""),
            )
            flash("Risk exception saved.", "success")
        except Exception as error:
            flash(f"Could not accept risk: {error}", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id))

    @app.post("/findings/<int:finding_id>/notes")
    def finding_note(finding_id: int):
        try:
            platform.add_note(
                finding_id,
                request.form.get("note", ""),
                request.form.get("author", ""),
            )
            flash("Note added.", "success")
        except Exception as error:
            flash(f"Could not add note: {error}", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id))

    @app.get("/assets")
    def assets():
        return render_template(
            "assets.html",
            page="assets",
            assets=manager.db.list_assets(),
            aliases=manager.assets.list_aliases(),
            asset_tags=platform.asset_tags_map(),
        )

    @app.post("/assets/update")
    def asset_update():
        asset_key = request.form.get("asset", "")
        try:
            manager.set_asset_context(
                asset_key,
                criticality=int(request.form.get("criticality", "3")),
                internet_exposed=request.form.get("internet_exposed") == "on",
                owner=request.form.get("owner", ""),
                environment=request.form.get("environment", ""),
            )
            flash(f"Updated {asset_key}.", "success")
        except Exception as error:
            flash(f"Could not update asset: {error}", "error")
        return redirect(url_for("assets"))

    @app.post("/assets/alias")
    def asset_alias():
        try:
            manager.assets.add_alias(
                request.form.get("asset", ""),
                request.form.get("alias", ""),
            )
            flash("Asset alias saved.", "success")
        except Exception as error:
            flash(f"Could not save alias: {error}", "error")
        return redirect(url_for("assets"))

    @app.post("/assets/tag")
    def asset_tag():
        try:
            platform.add_asset_tag(request.form.get("asset", ""), request.form.get("tag", ""))
            flash("Asset tag added.", "success")
        except Exception as error:
            flash(f"Could not add tag: {error}", "error")
        return redirect(url_for("assets"))

    @app.post("/assets/tag/remove")
    def asset_tag_remove():
        platform.remove_asset_tag(request.form.get("asset", ""), request.form.get("tag", ""))
        flash("Asset tag removed.", "success")
        return redirect(url_for("assets"))

    @app.route("/campaigns", methods=["GET", "POST"])
    def campaign_list():
        if request.method == "POST":
            try:
                min_risk_raw = request.form.get("min_risk", "").strip()
                campaigns.create(
                    request.form.get("name", ""),
                    owner=request.form.get("owner", ""),
                    due_at=request.form.get("due_at") or None,
                    notes=request.form.get("notes", ""),
                    min_risk=int(min_risk_raw) if min_risk_raw.isdigit() else None,
                    severity=request.form.get("severity") or None,
                    source=request.form.get("source") or None,
                    finding_owner=request.form.get("finding_owner") or None,
                )
                flash("Campaign created.", "success")
            except Exception as error:
                flash(f"Could not create campaign: {error}", "error")
            return redirect(url_for("campaign_list"))

        return render_template(
            "campaigns.html",
            page="campaigns",
            campaigns=campaigns.list(),
        )

    @app.get("/campaigns/<campaign_id>")
    def campaign_detail(campaign_id: str):
        try:
            campaign = campaigns.get(campaign_id)
        except KeyError:
            flash("Campaign not found.", "error")
            return redirect(url_for("campaign_list"))
        return render_template(
            "campaign.html",
            page="campaigns",
            campaign=campaign,
        )

    @app.post("/campaigns/<campaign_id>/sync")
    def campaign_sync(campaign_id: str):
        try:
            campaigns.sync_status(campaign_id)
            flash("Campaign status refreshed.", "success")
        except Exception as error:
            flash(f"Could not refresh campaign: {error}", "error")
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.get("/analytics")
    def analytics():
        return render_template(
            "analytics.html",
            page="analytics",
            analytics=build_analytics(manager.db),
        )

    @app.route("/intel", methods=["GET", "POST"])
    def intel():
        if request.method == "GET":
            return render_template("intel.html", page="intel")

        paths: list[Path] = []
        try:
            kwargs = {}
            for field, key in (("kev_file", "kev_path"), ("epss_file", "epss_path")):
                upload = request.files.get(field)
                if upload and upload.filename:
                    suffix = Path(upload.filename).suffix
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
                        path = Path(handle.name)
                        upload.save(handle)
                    paths.append(path)
                    kwargs[key] = path

            if not kwargs:
                raise ValueError("Choose a KEV JSON file, an EPSS CSV file, or both.")

            result = enrich_findings(manager.db, **kwargs)
            flash(
                f"Threat intel updated {result['updated_findings']} findings.",
                "success",
            )
            return redirect(url_for("findings"))
        except Exception as error:
            flash(f"Enrichment failed: {error}", "error")
            return redirect(url_for("intel"))
        finally:
            for path in paths:
                path.unlink(missing_ok=True)

    @app.post("/intel/online")
    def intel_online():
        try:
            result = enrich_findings_online(manager.db)
            flash(
                f"Checked {result.get('cves_checked', 0)} CVEs and updated "
                f"{result['updated_findings']} findings.",
                "success",
            )
        except Exception as error:
            flash(f"Online enrichment failed: {error}", "error")
        return redirect(url_for("intel"))

    @app.route("/automation", methods=["GET"])
    def automation():
        return render_template(
            "automation.html",
            page="automation",
            providers=scanner.providers(),
            profiles=platform.list_profiles(),
            schedules=platform.list_schedules(),
        )

    @app.post("/automation/profiles")
    def automation_profile_create():
        try:
            profile = platform.create_profile(
                name=request.form.get("name", ""),
                provider=request.form.get("provider", ""),
                target=request.form.get("target", ""),
                scope=request.form.get("scope", "default"),
                ports=request.form.get("ports", "quick"),
                partial=request.form.get("partial") == "on",
            )
            scanner._validate(profile["provider"], profile["target"], profile["ports"])
            flash("Scan profile saved.", "success")
        except Exception as error:
            flash(f"Could not save profile: {error}", "error")
        return redirect(url_for("automation"))

    @app.post("/automation/profiles/<profile_id>/run")
    def automation_profile_run(profile_id: str):
        try:
            profile = platform.get_profile(profile_id)
            job = scanner.start(
                provider=profile["provider"],
                target=profile["target"],
                scope=profile["scope"],
                ports=profile["ports"],
                partial=bool(profile["partial"]),
            )
            return redirect(url_for("scan_job", job_id=job["id"]))
        except Exception as error:
            flash(f"Could not run profile: {error}", "error")
            return redirect(url_for("automation"))

    @app.post("/automation/profiles/<profile_id>/delete")
    def automation_profile_delete(profile_id: str):
        try:
            platform.delete_profile(profile_id)
            flash("Profile deleted.", "success")
        except Exception as error:
            flash(f"Could not delete profile: {error}", "error")
        return redirect(url_for("automation"))

    @app.post("/automation/schedules")
    def automation_schedule_create():
        try:
            platform.create_schedule(
                request.form.get("profile_id", ""),
                interval_hours=int(request.form.get("interval_hours", "24")),
                run_immediately=request.form.get("run_immediately") == "on",
            )
            scheduler.run_due_once()
            flash("Schedule created.", "success")
        except Exception as error:
            flash(f"Could not create schedule: {error}", "error")
        return redirect(url_for("automation"))

    @app.post("/automation/schedules/<schedule_id>/toggle")
    def automation_schedule_toggle(schedule_id: str):
        try:
            current = platform.get_schedule(schedule_id)
            platform.set_schedule_enabled(schedule_id, not bool(current["enabled"]))
            flash("Schedule updated.", "success")
        except Exception as error:
            flash(f"Could not update schedule: {error}", "error")
        return redirect(url_for("automation"))

    @app.post("/automation/schedules/<schedule_id>/delete")
    def automation_schedule_delete(schedule_id: str):
        try:
            platform.delete_schedule(schedule_id)
            flash("Schedule deleted.", "success")
        except Exception as error:
            flash(f"Could not delete schedule: {error}", "error")
        return redirect(url_for("automation"))

    @app.route("/triage", methods=["GET"])
    def triage():
        return render_template(
            "triage.html",
            page="triage",
            suppressions=platform.list_suppressions(),
        )

    @app.post("/triage/suppressions")
    def triage_suppression_create():
        try:
            platform.create_suppression(
                name=request.form.get("name", ""),
                source_pattern=request.form.get("source_pattern", "*"),
                asset_pattern=request.form.get("asset_pattern", "*"),
                title_pattern=request.form.get("title_pattern", "*"),
                external_id_pattern=request.form.get("external_id_pattern", "*"),
                reason=request.form.get("reason", ""),
                expires_at=request.form.get("expires_at") or None,
            )
            result = platform.apply_suppressions()
            flash(
                f"Suppression rule saved. {result['suppressed_findings']} existing findings matched.",
                "success",
            )
        except Exception as error:
            flash(f"Could not save suppression: {error}", "error")
        return redirect(url_for("triage"))

    @app.post("/triage/suppressions/<rule_id>/toggle")
    def triage_suppression_toggle(rule_id: str):
        try:
            current = platform.get_suppression(rule_id)
            platform.set_suppression_enabled(rule_id, not bool(current["enabled"]))
            flash("Suppression rule updated.", "success")
        except Exception as error:
            flash(f"Could not update suppression: {error}", "error")
        return redirect(url_for("triage"))

    def api_allowed() -> bool:
        configured = os.environ.get("EXPOSURE_API_TOKEN")
        if configured:
            supplied = request.headers.get("Authorization", "")
            expected = f"Bearer {configured}"
            return hmac.compare_digest(supplied, expected)
        return request.remote_addr in {"127.0.0.1", "::1"}

    def api_guard():
        if api_allowed():
            return None
        return {"error": "unauthorized"}, 401

    @app.get("/api/v1/summary")
    def api_v1_summary():
        denied = api_guard()
        if denied:
            return denied
        return {
            "summary": manager.summary(),
            "analytics": build_analytics(manager.db),
        }

    @app.get("/api/v1/findings")
    def api_v1_findings():
        denied = api_guard()
        if denied:
            return denied
        limit = min(500, max(1, int(request.args.get("limit", "100"))))
        return {
            "findings": manager.db.list_findings(
                status=request.args.get("status") or None,
                severity=request.args.get("severity") or None,
                source=request.args.get("source") or None,
                owner=request.args.get("owner") or None,
                query=request.args.get("q") or None,
                limit=limit,
            )
        }

    @app.get("/api/v1/assets")
    def api_v1_assets():
        denied = api_guard()
        if denied:
            return denied
        tags = platform.asset_tags_map()
        assets_payload = manager.db.list_assets()
        for asset in assets_payload:
            asset["tags"] = tags.get(asset["asset_key"], [])
        return {"assets": assets_payload}

    @app.get("/api/v1/scans")
    def api_v1_scans():
        denied = api_guard()
        if denied:
            return denied
        return {
            "jobs": scanner.store.list(min(200, max(1, int(request.args.get("limit", "50"))))),
            "profiles": platform.list_profiles(),
            "schedules": platform.list_schedules(),
        }

    @app.post("/api/v1/scans")
    def api_v1_scan_start():
        denied = api_guard()
        if denied:
            return denied
        payload = request.get_json(silent=True) or {}
        if payload.get("authorized") is not True:
            return {"error": "authorized=true is required"}, 400
        try:
            job = scanner.start(
                provider=str(payload.get("provider") or ""),
                target=str(payload.get("target") or ""),
                scope=str(payload.get("scope") or "default"),
                ports=str(payload.get("ports") or "quick"),
                partial=bool(payload.get("partial", False)),
            )
        except Exception as error:
            return {"error": str(error)}, 400
        return {"job": job}, 202

    @app.get("/reports/<report_format>")
    def download_report(report_format: str):
        queue = manager.remediation_queue(5000)
        summary = manager.summary()
        if report_format == "json":
            body = to_json(summary, queue)
            mimetype = "application/json"
            filename = "exposure-report.json"
        elif report_format == "csv":
            body = to_csv(queue)
            mimetype = "text/csv"
            filename = "exposure-report.csv"
        elif report_format == "markdown":
            body = to_markdown(summary, queue)
            mimetype = "text/markdown"
            filename = "exposure-report.md"
        else:
            return Response("Unknown report format.", status=404)

        return Response(
            body,
            mimetype=mimetype,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/health")
    def health():
        return {"status": "ok", "database": app.config["DATABASE_PATH"]}

    return app


app = create_app(start_scheduler=False)


def _open_browser() -> None:
    webbrowser.open("http://127.0.0.1:5055")


if __name__ == "__main__":
    if os.environ.get("EXPOSURE_DISABLE_SCHEDULER") != "1":
        app.config["SCHEDULER"].start()
    if os.environ.get("EXPOSURE_NO_BROWSER") != "1":
        threading.Timer(1.0, _open_browser).start()
    app.run(host="127.0.0.1", port=5055, debug=False)
