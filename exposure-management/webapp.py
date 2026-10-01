from __future__ import annotations

import json
import os
import tempfile
import threading
import webbrowser
from pathlib import Path

from flask import Flask, Response, flash, redirect, render_template, request, url_for

from exposure_manager.analytics import build_analytics
from exposure_manager.campaigns import CampaignManager
from exposure_manager.intel import enrich_findings
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


def create_app(database_path: str | Path | None = None) -> Flask:
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

    app.config["MANAGER"] = manager
    app.config["CAMPAIGNS"] = campaigns
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
        return render_template(
            "dashboard.html",
            page="dashboard",
            summary=summary,
            analytics=analytics,
            queue=queue,
            scans=scans,
        )

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
        min_risk_raw = request.args.get("min_risk", "").strip()
        min_risk = int(min_risk_raw) if min_risk_raw.isdigit() else None
        rows = manager.db.list_findings(
            status=filters["status"],
            severity=filters["severity"],
            source=filters["source"],
            owner=filters["owner"],
            min_risk=min_risk,
            limit=1000,
        )
        return render_template(
            "findings.html",
            page="findings",
            findings=rows,
            filters=filters,
            min_risk=min_risk_raw,
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

    @app.get("/assets")
    def assets():
        return render_template(
            "assets.html",
            page="assets",
            assets=manager.db.list_assets(),
            aliases=manager.assets.list_aliases(),
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


app = create_app()


def _open_browser() -> None:
    webbrowser.open("http://127.0.0.1:5055")


if __name__ == "__main__":
    if os.environ.get("EXPOSURE_NO_BROWSER") != "1":
        threading.Timer(1.0, _open_browser).start()
    app.run(host="127.0.0.1", port=5055, debug=False)
