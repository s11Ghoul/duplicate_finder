"""Flask web application for phishing detection."""

import json
import os
import time

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_from_directory,
)

from countries import list_countries, resolve_country
from webapp.models import ScanJob
from webapp.worker import JobQueue

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")


def create_app() -> Flask:
    app = Flask(__name__)
    job_queue = JobQueue()
    job_queue.start()

    # Store job_queue on app for access in routes
    app.config["job_queue"] = job_queue

    # --- Pages ---

    @app.route("/")
    def index():
        countries = list_countries()
        jobs = job_queue.get_all_jobs()
        return render_template("index.html", countries=countries, jobs=jobs)

    @app.route("/jobs/<job_id>")
    def job_detail(job_id):
        job = job_queue.get_job(job_id)
        if not job:
            return "Job not found", 404
        return render_template("job.html", job=job)

    # --- API ---

    @app.route("/api/countries")
    def api_countries():
        return jsonify([
            {"code": code, "name": name}
            for code, name in list_countries()
        ])

    @app.route("/api/scan", methods=["POST"])
    def api_create_scan():
        data = request.get_json() or {}
        brands_raw = data.get("brands", "")
        countries_raw = data.get("countries", [])

        # Parse brands (one per line or comma-separated)
        if isinstance(brands_raw, str):
            brands = [
                b.strip()
                for b in brands_raw.replace(",", "\n").split("\n")
                if b.strip()
            ]
        else:
            brands = [b.strip() for b in brands_raw if b.strip()]

        if not brands:
            return jsonify({"error": "No brands specified"}), 400

        # Validate countries
        valid_countries = []
        for c in countries_raw:
            resolved = resolve_country(c)
            if resolved:
                valid_countries.append(resolved["code"])
            else:
                return jsonify({"error": f"Unknown country: {c}"}), 400

        if not valid_countries:
            return jsonify({"error": "No countries specified"}), 400

        job = ScanJob(brands=brands, countries=valid_countries)
        job.add_log(
            f"Job created: {len(brands)} brand(s), {len(valid_countries)} country(ies)"
        )
        job_queue.enqueue(job)

        return jsonify({"job_id": job.id, "status": "queued"}), 201

    @app.route("/api/jobs")
    def api_list_jobs():
        jobs = job_queue.get_all_jobs()
        return jsonify([j.to_dict() for j in jobs])

    @app.route("/api/jobs/<job_id>")
    def api_get_job(job_id):
        job = job_queue.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(job.to_dict())

    @app.route("/api/jobs/<job_id>/stream")
    def api_stream(job_id):
        """SSE endpoint for live progress updates."""
        job = job_queue.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404

        def generate():
            last_log_idx = 0
            last_progress = None
            while True:
                # Send new log entries
                current_log = job.log[last_log_idx:]
                for entry in current_log:
                    yield f"data: {json.dumps({'type': 'log', 'message': entry})}\n\n"
                last_log_idx = len(job.log)

                # Send progress updates if changed
                progress_snapshot = json.dumps(job.progress)
                if progress_snapshot != last_progress:
                    yield f"data: {json.dumps({'type': 'progress', 'data': job.progress, 'status': job.status, 'captcha_pending': job.captcha_pending})}\n\n"
                    last_progress = progress_snapshot

                # Send completion event
                if job.status in ("completed", "failed"):
                    result = {
                        "type": "done",
                        "status": job.status,
                        "error": job.error,
                        "result_files": list(job.result_files.keys()),
                    }
                    yield f"data: {json.dumps(result)}\n\n"
                    break

                time.sleep(1)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.route("/api/jobs/<job_id>/captcha-solved", methods=["POST"])
    def api_captcha_solved(job_id):
        """Signal that the user has solved the CAPTCHA."""
        job = job_queue.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        if job.captcha_event:
            job.captcha_event.set()
        return jsonify({"status": "ok"})

    @app.route("/api/jobs/<job_id>/results/<brand>")
    def api_download_result(job_id, brand):
        """Download CSV results for a specific brand."""
        job = job_queue.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        filename = job.result_files.get(brand)
        if not filename:
            return jsonify({"error": f"No results for brand: {brand}"}), 404
        return send_from_directory(
            RESULTS_DIR, filename, as_attachment=True
        )

    return app
