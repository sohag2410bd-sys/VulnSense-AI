"""
VulnSense AI - Flask Web Dashboard Backend
"""

from __future__ import annotations

import os
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request

from scanner import (
    render_csv_report,
    render_markdown_report,
    render_pdf_report,
    run_full_scan,
)

load_dotenv()

app = Flask(__name__)


@app.get("/")
def index() -> str:
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("url", "")).strip()
    if not target_url:
        return jsonify({"error": "Please supply a target URL."}), 400

    try:
        report = run_full_scan(target_url)
        return jsonify(report)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        msg = str(exc)
        status = 503 if ("503" in msg or "high demand" in msg.lower()) else 500
        return jsonify({"error": f"Scan execution error: {msg}"}), status


@app.post("/api/report/markdown")
def api_markdown_report():
    report = request.get_json(silent=True)
    if not report or "recon" not in report or "analysis" not in report:
        return jsonify({"error": "Invalid report payload."}), 400

    domain = report["recon"].get("domain", "target")
    markdown = render_markdown_report(report)
    return Response(
        markdown,
        mimetype="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="report_{domain}.md"'},
    )


@app.post("/api/report/csv")
def api_csv_report():
    report = request.get_json(silent=True)
    if not report or "recon" not in report or "analysis" not in report:
        return jsonify({"error": "Invalid report payload."}), 400

    domain = report["recon"].get("domain", "target")
    csv_text = render_csv_report(report)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="report_{domain}.csv"'},
    )


@app.post("/api/report/pdf")
def api_pdf_report():
    report = request.get_json(silent=True)
    if not report or "recon" not in report or "analysis" not in report:
        return jsonify({"error": "Invalid report payload."}), 400

    domain = report["recon"].get("domain", "target")
    pdf_bytes = render_pdf_report(report)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{domain}.pdf"'},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
