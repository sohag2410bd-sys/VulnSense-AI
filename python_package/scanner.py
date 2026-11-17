"""
VulnSense AI - Core Passive Reconnaissance & Gemini Analysis Engine
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urljoin, urlparse

import requests
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


class VulnerabilityFinding(BaseModel):
    title: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    category: str
    affected_component: str
    risk_explanation: str
    remediation_steps: list[str]
    nginx_snippet: str
    apache_snippet: str


class GeminiSecurityAnalysis(BaseModel):
    security_score: float = Field(ge=0.0, le=10.0)
    grade: Literal["A", "B", "C", "D", "F"]
    executive_summary: str
    findings: list[VulnerabilityFinding]


def normalize_and_validate_url(raw_url: str) -> tuple[str, str]:
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("Target URL cannot be empty.")
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Invalid URL. Provide a valid http:// or https:// target.")

    hostname = parsed.hostname.lower()
    if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith((".local", ".internal")):
        raise ValueError("Private or loopback addresses are blocked for safety.")

    try:
        resolved_ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            raise ValueError(f"Resolved IP {resolved_ip} is non-public.")
    except socket.gaierror:
        pass

    return parsed.geturl(), hostname


def inspect_tls(hostname: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                not_after = cert.get("notAfter") if cert else None
                days_remaining = None
                if not_after:
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days_remaining = (expiry_dt - datetime.now(timezone.utc)).days

                issuer_parts = []
                for rdn in cert.get("issuer", ()) if cert else ():
                    for key, val in rdn:
                        if key in ("organizationName", "commonName"):
                            issuer_parts.append(val)

                return {
                    "enabled": True,
                    "protocol": ssock.version(),
                    "cipher": cipher_info[0] if cipher_info else None,
                    "authorized": True,
                    "issuer": ", ".join(issuer_parts) or "Unknown",
                    "valid_to": not_after,
                    "days_remaining": days_remaining,
                    "error": None,
                }
    except Exception as exc:
        return {
            "enabled": False,
            "protocol": None,
            "cipher": None,
            "authorized": False,
            "issuer": None,
            "valid_to": None,
            "days_remaining": None,
            "error": str(exc),
        }


def parse_cookies(response: requests.Response) -> list[dict[str, Any]]:
    raw_cookies: list[str] = []
    if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "getlist"):
        raw_cookies = response.raw.headers.getlist("Set-Cookie")
    elif "Set-Cookie" in response.headers:
        raw_cookies = [response.headers["Set-Cookie"]]

    audited: list[dict[str, Any]] = []
    for raw in raw_cookies:
        segments = [seg.strip() for seg in raw.split(";") if seg.strip()]
        if not segments:
            continue
        name_val = segments[0]
        cookie_name = name_val.split("=", 1)[0].strip()
        lower_attrs = [s.lower() for s in segments[1:]]
        http_only = "httponly" in lower_attrs
        secure = "secure" in lower_attrs
        same_site = next(
            (s.split("=", 1)[1].strip() for s in segments[1:] if s.lower().startswith("samesite=")),
            None,
        )

        issues: list[str] = []
        if not http_only:
            issues.append("Missing HttpOnly")
        if not secure:
            issues.append("Missing Secure")
        if not same_site:
            issues.append("Missing SameSite")

        audited.append(
            {
                "name": cookie_name,
                "http_only": http_only,
                "secure": secure,
                "same_site": same_site,
                "issues": issues,
            }
        )
    return audited


def collect_passive_recon(raw_url: str, timeout: float = 12.0) -> dict[str, Any]:
    target_url, domain = normalize_and_validate_url(raw_url)
    headers = {"User-Agent": "VulnSense-AI/1.0 (Passive Security Recon)"}

    started = time.perf_counter()
    resp = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True)
    elapsed_ms = round((time.perf_counter() - started) * 1000)

    lower_headers = {k.lower(): v for k, v in resp.headers.items()}
    header_checks = [
        {
            "name": hdr,
            "present": hdr.lower() in lower_headers,
            "value": lower_headers.get(hdr.lower()),
        }
        for hdr in SECURITY_HEADERS
    ]

    final_parsed = urlparse(resp.url)
    tls_info = (
        inspect_tls(final_parsed.hostname or domain, final_parsed.port or 443)
        if final_parsed.scheme == "https"
        else {
            "enabled": False,
            "protocol": None,
            "cipher": None,
            "authorized": False,
            "issuer": None,
            "valid_to": None,
            "days_remaining": None,
            "error": "Target did not negotiate HTTPS",
        }
    )

    robots_url = urljoin(f"{final_parsed.scheme}://{final_parsed.netloc}", "/robots.txt")
    robots_found = False
    robots_status = None
    robots_preview = None
    disallowed_paths: list[str] = []
    try:
        r_resp = requests.get(robots_url, headers=headers, timeout=6.0)
        robots_status = r_resp.status_code
        if r_resp.status_code == 200 and "text" in r_resp.headers.get("Content-Type", ""):
            robots_found = True
            robots_preview = "\n".join(r_resp.text.splitlines()[:15])
            for line in r_resp.text.splitlines():
                if line.strip().lower().startswith("disallow:"):
                    path_val = line.split(":", 1)[1].strip()
                    if path_val:
                        disallowed_paths.append(path_val)
    except requests.RequestException:
        pass

    return {
        "target_url": target_url,
        "final_url": resp.url,
        "domain": domain,
        "status_code": resp.status_code,
        "response_time_ms": elapsed_ms,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "security_headers": header_checks,
        "tls": tls_info,
        "cookies": parse_cookies(resp),
        "metadata": {
            "server_banner": resp.headers.get("Server"),
            "powered_by": resp.headers.get("X-Powered-By"),
            "robots_txt_found": robots_found,
            "robots_txt_status": robots_status,
            "robots_txt_preview": robots_preview,
            "disallowed_paths": disallowed_paths[:15],
        },
    }


PRIMARY_MODEL = "gemini-2.5-flash"
FALLBACK_MODEL = "gemini-2.5-flash-lite"


def _is_transient_overload_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(
        token in text
        for token in (
            "503",
            "429",
            "high demand",
            "overloaded",
            "unavailable",
            "resource_exhausted",
            "rate limit",
            "timeout",
        )
    )


def analyze_with_gemini(recon_data: dict[str, Any]) -> dict[str, Any]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY environment variable is not configured.")

    client = genai.Client(api_key=api_key)
    prompt = (
        "Analyze the following passive web reconnaissance telemetry and return a strict JSON "
        "security assessment. Categorize each finding into CRITICAL, HIGH, MEDIUM, or LOW, "
        "provide clear risk explanations, concrete remediation steps, working Nginx and Apache "
        "configuration snippets, an overall security score out of 10, and an A-F letter grade.\n\n"
        f"Recon Telemetry:\n{recon_data}"
    )

    last_error: Exception | None = None
    for model_name in (PRIMARY_MODEL, FALLBACK_MODEL):
        for attempt in range(1, 4):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=(
                            "You are a senior application security architect. Produce factual, evidence-based "
                            "findings grounded strictly in the provided passive reconnaissance telemetry."
                        ),
                        response_mime_type="application/json",
                        response_schema=GeminiSecurityAnalysis,
                    ),
                )
                parsed = GeminiSecurityAnalysis.model_validate_json(response.text)
                return parsed.model_dump()
            except Exception as exc:
                last_error = exc
                if not _is_transient_overload_error(exc):
                    raise
                if attempt < 3:
                    time.sleep(1.2 * (2 ** (attempt - 1)))

    raise RuntimeError(
        f"Gemini analysis failed after retries and lighter-model fallback: {last_error}"
    )


def render_csv_report(report: dict[str, Any]) -> str:
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Severity", "Title", "Description", "Remediation Fix"])

    for finding in report["analysis"]["findings"]:
        description = f"{finding['affected_component']}: {finding['risk_explanation']}"
        fix = (
            f"{' '.join(finding['remediation_steps'])} | "
            f"Nginx: {finding['nginx_snippet']} | Apache: {finding['apache_snippet']}"
        )
        writer.writerow([finding["severity"], finding["title"], description, fix])

    return output.getvalue()


def render_pdf_report(report: dict[str, Any]) -> bytes:
    from fpdf import FPDF

    recon = report["recon"]
    analysis = report["analysis"]

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "VulnSense AI - Security Audit Report", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Target URL: {recon['target_url']}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0,
        6,
        f"Security Score: {analysis['security_score']:.1f} / 10.0   |   Grade: {analysis['grade']}",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, analysis["executive_summary"])
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Identified Findings", new_x="LMARGIN", new_y="NEXT")

    for idx, f in enumerate(analysis["findings"], start=1):
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 6, f"{idx}. [{f['severity']}] {f['title']}")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, f"Component: {f['affected_component']} — {f['risk_explanation']}")
        pdf.multi_cell(0, 5, f"Remediation: {' '.join(f['remediation_steps'])}")
        pdf.multi_cell(0, 5, f"Nginx Fix: {f['nginx_snippet']}")
        pdf.ln(3)

    return bytes(pdf.output())


def render_markdown_report(report: dict[str, Any]) -> str:
    recon = report["recon"]
    analysis = report["analysis"]
    lines = [
        "# VulnSense AI Security Assessment Report",
        "",
        f"- **Target:** {recon['target_url']}",
        f"- **Domain:** {recon['domain']}",
        f"- **HTTP Status:** {recon['status_code']} ({recon['response_time_ms']} ms)",
        f"- **Security Score:** {analysis['security_score']:.1f} / 10.0 (Grade **{analysis['grade']}**)",
        "",
        "## Executive Summary",
        "",
        analysis["executive_summary"],
        "",
        "## Vulnerability Findings",
        "",
    ]

    for idx, f in enumerate(analysis["findings"], start=1):
        lines.extend(
            [
                f"### {idx}. [{f['severity']}] {f['title']}",
                f"- **Category:** {f['category']}",
                f"- **Affected Component:** {f['affected_component']}",
                "",
                f["risk_explanation"],
                "",
                "**Remediation Steps**",
                *[f"- {step}" for step in f["remediation_steps"]],
                "",
                "**Nginx Fix**",
                "```nginx",
                f["nginx_snippet"].strip(),
                "```",
                "",
                "**Apache Fix**",
                "```apache",
                f["apache_snippet"].strip(),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def run_full_scan(target_url: str) -> dict[str, Any]:
    recon = collect_passive_recon(target_url)
    analysis = analyze_with_gemini(recon)
    return {"recon": recon, "analysis": analysis}
