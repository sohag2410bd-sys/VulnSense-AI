"""
VulnSense AI - Adaptive CLI for Termux (vertical cards) & Linux (multi-column tables)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scanner import render_markdown_report, run_full_scan

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
}


def is_compact_terminal(console: Console) -> bool:
    return bool(os.environ.get("TERMUX_VERSION")) or console.width < 100


def render_termux_cards(console: Console, report: dict) -> None:
    recon = report["recon"]
    analysis = report["analysis"]

    summary = (
        f"[bold cyan]Target:[/] {recon['target_url']}\n"
        f"[bold cyan]Score:[/] {analysis['security_score']:.1f}/10  "
        f"[bold cyan]Grade:[/] {analysis['grade']}\n"
        f"[bold cyan]TLS:[/] {recon['tls'].get('protocol') or 'Disabled'}  "
        f"[bold cyan]HTTP:[/] {recon['status_code']}"
    )
    console.print(Panel(summary, title="VulnSense AI Summary", border_style="cyan", box=box.ROUNDED))
    console.print(Panel(analysis["executive_summary"], title="Executive Summary", border_style="blue"))

    for idx, finding in enumerate(analysis["findings"], start=1):
        sev = finding["severity"]
        style = SEVERITY_COLORS.get(sev, "white")
        steps = "\n".join(f"• {s}" for s in finding["remediation_steps"])
        body = (
            f"[{style}][{sev}][/] [bold]{finding['title']}[/]\n"
            f"[dim]{finding['category']} · {finding['affected_component']}[/]\n\n"
            f"{finding['risk_explanation']}\n\n"
            f"[bold green]Remediation:[/]\n{steps}\n\n"
            f"[bold magenta]Nginx Snippet:[/]\n{finding['nginx_snippet']}"
        )
        console.print(Panel(body, title=f"Finding #{idx}", border_style="bright_black", box=box.ROUNDED))


def render_linux_table(console: Console, report: dict) -> None:
    recon = report["recon"]
    analysis = report["analysis"]

    header_text = Text()
    header_text.append("VulnSense AI Assessment  ", style="bold cyan")
    header_text.append(f"{recon['domain']}  ", style="bold white")
    header_text.append(
        f"Score: {analysis['security_score']:.1f}/10 (Grade {analysis['grade']})",
        style="bold green" if analysis["security_score"] >= 7.5 else "bold yellow",
    )
    console.print(Panel(header_text, subtitle=analysis["executive_summary"], border_style="cyan"))

    table = Table(title="Vulnerability Findings", box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Finding & Component", ratio=2)
    table.add_column("Risk Explanation", ratio=3)
    table.add_column("Primary Remediation", ratio=2)

    for f in analysis["findings"]:
        sev = f["severity"]
        style = SEVERITY_COLORS.get(sev, "white")
        remediation = f["remediation_steps"][0] if f["remediation_steps"] else "Apply hardened headers"
        table.add_row(
            f"[{style}]{sev}[/]",
            f"[bold]{f['title']}[/]\n[dim]{f['affected_component']}[/]",
            f["risk_explanation"],
            remediation,
        )

    console.print(table)


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="VulnSense AI Passive Web Security Scanner")
    parser.add_argument("url", help="Target website URL or domain (e.g. https://example.com)")
    parser.add_argument("--out", help="Custom output Markdown filename", default=None)
    args = parser.parse_args()

    console = Console()
    with console.status(f"[bold cyan]Running passive recon & Gemini AI audit on {args.url}..."):
        try:
            report = run_full_scan(args.url)
        except Exception as exc:
            console.print(f"[bold red]Scan failed:[/] {exc}")
            return 1

    if is_compact_terminal(console):
        render_termux_cards(console, report)
    else:
        render_linux_table(console, report)

    domain = report["recon"]["domain"]
    out_path = Path(args.out or f"report_{domain}.md")
    out_path.write_text(render_markdown_report(report), encoding="utf-8")
    console.print(f"\n[bold green]Saved Markdown report:[/] {out_path.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
