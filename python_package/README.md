# VulnSense AI

**VulnSense AI** is an open-source hybrid passive web security reconnaissance and AI analysis toolkit built for **Termux (Android)**, **Linux terminals**, and **Web SOC Dashboards**.

## Directory Structure

```text
vulnsense-ai/
├── requirements.txt
├── scanner.py
├── cli.py
├── app.py
├── templates/
│   └── index.html
└── README.md
```

## Features

- **Passive Reconnaissance**: Inspects HTTP security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), TLS/SSL certificate validity & protocol version, `Set-Cookie` security flags (`HttpOnly`, `Secure`, `SameSite`), server banners, and `robots.txt`.
- **Gemini AI Vulnerability Engine**: Uses strict JSON schema structured outputs to classify findings into `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`, provide actionable remediation steps, generate Nginx & Apache hardening snippets, and compute an overall score (`0–10`) and letter grade (`A–F`).
- **Adaptive CLI (`rich`)**: Renders compact vertical cards on Termux / narrow mobile terminals and multi-column tables on Linux desktops, automatically writing `report_<domain>.md`.
- **Flask Web Dashboard**: Dark SOC web interface with live URL scanning, risk metrics, interactive findings accordions, and Markdown report download.

## Installation

### 1. Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install python git openssl -y
git clone https://github.com/your-username/vulnsense-ai.git
cd vulnsense-ai
pip install -r requirements.txt
export GEMINI_API_KEY="your_gemini_api_key"
python cli.py https://example.com
```

### 2. Linux / macOS

```bash
git clone https://github.com/your-username/vulnsense-ai.git
cd vulnsense-ai
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export GEMINI_API_KEY="your_gemini_api_key"
```

#### Run CLI Mode
```bash
python cli.py https://example.com
```

#### Run Web Dashboard Mode
```bash
python app.py
# Open http://localhost:5000 in your browser
```

## Disclaimer

Use VulnSense AI strictly for authorized security assessments and educational hardening of systems you own or have explicit permission to evaluate.
