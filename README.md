<div align="center">

# 🛡️ BlackScope

### Open-Source OSINT & Domain Intelligence Framework

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-000000?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![OSINT](https://img.shields.io/badge/Category-OSINT-red?style=for-the-badge)

*A modular reconnaissance framework for gathering domain intelligence, analyzing security posture, and generating actionable risk assessments.*

</div>

---

# Overview

BlackScope is an open-source OSINT framework written in Python that automates domain reconnaissance and security analysis.

The framework combines multiple intelligence modules into a single workflow, providing a comprehensive overview of a target's public-facing infrastructure.

Unlike traditional lookup tools, BlackScope also performs automated risk analysis and presents the results in a clean, professional command-line interface.

---

# Features

## Domain Intelligence

- DNS Enumeration
- WHOIS Lookup
- IP Resolution
- Reverse DNS Lookup
- ASN Intelligence
- Network Allocation Detection

---

## Security Analysis

- SSL Certificate Inspection
- Certificate Expiration Monitoring
- HTTP Security Header Analysis
- Security Misconfiguration Detection

---

## Technology Detection

Automatically detects technologies such as:

- React
- Next.js
- Vue.js
- Angular
- Bootstrap
- Tailwind CSS
- jQuery
- WordPress
- Drupal
- Laravel
- Django
- Flask
- GitHub Pages
- Cloudflare
- Apache
- Nginx
- Microsoft IIS

---

## Risk Assessment Engine

BlackScope automatically evaluates findings and assigns a security score.

Example:

```text
Overall Score

88 / 100

Risk Level

LOW

Findings

✓ Valid SSL Certificate
✓ Domain is 19 years old
✓ HTTPS Enabled
✓ HSTS Enabled
✓ CSP Enabled

Warnings

⚠ Permissions Policy Missing
⚠ COOP Missing
⚠ CORP Missing
⚠ COEP Missing
```

---

# Current Modules

| Module | Status |
|---------|--------|
| DNS Lookup | ✅ |
| WHOIS Lookup | ✅ |
| SSL Certificate Analysis | ✅ |
| HTTP Header Analysis | ✅ |
| IP Intelligence | ✅ |
| Technology Detection | ✅ |
| Risk Assessment Engine | ✅ |
| Rich Terminal Dashboard | ✅ |

---

# Project Structure

```text
BlackScope
│
├── blackscope
│   ├── intelligence
│   │   ├── dns_lookup.py
│   │   ├── whois_lookup.py
│   │   ├── ssl_checker.py
│   │   ├── headers.py
│   │   ├── ip_lookup.py
│   │   └── tech_detector.py
│   │
│   ├── scoring
│   │   └── threat_score.py
│   │
│   ├── report
│   │   ├── html_report.py
│   │   └── json_report.py
│   │
│   ├── scanner.py
│   ├── display.py
│   ├── banner.py
│   └── cli.py
│
├── reports
├── screenshots
└── tests
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/cojjjj/BlackScope.git

cd BlackScope
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Usage

Scan a domain

```bash
python -m blackscope.cli github.com
```

Example

```bash
python -m blackscope.cli google.com

python -m blackscope.cli microsoft.com

python -m blackscope.cli cloudflare.com
```

---

# Example Output

BlackScope provides:

- Executive Dashboard
- DNS Records
- WHOIS Information
- SSL Certificate Details
- HTTP Security Headers
- IP Intelligence
- Technology Detection
- Automated Risk Assessment

---

# Roadmap

## Version 0.4

- HTML Reports
- JSON Export
- Website Screenshots
- robots.txt Scanner
- sitemap.xml Scanner
- security.txt Scanner

---

## Version 0.5

- VirusTotal Integration
- AbuseIPDB Integration
- Shodan Integration
- Censys Integration
- GreyNoise Integration

---

## Version 1.0

- PDF Reports
- Multi-threaded Scanning
- Batch Target Support
- Plugin Architecture
- REST API
- Dark Theme Dashboard
- AI-Assisted Risk Explanations

---

# Technologies Used

- Python
- Requests
- dnspython
- python-whois
- Rich
- Socket
- SSL
- JSON

---

# Disclaimer

BlackScope is intended for educational purposes, security research, and authorized assessments only.

Always obtain permission before scanning systems you do not own or administer.

---

# Contributing

Contributions are welcome.

Feel free to submit issues, feature requests, or pull requests to help improve BlackScope.

---

# Author

**Tyler Deppa**

Cybersecurity Student

Ethical Hacking • Blue Team • OSINT • Python Development

GitHub

https://github.com/cojjjj

---

# License

This project is licensed under the MIT License.

---

<div align="center">

### ⭐ If you found this project useful, consider giving it a star!

</div>
