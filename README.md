# VEYRiON v5.1

An authorized, non-destructive web security assessment tool for Kali Linux.

> Use this tool only against domains you own or have explicit permission to assess.

## Features

- Colorful multi-color terminal interface.
- Security header checks.
- Cookie security checks.
- CORS checks.
- HTTPS and transport security checks.
- HTTP redirect validation.
- Mixed-content detection.
- Basic CSRF indicator checks for forms.
- Optional conservative SQL error disclosure checks.
- Same-origin and same-root crawling.
- `robots.txt` and `sitemap.xml` discovery.
- Technology detection.
- Automatic retry for temporary HTTP failures.
- JSON, HTML, CSV, and log reports.
- Interactive terminal mode.
- Command-line interface.
- Responsibility confirmation using `[y/n]`.
- Scope protection to keep crawling within the target domain.

## Installation on Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-pip
python3 -m pip install -r requirements.txt
chmod +x veyrion.py
