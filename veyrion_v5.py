"""
VEYRiON v5.1
Web Security Assessment Framework

AUTHORIZED / NON-DESTRUCTIVE WEB SECURITY AUDITING

This scanner:
- accepts domain-only targets
- crawls same-origin/same-root in-scope pages
- checks security headers, cookies, CORS, transport, mixed content
- checks forms for obvious CSRF indicators
- performs conservative SQL-error disclosure checks on GET parameters
- discovers sitemap/robots links and common API/JS references
- supports optional Authorization/Cookie headers for systems you own
- produces JSON and HTML reports

It does NOT:
- exploit vulnerabilities
- dump databases
- bypass authentication
- brute-force credentials
- upload files
- execute destructive requests
"""

# ============================================================
# AUTO INSTALL REQUIRED LIBRARIES
# ============================================================

import sys
import subprocess
import importlib
import html
import argparse
import csv
import logging
import socket
from urllib.parse import quote

REQUIRED_PACKAGES = {
    "requests": "requests",
    "bs4": "beautifulsoup4",
    "colorama": "colorama",
}


def install_missing_packages():
    missing = []

    for module_name, package_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(package_name)

    if not missing:
        return

    print("[*] Installing missing libraries...")

    try:
        subprocess.check_call([
            sys.executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            *missing
        ])
    except subprocess.CalledProcessError:
        print("[!] Failed to install required libraries.")
        print("[!] Try manually:")
        print(
            f"{sys.executable} -m pip install "
            + " ".join(missing)
        )
        sys.exit(1)


install_missing_packages()

# ============================================================
# NORMAL IMPORTS
# ============================================================

import os
import re
import json
import time
import random
import signal
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import (
    urlparse,
    urljoin,
    urlunparse,
    parse_qsl,
    urlencode,
    urldefrag,
)
from xml.etree import ElementTree as ET

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True, strip=False, convert=False)

VERSION = "5.1"
TIMEOUT = 10
MAX_PAGES = 100
MAX_WORKERS = 4
REQUEST_DELAY = 0.25
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
REPORT_DIR = "reports"
DEFAULT_OUTPUT_DIR = "reports"
ENABLE_SQL_ERROR_CHECK = False
MAX_URL_LENGTH = 4096
MAX_PARAMETERS_PER_URL = 20
RETRY_COUNT = 2
USER_AGENT = "VEYRiON/5.1 Kali-Terminal Authorized-Web-Security-Auditor"

STOP_EVENT = threading.Event()
PRINT_LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
LAST_REQUEST = 0.0

# =========================
# ALLOWED TLDs / SUFFIXES
# =========================

AUTHORIZED_DOMAINS = [
    # Commercial
    ".com",
    ".biz",
    ".co",
    ".company",
    ".corp",
    ".corporate",
    ".enterprises",
    ".enterprise",
    ".inc",
    ".ltd",
    ".llc",
    ".plc",
    ".limited",
    ".industries",
    ".industry",
    ".business",
    ".consulting",
    ".consultant",
    ".services",
    ".solutions",
    ".agency",
    ".management",
    ".marketing",
    ".finance",
    ".financial",
    ".insurance",
    ".investments",
    ".investment",
    ".capital",
    ".partners",
    ".partnership",
    ".ventures",
    ".venture",
    ".group",
    ".holdings",
    ".store",
    ".shop",
    ".shopping",
    ".market",
    ".markets",
    ".sale",
    ".deals",
    ".online",
    ".digital",
    ".tech",
    ".technology",
    ".software",
    ".cloud",
    ".network",
    ".media",
    ".studio",
    ".design",
    ".works",

    # Education
    ".edu",
    ".ac",
    ".ac.uk",
    ".edu.au",
    ".edu.iq",
    ".edu.sa",
    ".edu.ae",
    ".edu.eg",
    ".edu.jo",
    ".edu.kw",
    ".edu.qa",
    ".edu.bh",
    ".edu.om",
    ".edu.pk",
    ".edu.in",
    ".edu.bd",
    ".edu.lk",
    ".edu.my",
    ".edu.sg",
    ".edu.cn",
    ".edu.hk",
    ".edu.tw",
    ".ac.jp",
    ".ac.kr",
    ".edu.ph",
    ".edu.vn",
    ".edu.th",
    ".edu.tr",
    ".edu.br",
    ".edu.mx",
    ".edu.ar",
    ".edu.co",
    ".edu.pe",
    ".edu.cl",
    ".edu.za",
    ".ac.za",
    ".ac.nz",
    ".ac.in",
    ".ac.il",
    ".ac.at",
    ".ac.be",
    ".ac.cy",
    ".ac.gr",
    ".ac.hu",
    ".ac.pl",
    ".ac.rs",
    ".ac.ro",
    ".ac.ru",

    # Government
    ".gov.iq",
    ".gov.sa",
    ".gov.ae",
    ".gov.qa",
    ".gov.kw",
    ".gov.bh",
    ".gov.om",
    ".gov.jo",
    ".gov.lb",
    ".gov.eg",
    ".gov.ma",
    ".gov.tn",
    ".gov.dz",
    ".gov.sd",
    ".gov.uk",
    ".gov.au",
    ".gov.nz",
    ".gov.sg",
    ".gov.in",
    ".gov.pk",
    ".gov.bd",
    ".gov.lk",
    ".gov.my",
    ".gov.jp",
    ".gov.kr",
    ".gov.cn",
    ".gov.br",
    ".gov.mx",
    ".gov.ar",
    ".gov.za",
    ".gov.ke",
    ".gov.ng",
    ".gov.gh",
    ".gov.ca",
    ".gov.us",
]

# Optional credentials for systems you are authorized to assess.
# Leave empty for unauthenticated scanning.
AUTH_HEADERS = {
    # "Authorization": "Bearer YOUR_TOKEN",
    # "Cookie": "session=YOUR_AUTHORIZED_SESSION",
}

C = Fore.LIGHTCYAN_EX
G = Fore.LIGHTGREEN_EX
Y = Fore.LIGHTYELLOW_EX
R = Fore.LIGHTRED_EX
M = Fore.LIGHTMAGENTA_EX
B = Fore.LIGHTBLUE_EX
W = Fore.WHITE
D = Style.DIM
RESET = Style.RESET_ALL

# Modern Kali-style terminal palette.
THEME = {
    "cyan": "\033[38;5;51m", "blue": "\033[38;5;45m",
    "purple": "\033[38;5;141m", "pink": "\033[38;5;213m",
    "green": "\033[38;5;120m", "yellow": "\033[38;5;226m",
    "orange": "\033[38;5;215m", "red": "\033[38;5;203m",
    "white": "\033[38;5;255m", "dim": "\033[38;5;245m",
}

def paint(text, color):
    return THEME.get(color, "") + text + RESET

def colorize_block(text, colors):
    lines = text.strip("\n").splitlines()
    return "\n".join(paint(line, colors[i % len(colors)]) for i, line in enumerate(lines))

def menu_block(text):
    result = []
    for line in text.strip("\n").splitlines():
        if "SCAN MENU" in line: color = "pink"
        elif "[1]" in line: color = "cyan"
        elif "[2]" in line: color = "purple"
        elif "[3]" in line: color = "yellow"
        elif "[4]" in line: color = "green"
        elif "[5]" in line: color = "red"
        elif any(x in line for x in ("═", "╔", "╚", "║", "╠")): color = "blue"
        else: color = "dim"
        result.append(paint(line, color))
    return "\n".join(result)


def out(*args, **kwargs):
    with PRINT_LOCK:
        print(*args, **kwargs)


def banner():
    os.system("cls" if os.name == "nt" else "clear")
    banner_art = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██╗   ██╗███████╗██╗   ██╗██████╗ ██╗ ██████╗ ███╗   ██╗║
║  ██║   ██║██╔════╝╚██╗ ██╔╝╚════██╗██║██╔═══██╗████╗  ██║║
║  ╚██╗ ██╔╝█████╗   ╚████╔╝  █████╔╝██║██║   ██║██╔██╗ ██║║
║   ╚████╔╝ ██╔══╝    ╚██╔╝   ╚═══██╗██║██║   ██║██║╚██╗██║║
║    ╚██╔╝  ███████╗   ██║   ██████╔╝██║╚██████╔╝██║ ╚████║║
║     ╚═╝   ╚══════╝   ╚═╝   ╚═════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═══╝║
║                                                              ║
║           WEB SECURITY ASSESSMENT FRAMEWORK                 ║
║                         v5.1                                 ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(colorize_block(banner_art, ["blue", "cyan", "purple", "pink", "cyan"]))
    print(paint("DOMAIN-ONLY • AUTHORIZED • NON-DESTRUCTIVE", "green"))
    print()


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def validate_domain(value):
    value = value.strip().lower()
    if not value or "://" in value:
        return None
    if any(x in value for x in ["/", "?", "#", ":"]):
        return None
    value = value.rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        return None
    return value


def base_url(domain):
    return f"https://{domain}/"


def in_scope(domain, url):
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    root = domain.lower().rstrip(".")
    return host == root or host.endswith("." + root)


def normalize_url(url):
    if not url or len(url) > MAX_URL_LENGTH:
        return None
    url, _ = urldefrag(url)
    p = urlparse(url)
    if p.scheme.lower() not in ("http", "https"):
        return None
    host = (p.hostname or "").lower()
    if not host:
        return None
    port = p.port
    netloc = host
    if port and not ((p.scheme == "http" and port == 80) or
                     (p.scheme == "https" and port == 443)):
        netloc += f":{port}"
    path = p.path or "/"
    return urlunparse((p.scheme.lower(), netloc, path, "", p.query, ""))


@dataclass
class Finding:
    finding_id: str
    category: str
    severity: str
    confidence: str
    domain: str
    url: str
    title: str
    evidence: str
    recommendation: str


@dataclass
class PageRecord:
    url: str
    status: int
    content_type: str
    length: int
    technologies: list


def severity_rank(value):
    return {
        "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3,
        "LOW": 2, "INFO": 1
    }.get(value, 0)


class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json,"
                      "text/plain;q=0.9,*/*;q=0.8",
        })
        if AUTH_HEADERS:
            self.session.headers.update(AUTH_HEADERS)

    def request(self, method, url, **kwargs):
        if STOP_EVENT.is_set():
            return None

        global LAST_REQUEST
        with RATE_LOCK:
            now = time.monotonic()
            wait = REQUEST_DELAY - (now - LAST_REQUEST)
            if wait > 0:
                time.sleep(wait)
            LAST_REQUEST = time.monotonic()

        last_error = None
        for attempt in range(RETRY_COUNT + 1):
            try:
                response = self.session.request(
                    method, url, timeout=TIMEOUT, allow_redirects=False,
                    stream=False, **kwargs
                )
                # Retry transient server/rate-limit responses only.
                if response.status_code in (429, 500, 502, 503, 504) and attempt < RETRY_COUNT:
                    time.sleep(min(2 ** attempt, 4))
                    continue
                return response
            except requests.RequestException as exc:
                last_error = exc
                if attempt < RETRY_COUNT:
                    time.sleep(min(2 ** attempt, 4))
        out(R + f"[HTTP] {url} -> {last_error}" + RESET)
        return None


def response_text(response):
    try:
        raw = response.content[:MAX_RESPONSE_BYTES]
        encoding = response.encoding or "utf-8"
        return raw.decode(encoding, errors="replace")
    except Exception:
        return ""


def safe_header(value):
    return value.replace("\r", " ").replace("\n", " ")


class Crawler:
    def __init__(self, domain, client):
        self.domain = domain
        self.client = client
        self.queue = deque([base_url(domain)])
        self.queued = {base_url(domain)}
        self.visited = set()
        self.pages = []
        self.discovered = set()

    def add(self, url):
        url = normalize_url(url)
        if not url or not in_scope(self.domain, url):
            return
        if url not in self.queued and url not in self.visited:
            self.queue.append(url)
            self.queued.add(url)

    def extract_links(self, current, text):
        soup = BeautifulSoup(text, "html.parser")

        for tag in soup.find_all("a", href=True):
            href = tag.get("href", "").strip()
            if not href or href.lower().startswith(
                ("javascript:", "mailto:", "tel:", "data:")
            ):
                continue
            target = normalize_url(urljoin(current, href))
            if target and in_scope(self.domain, target):
                self.discovered.add(target)
                self.add(target)

        # Discover common resource/API references without executing JS.
        for tag in soup.find_all(["script", "link"], src=True):
            target = normalize_url(urljoin(current, tag.get("src", "")))
            if target and in_scope(self.domain, target):
                self.discovered.add(target)

        for tag in soup.find_all("link", href=True):
            target = normalize_url(urljoin(current, tag.get("href", "")))
            if target and in_scope(self.domain, target):
                self.discovered.add(target)

    def run(self):
        while self.queue and len(self.visited) < MAX_PAGES and not STOP_EVENT.is_set():
            url = self.queue.popleft()
            if url in self.visited or not in_scope(self.domain, url):
                continue

            self.visited.add(url)
            out(B + f"[CRAWL {len(self.visited):03d}] {url}" + RESET)

            response = self.client.request("GET", url)
            if response is None:
                continue

            text = response_text(response)
            ctype = response.headers.get("Content-Type", "").lower()
            tech = detect_technology(response, text)

            self.pages.append((url, response, text))
            if "html" in ctype:
                self.extract_links(url, text)

        return self.pages


REQUIRED_HEADERS = {
    "strict-transport-security": (
        "MEDIUM", "Enable HSTS for HTTPS deployments."
    ),
    "content-security-policy": (
        "MEDIUM", "Define an appropriate Content-Security-Policy."
    ),
    "x-content-type-options": (
        "LOW", "Set X-Content-Type-Options: nosniff."
    ),
    "referrer-policy": (
        "LOW", "Define an explicit Referrer-Policy."
    ),
    "permissions-policy": (
        "LOW", "Define an appropriate Permissions-Policy."
    ),
}


def add_finding(findings, **kwargs):
    findings.append(Finding(**kwargs))


def audit_headers(domain, url, response, findings):
    headers = {k.lower(): v for k, v in response.headers.items()}

    for header, (severity, recommendation) in REQUIRED_HEADERS.items():
        if header not in headers:
            add_finding(
                findings,
                finding_id="VYR-HDR",
                category="Security Headers",
                severity=severity,
                confidence="HIGH",
                domain=domain,
                url=url,
                title=f"Missing {header}",
                evidence=f"Response does not contain {header}.",
                recommendation=recommendation,
            )

    if response.url.startswith("https://"):
        csp = headers.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp.lower():
            add_finding(
                findings,
                finding_id="VYR-CSP",
                category="Security Headers",
                severity="LOW",
                confidence="MEDIUM",
                domain=domain,
                url=url,
                title="CSP contains unsafe-inline",
                evidence=safe_header(csp[:500]),
                recommendation=(
                    "Review whether unsafe-inline can be removed "
                    "or replaced with nonces/hashes."
                ),
            )


def parse_set_cookie_headers(response):
    # Requests combines some headers, but getlist is available on raw headers.
    try:
        values = response.raw.headers.getlist("Set-Cookie")
        if values:
            return values
    except Exception:
        pass

    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def audit_cookies(domain, url, response, findings):
    for cookie in parse_set_cookie_headers(response):
        first = cookie.split(";", 1)[0]
        name = first.split("=", 1)[0].strip() or "(unnamed)"
        lower = cookie.lower()

        if "secure" not in lower:
            add_finding(
                findings,
                finding_id="VYR-COOKIE",
                category="Cookies",
                severity="MEDIUM",
                confidence="HIGH",
                domain=domain,
                url=url,
                title="Cookie without Secure flag",
                evidence=f"Cookie: {name}",
                recommendation="Set Secure for cookies that should only travel over HTTPS.",
            )

        if "httponly" not in lower:
            add_finding(
                findings,
                finding_id="VYR-COOKIE",
                category="Cookies",
                severity="MEDIUM",
                confidence="HIGH",
                domain=domain,
                url=url,
                title="Cookie without HttpOnly flag",
                evidence=f"Cookie: {name}",
                recommendation="Use HttpOnly where client-side JavaScript does not need the cookie.",
            )

        if "samesite" not in lower:
            add_finding(
                findings,
                finding_id="VYR-COOKIE",
                category="Cookies",
                severity="LOW",
                confidence="HIGH",
                domain=domain,
                url=url,
                title="Cookie without SameSite attribute",
                evidence=f"Cookie: {name}",
                recommendation="Set an appropriate SameSite policy.",
            )


def audit_cors(domain, url, response, findings):
    value = response.headers.get("Access-Control-Allow-Origin")
    if value and value.strip() == "*":
        add_finding(
            findings,
            finding_id="VYR-CORS",
            category="CORS",
            severity="LOW",
            confidence="HIGH",
            domain=domain,
            url=url,
            title="Wildcard CORS policy",
            evidence="Access-Control-Allow-Origin: *",
            recommendation=(
                "Use narrowly defined origins when cross-origin access "
                "to sensitive resources is required."
            ),
        )


def audit_disclosure(domain, url, response, findings):
    server = response.headers.get("Server")
    powered = response.headers.get("X-Powered-By")

    if server:
        add_finding(
            findings,
            finding_id="VYR-DISC",
            category="Information Disclosure",
            severity="INFO",
            confidence="HIGH",
            domain=domain,
            url=url,
            title="Server header exposed",
            evidence=f"Server: {safe_header(server)}",
            recommendation="Consider minimizing unnecessary technology disclosure.",
        )

    if powered:
        add_finding(
            findings,
            finding_id="VYR-DISC",
            category="Information Disclosure",
            severity="LOW",
            confidence="HIGH",
            domain=domain,
            url=url,
            title="Technology header exposed",
            evidence=f"X-Powered-By: {safe_header(powered)}",
            recommendation="Remove unnecessary framework identification headers.",
        )


def audit_transport(domain, client, findings):
    http_url = f"http://{domain}/"
    response = client.request("GET", http_url)
    if response is None:
        return

    location = response.headers.get("Location", "")
    if response.status_code not in (301, 302, 303, 307, 308):
        add_finding(
            findings,
            finding_id="VYR-TLS",
            category="Transport Security",
            severity="MEDIUM",
            confidence="HIGH",
            domain=domain,
            url=http_url,
            title="HTTP is not redirected to HTTPS",
            evidence=f"HTTP status: {response.status_code}; Location: {location or 'none'}",
            recommendation="Redirect HTTP traffic to HTTPS.",
        )
    elif not urljoin(http_url, location).startswith("https://"):
        add_finding(
            findings,
            finding_id="VYR-TLS",
            category="Transport Security",
            severity="MEDIUM",
            confidence="HIGH",
            domain=domain,
            url=http_url,
            title="HTTP redirect does not clearly lead to HTTPS",
            evidence=f"HTTP status: {response.status_code}; Location: {location or 'none'}",
            recommendation="Redirect HTTP traffic to HTTPS.",
        )


def audit_html(domain, url, response, findings):
    ctype = response.headers.get("Content-Type", "").lower()
    if "html" not in ctype:
        return

    text = response_text(response)
    soup = BeautifulSoup(text, "html.parser")

    if url.startswith("https://"):
        for tag in soup.find_all(src=True):
            src = tag.get("src", "").strip()
            if src.lower().startswith("http://"):
                add_finding(
                    findings,
                    finding_id="VYR-MIXED",
                    category="Content Security",
                    severity="MEDIUM",
                    confidence="HIGH",
                    domain=domain,
                    url=url,
                    title="Mixed content detected",
                    evidence=src,
                    recommendation="Load active/passive resources over HTTPS.",
                )

        for tag in soup.find_all(href=True):
            href = tag.get("href", "").strip()
            if href.lower().startswith("http://"):
                add_finding(
                    findings,
                    finding_id="VYR-MIXED",
                    category="Content Security",
                    severity="MEDIUM",
                    confidence="HIGH",
                    domain=domain,
                    url=url,
                    title="HTTP resource/link on HTTPS page",
                    evidence=href,
                    recommendation="Use HTTPS resources where applicable.",
                )

    for form in soup.find_all("form"):
        method = form.get("method", "get").lower()
        action = form.get("action", "")
        inputs = form.find_all(["input", "textarea", "select"])

        if method == "post":
            names = [x.get("name", "").lower() for x in inputs]
            csrf_words = ("csrf", "xsrf", "authenticity", "antiforgery", "verificationtoken")
            has_token = any(any(w in n for w in csrf_words) for n in names)

            if not has_token:
                add_finding(
                    findings,
                    finding_id="VYR-CSRF",
                    category="Forms",
                    severity="LOW",
                    confidence="LOW",
                    domain=domain,
                    url=url,
                    title="POST form without an obvious CSRF token",
                    evidence=f"Form action: {action or '(current page)'}",
                    recommendation=(
                        "Manually verify CSRF protection. This heuristic does not "
                        "prove that the form is vulnerable."
                    ),
                )

        if method == "get":
            for field in inputs:
                name = field.get("name", "").lower()
                if any(word in name for word in ("password", "passwd", "secret")):
                    # Password fields should normally use POST rather than GET.
                    add_finding(
                        findings,
                        finding_id="VYR-FORM",
                        category="Forms",
                        severity="MEDIUM",
                        confidence="HIGH",
                        domain=domain,
                        url=url,
                        title="Potential sensitive field in GET form",
                        evidence=f"Field: {field.get('name', '')}",
                        recommendation="Avoid transmitting sensitive values in URLs.",
                    )


SQL_PATTERNS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"mysql_fetch",
        r"mysqli?_",
    ],
    "PostgreSQL": [
        r"postgresql.*error",
        r"pg_query",
        r"syntax error at or near",
    ],
    "MSSQL": [
        r"microsoft sql server",
        r"unclosed quotation mark",
        r"sql server.*error",
    ],
    "Oracle": [
        r"ora-\d{5}",
        r"oracle.*error",
    ],
    "SQLite": [
        r"sqlite error",
        r"sqlite3\.operationalerror",
    ],
}


def detect_sql_errors(text):
    found = []
    sample = text[:MAX_RESPONSE_BYTES]
    for db, patterns in SQL_PATTERNS.items():
        if any(re.search(pattern, sample, re.I) for pattern in patterns):
            found.append(db)
    return found


def audit_parameters(domain, url, client, findings):
    if not ENABLE_SQL_ERROR_CHECK:
        return
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return

    # Conservative, non-destructive indicator check.
    # One quote marker is used only to see whether the application exposes
    # database error messages. It does not attempt exploitation.
    for name, original in params[:MAX_PARAMETERS_PER_URL]:
        if not name:
            continue

        modified = [(k, "'" if k == name else v) for k, v in params]
        query = urlencode(modified, doseq=True)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, "", query, ""
        ))

        response = client.request("GET", test_url)
        if response is None:
            continue

        databases = detect_sql_errors(response_text(response))
        if databases:
            add_finding(
                findings,
                finding_id="VYR-SQL-ERROR",
                category="Injection Indicators",
                severity="HIGH",
                confidence="MEDIUM",
                domain=domain,
                url=url,
                title="Possible SQL error disclosure",
                evidence=(
                    f"Parameter: {name}; Database indicators: "
                    f"{', '.join(databases)}"
                ),
                recommendation=(
                    "Review server-side parameter handling and use "
                    "parameterized queries. This result is an indicator, "
                    "not proof of exploitable SQL injection."
                ),
            )


def detect_technology(response, text=""):
    technologies = []
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")

    checks = [
        ("nginx", server, "nginx"),
        ("apache", server, "Apache"),
        ("cloudflare", server, "Cloudflare"),
        ("php", powered, "PHP"),
        ("express", powered, "Express"),
        ("asp.net", powered, "ASP.NET"),
    ]
    for needle, haystack, label in checks:
        if needle in haystack:
            technologies.append(label)

    lower = text.lower()
    if "wp-content/" in lower or "wp-includes/" in lower:
        technologies.append("WordPress")
    if "__next_data__" in lower or "/_next/" in lower:
        technologies.append("Next.js")
    if "ng-version" in lower:
        technologies.append("Angular")
    if "data-reactroot" in lower:
        technologies.append("React")

    return sorted(set(technologies))


def discover_robots_and_sitemap(domain, client):
    discovered = set()

    robots_url = f"https://{domain}/robots.txt"
    response = client.request("GET", robots_url)
    if response and response.status_code < 400:
        for line in response_text(response).splitlines():
            if line.lower().startswith("sitemap:"):
                target = line.split(":", 1)[1].strip()
                if target and in_scope(domain, target):
                    discovered.add(target)

    sitemap_url = f"https://{domain}/sitemap.xml"
    response = client.request("GET", sitemap_url)
    if response and response.status_code < 400:
        text = response_text(response)
        try:
            root = ET.fromstring(text)
            for loc in root.iter():
                if loc.tag.lower().endswith("loc") and loc.text:
                    target = normalize_url(loc.text.strip())
                    if target and in_scope(domain, target):
                        discovered.add(target)
        except ET.ParseError:
            pass

    return discovered


def deduplicate(findings):
    seen = set()
    output = []
    for finding in findings:
        key = (
            finding.finding_id, finding.url,
            finding.title, finding.evidence
        )
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return sorted(output, key=lambda x: (
        -severity_rank(x.severity), x.category, x.url, x.title
    ))


def scan_domain(domain):
    client = HTTPClient()
    findings = []

    out(M + f"\n{'=' * 64}\nVEYRiON TARGET: {domain}\n{'=' * 64}" + RESET)

    audit_transport(domain, client, findings)

    sitemap_urls = discover_robots_and_sitemap(domain, client)
    if sitemap_urls:
        out(G + f"[+] Sitemap URLs discovered: {len(sitemap_urls)}" + RESET)

    crawler = Crawler(domain, client)
    for target in sitemap_urls:
        crawler.add(target)

    pages = crawler.run()
    out(G + f"[+] Discovered pages: {len(pages)}" + RESET)

    for index, (url, response, text) in enumerate(pages, 1):
        if STOP_EVENT.is_set():
            break

        out(C + f"[AUDIT {index:03d}] {url}" + RESET)

        audit_headers(domain, url, response, findings)
        audit_cookies(domain, url, response, findings)
        audit_cors(domain, url, response, findings)
        audit_disclosure(domain, url, response, findings)
        audit_html(domain, url, response, findings)
        audit_parameters(domain, url, client, findings)

        tech = detect_technology(response, text)
        if tech:
            out(D + f"    Technology: {', '.join(tech)}" + RESET)

    return deduplicate(findings), pages, crawler.discovered


def save_reports(domain, findings, pages=None, discovered=None):
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = os.path.join(REPORT_DIR, f"{domain}_{timestamp}")

    data = [asdict(x) for x in findings]
    severity_counts = Counter(x.severity for x in findings)

    payload = {
        "tool": "VEYRiON",
        "version": VERSION,
        "domain": domain,
        "generated": datetime.now().isoformat(),
        "authorized_mode": True,
        "non_destructive": True,
        "summary": dict(severity_counts),
        "pages_scanned": len(pages or []),
        "discovered_urls": len(discovered or []),
        "findings": data,
    }

    json_file = prefix + ".json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)

    rows = []
    for item in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.severity)}</td>"
            f"<td>{html.escape(item.category)}</td>"
            f"<td>{html.escape(item.title)}</td>"
            f"<td>{html.escape(item.confidence)}</td>"
            f"<td>{html.escape(item.url)}</td>"
            f"<td>{html.escape(item.evidence)}</td>"
            f"<td>{html.escape(item.recommendation)}</td>"
            "</tr>"
        )

    page_rows = []
    for url, response, text in (pages or []):
        page_rows.append(
            "<tr>"
            f"<td>{html.escape(url)}</td>"
            f"<td>{response.status_code}</td>"
            f"<td>{html.escape(response.headers.get('Content-Type', ''))}</td>"
            f"<td>{len(text)}</td>"
            f"<td>{html.escape(', '.join(detect_technology(response, text)))}</td>"
            "</tr>"
        )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VEYRiON Report - {html.escape(domain)}</title>
<style>
body{{background:#0b0f14;color:#e6edf3;font-family:Arial,sans-serif;margin:24px}}
h1{{color:#55d6ff}} h2{{color:#9cdcfe}}
table{{width:100%;border-collapse:collapse;margin:16px 0}}
th,td{{padding:10px;border:1px solid #30363d;vertical-align:top;text-align:left}}
th{{background:#161b22}} td{{word-break:break-word}}
.badge{{display:inline-block;padding:6px 10px;margin:3px;border-radius:6px;background:#161b22}}
</style>
</head>
<body>
<h1>VEYRiON Security Assessment</h1>
<p><b>Domain:</b> {html.escape(domain)}</p>
<p><b>Generated:</b> {html.escape(generated)}</p>
<p><b>Pages scanned:</b> {len(pages or [])}</p>
<p><b>Discovered URLs:</b> {len(discovered or [])}</p>
<h2>Summary</h2>
{"".join(f'<span class="badge">{html.escape(k)}: {v}</span>' for k,v in severity_counts.items())}
<h2>Findings</h2>
<table>
<tr><th>Severity</th><th>Category</th><th>Finding</th><th>Confidence</th><th>URL</th><th>Evidence</th><th>Recommendation</th></tr>
{"".join(rows) or '<tr><td colspan="7">No findings recorded.</td></tr>'}
</table>
<h2>Scanned Pages</h2>
<table>
<tr><th>URL</th><th>Status</th><th>Content-Type</th><th>Bytes/Text Length</th><th>Technologies</th></tr>
{"".join(page_rows) or '<tr><td colspan="5">No pages scanned.</td></tr>'}
</table>
</body>
</html>"""

    html_file = prefix + ".html"
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_report)

    return json_file, html_file


def save_csv(domain, findings):
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = os.path.join(REPORT_DIR, f"{domain}_{timestamp}_findings.csv")
    fields = ["finding_id", "category", "severity", "confidence", "domain", "url", "title", "evidence", "recommendation"]
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))
    return csv_file


def write_scan_log(domain, message):
    os.makedirs(REPORT_DIR, exist_ok=True)
    log_file = os.path.join(REPORT_DIR, f"{domain}_veyrion.log")
    logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info(message)


def summary(findings):
    counts = Counter(f.severity for f in findings)
    print()
    print(C + "╔══════════════════════════════════════════════╗")
    print(C + "║              VEYRiON SUMMARY                ║")
    print(C + "╠══════════════════════════════════════════════╣")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(C + f"║ {severity:<10} : {counts.get(severity, 0):<20}║")
    print(C + f"║ {'TOTAL':<10} : {len(findings):<20}║")
    print(C + "╚══════════════════════════════════════════════╝")


def load_domains():
    domains = []
    for line in AUTHORIZED_DOMAINS:
        line = str(line).strip()
        if not line or line.startswith("#"):
            continue
        domain = validate_domain(line)
        if domain:
            domains.append(domain)
    return list(dict.fromkeys(domains))


def ask_domain():
    while True:
        value = input(C + "Enter authorized domain: " + RESET).strip()
        domain = validate_domain(value)
        if domain:
            return domain
        print(R + "[!] Domain only. Example: example.com" + RESET)


def finish_report(domain, findings, pages, discovered):
    summary(findings)
    files = save_reports(domain, findings, pages, discovered)
    csv_file = save_csv(domain, findings)
    write_scan_log(domain, f"Completed scan: pages={len(pages)} findings={len(findings)}")
    print(G + f"\n[+] JSON: {files[0]}" + RESET)
    print(G + f"[+] HTML: {files[1]}" + RESET)
    print(G + f"[+] CSV : {csv_file}" + RESET)


def run_single():
    domain = ask_domain()
    findings, pages, discovered = scan_domain(domain)
    finish_report(domain, findings, pages, discovered)


def run_random():
    domains = load_domains()
    if not domains:
        print(R + "[!] AUTHORIZED_DOMAINS contains no valid domains." + RESET)
        return
    domain = random.choice(domains)
    print(G + f"[+] Selected: {domain}" + RESET)
    findings, pages, discovered = scan_domain(domain)
    finish_report(domain, findings, pages, discovered)


def run_list():
    domains = load_domains()
    if not domains:
        print(R + "[!] No authorized domains found." + RESET)
        return

    all_findings = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(scan_domain, domain): domain
            for domain in domains
        }
        for future in as_completed(futures):
            if STOP_EVENT.is_set():
                break
            domain = futures[future]
            try:
                findings, pages, discovered = future.result()
                all_findings.extend(findings)
                save_reports(domain, findings, pages, discovered)
            except Exception as exc:
                out(R + f"[!] {domain}: {exc}" + RESET)

    summary(deduplicate(all_findings))


def stop_handler(signum, frame):
    STOP_EVENT.set()
    print(Y + "\n[!] Safe shutdown requested..." + RESET)


signal.signal(signal.SIGINT, stop_handler)


def build_parser():
    parser = argparse.ArgumentParser(
        description="VEYRiON - Authorized, non-destructive web security assessment tool"
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("-d", "--domain", help="Single authorized domain, e.g. example.com")
    target.add_argument("--domains-file", help="Text file containing one authorized domain per line")
    parser.add_argument("--max-pages", type=int, default=None, help="Maximum pages to crawl")
    parser.add_argument("--workers", type=int, default=None, help="Workers for domain-list mode")
    parser.add_argument("--delay", type=float, default=None, help="Delay between requests in seconds")
    parser.add_argument("--timeout", type=int, default=None, help="HTTP timeout in seconds")
    parser.add_argument("--output", default=None, help="Output directory for reports")
    parser.add_argument("--enable-sql-check", action="store_true", help="Enable conservative SQL-error indicator checks")
    parser.add_argument("--i-accept-responsibility", dest="accept_responsibility", action="store_true", help="Acknowledge responsibility and skip the confirmation prompt")
    # Backward-compatible alias; the displayed interface uses the responsibility wording.
    parser.add_argument("--yes-i-am-authorized", dest="accept_responsibility", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-banner", action="store_true", help="Do not show the banner")
    parser.add_argument("--version", action="version", version=f"VEYRiON {VERSION}")
    return parser


def apply_cli_options(args):
    global MAX_PAGES, MAX_WORKERS, REQUEST_DELAY, TIMEOUT, REPORT_DIR, ENABLE_SQL_ERROR_CHECK
    if args.max_pages is not None:
        MAX_PAGES = max(1, min(args.max_pages, 10000))
    if args.workers is not None:
        MAX_WORKERS = max(1, min(args.workers, 16))
    if args.delay is not None:
        REQUEST_DELAY = max(0.0, args.delay)
    if args.timeout is not None:
        TIMEOUT = max(1, min(args.timeout, 120))
    if args.output:
        REPORT_DIR = os.path.abspath(args.output)
    ENABLE_SQL_ERROR_CHECK = bool(args.enable_sql_check)


def responsibility_confirmation(domain, skip=False):
    if skip:
        return True
    answer = input(Y + f"Do you accept full responsibility for scanning {domain}? [y/n]: " + RESET).strip().lower()
    return answer in ("y", "yes")


def run_cli(args):
    if args.domain:
        domain = validate_domain(args.domain)
        if not domain:
            print(R + "[!] Invalid domain. Use domain only, e.g. example.com" + RESET)
            return 2
        if not responsibility_confirmation(domain, args.accept_responsibility):
            print(Y + "[!] Scan cancelled: responsibility was not accepted." + RESET)
            return 3
        findings, pages, discovered = scan_domain(domain)
        finish_report(domain, findings, pages, discovered)
        return 2 if any(x.severity in ("HIGH", "CRITICAL") for x in findings) else 0
    if args.domains_file:
        if not os.path.isfile(args.domains_file):
            print(R + f"[!] Domains file not found: {args.domains_file}" + RESET)
            return 1
        with open(args.domains_file, encoding="utf-8") as f:
            domains = [validate_domain(x.strip()) for x in f if x.strip() and not x.lstrip().startswith("#")]
        domains = list(dict.fromkeys(x for x in domains if x))
        if not domains:
            print(R + "[!] No valid domains found in file." + RESET)
            return 1
        if not args.accept_responsibility:
            answer = input(Y + f"Do you accept full responsibility for scanning {len(domains)} domains? [y/n]: " + RESET).strip().lower()
            if answer not in ("y", "yes"):
                print(Y + "[!] Scan cancelled." + RESET)
                return 3
        # Preserve the existing list-mode behavior while using the file targets.
        global AUTHORIZED_DOMAINS
        old_domains = AUTHORIZED_DOMAINS
        AUTHORIZED_DOMAINS = domains
        try:
            run_list()
        finally:
            AUTHORIZED_DOMAINS = old_domains
        return 0
    return None


def main():
    args = build_parser().parse_args()
    apply_cli_options(args)
    if not args.no_banner:
        banner()
    cli_result = run_cli(args)
    if cli_result is not None:
        return cli_result

    while not STOP_EVENT.is_set():
        menu_text = r"""
╔══════════════════════════════════════════════════════════════╗
║                         SCAN MENU                            ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  [1] Random Authorized Domain                               ║
║  [2] Single Authorized Domain                               ║
║  [3] Scan Authorized Domain List                            ║
║  [4] Show Domain List                                       ║
║  [5] Exit                                                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(menu_block(menu_text))
        choice = input(paint("VEYRiON > ", "orange")).strip()

        try:
            if choice == "1":
                run_random()
            elif choice == "2":
                run_single()
            elif choice == "3":
                run_list()
            elif choice == "4":
                domains = load_domains()
                print()
                for i, domain in enumerate(domains, 1):
                    print(f"{i:03d}. {domain}")
            elif choice == "5":
                break
            else:
                print(R + "[!] Invalid option." + RESET)
        except KeyboardInterrupt:
            stop_handler(None, None)
        except Exception as exc:
            print(R + f"[!] Unexpected error: {exc}" + RESET)

        if not STOP_EVENT.is_set():
            input("\nPress ENTER to continue...")
            banner()


if __name__ == "__main__":
    raise SystemExit(main() or 0)
