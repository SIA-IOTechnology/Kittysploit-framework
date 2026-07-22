from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort, OptBool, OptInteger
from core.output_handler import print_error, print_status

import heapq
import json
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit, urlparse
import pathlib
from requests.auth import HTTPBasicAuth
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

_NEXT_DATA_BUILD_RE = re.compile(r'"buildId"\s*:\s*"([^"]+)"')
_NEXT_DATA_PATH_RE = re.compile(r'"(?:page|pathname)"\s*:\s*"([^"]+)"')
_API_PATH_RE = re.compile(r'["\'](/api[^"\']*)["\']')
_NEXT_DATA_ROUTE_RE = re.compile(r'/_next/data/[^"\']+')


class Http_crawler(BaseModule):

    target = OptString("mytarget.com", "Target domain/ip", True)
    port = OptPort(443, "Target HTTP port", True)
    ssl = OptBool(True, "SSL enabled: true/false", True, advanced=True)
    max_crawl = OptInteger(20, "Number of links to crawl, (if 0 = all links)", True)
    max_threads = OptInteger(5, "Maximum number of threads (legacy mode only)", True, advanced=True)
    request_timeout = OptInteger(15, "Request timeout in seconds", True, advanced=True)
    crawler_user = OptString("admin", "User for basic authentication", True, advanced=True)
    crawler_password = OptString("admin", "Password for basic authentication", True, advanced=True)
    seed_paths = OptString("", "Comma-separated priority seed paths (e.g. /,/robots.txt,/api)", False, advanced=True)
    intelligent = OptBool(True, "Guided crawl: forms, scripts, robots, Next.js/API routes", True, advanced=True)
    follow_forms = OptBool(True, "Enqueue form action URLs", True, advanced=True)
    follow_scripts = OptBool(True, "Enqueue same-origin script URLs", True, advanced=True)

    def __init__(self):
        super().__init__()
        self._output = []

    def crawler_start(self):
        if not self.target.startswith("http"):
            if self.ssl:
                if not self.target.startswith("https://"):
                    self.target = "https://" + self.target
            else:
                if not self.target.startswith("http://"):
                    self.target = "http://" + self.target

        if int(self.port) != 80 and int(self.port) != 443:
            target = self.target + ":" + str(self.port)
        else:
            target = self.target

        u = urlsplit(self.target)
        if u.path == '':
            self.target += "/"

        seed_list = [
            p.strip() for p in str(self.seed_paths or "").split(",") if str(p).strip()
        ]

        crawler = Crawler_core(
            target=self.target,
            max_threads=self.max_threads,
            max_crawl=self.max_crawl,
            request_timeout=self.request_timeout,
            user=self.crawler_user,
            password=self.crawler_password,
            intelligent=bool(self.intelligent),
            follow_forms=bool(self.follow_forms),
            follow_scripts=bool(self.follow_scripts),
            seed_paths=seed_list,
        )

        crawler.start_crawl(self.target)
        self._output += crawler.links


class Crawler_core:

    PRIORITY_HIGH = 10
    PRIORITY_NORMAL = 40
    PRIORITY_LOW = 70

    def __init__(
        self,
        target,
        max_threads=1,
        max_crawl=0,
        request_timeout=15,
        user="admin",
        password="admin",
        *,
        intelligent=True,
        follow_forms=True,
        follow_scripts=True,
        seed_paths=None,
    ):
        self.target_domain = urlparse(target).netloc
        self.links = set()
        self.max_threads = max_threads
        self.max_crawl = max_crawl
        self.request_timeout = request_timeout
        self.crawler_user = user
        self.crawler_password = password
        self.intelligent = bool(intelligent)
        self.follow_forms = bool(follow_forms)
        self.follow_scripts = bool(follow_scripts)
        self.seed_paths = list(seed_paths or [])
        self.ignored_extensions = ["gif", "jpg", "png", "css", "jpeg", "woff", "ttf", "eot", "svg", "woff2", "ico"]
        self.js_extensions = ["js"]
        self.static_extensions = ["html", "htm", "xhtml", "xhtm", "shtml", "txt", "json", "xml"]
        self.scripts_extensions = ["php", "jsp", "asp", "aspx", "py", "pl", "ashx", "php1", "php2", "php3", "php4"]
        self.cpt = 0
        self.crawled = set()
        self._queue: List[tuple] = []
        self._seq = 0
        self.ssl_warning_shown = False
        self._host_unreachable = False
        self._connection_error_logged = False

    _CONNECTION_ERROR_MARKERS = (
        "connection refused",
        "failed to establish a new connection",
        "max retries exceeded",
        "no route to host",
        "network is unreachable",
        "name or service not known",
        "nodename nor servname provided",
        "connection timeout",
        "connect timeout",
        "timed out",
    )

    def _is_connection_error(self, exc: BaseException) -> bool:
        blob = str(exc).lower()
        return any(marker in blob for marker in self._CONNECTION_ERROR_MARKERS)

    def _mark_connection_failure(self, exc: BaseException) -> None:
        if not self._is_connection_error(exc):
            return
        self._host_unreachable = True
        if not self._connection_error_logged:
            print_error(f"Target unreachable, aborting crawl: {exc}")
            self._connection_error_logged = True

    def start_crawl(self, url):
        if self.intelligent:
            self._start_crawl_intelligent(url)
        else:
            self._start_crawl_legacy(url)

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _enqueue(self, url: str, priority: int = PRIORITY_NORMAL) -> None:
        if not url or url in self.crawled:
            return
        if urlparse(url).netloc != self.target_domain:
            return
        ext = self.extension(url).lower()
        if ext in self.ignored_extensions:
            return
        self._seq += 1
        heapq.heappush(self._queue, (priority, self._seq, url))

    def _fetch(self, url: str):
        if self._host_unreachable:
            raise requests.RequestException("Target host unreachable (circuit open)")
        return requests.get(
            url,
            timeout=self.request_timeout,
            auth=HTTPBasicAuth(self.crawler_user, self.crawler_password),
            verify=False,
        )

    def _start_crawl_intelligent(self, url: str) -> None:
        self.crawlerstart()
        origin = self._origin(url)
        for path in self.seed_paths:
            if self._host_unreachable:
                break
            if path.startswith("/"):
                self._enqueue(urljoin(origin, path), self.PRIORITY_HIGH)
        if not self._host_unreachable:
            self._enqueue(url, self.PRIORITY_HIGH)
            self._bootstrap_robots_sitemap(origin)

        while self._queue and (self.cpt < self.max_crawl or self.max_crawl == 0):
            if self._host_unreachable:
                break
            _prio, _seq, current_url = heapq.heappop(self._queue)
            if current_url in self.crawled:
                continue
            self.crawled.add(current_url)
            self._crawl_intelligent(current_url)

        self.crawlerfinish()

    def _bootstrap_robots_sitemap(self, origin: str) -> None:
        for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
            if self._host_unreachable:
                break
            try:
                resp = self._fetch(origin + path)
            except requests.RequestException as exc:
                self._mark_connection_failure(exc)
                break
            if resp.status_code != 200:
                continue
            text = resp.text or ""
            if path.endswith(".txt"):
                for line in text.splitlines():
                    low = line.strip().lower()
                    if low.startswith("sitemap:"):
                        loc = line.split(":", 1)[1].strip()
                        if urlparse(loc).netloc == self.target_domain:
                            self._enqueue(loc, self.PRIORITY_HIGH)
                    elif low.startswith("allow:"):
                        allow_path = line.split(":", 1)[1].strip()
                        if allow_path.startswith("/"):
                            self._enqueue(urljoin(origin, allow_path), self.PRIORITY_HIGH)
            else:
                for loc in re.findall(r"<loc>([^<]+)</loc>", text, re.I):
                    if urlparse(loc.strip()).netloc == self.target_domain:
                        self._enqueue(loc.strip(), self.PRIORITY_HIGH)

    def _crawl_intelligent(self, url: str) -> None:
        if self.max_crawl and self.cpt >= self.max_crawl:
            return
        if self._host_unreachable:
            return
        try:
            response = self._fetch(url)
        except requests.exceptions.SSLError:
            if not self.ssl_warning_shown:
                print_error("Certificat SSL invalide")
                self.ssl_warning_shown = True
            return
        except requests.RequestException as exc:
            self._mark_connection_failure(exc)
            return

        if response.status_code not in (200, 301, 302, 401, 403):
            return

        self.requeststart(url)
        body = response.text or ""
        soup = BeautifulSoup(body, "html.parser")

        for link in soup.find_all("a", href=True):
            absolute_link = urljoin(url, link["href"])
            if self._same_origin(absolute_link):
                self._register_link(absolute_link, self.PRIORITY_NORMAL)

        if self.follow_forms:
            for form in soup.find_all("form"):
                action = form.get("action") or url
                action_url = urljoin(url, action)
                if self._same_origin(action_url):
                    self._register_link(action_url, self.PRIORITY_HIGH)

        if self.follow_scripts:
            for script in soup.find_all("script", src=True):
                src = urljoin(url, script["src"])
                if self._same_origin(src) and self.extension(src).lower() in self.js_extensions:
                    self._register_link(src, self.PRIORITY_NORMAL)

        self._extract_nextjs_and_api(body, url)
        self.requestfinish(url)

    def _extract_nextjs_and_api(self, body: str, base_url: str) -> None:
        low = body.lower()
        for match in _NEXT_DATA_ROUTE_RE.findall(body):
            self._register_link(urljoin(base_url, match), self.PRIORITY_HIGH)
        for match in _API_PATH_RE.findall(body):
            self._register_link(urljoin(base_url, match), self.PRIORITY_HIGH)

        if "__next_data__" in low or "buildid" in low:
            build_id = ""
            m = _NEXT_DATA_BUILD_RE.search(body)
            if m:
                build_id = m.group(1)
            pages = _NEXT_DATA_PATH_RE.findall(body)
            if build_id:
                for page in pages[:12]:
                    page_path = page if page.startswith("/") else f"/{page}"
                    data_url = f"/_next/data/{build_id}{page_path}.json"
                    self._register_link(urljoin(base_url, data_url), self.PRIORITY_HIGH)
                self._register_link(
                    urljoin(base_url, f"/_next/data/{build_id}/index.json"),
                    self.PRIORITY_HIGH,
                )
            try:
                for script in BeautifulSoup(body, "html.parser").find_all("script", id="__NEXT_DATA__"):
                    payload = script.string or ""
                    if not payload.strip():
                        continue
                    data = json.loads(payload)
                    bid = str(data.get("buildId") or build_id or "")
                    page = str((data.get("page") or data.get("pathname") or "/"))
                    if bid:
                        page_path = page if page.startswith("/") else f"/{page}"
                        self._register_link(
                            urljoin(base_url, f"/_next/data/{bid}{page_path}.json"),
                            self.PRIORITY_HIGH,
                        )
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

    def _same_origin(self, url: str) -> bool:
        return urlparse(url).netloc == self.target_domain

    def _register_link(self, absolute_link: str, priority: int) -> None:
        if absolute_link in self.crawled:
            return
        ext = self.extension(absolute_link).lower()
        if ext in self.ignored_extensions:
            return
        if self.max_crawl and self.cpt >= self.max_crawl:
            return
        if absolute_link not in self.links:
            self.links.add(absolute_link)
            self.cpt += 1
            print_status(f"Found link: {absolute_link}")
        self._enqueue(absolute_link, priority)

    def _start_crawl_legacy(self, url: str) -> None:
        import queue
        from concurrent.futures import ThreadPoolExecutor

        to_crawl = queue.Queue()
        self.crawlerstart()
        to_crawl.put(url)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while not to_crawl.empty() and (self.cpt < self.max_crawl or self.max_crawl == 0):
                current_url = to_crawl.get()
                if current_url not in self.crawled:
                    self.crawled.add(current_url)
                    executor.submit(self._crawl_legacy, current_url, to_crawl)

        self.crawlerfinish()

    def _crawl_legacy(self, url, to_crawl):
        if self.cpt == self.max_crawl and self.max_crawl != 0:
            return

        try:
            response = self._fetch(url)
            if response.status_code == 200:
                self.requeststart(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    absolute_link = urljoin(url, link['href'])
                    link_domain = urlparse(absolute_link).netloc
                    if (self.extension(absolute_link).lower() not in self.ignored_extensions
                        and absolute_link not in self.crawled
                        and link_domain == self.target_domain):
                        if self.cpt < self.max_crawl or self.max_crawl == 0:
                            self.links.add(absolute_link)
                            self.cpt += 1
                            print_status(f"Found link: {absolute_link}")
                            to_crawl.put(absolute_link)
                self.requestfinish(url)
        except requests.exceptions.SSLError:
            if not self.ssl_warning_shown:
                print_error("Certificat SSL invalide")
                self.ssl_warning_shown = True
        except requests.RequestException as e:
            print_error(f"Failed to crawl {url}: {e}")

    def extension(self, url):
        path = urlparse(url).path
        return pathlib.Path(path).suffix[1:]

    def crawlerstart(self):
        print_status("Crawler started")

    def crawlerfinish(self):
        print_status("Crawler finished")

    def requeststart(self, url):
        print_status(f"Starting request: {url}")

    def requestfinish(self, url):
        print_status(f"Finished request: {url}")
