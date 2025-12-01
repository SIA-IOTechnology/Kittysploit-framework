from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort, OptBool, OptInteger
from core.output_handler import print_error, print_status

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit, urlparse
import pathlib
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor
import queue
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

class Http_crawler(BaseModule):
    
    target = OptString("mytarget.com", "Target domain/ip", "yes")
    port = OptPort(80, "Target HTTP port", "yes")
    ssl = OptBool(True, "SSL enabled: true/false", "no", True)
    max_crawl = OptInteger(20, "Number of links to crawl, (if 0 = all links)", True)
    max_threads = OptInteger(5, "Maximum number of threads", True)  # Adjusted default to 5 for better manageability
    request_timeout = OptInteger(15, "Request timeout in seconds", True)
    crawler_user = OptString("admin", "User for basic authentication", True)
    crawler_password = OptString("admin", "Password for basic authentication", True)
    
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

        crawler = Crawler_core(target=self.target,
                               max_threads=self.max_threads,
                               max_crawl=self.max_crawl,
                               request_timeout=self.request_timeout,
                               user=self.crawler_user,
                               password=self.crawler_password)
        
        crawler.start_crawl(target)
        self._output += crawler.links

class Crawler_core:

    def __init__(self, target, max_threads=1, max_crawl=0, request_timeout=15, user="admin", password="admin"):
        self.target_domain = urlparse(target).netloc
        self.links = set()  # Use set to store unique links
        self.max_threads = max_threads
        self.max_crawl = max_crawl
        self.request_timeout = request_timeout
        self.crawler_user = user
        self.crawler_password = password
        self.ignored_extensions = ["gif", "jpg", "png", "css", "jpeg", "woff", "ttf", "eot", "svg", "woff2", "ico"]
        self.js_extensions = ["js"]
        self.static_extensions = ["html", "htm", "xhtml", "xhtm", "shtml", "txt"]
        self.scripts_extensions = ["php", "jsp", "asp", "aspx", "py", "pl", "ashx", "php1", "php2", "php3", "php4"]
        self.cpt = 0
        self.to_crawl = queue.Queue()
        self.crawled = set()
        self.ssl_warning_shown = False

    def start_crawl(self, url):
        self.crawlerstart()
        self.to_crawl.put(url)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while not self.to_crawl.empty() and (self.cpt < self.max_crawl or self.max_crawl == 0):
                current_url = self.to_crawl.get()
                if current_url not in self.crawled:
                    self.crawled.add(current_url)
                    executor.submit(self._crawl, current_url)
        
        self.crawlerfinish()

    def _crawl(self, url):
        if self.cpt == self.max_crawl and self.max_crawl != 0:
            return

        try:
            response = requests.get(url, timeout=self.request_timeout, auth=HTTPBasicAuth(self.crawler_user, self.crawler_password), verify=False)  # Disable SSL verification
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
                            self.to_crawl.put(absolute_link)
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
