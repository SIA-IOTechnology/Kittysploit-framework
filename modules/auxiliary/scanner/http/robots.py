from kittysploit import *
from lib.protocols.http.http_client import Http_client
from colorama import Fore, Style
        
class Module(Auxiliary, Http_client):


    __info__ = {
        'name': 'Check robots.txt',
        'description': 'Crawl a web site and store information about what was found',	
        'author': 'KittySploit Team',
        'tags': ['web', 'scanner'],
        }
    
    def default_options(self):
        options = {}
        options['port'] = 443
        options['ssl'] = 'true'
        options['uripath'] = '/robots.txt'
        return options

    def color_green(self, text):
        """Return text with green color"""
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
    
    def color_red(self, text):
        """Return text with red color"""
        return f"{Fore.RED}{text}{Style.RESET_ALL}"

    def get_robots_txt(self):
        response = self.http_request(
                                method="GET",
                                path="/robots.txt")

        if response.status_code == 200:
            print_success("File robots.txt found")
            
            print_info(response.text)
            return response.text
        else:
            print_error(f"Unable to fetch robots.txt from {self.target}. Status code: {response.status_code}")
            return False

    def parse_robots_txt(self, robots_txt):
        lines = robots_txt.splitlines()
        urls = []
        print_success("Extract and test url...")
        for line in lines:
            line = line.strip()
            if line.startswith('Allow:') or line.startswith('Disallow:'):
                url = line.split(':', 1)[1].strip()
                if url:
                    urls.append(url)
        return urls

    def test_urls(self, urls):
        results = []
        for url in urls:
            response = self.http_request(
                                method="GET",
                                path=url,
                                allow_redirects=False
            )
            page_weight = len(response.content)
            if response.status_code == 200:
                results.append((self.target+url, self.color_green(response.status_code), page_weight))
            else:    
                results.append((self.target+url, self.color_red(response.status_code), page_weight))

        return results

    def run(self):
        robots_txt = self.get_robots_txt()
        if robots_txt:
            urls = self.parse_robots_txt(robots_txt)
            results = self.test_urls(urls)
            print_table(['Url', 'Code', 'Weight'], results)
        return True