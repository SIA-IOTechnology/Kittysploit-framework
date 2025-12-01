from kittysploit import *
import requests

class Module(Auxiliary):

    __info__ = {
        'name': 'Check archive website',
        'description': 'Check a web site and store information about what was found',	
        'author': 'KittySploit Team',
        'tags': ['web', 'scanner'],
        }
    
    website = OptString("mywebsite.com", "Website to get archive", True)

    def test_urls(self, urls):
        results = []
        for url in urls:
            response = requests.get(url, allow_redirects=False)
            page_weight = len(response.content)
            if response.status_code == 200:
                results.append((url, color_green(response.status_code), page_weight))
            else:    
                results.append((url, color_red(response.status_code), page_weight))

        return results

    def run(self):

        response = requests.get(f"https://web.archive.org/cdx/search/cdx?url={self.website}/*&output=text&fl=original&collapse=urlkey")
        if response:
            
            results = self.test_urls(response.content.splitlines())
            print_table(['Url', 'Code', 'Weight'], results)