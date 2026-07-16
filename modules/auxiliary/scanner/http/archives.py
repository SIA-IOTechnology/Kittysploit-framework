from kittysploit import *
import requests

class Module(Auxiliary):

    __info__ = {
        'name': 'Check archive website',
        'description': 'Check a web site and store information about what was found',	
        'author': 'KittySploit Team',
        'tags': ['web', 'scanner'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
            'cost': 1.0,
            'noise': 0.5,
            'value': 1.0,
            'requires':             {'min_endpoints': 0,
             'min_params': 0,
             'tech_hints_any': [],
             'tech_hints_all': [],
             'specializations_any': [],
             'risk_signals_any': [],
             'auth_session': False,
             'capabilities_any': [],
             'capabilities_all': [],
             'confidence_min': {},
             'confidence_min_any': {},
             'endpoint_pattern_any': [],
             'param_any': [],
             'api_surface_ready': False},
            'chain':             {'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
             'consumes_capabilities': [],
             'option_bindings': {},
             'suggested_followups': []},
        },
        }
    
    website = OptString("mywebsite.com", "Website to get archive", True)

    def test_urls(self, urls):
        results = []
        for url in urls:
            response = requests.get(url, allow_redirects=False)
            page_weight = len(response.content)
            if response.status_code == 200:
                results.append((url.decode('utf-8'), color_green(response.status_code), page_weight))
            else:    
                results.append((url.decode('utf-8'), color_red(response.status_code), page_weight))

        return results

    def run(self):
        print_info(f"Checking {self.website}...")
        response = requests.get(f"https://web.archive.org/cdx/search/cdx?url={self.website}/*&output=text&fl=original&collapse=urlkey")
        
        if response:
            print_status("Archive URLs found:")
            lines = response.content.splitlines()
            print_status(f"Found {len(lines)} URLs")
            print_info("Extracting and testing URLs... wait a moment...")
            results = self.test_urls(response.content.splitlines())
            print_table(['Url', 'Code', 'Weight'], results)
            print_success("Done")
        return True