#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import urllib.parse

class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'CORS Misconfiguration Scanner',
        'description': 'Scans for common CORS (Cross-Origin Resource Sharing) misconfigurations that could allow unauthorized cross-origin requests',
        'author': 'KittySploit Team',
        'tags': ['web', 'cors', 'scanner', 'security'],
    }

    def check(self):
        """
        Check if the target is accessible
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response and response.status_code in [200, 301, 302, 403, 404]:
                return True
            return False
        except Exception as e:
            return False
    
    def test_cors_headers(self, origin_header):
        """
        Test CORS configuration with a specific Origin header
        
        Args:
            origin_header: The Origin header value to test
            
        Returns:
            dict: Test results including headers and vulnerability status
        """
        try:
            # Prepare custom headers with the test Origin
            custom_headers = {
                'Origin': origin_header,
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'Content-Type'
            }
            
            # Send OPTIONS request (preflight)
            preflight_response = self.http_request(
                method="OPTIONS",
                path="/",
                headers=custom_headers
            )
            
            # Send GET request with Origin header
            get_response = self.http_request(
                method="GET",
                path="/",
                headers={'Origin': origin_header}
            )
            
            # Check both responses for CORS headers
            cors_headers = {}
            vulnerable = False
            vulnerability_type = None
            details = []
            
            for response in [preflight_response, get_response]:
                if response:
                    # Check for Access-Control-Allow-Origin
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    acam = response.headers.get('Access-Control-Allow-Methods', '')
                    acah = response.headers.get('Access-Control-Allow-Headers', '')
                    acmax = response.headers.get('Access-Control-Max-Age', '')
                    
                    if acao:
                        cors_headers['Access-Control-Allow-Origin'] = acao
                    if acac:
                        cors_headers['Access-Control-Allow-Credentials'] = acac
                    if acam:
                        cors_headers['Access-Control-Allow-Methods'] = acam
                    if acah:
                        cors_headers['Access-Control-Allow-Headers'] = acah
                    if acmax:
                        cors_headers['Access-Control-Max-Age'] = acmax
                    
                    # Analyze for vulnerabilities
                    if acao == '*':
                        if acac.lower() == 'true':
                            vulnerable = True
                            vulnerability_type = 'Wildcard origin with credentials'
                            details.append('Access-Control-Allow-Origin is set to * with Access-Control-Allow-Credentials: true (browsers will reject this)')
                        else:
                            vulnerable = True
                            vulnerability_type = 'Wildcard origin'
                            details.append('Access-Control-Allow-Origin is set to * (allows all origins)')
                    
                    elif acao == origin_header:
                        if acac.lower() == 'true':
                            vulnerable = True
                            vulnerability_type = 'Reflected origin with credentials'
                            details.append(f'Access-Control-Allow-Origin reflects the Origin header ({origin_header}) with credentials enabled')
                        else:
                            vulnerable = True
                            vulnerability_type = 'Reflected origin'
                            details.append(f'Access-Control-Allow-Origin reflects the Origin header ({origin_header}) without validation')
                    
                    elif origin_header == 'null' and acao == 'null':
                        vulnerable = True
                        vulnerability_type = 'Null origin allowed'
                        details.append('Access-Control-Allow-Origin allows null origin')
                    
                    elif origin_header.startswith('http://') and acao == origin_header:
                        vulnerable = True
                        vulnerability_type = 'HTTP origin allowed'
                        details.append(f'Access-Control-Allow-Origin allows insecure HTTP origin: {origin_header}')
            
            return {
                'origin': origin_header,
                'vulnerable': vulnerable,
                'vulnerability_type': vulnerability_type,
                'details': details,
                'cors_headers': cors_headers,
                'status_code': get_response.status_code if get_response else None
            }
            
        except Exception as e:
            return {
                'origin': origin_header,
                'vulnerable': False,
                'error': str(e),
                'cors_headers': {}
            }
    
    def test_subdomain_bypass(self, base_domain):
        """
        Test for subdomain bypass vulnerabilities
        
        Args:
            base_domain: Base domain to test (e.g., example.com)
            
        Returns:
            dict: Test results
        """
        try:
            # Extract base domain from target
            parsed = urllib.parse.urlparse(self.target)
            domain = parsed.netloc.split(':')[0]
            
            # Test various subdomain combinations
            test_origins = [
                f'http://evil.{domain}',
                f'https://evil.{domain}',
                f'http://subdomain.{domain}',
                f'https://subdomain.{domain}',
                f'http://{domain}.evil.com',
                f'https://{domain}.evil.com',
            ]
            
            results = []
            for origin in test_origins:
                result = self.test_cors_headers(origin)
                if result.get('vulnerable'):
                    results.append(result)
            
            return results
            
        except Exception as e:
            return []
    
    def run(self):
        """
        Execute the CORS misconfiguration scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting CORS misconfiguration scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # List of origins to test
        test_origins = [
            '*',  # Wildcard
            'null',  # Null origin
            'https://evil.com',  # External domain
            'http://evil.com',  # External HTTP domain
            'https://attacker.com',  # Another external domain
            'http://localhost',  # Localhost
            'http://127.0.0.1',  # Local IP
            'https://example.com',  # Example domain
        ]
        
        # Add target's own origin variations
        try:
            parsed = urllib.parse.urlparse(self.target)
            domain = parsed.netloc.split(':')[0]
            scheme = parsed.scheme or 'http'
            
            # Add variations of the target domain
            test_origins.extend([
                f'{scheme}://{domain}',
                f'http://{domain}',
                f'https://{domain}',
                f'{scheme}://www.{domain}',
                f'http://www.{domain}',
                f'https://www.{domain}',
            ])
        except:
            pass
        
        print_status(f"Testing {len(test_origins)} origin configurations...")
        print_info("")
        
        vulnerable_count = 0
        
        # Test each origin
        for i, origin in enumerate(test_origins, 1):
            print_info(f"[{i}/{len(test_origins)}] Testing origin: {origin}")
            
            result = self.test_cors_headers(origin)
            self.test_results.append(result)
            
            if result.get('vulnerable'):
                vulnerable_count += 1
                print_success(f"\n[!] VULNERABILITY FOUND: {result.get('vulnerability_type')}")
                print_info(f"    Origin: {origin}")
                print_info(f"    Status Code: {result.get('status_code', 'N/A')}")
                
                if result.get('details'):
                    for detail in result['details']:
                        print_warning(f"    {detail}")
                
                if result.get('cors_headers'):
                    print_info("    CORS Headers:")
                    for header, value in result['cors_headers'].items():
                        print_info(f"      {header}: {value}")
                
                print_info("")
                
                self.vulnerabilities.append(result)
        
        # Test subdomain bypass
        print_info("")
        print_status("Testing subdomain bypass scenarios...")
        try:
            parsed = urllib.parse.urlparse(self.target)
            domain = parsed.netloc.split(':')[0]
            subdomain_results = self.test_subdomain_bypass(domain)
            
            if subdomain_results:
                for result in subdomain_results:
                    if result.get('vulnerable'):
                        vulnerable_count += 1
                        print_success(f"\n[!] SUBDOMAIN BYPASS: {result.get('vulnerability_type')}")
                        print_info(f"    Origin: {result.get('origin')}")
                        self.vulnerabilities.append(result)
        except Exception as e:
            print_debug(f"Subdomain bypass test error: {str(e)}")
        
        # Summary
        print_info("")
        print_status("=" * 60)
        print_status("CORS Scan Summary")
        print_status("=" * 60)
        print_info(f"Total origins tested: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {vulnerable_count}")
        print_status("=" * 60)
        
        if self.vulnerabilities:
            print_success("\nVulnerabilities detected:")
            print_info("")
            
            # Group by vulnerability type
            vuln_groups = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                if vuln_type not in vuln_groups:
                    vuln_groups[vuln_type] = []
                vuln_groups[vuln_type].append(vuln)
            
            # Display grouped results
            table_data = []
            for vuln_type, vulns in vuln_groups.items():
                origins = [v.get('origin') for v in vulns]
                table_data.append([
                    vuln_type,
                    ', '.join(origins[:3]) + ('...' if len(origins) > 3 else ''),
                    len(vulns)
                ])
            
            if table_data:
                print_table(['Vulnerability Type', 'Affected Origins', 'Count'], table_data)
        return True