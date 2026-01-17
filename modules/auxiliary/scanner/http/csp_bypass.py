#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'CSP Bypass Scanner',
        'description': 'Scans for Content Security Policy (CSP) misconfigurations and tests various bypass techniques',
        'author': 'KittySploit Team',
        'tags': ['web', 'csp', 'scanner', 'security', 'bypass'],
        'references': [
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
            'https://csp-evaluator.withgoogle.com/',
            'https://content-security-policy.com/',
        ]
    }

    # CSP bypass techniques
    CSP_BYPASS_PAYLOADS = [
        # Wildcard bypasses
        "https://*",
        "https://*.*",
        "https://*.com",
        
        # Data URI bypasses
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        
        # JSONP bypasses
        "https://example.com/jsonp?callback=alert",
        "https://example.com/jsonp?callback=eval",
        
        # Unsafe-inline bypasses
        "'unsafe-inline'",
        "'unsafe-eval'",
        
        # Nonce/hash bypasses
        "'nonce-test'",
        "'sha256-test'",
        "'sha384-test'",
        "'sha512-test'",
        
        # Self bypasses
        "'self'",
        "self",
        
        # Scheme bypasses
        "http:",
        "https:",
        "data:",
        "javascript:",
        
        # Domain bypasses
        "*.example.com",
        ".example.com",
        "example.com",
        
        # Missing directives
        "script-src",
        "object-src",
        "base-uri",
        "frame-ancestors",
    ]

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

    def extract_csp(self, response):
        """
        Extract CSP header from response
        
        Args:
            response: HTTP response object
            
        Returns:
            dict: Parsed CSP information
        """
        csp_info = {
            'header': None,
            'directives': {},
            'raw': None
        }

        # Check Content-Security-Policy header
        csp_header = response.headers.get('Content-Security-Policy', '')
        if not csp_header:
            # Check X-Content-Security-Policy (deprecated)
            csp_header = response.headers.get('X-Content-Security-Policy', '')
        if not csp_header:
            # Check Content-Security-Policy-Report-Only
            csp_header = response.headers.get('Content-Security-Policy-Report-Only', '')

        if csp_header:
            csp_info['header'] = csp_header
            csp_info['raw'] = csp_header

            # Parse directives
            directives = csp_header.split(';')
            for directive in directives:
                directive = directive.strip()
                if ' ' in directive:
                    parts = directive.split(' ', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        csp_info['directives'][key] = value
                else:
                    csp_info['directives'][directive] = ''

        return csp_info

    def analyze_csp(self, csp_info):
        """
        Analyze CSP for misconfigurations
        
        Args:
            csp_info: Parsed CSP information
            
        Returns:
            list: List of misconfigurations found
        """
        misconfigurations = []

        if not csp_info['header']:
            misconfigurations.append({
                'type': 'Missing CSP',
                'severity': 'Medium',
                'description': 'No Content-Security-Policy header found',
                'recommendation': 'Implement a CSP header'
            })
            return misconfigurations

        directives = csp_info['directives']

        # Check for unsafe-inline in script-src
        if 'script-src' in directives:
            script_src = directives['script-src']
            if "'unsafe-inline'" in script_src:
                misconfigurations.append({
                    'type': 'Unsafe Inline',
                    'severity': 'High',
                    'description': "script-src contains 'unsafe-inline'",
                    'details': 'Allows inline scripts, making XSS easier',
                    'directive': 'script-src',
                    'value': script_src
                })

        # Check for unsafe-eval
        if 'script-src' in directives:
            script_src = directives['script-src']
            if "'unsafe-eval'" in script_src:
                misconfigurations.append({
                    'type': 'Unsafe Eval',
                    'severity': 'High',
                    'description': "script-src contains 'unsafe-eval'",
                    'details': 'Allows eval(), Function(), and similar functions',
                    'directive': 'script-src',
                    'value': script_src
                })

        # Check for wildcards
        for directive, value in directives.items():
            if '*' in value or 'https://*' in value:
                misconfigurations.append({
                    'type': 'Wildcard Source',
                    'severity': 'High',
                    'description': f"{directive} contains wildcard",
                    'details': 'Wildcards allow loading from any domain',
                    'directive': directive,
                    'value': value
                })

        # Check for missing object-src
        if 'object-src' not in directives:
            misconfigurations.append({
                'type': 'Missing object-src',
                'severity': 'Medium',
                'description': 'object-src directive is missing',
                'details': 'Defaults to allowing all sources',
                'recommendation': "Add 'object-src \"none\"'"
            })

        # Check for missing base-uri
        if 'base-uri' not in directives:
            misconfigurations.append({
                'type': 'Missing base-uri',
                'severity': 'Medium',
                'description': 'base-uri directive is missing',
                'details': 'Allows <base> tag manipulation',
                'recommendation': "Add 'base-uri \"self\"'"
            })

        # Check for missing frame-ancestors
        if 'frame-ancestors' not in directives:
            misconfigurations.append({
                'type': 'Missing frame-ancestors',
                'severity': 'Low',
                'description': 'frame-ancestors directive is missing',
                'details': 'Allows framing (clickjacking risk)',
                'recommendation': "Add 'frame-ancestors \"none\"' or 'frame-ancestors \"self\"'"
            })

        # Check for overly permissive script-src
        if 'script-src' in directives:
            script_src = directives['script-src']
            if script_src == '*' or script_src == "'unsafe-inline' 'unsafe-eval' *":
                misconfigurations.append({
                    'type': 'Overly Permissive script-src',
                    'severity': 'Critical',
                    'description': 'script-src is too permissive',
                    'details': 'Allows scripts from any source',
                    'directive': 'script-src',
                    'value': script_src
                })

        # Check for data: in script-src
        if 'script-src' in directives:
            script_src = directives['script-src']
            if 'data:' in script_src:
                misconfigurations.append({
                    'type': 'Data URI in script-src',
                    'severity': 'High',
                    'description': "script-src allows data: URIs",
                    'details': 'Allows inline scripts via data URIs',
                    'directive': 'script-src',
                    'value': script_src
                })

        return misconfigurations

    def test_csp_bypass(self, csp_info):
        """
        Test for CSP bypass techniques
        
        Args:
            csp_info: Parsed CSP information
            
        Returns:
            list: List of potential bypasses
        """
        bypasses = []

        if not csp_info['header']:
            return bypasses

        directives = csp_info['directives']

        # Test if script-src allows specific domains that might be vulnerable
        if 'script-src' in directives:
            script_src = directives['script-src']
            
            # Check for CDN domains that might be vulnerable
            cdn_patterns = ['cdn', 'ajax', 'googleapis', 'cloudflare', 'jsdelivr']
            for pattern in cdn_patterns:
                if pattern in script_src.lower():
                    bypasses.append({
                        'type': 'CDN Domain Allowed',
                        'severity': 'Medium',
                        'description': f'CDN domain ({pattern}) allowed in script-src',
                        'details': 'CDN domains might be vulnerable to subdomain takeover',
                        'directive': 'script-src',
                        'value': script_src
                    })

        # Check for JSONP endpoints
        if 'script-src' in directives:
            script_src = directives['script-src']
            if 'https://' in script_src or 'http://' in script_src:
                bypasses.append({
                    'type': 'External Scripts Allowed',
                    'severity': 'Medium',
                    'description': 'External domains allowed in script-src',
                    'details': 'Might allow JSONP callback injection',
                    'directive': 'script-src',
                    'value': script_src
                })

        return bypasses

    def run(self):
        """
        Execute the CSP bypass scan
        """
        self.misconfigurations = []
        self.bypasses = []
        self.csp_info = None

        print_status("Starting CSP bypass scan...")
        print_info(f"Target: {self.target}")
        print_info("")

        # Get initial response
        print_status("Analyzing CSP headers...")
        response = self.http_request(method="GET", path="/")

        if not response:
            print_error("Could not connect to target")
            return False

        # Extract CSP
        self.csp_info = self.extract_csp(response)

        if self.csp_info['header']:
            print_success("CSP header found:")
            print_info(f"  {self.csp_info['header']}")
            print_info("")
            
            # Display directives
            if self.csp_info['directives']:
                print_info("CSP Directives:")
                for directive, value in self.csp_info['directives'].items():
                    print_info(f"  {directive}: {value}")
                print_info("")
        else:
            print_warning("No CSP header found")
            print_info("")

        # Analyze CSP
        print_status("Analyzing CSP for misconfigurations...")
        self.misconfigurations = self.analyze_csp(self.csp_info)
        print_info("")

        # Test bypasses
        if self.csp_info['header']:
            print_status("Testing for CSP bypass techniques...")
            self.bypasses = self.test_csp_bypass(self.csp_info)
            print_info("")

        # Summary
        print_status("=" * 60)
        print_status("CSP Bypass Scan Summary")
        print_status("=" * 60)

        if self.csp_info['header']:
            print_info("CSP Status: Present")
        else:
            print_warning("CSP Status: Missing")

        print_info(f"Misconfigurations found: {len(self.misconfigurations)}")
        print_info(f"Potential bypasses found: {len(self.bypasses)}")
        print_status("=" * 60)
        print_info("")

        # Display misconfigurations
        if self.misconfigurations:
            print_warning("CSP Misconfigurations:")
            print_info("")
            
            # Group by severity
            by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
            for misconfig in self.misconfigurations:
                severity = misconfig.get('severity', 'Medium')
                by_severity[severity].append(misconfig)

            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if by_severity[severity]:
                    print_info(f"{severity} Severity:")
                    for misconfig in by_severity[severity]:
                        print_info(f"  - {misconfig['type']}: {misconfig['description']}")
                        if 'details' in misconfig:
                            print_info(f"    Details: {misconfig['details']}")
                        if 'recommendation' in misconfig:
                            print_info(f"    Recommendation: {misconfig['recommendation']}")
                    print_info("")

        # Display bypasses
        if self.bypasses:
            print_warning("Potential CSP Bypasses:")
            print_info("")
            for bypass in self.bypasses:
                print_info(f"  - {bypass['type']}: {bypass['description']}")
                if 'details' in bypass:
                    print_info(f"    Details: {bypass['details']}")
            print_info("")

        if not self.misconfigurations and not self.bypasses:
            if self.csp_info['header']:
                print_success("No obvious CSP misconfigurations detected.")
            else:
                print_warning("No CSP header found. Consider implementing one.")

        return True
