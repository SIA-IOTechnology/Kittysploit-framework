#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import json
import urllib.parse
import random
import string


class Module(Auxiliary, Http_client):
    
    __info__ = {
        'name': 'API Fuzzer',
        'description': 'Fuzzes API endpoints to discover vulnerabilities, misconfigurations, exposed endpoints, and test various HTTP methods',
        'author': 'KittySploit Team',
        'tags': ['web', 'api', 'fuzzer', 'scanner', 'security'],
        'references': [
            'https://owasp.org/www-project-api-security/',
            'https://portswigger.net/web-security/api',
        ]
    }

    # Common API endpoints to fuzz
    API_ENDPOINTS = [
        '/api',
        '/api/v1',
        '/api/v2',
        '/api/v3',
        '/rest',
        '/rest/api',
        '/graphql',
        '/graphql/v1',
        '/swagger',
        '/swagger.json',
        '/swagger.yaml',
        '/openapi.json',
        '/openapi.yaml',
        '/api-docs',
        '/api/docs',
        '/documentation',
        '/docs',
        '/v1',
        '/v2',
        '/v3',
        '/users',
        '/user',
        '/admin',
        '/auth',
        '/login',
        '/logout',
        '/register',
        '/token',
        '/oauth',
        '/oauth2',
        '/health',
        '/status',
        '/info',
        '/version',
        '/config',
        '/settings',
        '/data',
        '/files',
        '/upload',
        '/download',
    ]

    # HTTP methods to test
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']

    # Fuzzing payloads
    FUZZ_PAYLOADS = [
        # SQL Injection
        "' OR '1'='1",
        "' OR 1=1--",
        "1' UNION SELECT NULL--",
        "admin'--",
        "admin'/*",
        
        # NoSQL Injection
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$where": "1==1"}',
        
        # Command Injection
        '; ls',
        '| whoami',
        '`id`',
        '$(whoami)',
        
        # Path Traversal
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        
        # XSS
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        
        # XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        
        # JSON Injection
        '{"test": "value"}',
        '{"__proto__": {"isAdmin": true}}',
        
        # Special characters
        '../../',
        '..%2f..%2f',
        '%00',
        '\x00',
        '\n',
        '\r',
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

    def fuzz_endpoint(self, endpoint, method='GET', payload=None):
        """
        Fuzz a specific endpoint
        
        Args:
            endpoint: The endpoint to fuzz
            method: HTTP method to use
            payload: Optional payload to include
            
        Returns:
            dict: Fuzzing results
        """
        try:
            if method in ['POST', 'PUT', 'PATCH']:
                data = payload if payload else {'test': 'value'}
                response = self.http_request(
                    method=method,
                    path=endpoint,
                    data=data,
                    allow_redirects=False
                )
            else:
                if payload:
                    # Add payload as query parameter
                    endpoint = f"{endpoint}?test={urllib.parse.quote(str(payload))}"
                response = self.http_request(
                    method=method,
                    path=endpoint,
                    allow_redirects=False
                )

            if not response:
                return {
                    'endpoint': endpoint,
                    'method': method,
                    'found': False,
                    'error': 'No response'
                }

            # Analyze response
            status_code = response.status_code
            content_length = len(response.content)
            content_type = response.headers.get('Content-Type', 'unknown')

            # Check for interesting responses
            is_interesting = False
            indicators = []

            # Status codes that might indicate something interesting
            if status_code in [200, 201, 202]:
                is_interesting = True
                indicators.append(f'Status {status_code}')
            elif status_code in [401, 403]:
                is_interesting = True
                indicators.append(f'Authentication required ({status_code})')
            elif status_code in [500, 502, 503]:
                is_interesting = True
                indicators.append(f'Server error ({status_code})')

            # Check for API indicators
            if 'json' in content_type.lower():
                is_interesting = True
                indicators.append('JSON response')
                try:
                    json_data = json.loads(response.text)
                    if isinstance(json_data, dict):
                        indicators.append(f'JSON object with {len(json_data)} keys')
                except:
                    pass

            # Check for error messages that might reveal information
            error_indicators = ['error', 'exception', 'stack trace', 'sql', 'database', 'mysql', 'postgresql']
            if any(indicator in response.text.lower() for indicator in error_indicators):
                is_interesting = True
                indicators.append('Error message detected')

            # Check for API documentation
            doc_indicators = ['swagger', 'openapi', 'api', 'endpoint', 'method', 'parameter']
            if any(indicator in response.text.lower() for indicator in doc_indicators):
                is_interesting = True
                indicators.append('API documentation detected')

            return {
                'endpoint': endpoint,
                'method': method,
                'found': is_interesting,
                'status_code': status_code,
                'content_length': content_length,
                'content_type': content_type,
                'indicators': indicators,
                'response_preview': response.text[:200] if response.text else ''
            }

        except Exception as e:
            return {
                'endpoint': endpoint,
                'method': method,
                'found': False,
                'error': str(e)
            }

    def discover_endpoints(self):
        """
        Discover API endpoints by fuzzing common paths
        """
        print_status("Discovering API endpoints...")
        discovered = []

        for endpoint in self.API_ENDPOINTS:
            result = self.fuzz_endpoint(endpoint, method='GET')
            if result.get('found'):
                discovered.append(result)
                print_success(f"  Found: {endpoint} (Status: {result.get('status_code')})")
                if result.get('indicators'):
                    print_info(f"    Indicators: {', '.join(result['indicators'])}")

        return discovered

    def test_http_methods(self, endpoint):
        """
        Test various HTTP methods on an endpoint
        
        Args:
            endpoint: The endpoint to test
            
        Returns:
            list: List of allowed methods
        """
        allowed_methods = []

        for method in self.HTTP_METHODS:
            result = self.fuzz_endpoint(endpoint, method=method)
            if result.get('status_code') not in [405, 501]:  # Method not allowed / not implemented
                allowed_methods.append({
                    'method': method,
                    'status_code': result.get('status_code'),
                    'indicators': result.get('indicators', [])
                })

        return allowed_methods

    def fuzz_parameters(self, endpoint):
        """
        Fuzz parameters on an endpoint
        
        Args:
            endpoint: The endpoint to fuzz
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []

        for payload in self.FUZZ_PAYLOADS[:10]:  # Test first 10 payloads
            result = self.fuzz_endpoint(endpoint, method='GET', payload=payload)

            if result.get('found'):
                # Check for potential vulnerabilities
                if 'error' in result.get('response_preview', '').lower():
                    vulnerabilities.append({
                        'endpoint': endpoint,
                        'payload': payload[:50],
                        'type': 'Potential injection',
                        'status_code': result.get('status_code')
                    })

        return vulnerabilities

    def run(self):
        """
        Execute the API fuzzing scan
        """
        self.discovered_endpoints = []
        self.vulnerabilities = []
        self.test_results = []

        print_status("Starting API fuzzing scan...")
        print_info(f"Target: {self.target}")
        print_info("")

        # Discover endpoints
        self.discovered_endpoints = self.discover_endpoints()
        print_info("")

        # If no endpoints discovered, try root API paths
        if not self.discovered_endpoints:
            print_status("No common endpoints found, testing root API paths...")
            root_paths = ['/api', '/rest', '/v1', '/graphql']
            for path in root_paths:
                result = self.fuzz_endpoint(path, method='GET')
                if result.get('status_code') != 404:
                    self.discovered_endpoints.append(result)
                    print_info(f"  Testing: {path} (Status: {result.get('status_code')})")
        print_info("")

        # Test HTTP methods on discovered endpoints
        if self.discovered_endpoints:
            print_status("Testing HTTP methods on discovered endpoints...")
            for endpoint_info in self.discovered_endpoints[:5]:  # Test first 5
                endpoint = endpoint_info['endpoint']
                print_info(f"Testing methods on: {endpoint}")
                methods = self.test_http_methods(endpoint)
                if methods:
                    for method_info in methods:
                        print_success(f"  {method_info['method']}: Status {method_info['status_code']}")
                print_info("")

        # Fuzz parameters
        if self.discovered_endpoints:
            print_status("Fuzzing parameters on discovered endpoints...")
            for endpoint_info in self.discovered_endpoints[:3]:  # Fuzz first 3
                endpoint = endpoint_info['endpoint']
                print_info(f"Fuzzing parameters on: {endpoint}")
                vulns = self.fuzz_parameters(endpoint)
                if vulns:
                    for vuln in vulns:
                        print_warning(f"  Potential vulnerability: {vuln['type']}")
                        self.vulnerabilities.append(vuln)
                print_info("")

        # Summary
        print_status("=" * 60)
        print_status("API Fuzzing Scan Summary")
        print_status("=" * 60)
        print_info(f"Endpoints discovered: {len(self.discovered_endpoints)}")
        print_info(f"Potential vulnerabilities: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")

        if self.discovered_endpoints:
            print_success("Discovered endpoints:")
            print_info("")
            table_data = []
            for endpoint_info in self.discovered_endpoints:
                indicators = ', '.join(endpoint_info.get('indicators', [])[:2])
                table_data.append([
                    endpoint_info['endpoint'],
                    endpoint_info.get('method', 'GET'),
                    endpoint_info.get('status_code', 'N/A'),
                    indicators
                ])
            print_table(['Endpoint', 'Method', 'Status', 'Indicators'], table_data)
            print_info("")

        if self.vulnerabilities:
            print_warning("Potential vulnerabilities:")
            print_info("")
            for vuln in self.vulnerabilities:
                print_info(f"  - {vuln['endpoint']}: {vuln['type']}")
        else:
            print_info("No obvious vulnerabilities detected during fuzzing.")

        return True
