#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse
import json


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'SPA Scanner',
        'description': 'Scans for vulnerabilities and misconfigurations in Single Page Applications including exposed API endpoints, authentication issues, and client-side vulnerabilities',
        'author': 'KittySploit Team',
        'tags': ['web', 'spa', 'scanner', 'security', 'api'],
        'references': [
            'https://owasp.org/www-project-web-security-testing-guide/',
            'https://portswigger.net/web-security',
        ]
    }

    # Common SPA frameworks
    SPA_FRAMEWORKS = ['react', 'angular', 'vue', 'ember', 'backbone', 'knockout']

    # Common API endpoints in SPAs
    API_ENDPOINTS = [
        '/api',
        '/api/v1',
        '/api/v2',
        '/rest',
        '/rest/api',
        '/graphql',
        '/auth',
        '/auth/login',
        '/auth/register',
        '/auth/token',
        '/auth/refresh',
        '/user',
        '/users',
        '/profile',
        '/admin',
        '/config',
        '/settings',
    ]

    # Sensitive files that might be exposed
    SENSITIVE_FILES = [
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/config.js',
        '/config.json',
        '/settings.js',
        '/settings.json',
        '/package.json',
        '/package-lock.json',
        '/yarn.lock',
        '/.git/config',
        '/.git/HEAD',
        '/.gitignore',
        '/webpack.config.js',
        '/.htaccess',
        '/web.config',
    ]

    def check(self):
        """
        Check if the target is accessible and might be a SPA
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for SPA indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                spa_indicators = [
                    'react', 'angular', 'vue', 'ember',
                    'single page application', 'spa',
                    'app.js', 'main.js', 'bundle.js',
                    'webpack', 'vite', 'parcel',
                ]
                
                if any(indicator in content or indicator in headers for indicator in spa_indicators):
                    return True
                
                # Check for typical SPA structure (minimal HTML, lots of JS)
                if len(content) < 5000 and ('<script' in content or 'bundle' in content.lower()):
                    return True
                
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_spa_framework(self):
        """
        Detect SPA framework
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None
            
            content = response.text.lower()
            
            # Check for React
            if 'react' in content or 'react-dom' in content:
                return "React"
            
            # Check for Angular
            if 'angular' in content or 'ng-app' in content or '[ng-' in content:
                return "Angular"
            
            # Check for Vue
            if 'vue' in content or 'v-if' in content or 'v-for' in content:
                return "Vue.js"
            
            # Check for Ember
            if 'ember' in content:
                return "Ember.js"
            
            # Check for Backbone
            if 'backbone' in content:
                return "Backbone.js"
            
            return "SPA (unknown framework)"
        except Exception as e:
            print_debug(f"Error detecting SPA framework: {str(e)}")
            return None

    def discover_api_endpoints(self):
        """
        Discover API endpoints
        """
        print_status("Discovering API endpoints...")
        discovered = []
        
        for endpoint in self.API_ENDPOINTS:
            try:
                response = self.http_request(
                    method="GET",
                    path=endpoint,
                    allow_redirects=False
                )
                
                if response and response.status_code not in [404, 403]:
                    discovered.append({
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'method': 'GET',
                        'accessible': True
                    })
                    
                    # Try POST as well
                    post_response = self.http_request(
                        method="POST",
                        path=endpoint,
                        allow_redirects=False
                    )
                    
                    if post_response and post_response.status_code not in [404, 403, 405]:
                        discovered.append({
                            'endpoint': endpoint,
                            'status_code': post_response.status_code,
                            'method': 'POST',
                            'accessible': True
                        })
            except:
                pass
        
        return discovered

    def check_sensitive_files(self):
        """
        Check for exposed sensitive files
        """
        print_status("Checking for exposed sensitive files...")
        exposed = []
        
        for file_path in self.SENSITIVE_FILES:
            try:
                response = self.http_request(
                    method="GET",
                    path=file_path,
                    allow_redirects=False
                )
                
                if response and response.status_code == 200:
                    content_length = len(response.content)
                    content_type = response.headers.get('Content-Type', 'unknown')
                    
                    is_sensitive = False
                    indicators = []
                    
                    if '.env' in file_path:
                        is_sensitive = True
                        indicators.append('Environment file')
                    
                    if 'config' in file_path.lower() or 'settings' in file_path.lower():
                        is_sensitive = True
                        indicators.append('Configuration file')
                    
                    if 'package.json' in file_path:
                        is_sensitive = True
                        indicators.append('Package manifest')
                    
                    if '.git' in file_path:
                        is_sensitive = True
                        indicators.append('Git repository')
                    
                    if is_sensitive or content_length > 0:
                        exposed.append({
                            'path': file_path,
                            'status_code': response.status_code,
                            'content_length': content_length,
                            'content_type': content_type,
                            'indicators': indicators,
                            'is_sensitive': is_sensitive
                        })
            except:
                pass
        
        return exposed

    def check_authentication(self):
        """
        Check for authentication issues
        """
        print_status("Checking for authentication issues...")
        issues = []
        
        # Check if authentication endpoints are accessible
        auth_endpoints = ['/auth', '/auth/login', '/auth/register', '/login', '/register']
        
        for endpoint in auth_endpoints:
            try:
                response = self.http_request(
                    method="GET",
                    path=endpoint,
                    allow_redirects=False
                )
                
                if response and response.status_code == 200:
                    # Check if it's actually an auth page
                    if 'login' in response.text.lower() or 'password' in response.text.lower():
                        issues.append({
                            'type': 'Information Disclosure',
                            'issue': f'Authentication endpoint accessible: {endpoint}',
                            'severity': 'Low',
                            'details': 'Authentication page is accessible'
                        })
            except:
                pass
        
        return issues

    def check_cors_configuration(self):
        """
        Check CORS configuration
        """
        print_status("Checking CORS configuration...")
        issues = []
        
        try:
            # Try to make a request with Origin header
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET'
            }
            
            response = self.http_request(
                method="OPTIONS",
                path="/",
                headers=headers,
                allow_redirects=False
            )
            
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*':
                    issues.append({
                        'type': 'CORS Misconfiguration',
                        'issue': 'CORS allows all origins (*)',
                        'severity': 'High',
                        'details': 'Access-Control-Allow-Origin is set to *'
                    })
                
                if acao == 'https://evil.com' and acac.lower() == 'true':
                    issues.append({
                        'type': 'CORS Misconfiguration',
                        'issue': 'CORS reflects Origin header with credentials',
                        'severity': 'High',
                        'details': 'Allows arbitrary origin with credentials'
                    })
        except:
            pass
        
        return issues

    def run(self):
        """
        Execute the SPA scan
        """
        self.discovered_endpoints = []
        self.exposed_files = []
        self.authentication_issues = []
        self.cors_issues = []
        
        print_status("Starting SPA scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect SPA framework
        print_status("Detecting SPA framework...")
        framework = self.detect_spa_framework()
        if framework:
            print_success(f"SPA framework detected: {framework}")
        else:
            print_warning("Could not detect SPA framework")
            print_info("Continuing with generic SPA checks...")
        print_info("")
        
        # Discover API endpoints
        self.discovered_endpoints = self.discover_api_endpoints()
        print_info("")
        
        # Check sensitive files
        self.exposed_files = self.check_sensitive_files()
        print_info("")
        
        # Check authentication
        self.authentication_issues = self.check_authentication()
        print_info("")
        
        # Check CORS
        self.cors_issues = self.check_cors_configuration()
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("SPA Scan Summary")
        print_status("=" * 60)
        
        if framework:
            print_info(f"SPA Framework: {framework}")
        else:
            print_warning("SPA Framework: Not detected")
        
        print_info(f"API Endpoints Found: {len(self.discovered_endpoints)}")
        print_info(f"Exposed Files Found: {len(self.exposed_files)}")
        print_info(f"Authentication Issues: {len(self.authentication_issues)}")
        print_info(f"CORS Issues: {len(self.cors_issues)}")
        print_status("=" * 60)
        print_info("")
        
        # Display discovered endpoints
        if self.discovered_endpoints:
            print_success("Discovered API endpoints:")
            print_info("")
            table_data = []
            for endpoint_info in self.discovered_endpoints:
                table_data.append([
                    endpoint_info['endpoint'],
                    endpoint_info['method'],
                    endpoint_info['status_code']
                ])
            print_table(['Endpoint', 'Method', 'Status'], table_data)
            print_info("")
        
        # Display exposed files
        if self.exposed_files:
            print_warning(f"Found {len(self.exposed_files)} exposed sensitive files")
            table_data = []
            for file_info in self.exposed_files:
                sensitivity = "SENSITIVE" if file_info['is_sensitive'] else "Exposed"
                table_data.append([
                    file_info['path'],
                    file_info['status_code'],
                    f"{file_info['content_length']} bytes",
                    sensitivity
                ])
            print_table(['Path', 'Status', 'Size', 'Type'], table_data)
            print_info("")
        
        # Display authentication issues
        if self.authentication_issues:
            print_status("Authentication Issues:")
            print_info("")
            for issue in self.authentication_issues:
                print_info(f" - [{issue['severity']}] {issue['type']}: {issue['issue']}")
                print_info(f"   - Details: {issue['details']}")
            print_info("")
        
        # Display CORS issues
        if self.cors_issues:
            print_warning("CORS Issues:")
            print_info("")
            for issue in self.cors_issues:
                print_info(f" - [{issue['severity']}] {issue['type']}: {issue['issue']}")
                print_info(f"   - Details: {issue['details']}")
            print_info("")
        
        return True
