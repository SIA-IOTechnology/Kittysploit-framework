#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'WordPress Vulnerability Scanner',
        'description': 'Scans for WordPress-specific vulnerabilities, version information, exposed files, and security misconfigurations',
        'author': 'KittySploit Team',
        'tags': ['web', 'wordpress', 'scanner', 'security', 'vulnerability', 'cms'],
        'references': [
            'https://wordpress.org/support/article/faq-my-site-was-hacked/',
            'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=wordpress',
            'https://owasp.org/www-project-web-security-testing-guide/'
        ]
    }

    # Known WordPress CVEs
    WORDPRESS_CVES = {
        'CVE-2023-5360': {
            'name': 'SQL Injection',
            'affected_versions': ['< 6.3.2'],
            'severity': 'High',
            'description': 'SQL injection vulnerability'
        },
        'CVE-2023-5361': {
            'name': 'Cross-Site Scripting',
            'affected_versions': ['< 6.3.2'],
            'severity': 'Medium',
            'description': 'Cross-site scripting vulnerability'
        },
        'CVE-2023-4519': {
            'name': 'Remote Code Execution',
            'affected_versions': ['< 6.3.1'],
            'severity': 'Critical',
            'description': 'Remote code execution vulnerability'
        },
        'CVE-2022-3593': {
            'name': 'SQL Injection',
            'affected_versions': ['< 6.0.3'],
            'severity': 'High',
            'description': 'SQL injection vulnerability'
        },
        'CVE-2022-3594': {
            'name': 'Cross-Site Scripting',
            'affected_versions': ['< 6.0.3'],
            'severity': 'Medium',
            'description': 'Cross-site scripting vulnerability'
        },
    }

    # WordPress-specific paths
    WORDPRESS_PATHS = [
        '/wp-admin',
        '/wp-admin/admin.php',
        '/wp-admin/install.php',
        '/wp-admin/setup-config.php',
        '/wp-content',
        '/wp-content/plugins',
        '/wp-content/themes',
        '/wp-content/uploads',
        '/wp-includes',
        '/wp-login.php',
        '/wp-register.php',
        '/wp-signup.php',
        '/wp-config.php',
        '/wp-config.php.bak',
        '/wp-config.php.old',
        '/wp-config.php.save',
        '/wp-config.php.swp',
        '/wp-config.php~',
        '/wp-load.php',
        '/xmlrpc.php',
        '/readme.html',
        '/license.txt',
        '/wp-json',
        '/wp-json/wp/v2',
    ]

    # Sensitive files
    SENSITIVE_FILES = [
        '/wp-config.php',
        '/wp-config.php.bak',
        '/wp-config.php.old',
        '/wp-config.php.save',
        '/wp-config.php.swp',
        '/wp-config.php~',
        '/.htaccess',
        '/.git/config',
        '/.git/HEAD',
        '/.env',
        '/readme.html',
        '/license.txt',
    ]

    def check(self):
        """
        Check if the target is accessible and running WordPress
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for WordPress indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                wp_indicators = [
                    'wordpress', 'wp-content', 'wp-includes',
                    'wp-admin', 'wp-json', 'generator.*wordpress',
                    'x-powered-by.*wordpress',
                ]
                
                if any(indicator in content or indicator in headers for indicator in wp_indicators):
                    return True
                
                # Check for WordPress paths
                test_response = self.http_request(method="GET", path="/wp-login.php")
                if test_response and ('wordpress' in test_response.text.lower() or test_response.status_code in [200, 301, 302, 403]):
                    return True
                
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_wordpress_version(self):
        """
        Detect WordPress version
        """
        try:
            # Try readme.html
            response = self.http_request(method="GET", path="/readme.html")
            if response and response.status_code == 200:
                version_match = re.search(r'Version\s+([\d\.]+)', response.text, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
            
            # Check generator meta tag
            response = self.http_request(method="GET", path="/")
            if response:
                generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d\.]+)', response.text, re.IGNORECASE)
                if generator_match:
                    return generator_match.group(1)
                
                # Check for WordPress in JavaScript
                wp_js_match = re.search(r'wp.*version["\']?\s*:\s*["\']?([\d\.]+)', response.text, re.IGNORECASE)
                if wp_js_match:
                    return wp_js_match.group(1)
            
            # Check wp-includes/version.php (if accessible)
            response = self.http_request(method="GET", path="/wp-includes/version.php")
            if response and response.status_code == 200:
                version_match = re.search(r'\$wp_version\s*=\s*["\']([\d\.]+)', response.text, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
            
            return None
        except Exception as e:
            print_debug(f"Error detecting WordPress version: {str(e)}")
            return None

    def compare_versions(self, version1, version2):
        """
        Compare two version strings
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            return 0
        except:
            return 0

    def is_version_vulnerable(self, version, affected_versions):
        """
        Check if a version is vulnerable
        """
        if not version:
            return False
        
        for affected in affected_versions:
            if affected.startswith('< '):
                threshold = affected[2:].strip()
                if self.compare_versions(version, threshold) < 0:
                    return True
        
        return False

    def check_cves(self):
        """
        Check for known CVEs
        """
        if not self.wp_version:
            return
        
        for cve_id, cve_info in self.WORDPRESS_CVES.items():
            if self.is_version_vulnerable(self.wp_version, cve_info['affected_versions']):
                self.vulnerabilities.append({
                    'type': 'CVE',
                    'id': cve_id,
                    'name': cve_info['name'],
                    'severity': cve_info['severity'],
                    'description': cve_info['description'],
                    'version': self.wp_version
                })

    def check_sensitive_files(self):
        """
        Check for exposed sensitive files
        """
        print_status("Checking for exposed sensitive files...")
        
        for path in self.SENSITIVE_FILES:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False
                )
                
                if response and response.status_code == 200:
                    content_length = len(response.content)
                    content_type = response.headers.get('Content-Type', 'unknown')
                    
                    is_sensitive = False
                    indicators = []
                    
                    if 'wp-config.php' in path:
                        is_sensitive = True
                        indicators.append('WordPress configuration file')
                    
                    if 'password' in response.text.lower() or 'secret' in response.text.lower() or 'database' in response.text.lower():
                        is_sensitive = True
                        indicators.append('Contains sensitive configuration')
                    
                    if '.git' in path and ('ref:' in response.text or 'repositoryformatversion' in response.text.lower()):
                        is_sensitive = True
                        indicators.append('Git repository exposed')
                    
                    if 'readme.html' in path and 'wordpress' in response.text.lower():
                        is_sensitive = True
                        indicators.append('WordPress version information')
                    
                    if is_sensitive or content_length > 0:
                        self.exposed_files.append({
                            'path': path,
                            'status_code': response.status_code,
                            'content_length': content_length,
                            'content_type': content_type,
                            'indicators': indicators,
                            'is_sensitive': is_sensitive
                        })
            except:
                pass

    def check_wordpress_paths(self):
        """
        Check for WordPress-specific paths
        """
        print_status("Checking for WordPress-specific paths...")
        
        for path in self.WORDPRESS_PATHS:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False
                )
                
                if response and response.status_code in [200, 301, 302, 403]:
                    # Check if it's actually a WordPress path
                    if 'wordpress' in response.text.lower() or path in ['/wp-admin', '/wp-login.php', '/wp-json']:
                        self.wp_paths.append({
                            'path': path,
                            'status_code': response.status_code,
                            'accessible': True
                        })
            except:
                pass

    def check_misconfigurations(self):
        """
        Check for common WordPress misconfigurations
        """
        print_status("Checking for misconfigurations...")
        
        # Check if xmlrpc.php is enabled
        try:
            response = self.http_request(method="POST", path="/xmlrpc.php", data={'test': 'test'})
            if response and response.status_code == 200:
                if 'xml' in response.text.lower():
                    self.misconfigurations.append({
                        'type': 'Information Disclosure',
                        'issue': 'XML-RPC enabled',
                        'details': 'XML-RPC is enabled and may be used for brute force attacks',
                        'severity': 'Medium'
                    })
        except:
            pass
        
        # Check if wp-admin is accessible
        try:
            response = self.http_request(method="GET", path="/wp-admin")
            if response and response.status_code == 200:
                if 'login' in response.text.lower():
                    self.misconfigurations.append({
                        'type': 'Information Disclosure',
                        'issue': 'wp-admin accessible',
                        'details': 'Admin login page is accessible',
                        'severity': 'Low'
                    })
        except:
            pass
        
        # Check if readme.html is exposed
        try:
            response = self.http_request(method="GET", path="/readme.html")
            if response and response.status_code == 200:
                self.misconfigurations.append({
                    'type': 'Information Disclosure',
                    'issue': 'readme.html exposed',
                    'details': 'Version information exposed',
                    'severity': 'Low'
                })
        except:
            pass

    def run(self):
        """
        Execute the WordPress vulnerability scan
        """
        self.wp_version = None
        self.vulnerabilities = []
        self.misconfigurations = []
        self.exposed_files = []
        self.wp_paths = []
        
        print_status("Starting WordPress vulnerability scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect WordPress version
        print_status("Detecting WordPress version...")
        version = self.detect_wordpress_version()
        self.wp_version = version
        
        if version:
            print_success(f"WordPress version detected: {version}")
        else:
            print_warning("Could not detect WordPress version")
            print_info("Continuing with generic WordPress checks...")
        print_info("")
        
        # Check for CVEs
        if version:
            print_status("Checking for known CVEs...")
            self.check_cves()
            print_info("")
        
        # Check sensitive files
        self.check_sensitive_files()
        print_info("")
        
        # Check WordPress paths
        self.check_wordpress_paths()
        print_info("")
        
        # Check misconfigurations
        self.check_misconfigurations()
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("WordPress Vulnerability Scan Summary")
        print_status("=" * 60)
        
        if version:
            print_info(f"WordPress Version: {version}")
        else:
            print_warning("WordPress Version: Not detected")
        
        print_info(f"CVEs Found: {len(self.vulnerabilities)}")
        print_info(f"Misconfigurations Found: {len(self.misconfigurations)}")
        print_info(f"Exposed Files Found: {len(self.exposed_files)}")
        print_info(f"WordPress Paths Found: {len(self.wp_paths)}")
        print_status("=" * 60)
        print_info("")
        
        # Display CVEs
        if self.vulnerabilities:
            print_warning("Vulnerabilities (CVEs):")
            print_info("")
            table_data = []
            for vuln in self.vulnerabilities:
                table_data.append([
                    vuln['id'],
                    vuln['severity'],
                    vuln['name'],
                    vuln.get('version', 'N/A')
                ])
            print_table(['CVE ID', 'Severity', 'Name', 'Version'], table_data)
            print_info("")
        
        # Display misconfigurations
        if self.misconfigurations:
            print_status("Misconfigurations:")
            print_info("")
            for misconfig in self.misconfigurations:
                print_info(f" - [{misconfig['severity']}] {misconfig['type']}: {misconfig['issue']}")
                print_info(f"   - Details: {misconfig['details']}")
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
        
        # Display WordPress paths
        if self.wp_paths:
            print_info(f"Found {len(self.wp_paths)} accessible WordPress paths")
            for path_info in self.wp_paths[:10]:  # Show first 10
                print_info(f"  - {path_info['path']} (Status: {path_info['status_code']})")
        
        return True
