#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Apache Vulnerability Scanner',
        'description': 'Scans for Apache-specific vulnerabilities, version information, misconfigurations, and exposed sensitive files',
        'author': 'KittySploit Team',
        'tags': ['web', 'apache', 'scanner', 'security', 'vulnerability'],
        'references': [
            'https://httpd.apache.org/security/',
            'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=apache',
            'https://owasp.org/www-project-web-security-testing-guide/'
        ]
    }

    # Known Apache CVEs and vulnerable versions
    APACHE_CVES = {
        'CVE-2023-43622': {
            'name': 'mod_rewrite vulnerability',
            'affected_versions': ['< 2.4.58'],
            'severity': 'High',
            'description': 'mod_rewrite vulnerability in Apache HTTP Server'
        },
        'CVE-2023-45802': {
            'name': 'HTTP/2 Request Smuggling',
            'affected_versions': ['< 2.4.58'],
            'severity': 'High',
            'description': 'HTTP/2 request smuggling vulnerability'
        },
        'CVE-2023-27522': {
            'name': 'HTTP/2 Request Smuggling',
            'affected_versions': ['< 2.4.56'],
            'severity': 'High',
            'description': 'HTTP/2 request smuggling via mod_proxy'
        },
        'CVE-2022-31813': {
            'name': 'HTTP Response Splitting',
            'affected_versions': ['< 2.4.55'],
            'severity': 'Medium',
            'description': 'HTTP response splitting in mod_rewrite'
        },
        'CVE-2022-30556': {
            'name': 'mod_proxy_uwsgi vulnerability',
            'affected_versions': ['< 2.4.54'],
            'severity': 'Medium',
            'description': 'mod_proxy_uwsgi vulnerability'
        },
        'CVE-2022-30522': {
            'name': 'mod_proxy vulnerability',
            'affected_versions': ['< 2.4.54'],
            'severity': 'Medium',
            'description': 'mod_proxy vulnerability'
        },
        'CVE-2021-44224': {
            'name': 'mod_lua vulnerability',
            'affected_versions': ['< 2.4.52'],
            'severity': 'High',
            'description': 'mod_lua vulnerability'
        },
        'CVE-2021-44790': {
            'name': 'Buffer Overflow',
            'affected_versions': ['< 2.4.52'],
            'severity': 'High',
            'description': 'Buffer overflow in mod_lua'
        },
        'CVE-2021-39275': {
            'name': 'Buffer Overflow',
            'affected_versions': ['< 2.4.49'],
            'severity': 'High',
            'description': 'Buffer overflow in mod_proxy_uwsgi'
        },
    }

    # Sensitive files and paths to check
    SENSITIVE_PATHS = [
        '/.htaccess',
        '/.htpasswd',
        '/.htgroup',
        '/.well-known/security.txt',
        '/server-status',
        '/server-info',
        '/apache-status',
        '/status',
        '/.git/config',
        '/.git/HEAD',
        '/.svn/entries',
        '/.env',
        '/backup',
        '/backups',
        '/backup.tar.gz',
        '/backup.sql',
        '/config.php',
        '/config.inc.php',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/admin',
        '/administrator',
        '/wp-admin',
        '/wp-config.php',
        '/web.config',
        '/.DS_Store',
        '/.gitignore',
        '/httpd.conf',
        '/apache2.conf',
        '/conf/httpd.conf',
        '/etc/apache2/apache2.conf',
        '/usr/local/apache2/conf/httpd.conf',
    ]

    # Dangerous configurations to check
    DANGEROUS_CONFIGS = [
        ('/../', 'Path Traversal'),
        ('/%2e%2e%2f', 'URL Encoded Path Traversal'),
        ('/..\\', 'Windows Path Traversal'),
        ('/....//....//', 'Double Slash Bypass'),
        ('/%2e%2e/', 'Double Encoded Path Traversal'),
    ]

    def check(self):
        """
        Check if the target is accessible and running Apache
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check if it's Apache
                server_header = response.headers.get('Server', '').lower()
                if 'apache' in server_header:
                    return True
                # Also check in response body
                if 'apache' in response.text.lower():
                    return True
            return False
        except Exception as e:
            return False

    def detect_apache_version(self):
        """
        Detect Apache version from Server header
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None

            server_header = response.headers.get('Server', '')

            # Extract version from Server header (e.g., "Apache/2.4.41")
            version_match = re.search(r'Apache(?:/)?([\d\.]+)', server_header, re.IGNORECASE)
            if version_match:
                version = version_match.group(1)
                self.apache_version = version
                self.server_info['version'] = version
                self.server_info['server_header'] = server_header
                return version

            # Check in response body
            body_match = re.search(r'Apache(?:/)?([\d\.]+)', response.text, re.IGNORECASE)
            if body_match:
                version = body_match.group(1)
                self.apache_version = version
                self.server_info['version'] = version
                return version

            return None

        except Exception as e:
            print_debug(f"Error detecting Apache version: {str(e)}")
            return None

    def compare_versions(self, version1, version2):
        """
        Compare two version strings
        Returns: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]

            # Pad with zeros to make same length
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
        Check if a version is vulnerable based on affected versions list
        """
        if not version:
            return False

        for affected in affected_versions:
            if affected.startswith('< '):
                # Version less than specified
                threshold = affected[2:].strip()
                if self.compare_versions(version, threshold) < 0:
                    return True
            elif affected.startswith('<= '):
                # Version less than or equal to specified
                threshold = affected[3:].strip()
                if self.compare_versions(version, threshold) <= 0:
                    return True

        return False

    def check_cves(self):
        """
        Check for known CVEs based on detected version
        """
        if not self.apache_version:
            return

        for cve_id, cve_info in self.APACHE_CVES.items():
            if self.is_version_vulnerable(self.apache_version, cve_info['affected_versions']):
                self.vulnerabilities.append({
                    'type': 'CVE',
                    'id': cve_id,
                    'name': cve_info['name'],
                    'severity': cve_info['severity'],
                    'description': cve_info['description'],
                    'version': self.apache_version
                })

    def check_sensitive_files(self):
        """
        Check for exposed sensitive files
        """
        print_status("Checking for exposed sensitive files...")

        for path in self.SENSITIVE_PATHS:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False
                )

                if response:
                    # Check if file is accessible (not 404)
                    if response.status_code == 200:
                        content_length = len(response.content)
                        content_type = response.headers.get('Content-Type', 'unknown')

                        # Check for indicators of sensitive content
                        is_sensitive = False
                        indicators = []

                        if 'apache' in response.text.lower() and 'conf' in path:
                            is_sensitive = True
                            indicators.append('Apache configuration file')

                        if 'password' in response.text.lower() or 'secret' in response.text.lower():
                            is_sensitive = True
                            indicators.append('Contains passwords/secrets')

                        if '.htaccess' in path or '.htpasswd' in path:
                            is_sensitive = True
                            indicators.append('Apache access control file')

                        if '.git' in path and ('ref:' in response.text or 'repositoryformatversion' in response.text.lower()):
                            is_sensitive = True
                            indicators.append('Git repository exposed')

                        if 'php' in content_type.lower() and 'phpinfo' in response.text.lower():
                            is_sensitive = True
                            indicators.append('PHP info exposed')

                        if is_sensitive or (response.status_code == 200 and content_length > 0):
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

    def check_misconfigurations(self):
        """
        Check for common Apache misconfigurations
        """
        print_status("Checking for misconfigurations...")

        # Check for server header disclosure
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                server_header = response.headers.get('Server', '')
                if server_header and 'apache' in server_header.lower():
                    # Check if full version is exposed
                    if re.search(r'Apache(?:/)?[\d\.]+', server_header):
                        self.misconfigurations.append({
                            'type': 'Information Disclosure',
                            'issue': 'Server version exposed in headers',
                            'details': f'Server header: {server_header}',
                            'severity': 'Low'
                        })
        except:
            pass

        # Check for missing security headers
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                security_headers = {
                    'X-Frame-Options': 'Clickjacking protection',
                    'X-Content-Type-Options': 'MIME type sniffing protection',
                    'X-XSS-Protection': 'XSS protection',
                    'Strict-Transport-Security': 'HSTS',
                    'Content-Security-Policy': 'CSP',
                    'Referrer-Policy': 'Referrer policy'
                }

                missing_headers = []
                for header, description in security_headers.items():
                    if header not in response.headers:
                        missing_headers.append(header)

                if missing_headers:
                    self.misconfigurations.append({
                        'type': 'Missing Security Headers',
                        'issue': 'Security headers not configured',
                        'details': f'Missing: {", ".join(missing_headers)}',
                        'severity': 'Medium'
                    })
        except:
            pass

        # Check for path traversal vulnerabilities
        for path, description in self.DANGEROUS_CONFIGS:
            try:
                test_path = f"{path}etc/passwd"
                response = self.http_request(
                    method="GET",
                    path=test_path,
                    allow_redirects=False
                )

                if response and response.status_code == 200:
                    # Check if we got /etc/passwd content
                    if 'root:' in response.text and 'bin/bash' in response.text:
                        self.misconfigurations.append({
                            'type': 'Path Traversal',
                            'issue': description,
                            'details': f'Path traversal successful: {test_path}',
                            'severity': 'High'
                        })
                        break
            except:
                pass

    def check_status_endpoints(self):
        """
        Check for exposed status endpoints
        """
        status_paths = ['/server-status', '/server-info', '/apache-status', '/status']

        for path in status_paths:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False
                )

                if response and response.status_code == 200:
                    # Check if it's actually a status page
                    if 'server-status' in response.text.lower() or 'apache server status' in response.text.lower():
                        self.misconfigurations.append({
                            'type': 'Information Disclosure',
                            'issue': 'Status endpoint exposed',
                            'details': f'Status endpoint accessible at: {path}',
                            'severity': 'Medium'
                        })
            except:
                pass

    def run(self):
        """
        Execute the Apache vulnerability scan
        """
        # Initialize variables
        self.apache_version = None
        self.vulnerabilities = []
        self.misconfigurations = []
        self.exposed_files = []
        self.server_info = {}

        print_status("Starting Apache vulnerability scan...")
        print_info(f"Target: {self.target}")
        print_info("")

        # Detect Apache version
        print_status("Detecting Apache version...")
        version = self.detect_apache_version()

        if version:
            print_success(f"Apache version detected: {version}")
            if 'server_header' in self.server_info:
                print_info(f"Server header: {self.server_info['server_header']}")
        else:
            print_warning("Could not detect Apache version")
            print_info("Continuing with generic checks...")

        print_info("")

        # Check for CVEs
        if version:
            print_status("Checking for known CVEs...")
            self.check_cves()
            print_info("")

        # Check for sensitive files
        self.check_sensitive_files()
        print_info("")

        # Check for misconfigurations
        self.check_misconfigurations()
        print_info("")

        # Check status endpoints
        self.check_status_endpoints()
        print_info("")

        # Summary
        print_status("=" * 60)
        print_status("Apache Vulnerability Scan Summary")
        print_status("=" * 60)

        if version:
            print_info(f"Apache Version: {version}")
        else:
            print_warning("Apache Version: Not detected")

        print_info(f"CVEs Found: {len(self.vulnerabilities)}")
        print_info(f"Misconfigurations Found: {len(self.misconfigurations)}")
        print_info(f"Exposed Files Found: {len(self.exposed_files)}")
        print_status("=" * 60)
        print_info("")

        # Display CVEs
        if self.vulnerabilities:
            print_success("Vulnerabilities (CVEs):")
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
            print_success(f"Found {len(self.exposed_files)} exposed sensitive files")
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
        return True
