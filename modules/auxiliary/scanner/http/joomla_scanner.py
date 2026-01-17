#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'Joomla Vulnerability Scanner',
        'description': 'Scans for Joomla-specific vulnerabilities, version information, exposed files, and security misconfigurations',
        'author': 'KittySploit Team',
        'tags': ['web', 'joomla', 'scanner', 'security', 'vulnerability', 'cms'],
        'references': [
            'https://developer.joomla.org/security-centre.html',
            'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=joomla',
            'https://owasp.org/www-project-web-security-testing-guide/'
        ]
    }

    # Known Joomla CVEs
    JOOMLA_CVES = {
        'CVE-2023-23752': {
            'name': 'Information Disclosure',
            'affected_versions': ['< 4.2.8', '< 5.0.0'],
            'severity': 'Medium',
            'description': 'Information disclosure vulnerability'
        },
        'CVE-2023-23753': {
            'name': 'SQL Injection',
            'affected_versions': ['< 4.2.8', '< 5.0.0'],
            'severity': 'High',
            'description': 'SQL injection vulnerability'
        },
        'CVE-2023-23754': {
            'name': 'Cross-Site Scripting',
            'affected_versions': ['< 4.2.8', '< 5.0.0'],
            'severity': 'Medium',
            'description': 'Cross-site scripting vulnerability'
        },
        'CVE-2022-23708': {
            'name': 'Remote Code Execution',
            'affected_versions': ['< 4.0.0'],
            'severity': 'Critical',
            'description': 'Remote code execution vulnerability'
        },
        'CVE-2021-23132': {
            'name': 'SQL Injection',
            'affected_versions': ['< 3.9.24'],
            'severity': 'Critical',
            'description': 'SQL injection vulnerability'
        },
        'CVE-2020-10238': {
            'name': 'SQL Injection',
            'affected_versions': ['< 3.9.16'],
            'severity': 'High',
            'description': 'SQL injection vulnerability'
        },
    }

    # Joomla-specific paths
    JOOMLA_PATHS = [
        '/administrator',
        '/administrator/index.php',
        '/administrator/components',
        '/administrator/modules',
        '/administrator/templates',
        '/components',
        '/modules',
        '/templates',
        '/plugins',
        '/libraries',
        '/includes',
        '/cache',
        '/tmp',
        '/images',
        '/media',
        '/configuration.php',
        '/.htaccess',
        '/web.config',
        '/index.php',
        '/README.txt',
        '/CHANGELOG.php',
    ]

    # Sensitive files
    SENSITIVE_FILES = [
        '/configuration.php',
        '/.htaccess',
        '/.git/config',
        '/.git/HEAD',
        '/.env',
        '/composer.json',
        '/package.json',
        '/README.txt',
        '/CHANGELOG.php',
    ]

    def check(self):
        """
        Check if the target is accessible and running Joomla
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for Joomla indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                joomla_indicators = [
                    'joomla', 'joomla!', 'joomla.org',
                    '/administrator', '/components/',
                    '/modules/', '/templates/',
                    'option=com_', 'view=',
                    'generator.*joomla'
                ]
                
                if any(indicator in content or indicator in headers for indicator in joomla_indicators):
                    return True
                
                # Check for Joomla paths
                test_response = self.http_request(method="GET", path="/administrator")
                if test_response and ('joomla' in test_response.text.lower() or test_response.status_code in [200, 301, 302, 403]):
                    return True
                
                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_joomla_version(self):
        """
        Detect Joomla version
        """
        try:
            # Try README.txt
            response = self.http_request(method="GET", path="/README.txt")
            if response and response.status_code == 200:
                version_match = re.search(r'Joomla!\s+([\d\.]+)', response.text, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
            
            # Check generator meta tag
            response = self.http_request(method="GET", path="/")
            if response:
                generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla!\s+([\d\.]+)', response.text, re.IGNORECASE)
                if generator_match:
                    return generator_match.group(1)
                
                # Check for Joomla in JavaScript
                joomla_js_match = re.search(r'joomla.*version["\']?\s*:\s*["\']?([\d\.]+)', response.text, re.IGNORECASE)
                if joomla_js_match:
                    return joomla_js_match.group(1)
                
                # Check CHANGELOG.php
                response = self.http_request(method="GET", path="/CHANGELOG.php")
                if response and response.status_code == 200:
                    version_match = re.search(r'Joomla!\s+([\d\.]+)', response.text, re.IGNORECASE)
                    if version_match:
                        return version_match.group(1)
            
            return None
        except Exception as e:
            print_debug(f"Error detecting Joomla version: {str(e)}")
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
        if not self.joomla_version:
            return
        
        for cve_id, cve_info in self.JOOMLA_CVES.items():
            if self.is_version_vulnerable(self.joomla_version, cve_info['affected_versions']):
                self.vulnerabilities.append({
                    'type': 'CVE',
                    'id': cve_id,
                    'name': cve_info['name'],
                    'severity': cve_info['severity'],
                    'description': cve_info['description'],
                    'version': self.joomla_version
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
                    
                    if 'configuration.php' in path:
                        is_sensitive = True
                        indicators.append('Joomla configuration file')
                    
                    if 'password' in response.text.lower() or 'secret' in response.text.lower() or 'database' in response.text.lower():
                        is_sensitive = True
                        indicators.append('Contains sensitive configuration')
                    
                    if '.git' in path and ('ref:' in response.text or 'repositoryformatversion' in response.text.lower()):
                        is_sensitive = True
                        indicators.append('Git repository exposed')
                    
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

    def check_joomla_paths(self):
        """
        Check for Joomla-specific paths
        """
        print_status("Checking for Joomla-specific paths...")
        
        for path in self.JOOMLA_PATHS:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False
                )
                
                if response and response.status_code in [200, 301, 302, 403]:
                    # Check if it's actually a Joomla path
                    if 'joomla' in response.text.lower() or path in ['/administrator', '/components', '/modules']:
                        self.joomla_paths.append({
                            'path': path,
                            'status_code': response.status_code,
                            'accessible': True
                        })
            except:
                pass

    def check_misconfigurations(self):
        """
        Check for common Joomla misconfigurations
        """
        print_status("Checking for misconfigurations...")
        
        # Check if administrator is accessible
        try:
            response = self.http_request(method="GET", path="/administrator")
            if response and response.status_code == 200:
                if 'login' in response.text.lower() or 'joomla' in response.text.lower():
                    self.misconfigurations.append({
                        'type': 'Information Disclosure',
                        'issue': 'Administrator panel accessible',
                        'details': 'Administrator login page is accessible',
                        'severity': 'Low'
                    })
        except:
            pass
        
        # Check if configuration.php is accessible
        try:
            response = self.http_request(method="GET", path="/configuration.php")
            if response and response.status_code == 200:
                self.misconfigurations.append({
                    'type': 'Information Disclosure',
                    'issue': 'configuration.php exposed',
                    'details': 'Configuration file is accessible and may contain sensitive information',
                    'severity': 'High'
                })
        except:
            pass
        
        # Check for exposed version information
        try:
            response = self.http_request(method="GET", path="/README.txt")
            if response and response.status_code == 200:
                self.misconfigurations.append({
                    'type': 'Information Disclosure',
                    'issue': 'README.txt exposed',
                    'details': 'Version information exposed',
                    'severity': 'Low'
                })
        except:
            pass

    def run(self):
        """
        Execute the Joomla vulnerability scan
        """
        self.joomla_version = None
        self.vulnerabilities = []
        self.misconfigurations = []
        self.exposed_files = []
        self.joomla_paths = []
        
        print_status("Starting Joomla vulnerability scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect Joomla version
        print_status("Detecting Joomla version...")
        version = self.detect_joomla_version()
        self.joomla_version = version
        
        if version:
            print_success(f"Joomla version detected: {version}")
        else:
            print_warning("Could not detect Joomla version")
            print_info("Continuing with generic Joomla checks...")
        print_info("")
        
        # Check for CVEs
        if version:
            print_status("Checking for known CVEs...")
            self.check_cves()
            print_info("")
        
        # Check sensitive files
        self.check_sensitive_files()
        print_info("")
        
        # Check Joomla paths
        self.check_joomla_paths()
        print_info("")
        
        # Check misconfigurations
        self.check_misconfigurations()
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("Joomla Vulnerability Scan Summary")
        print_status("=" * 60)
        
        if version:
            print_info(f"Joomla Version: {version}")
        else:
            print_warning("Joomla Version: Not detected")
        
        print_info(f"CVEs Found: {len(self.vulnerabilities)}")
        print_info(f"Misconfigurations Found: {len(self.misconfigurations)}")
        print_info(f"Exposed Files Found: {len(self.exposed_files)}")
        print_info(f"Joomla Paths Found: {len(self.joomla_paths)}")
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
        
        # Display Joomla paths
        if self.joomla_paths:
            print_info(f"Found {len(self.joomla_paths)} accessible Joomla paths")
            for path_info in self.joomla_paths[:10]:  # Show first 10
                print_info(f"  - {path_info['path']} (Status: {path_info['status_code']})")
        
        return True
