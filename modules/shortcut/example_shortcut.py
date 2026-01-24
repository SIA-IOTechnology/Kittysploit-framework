#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

class Module(Shortcut):

    __info__ = {
        'name': 'Example Shortcut - Scan and Exploit',
        'description': 'Example shortcut that scans a target and automatically exploits found vulnerabilities',
        'author': 'KittySploit Team',
        'tags': ['shortcut'],
    }

    target = OptString("", "Target URL or hostname (e.g., https://example.com)", required=True)
    auto_exploit = OptBool(True, "Automatically exploit found vulnerabilities", required=False)

    def run(self):


        print_info("=" * 70)
        print_success("Example Shortcut - Scan and Exploit")
        print_info("=" * 70)
        print_info(f"Target: {self.target}")
        print_info(f"Auto-exploit: {self.auto_exploit}")
        print_empty()

        # Step 1: Scan target
        print_info("[*] Step 1: Scanning target for vulnerabilities...")
        
        # Load scanner command (if available)
        # In a real shortcut, you would use the scanner command or load scanner modules
        # For this example, we'll simulate the scan
        print_info(f"Scanning {self.target}...")
        
        # Simulate finding vulnerabilities
        vulnerabilities_found = [
            {'name': 'Flask Debug Mode', 'module': 'exploits/http/flask_debug_rce'},
            {'name': 'WordPress RCE', 'module': 'exploits/http/wordpress_rce'},
        ]
        
        if vulnerabilities_found:
            print_success(f"Found {len(vulnerabilities_found)} vulnerability(ies):")
            for vuln in vulnerabilities_found:
                print_info(f"{vuln['name']} ({vuln['module']})")
            print_empty()
        else:
            print_info("No vulnerabilities found")
            return True

        # Step 2: Auto-exploit if enabled
        if self.auto_exploit:
            print_status("Step 2: Auto-exploiting vulnerabilities...")
            
            for vuln in vulnerabilities_found:
                exploit_module = vuln['module']
                print_status(f"Loading exploit: {exploit_module}")
                
                # Load the exploit module
                if self.load_module(exploit_module):
                    print_success(f"Loaded: {exploit_module}")
                    
                    self.add_option('target', self.target)
#                    if hasattr(self.current_module, 'rhost'):
#                        # Extract hostname from URL
#                        from urllib.parse import urlparse
#                        parsed = urlparse(self.target)
#                        hostname = parsed.hostname or parsed.netloc.split(':')[0]
#                        self.current_module.set_option('rhost', hostname)
                    
                    # Execute the exploit
                    print_info(f"    Executing exploit...")
                    try:
                        result = self.execute()
                        if result:
                            print_success(f"    Exploit succeeded: {exploit_module}")
                        else:
                            print_warning(f"    Exploit failed: {exploit_module}")
                    except Exception as e:
                        print_error(f"    Error executing exploit: {e}")
                    
                    # Unload module
                    self.unload_module()
                    print_empty()
                else:
                    print_error(f"    Failed to load: {exploit_module}")
        else:
            print_info("Step 2: Skipped (auto-exploit disabled)")
            print_info("Use 'set auto_exploit true' to enable auto-exploitation")

        print_info("=" * 70)
        print_success("Shortcut execution completed")
        print_info("=" * 70)
        
        return True
