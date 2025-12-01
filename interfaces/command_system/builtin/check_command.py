#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check command implementation for vulnerability verification using module check() method
"""

import argparse
import time
from datetime import datetime
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_table

class CheckCommand(BaseCommand):
    """Command to check if targets are vulnerable using module check() method"""
    
    @property
    def name(self) -> str:
        return "check"
    
    @property
    def description(self) -> str:
        return "Check if targets are vulnerable using the current module's check() method"
    
    @property
    def usage(self) -> str:
        return "check [--verbose] [--timeout <seconds>]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command uses the check() method of the currently selected module to verify
if the target is vulnerable before attempting exploitation. This helps avoid
failed exploitation attempts and reduces noise on the target.

Options:
    --verbose, -v           Verbose output with detailed information
    --timeout <seconds>     Timeout for the check operation (default: 30)

Examples:
    check                   # Check vulnerability with current module
    check --verbose         # Check with detailed output
    check --timeout 60      # Check with 60 second timeout

Note: This command only works when an exploit module is selected.
The module must implement the check() method.
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Check if targets are vulnerable using module check() method",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  check                   # Check vulnerability with current module
  check --verbose         # Check with detailed output
  check --timeout 60      # Check with 60 second timeout
            """
        )
        
        parser.add_argument("--verbose", "-v", action="store_true", 
                          help="Verbose output with detailed information")
        parser.add_argument("--timeout", type=int, default=30, 
                          help="Timeout for the check operation in seconds")
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the check command"""
        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True
        
        try:
            # Check if a module is selected
            if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
                print_error("No module selected. Use 'use <module>' first.")
                return False
            
            module = self.framework.current_module
            
            # Check if module supports check functionality
            if not hasattr(module, 'check'):
                print_error("Current module does not support vulnerability checking.")
                print_info("Only exploit modules with a check() method can be used.")
                return False
            
            # Check if module is an exploit
            if not hasattr(module, 'type') or module.type != 'exploit':
                print_warning("Current module is not an exploit. Check results may not be reliable.")
            
            # Check if required options are set
            if hasattr(module, 'check_options') and not module.check_options():
                missing = module.get_missing_options() if hasattr(module, 'get_missing_options') else []
                if missing:
                    print_error(f"Missing required options: {', '.join(missing)}")
                else:
                    print_error("Not all required options are set for checking.")
                print_info("Use 'show options' to see required options")
                return False
            
            # Show check information
            print_info(f"Checking vulnerability with module: {module.name}")
            print_info(f"Description: {module.description}")
            print_info(f"Timeout: {parsed_args.timeout} seconds")
            print_info("=" * 60)
            
            if parsed_args.verbose:
                print_info("Verbose mode enabled - showing detailed information")
                self._show_module_info(module)
            
            # Perform the check
            start_time = time.time()
            
            try:
                # Call the module's check method
                result = module.check()
                
                end_time = time.time()
                duration = end_time - start_time
                
                # Display results
                self._display_check_results(result, duration, parsed_args.verbose)
                
                return True
                
            except Exception as e:
                end_time = time.time()
                duration = end_time - start_time
                
                print_error(f"Check failed after {duration:.2f} seconds: {str(e)}")
                
                if parsed_args.verbose:
                    import traceback
                    print_error("Full traceback:")
                    traceback.print_exc()
                
                return False
                    
        except Exception as e:
            print_error(f"Error executing check command: {str(e)}")
            return False
    
    def _show_module_info(self, module):
        """Show detailed module information in verbose mode"""
        try:
            print_info("\nModule Information:")
            print_info("-" * 30)
            print_info(f"Name: {module.name}")
            print_info(f"Type: {getattr(module, 'type', 'unknown')}")
            print_info(f"Author: {getattr(module, 'author', 'unknown')}")
            print_info(f"Version: {getattr(module, 'version', 'unknown')}")
            
            if hasattr(module, 'cve') and module.cve:
                print_info(f"CVE: {module.cve}")
            
            if hasattr(module, 'references') and module.references:
                print_info(f"References: {module.references}")
            
            # Show current options
            if hasattr(module, 'get_options'):
                options = module.get_options()
                if options:
                    print_info("\nCurrent Options:")
                    print_info("-" * 20)
                    for name, value in options.items():
                        if isinstance(value, (list, tuple)) and len(value) >= 2:
                            # Handle option objects
                            current_value = value[0] if hasattr(value[0], 'value') else str(value[0])
                            print_info(f"{name}: {current_value}")
                        else:
                            print_info(f"{name}: {value}")
            
        except Exception as e:
            print_warning(f"Could not display module information: {e}")
    
    def _display_check_results(self, result, duration, verbose=False):
        """Display the results of the vulnerability check"""
        try:
            print_info(f"\nCheck completed in {duration:.2f} seconds")
            print_info("=" * 60)
            
            # Handle different result types
            if isinstance(result, bool):
                if result:
                    print_success("Target appears to be VULNERABLE")
                    print_info("The target may be exploitable with this module")
                else:
                    print_warning("Target does NOT appear to be vulnerable")
                    print_info("The target is likely not exploitable with this module")
            
            elif isinstance(result, dict):
                # Handle structured result
                vulnerable = result.get('vulnerable', False)
                confidence = result.get('confidence', 'unknown')
                details = result.get('details', '')
                reason = result.get('reason', '')
                
                if vulnerable:
                    print_success("Target appears to be VULNERABLE")
                    if details:
                        print_info(f"Details: {details}")
                else:
                    print_warning("Target does NOT appear to be vulnerable")
                    if reason:
                        print_info(f"Reason: {reason}")
                
                print_info(f"Confidence: {confidence}")
                
                if verbose and result.get('additional_info'):
                    print_info(f"Additional Info: {result['additional_info']}")
            
            elif isinstance(result, str):
                # Handle string result
                print_info(f"Check Result: {result}")
            
            else:
                # Handle other result types
                print_info(f"Check Result: {str(result)}")
            
            
        except Exception as e:
            print_error(f"Error displaying check results: {str(e)}")
            print_info(f"Raw result: {result}")
