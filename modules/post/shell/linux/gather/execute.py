#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin
import time
import threading


class Module(Post, System, LinuxSessionMixin):

    __info__ = {
        "name": "Linux Execute Command",
        "description": "Execute commands on Linux sessions with support for short/long responses and fire-and-forget mode",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }
    
    command = OptString("ls -la", "Command to execute", required=True)
    wait_for_response = OptBool(True, "Wait for command response (False for fire-and-forget)", required=False)
    timeout = OptInteger(30, "Timeout in seconds for command execution (0 = no timeout)", required=False, advanced=True)
    max_output_length = OptInteger(10000, "Maximum output length to display (0 = unlimited)", required=False, advanced=True)

    def run(self):
        if not self.linux_require_linux():
            return False

        if not self.wait_for_response:
            print_status(f"Executing command in background: {self.command}")
            try:
                def execute_async():
                    try:
                        self.linux_execute(str(self.command))
                    except Exception as e:
                        print_error(f"Background command error: {e}")
                
                thread = threading.Thread(target=execute_async, daemon=True)
                thread.start()
                print_success("Command sent in background (fire-and-forget mode)")
                return True
            except Exception as e:
                print_error(f"Error executing command in background: {e}")
                return False
        
        print_status(f"Executing command: {self.command}")
        
        try:
            start_time = time.time()
            to = int(self.timeout or 0)
            result = self.linux_execute(str(self.command), timeout=to if to > 0 else 0)
            execution_time = time.time() - start_time
            
            if not result:
                print_warning("Command executed but returned no output")
                return True
            
            if result.startswith("Error:") or "error" in result.lower():
                print_error(f"Command error: {result}")
                return False
            
            output_length = len(result)
            is_long_output = output_length > 1000
            
            display_result = result
            if self.max_output_length > 0 and output_length > self.max_output_length:
                display_result = result[:self.max_output_length]
                truncated = True
            else:
                truncated = False
            
            if truncated:
                print_info("\n--- Command Output (truncated) ---")
                print_info(display_result)
                print_warning(f"... ({output_length - self.max_output_length} more characters)")
            elif is_long_output:
                print_info("\n--- Command Output ---")
                print_info(display_result)
                print_info(f"\nExecution time: {execution_time:.2f} seconds")
            else:
                print_success("Command executed successfully")
                print_info("\n--- Command Output ---")
                print_info(display_result)
                print_info(f"Execution time: {execution_time:.2f} seconds")
                        
        except Exception as e:
            print_error(f"Error executing command: {e}")
            return False

        return True
