from kittysploit import *
from lib.post.linux.system import System
import time
import threading

class Module(Post, System):

    __info__ = {
        "name": "Linux Execute Command",
        "description": "Execute commands on Linux sessions with support for short/long responses and fire-and-forget mode",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }
    
    command = OptString("ls -la", "Command to execute", required=True)
    wait_for_response = OptBool(True, "Wait for command response (False for fire-and-forget)", required=False)
    timeout = OptInteger(30, "Timeout in seconds for command execution (0 = no timeout)", required=False, advanced=True)
    max_output_length = OptInteger(10000, "Maximum output length to display (0 = unlimited)", required=False, advanced=True)

    def run(self):
        """Execute command with intelligent response handling"""
        
        # Fire-and-forget mode
        if not self.wait_for_response:
            print_status(f"Executing command in background: {self.command}")
            try:
                # Execute command without waiting for response
                # We'll use a thread to send the command
                def execute_async():
                    try:
                        result = self.cmd_execute(self.command)
                        # In fire-and-forget mode, we don't wait for or display the result
                    except Exception as e:
                        print_error(f"Background command error: {e}")
                
                thread = threading.Thread(target=execute_async, daemon=True)
                thread.start()
                print_success("Command sent in background (fire-and-forget mode)")
                return True
            except Exception as e:
                print_error(f"Error executing command in background: {e}")
                return False
        
        # Normal execution with response
        print_status(f"Executing command: {self.command}")
        
        try:
            # Execute command
            start_time = time.time()
            result = self.cmd_execute(self.command)
            execution_time = time.time() - start_time
            
            if not result:
                print_warning("Command executed but returned no output")
                return True
            
            # Check if result is an error message
            if result.startswith("Error:") or "error" in result.lower():
                print_error(f"Command error: {result}")
                return False
            
            # Handle response based on length
            output_length = len(result)
            
            # Determine if output is "long"
            is_long_output = output_length > 1000  # Consider > 1000 chars as "long"
            
            # Apply max_output_length limit for display
            display_result = result
            if self.max_output_length > 0 and output_length > self.max_output_length:
                display_result = result[:self.max_output_length]
                truncated = True
            else:
                truncated = False
            
            # Display output
            if truncated:
                print_info("\n--- Command Output (truncated) ---")
                print_info(display_result)
                print_warning(f"... ({output_length - self.max_output_length} more characters)")
            elif is_long_output:
                print_info("\n--- Command Output ---")
                print_info(display_result)
                print_info(f"\nExecution time: {execution_time:.2f} seconds")
            else:
                # Short output - display normally
                print_success("Command executed successfully")
                print_info("\n--- Command Output ---")
                print_info(display_result)
                print_info(f"Execution time: {execution_time:.2f} seconds")
                        
        except Exception as e:
            print_error(f"Error executing command: {e}")