from core.framework.base_module import BaseModule
from core.framework.failure import ProcedureError, FailureType
from core.framework.option.option_string import OptString

class Post(BaseModule):

    TYPE_MODULE = "post"

    session_id = OptString("", "Session ID", required=True)

    def __init__(self):
        super().__init__()

    def run(self):
        raise NotImplementedError("Post modules must implement the run() method")

    def check(self):
        raise NotImplementedError("Post modules must implement the check() method")

    def _exploit(self):
        try:
            self.run()
            return True
        except ProcedureError as e:
            raise e
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, e)
    
    def cmd_execute(self, command: str) -> str:
        """
        Execute a command on the session.
        
        Args:
            command: The command to execute
            
        Returns:
            str: The output of the command, or empty string if execution failed
        """
        # Check if framework is available
        if not self.framework:
            raise ProcedureError(FailureType.ConfigurationError, "Framework not available")
        
        # Check if session_id is set
        session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
        if not session_id_value:
            raise ProcedureError(FailureType.ConfigurationError, "Session ID not set")
        
        # Execute command using shell_manager
        if not hasattr(self.framework, 'shell_manager') or not self.framework.shell_manager:
            raise ProcedureError(FailureType.ConfigurationError, "Shell manager not available")
        
        # Pass framework to execute_command so it can auto-create shell if needed
        result = self.framework.shell_manager.execute_command(session_id_value, command, framework=self.framework)
        
        # Check for errors
        if result.get('error'):
            # Return error message or empty string based on preference
            # For compatibility with old code that expects string output
            return result.get('error', '')
        
        # Return the output
        return result.get('output', '')
    
    def cmd_exec(self, command: str) -> str:
        """
        Alias for cmd_execute for backward compatibility.
        
        Args:
            command: The command to execute
            
        Returns:
            str: The output of the command, or empty string if execution failed
        """
        return self.cmd_execute(command)
    
    def send_php(self, php_code: str) -> bool:
        """
        Send PHP code to execute on the target session (fire and forget).
        Similar to send_js for JavaScript, this method sends PHP code for execution
        without waiting for the result.
        
        This method executes PHP code via the session's command execution mechanism.
        The exact execution method depends on the session type (webshell, command line, etc.).
        
        Args:
            php_code: PHP code to execute (can include <?php tags or be raw PHP code)
            
        Returns:
            bool: True if command was sent successfully, False otherwise
            
        Example:
            def run(self):
                # Send PHP code without waiting for result
                self.send_php("echo 'Hello from PHP';")
                # Or with PHP tags
                self.send_php("<?php echo 'Hello from PHP'; ?>")
        """
        # Check if framework is available
        if not self.framework:
            from core.output_handler import print_error
            print_error("Framework not available")
            return False
        
        # Check if session_id is set
        session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
        if not session_id_value:
            from core.output_handler import print_error
            print_error("Session ID not set")
            return False
        
        # Remove PHP tags if present (the code will be executed directly)
        code = php_code.strip()
        if code.startswith('<?php'):
            code = code[5:].strip()
        if code.startswith('<?'):
            code = code[2:].strip()
        if code.endswith('?>'):
            code = code[:-2].strip()
        
        # Execute using cmd_execute
        # The session should handle PHP code execution appropriately
        # For webshells, this might be eval($code), for CLI it might be php -r
        try:
            # Use cmd_execute to send the PHP code
            # The shell manager will route this to the appropriate shell
            result = self.cmd_execute(code)
            # Return True if command was sent (fire and forget)
            return True
        except Exception as e:
            from core.output_handler import print_error
            print_error(f"Error sending PHP code: {e}")
            return False
    
    def php_eval(self, php_code: str) -> bool:
        """
        Evaluate PHP code on the target session.
        
        Args:
            php_code: PHP code to evaluate
            
        Returns:
            bool: True if code was evaluated successfully, False otherwise
        """
        return self.send_php(php_code)