#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(VagrantEnvironment):
    __info__ = {
        "name": "Metasploitable3 Windows Environment",
        "description": (
            "Metasploitable3 Windows Server 2008 R2 lab VM via Vagrant — intentionally "
            "vulnerable Windows target for authorized internal-lab agent benchmarks."
        ),
        "author": "KittySploit Team",
        "references": [
            "https://github.com/rapid7/metasploitable3",
            "https://app.vagrantup.com/rapid7/boxes/metasploitable3-win2k8",
        ],
    }

    vagrant_target = OptString("win2k8", "Vagrant machine name", True)
    vagrant_box = OptString(
        "rapid7/metasploitable3-win2k8",
        "Vagrant box (build locally with metasploitable3 scripts)",
        True,
    )
    vagrantfile_template = OptString(
        "labs/vagrant/metasploitable3-windows/Vagrantfile",
        "Bundled Vagrantfile with host-only port forwards",
        True,
    )
    workspace_dir = OptString("", "Override Vagrant workspace directory", False)
    host_bind = OptString("127.0.0.1", "Host bind address for forwarded ports", True)

    smb_port = OptPort(5445, "SMB port forwarded to guest 445", True)
    web_port = OptPort(8881, "HTTP port forwarded to guest 80", True)
    rdp_port = OptPort(13389, "RDP port forwarded to guest 3389", True)
    winrm_port = OptPort(15985, "WinRM HTTP port forwarded to guest 5985", True)

    ready_timeout = OptInteger(900, "Timeout in seconds for VM boot and readiness", True)
    provider = OptString("virtualbox", "Vagrant provider (virtualbox, libvirt, vmware_desktop)", False)

    def _vagrant_env(self, workspace):
        env = super()._vagrant_env(workspace)
        env["MS3_SMB_HOST_PORT"] = str(int(self.smb_port))
        env["MS3_HTTP_HOST_PORT"] = str(int(self.web_port))
        env["MS3_RDP_HOST_PORT"] = str(int(self.rdp_port))
        env["MS3_WINRM_HOST_PORT"] = str(int(self.winrm_port))
        return env

    def readiness_checks(self):
        host = str(self.host_bind or "127.0.0.1")
        return [
            ("SMB", host, int(self.smb_port)),
            ("HTTP", host, int(self.web_port)),
            ("RDP", host, int(self.rdp_port)),
            ("WinRM", host, int(self.winrm_port)),
        ]

    def on_environment_ready(self):
        if not super().on_environment_ready():
            return False

        print_status("Metasploitable3 Windows — authorized lab only")
        print_info("=" * 60)
        print_info(f"SMB:   //127.0.0.1:{self.smb_port}/")
        print_info(f"Web:   http://127.0.0.1:{self.web_port}/")
        print_info(f"RDP:   127.0.0.1:{self.rdp_port}")
        print_info(f"WinRM: http://127.0.0.1:{self.winrm_port}/wsman")
        print_info("")
        print_info("Default credentials: vagrant / vagrant")
        print_info("Private network: 172.28.128.3 (host-only via Vagrant)")
        print_warning("Use only in isolated internal-lab mode — never against production targets.")
        print_info(
            "First run requires a local box: build MS3 with Rapid7 scripts or "
            "`vagrant box add rapid7/metasploitable3-win2k8 <path-to.box>`"
        )
        return True
