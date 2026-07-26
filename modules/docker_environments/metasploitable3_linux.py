#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(DockerEnvironment):
    __info__ = {
        "name": "Metasploitable3 Linux Environment",
        "description": (
            "Metasploitable3 Ubuntu 14.04 lab VM packaged for Docker — intentionally "
            "vulnerable Linux target for authorized internal-lab agent benchmarks."
        ),
        "author": "KittySploit Team",
        "references": [
            "https://github.com/rapid7/metasploitable3",
            "https://hub.docker.com/r/kirscht/metasploitable3-ub1404",
        ],
    }

    image_name = OptString(
        "kirscht/metasploitable3-ub1404:latest",
        "Docker image (community MS3 Ubuntu 14.04 build)",
        True,
    )
    expected_image_digest = OptString(
        "",
        "Optional sha256 digest pin — set after first verified pull",
        False,
    )
    container_name = OptString("kittysploit_ms3_linux", "Container name", True)
    lab_network_name = OptString(
        "kittysploit_lab_ms3_linux",
        "Isolated Docker network (internal, no outbound internet)",
        True,
    )
    lab_network_internal = OptBool(True, "Block outbound internet on the lab network", True)
    lab_network_subnet = OptString("172.30.0.0/24", "Lab network subnet", False)
    container_command = "/entrypoint.sh"

    ssh_port = OptPort(2223, "SSH port (mapped to container port 22)", True)
    web_port = OptPort(8880, "HTTP port (mapped to container port 80)", True)
    ftp_port = OptPort(2121, "FTP port (mapped to container port 21)", True)
    smb_port = OptPort(4445, "SMB port (mapped to container port 445)", True)
    mysql_port = OptPort(3307, "MySQL port (mapped to container port 3306)", True)

    ready_timeout = OptInteger(240, "Timeout in seconds for readiness checks", True)
    auto_cleanup = OptBool(False, "Keep container after stop for faster reset cycles", False)

    def expose_ports(self):
        bind = "127.0.0.1"
        self.exposed_ports = {
            "22/tcp": (bind, int(self.ssh_port)),
            "80/tcp": (bind, int(self.web_port)),
            "21/tcp": (bind, int(self.ftp_port)),
            "445/tcp": (bind, int(self.smb_port)),
            "3306/tcp": (bind, int(self.mysql_port)),
        }

    def _configure_environment(self):
        """Enable core vulnerable services via the image entrypoint flags."""
        self.environment_vars = {
            "PASS": "msfadmin",
            "SSH": "yes",
            "HTTP": "yes",
            "FTP": "yes",
            "SMB": "yes",
            "SQL": "yes",
        }

    def _readiness_checks(self):
        bind = "127.0.0.1"
        return [
            ("SSH", bind, int(self.ssh_port)),
            ("HTTP", bind, int(self.web_port)),
            ("FTP", bind, int(self.ftp_port)),
            ("SMB", bind, int(self.smb_port)),
            ("MySQL", bind, int(self.mysql_port)),
        ]

    def wait_for_readiness(self) -> bool:
        checks = self._readiness_checks()
        timeout = int(self.ready_timeout or 240)
        per_check = max(30, timeout // max(1, len(checks)))
        print_status(f"Running {len(checks)} readiness checks (budget={timeout}s)...")
        for label, host, port in checks:
            if not self.wait_for_service(host, port, timeout=per_check):
                print_error(f"Readiness check failed: {label} on {host}:{port}")
                return False
        print_success("All Metasploitable3 Linux readiness checks passed")
        return True

    def on_environment_ready(self):
        if not self.print_container_overview():
            return False

        print_status("Metasploitable3 Linux — authorized lab only")
        print_info("=" * 60)
        print_info(f"SSH:   ssh msfadmin@127.0.0.1 -p {self.ssh_port}")
        print_info(f"Web:   http://127.0.0.1:{self.web_port}/")
        print_info(f"FTP:   ftp://127.0.0.1:{self.ftp_port}/")
        print_info(f"SMB:   //127.0.0.1:{self.smb_port}/")
        print_info(f"MySQL: mysql -h 127.0.0.1 -P {self.mysql_port} -u root")
        print_info("")
        print_info("Default credentials: msfadmin / msfadmin")
        print_info(f"Lab network: {self.lab_network_name} (internal={self.lab_network_internal})")
        print_warning("Use only in isolated internal-lab mode — never against production targets.")
        return True

    def run(self, *args, **kwargs):
        self._configure_environment()
        if not self.run_docker():
            return False
        if not self.wait_for_readiness():
            print_warning("Container started but readiness checks did not all pass.")
            return False
        return self.on_environment_ready()
