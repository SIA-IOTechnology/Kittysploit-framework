#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    AZURE_AVAILABLE = True
except Exception:
    DefaultAzureCredential = ComputeManagementClient = None
    AZURE_AVAILABLE = False


class AzureRunCommandConnection:
    def __init__(self, compute_client, resource_group, vm_name, os_type, timeout):
        self.compute_client = compute_client
        self.resource_group = resource_group
        self.vm_name = vm_name
        self.os_type = (os_type or "linux").lower()
        self.timeout = int(timeout or 120)

    def run_command(self, command: str) -> str:
        command_id = "RunPowerShellScript" if self.os_type == "windows" else "RunShellScript"
        parameters = {"command_id": command_id, "script": [command]}
        poller = self.compute_client.virtual_machines.begin_run_command(
            self.resource_group,
            self.vm_name,
            parameters,
        )
        result = poller.result(timeout=self.timeout)
        values = getattr(result, "value", None) or []
        lines = []
        for item in values:
            message = getattr(item, "message", None)
            if message:
                lines.append(str(message))
        return "\n".join(lines)


class Module(Listener):
    __info__ = {
        "name": "Azure VM Run Command Listener",
        "description": "Creates a command session backed by Azure VM Run Command.",
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": "azure_run_command",
        "protocol": "azure_run_command",
        "dependencies": ["azure-identity", "azure-mgmt-compute"],
    }

    subscription_id = OptString("", "Azure subscription ID", True)
    resource_group = OptString("", "Azure resource group", True)
    vm_name = OptString("", "Azure VM name", True)
    os_type = OptChoice("linux", "Target OS type", False, choices=["linux", "windows"])
    test_command = OptString("id", "Command used to verify the session", False)
    timeout = OptInteger(120, "Run Command timeout in seconds", False, advanced=True)

    def run(self, background=False):
        if not AZURE_AVAILABLE:
            print_error("Azure SDK packages are missing. Install azure-identity and azure-mgmt-compute.")
            return False
        try:
            credential = DefaultAzureCredential()
            compute = ComputeManagementClient(credential, str(self.subscription_id))
            conn = AzureRunCommandConnection(
                compute,
                str(self.resource_group),
                str(self.vm_name),
                str(self.os_type),
                int(self.timeout),
            )
            print_status(f"Testing Azure Run Command on VM {self.vm_name}...")
            output = conn.run_command(str(self.test_command or "whoami"))
            if output:
                print_info(output[:4000])
            print_success("Azure Run Command session ready")
            return (
                conn,
                str(self.vm_name),
                0,
                {
                    "vm_name": str(self.vm_name),
                    "resource_group": str(self.resource_group),
                    "subscription_id": str(self.subscription_id),
                    "os_type": str(self.os_type),
                },
            )
        except Exception as e:
            print_error(f"Azure Run Command failed: {e}")
            return False
