#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Payload):
    __info__ = {
        "name": "Azure VM Run Command BIND",
        "description": (
            "BIND payload for listeners/azure/run_command. After VM metadata is known, "
            "the framework runs commands via Azure Run Command (operator-side SDK)."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/azure/run_command",
        "handler": Handler.BIND,
        "session_type": SessionType.AZURE_RUN_COMMAND,
    }

    subscription_id = OptString("", "Azure subscription ID", True)
    resource_group = OptString("", "Azure resource group", True)
    vm_name = OptString("", "Azure VM name", True)
    os_type = OptChoice("linux", "Target OS type", False, choices=["linux", "windows"])
    rhost = OptString("", "Alias: VM name (optional, copied to vm_name if set)", False)

    def generate(self):
        vm = str(self.vm_name or self.rhost or "").strip()
        return (
            f"# KittySploit Azure Run Command BIND\n"
            f"# subscription={self.subscription_id} rg={self.resource_group} vm={vm}\n"
            f"# Listener executes RunShellScript/RunPowerShellScript on operator side.\n"
            f"# Requires: azure-identity azure-mgmt-compute on operator host."
        )
