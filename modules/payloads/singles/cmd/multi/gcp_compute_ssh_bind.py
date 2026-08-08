#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


class Module(Payload):
    __info__ = {
        "name": "GCP Compute SSH BIND",
        "description": (
            "BIND payload for listeners/gcp/compute_ssh. Operator connects to a "
            "Compute Engine VM via gcloud compute ssh or direct Paramiko."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/gcp/compute_ssh",
        "handler": Handler.BIND,
        "session_type": SessionType.GCP_COMPUTE_SSH,
    }

    project_id = OptString("", "Google Cloud project ID", True)
    zone = OptString("", "Compute Engine zone", True)
    instance_name = OptString("", "Compute Engine instance name", True)
    ssh_username = OptString("", "SSH username (user@instance)", False)
    target_host = OptString("", "Direct SSH host/IP (skips Compute API lookup)", False)
    rhost = OptString("", "Alias: instance name or target_host", False)

    def generate(self):
        inst = str(self.instance_name or self.rhost or "").strip()
        host = str(self.target_host or "").strip()
        return (
            f"# KittySploit GCP Compute SSH BIND\n"
            f"# project={self.project_id} zone={self.zone} instance={inst}\n"
            f"# target_host={host or '(auto)'}\n"
            f"# Listener runs gcloud/Paramiko from operator host — no target-side agent."
        )
