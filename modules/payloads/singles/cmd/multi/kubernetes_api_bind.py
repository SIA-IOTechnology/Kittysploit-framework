#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

from lib.c2.kubernetes_bind import build_kubernetes_bind_hint


class Module(Payload):
    __info__ = {
        "name": "Kubernetes API BIND",
        "description": (
            "BIND payload for listeners/container/kubernetes_api. Operator authenticates "
            "to the cluster API (kubeconfig, token, or in-cluster SA on operator host)."
        ),
        "category": PayloadCategory.CMD,
        "platform": Platform.MULTI,
        "listener": "listeners/container/kubernetes_api",
        "handler": Handler.BIND,
        "session_type": SessionType.KUBERNETES,
    }

    api_server = OptString("", "Kubernetes API URL (optional with kubeconfig)", False)
    token = OptString("", "Bearer token", False)
    token_file = OptString("", "Path to token file", False)
    kubeconfig = OptString("", "Path to kubeconfig", False)
    context = OptString("", "kubeconfig context", False)
    namespace = OptString("default", "Default namespace", False)
    ca_file = OptString("", "Cluster CA certificate path", False)
    insecure = OptBool(False, "Skip TLS verification", False)
    in_cluster = OptBool(False, "Use in-cluster service account paths", False)
    rhost = OptString("", "Alias: api_server host (https://host:6443)", False)

    def generate(self):
        api = str(self.api_server or self.rhost or "").strip()
        if api and not api.startswith("http"):
            api = f"https://{api}"
        mode = "in_cluster" if bool(self.in_cluster) else (
            "kubeconfig" if str(self.kubeconfig or "").strip() else (
                "token" if str(self.token or self.token_file or "").strip() else "kubeconfig"
            )
        )
        return build_kubernetes_bind_hint(
            api,
            str(self.namespace or "default"),
            mode,
        )
