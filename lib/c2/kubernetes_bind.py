#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kubernetes API BIND session hints."""

from __future__ import annotations


def build_kubernetes_bind_hint(
    api_server: str = "",
    namespace: str = "default",
    auth_mode: str = "kubeconfig",
) -> str:
    server = api_server or "(from kubeconfig / in-cluster SA)"
    return (
        f"# KittySploit Kubernetes API BIND\n"
        f"# api_server={server} namespace={namespace} auth={auth_mode}\n"
        f"# Listener authenticates from operator host — no agent on cluster nodes.\n"
        f"kubectl --namespace {namespace} auth whoami 2>/dev/null || true"
    )
