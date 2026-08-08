#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Payload path conventions, recommendations, and listener pairing hints."""

from __future__ import annotations

from core.framework.payload_paths import NOPAYLOAD_PATHS, is_download_stager_path, is_nopayload_path, normalize_nopayload_path, requires_host_stager

BUILTIN_DELIVERY_MODES = frozenset(NOPAYLOAD_PATHS)

RECOMMENDED_BY_PROFILE: dict[str, tuple[str, ...]] = {
    "unix_cmd": (
        "payloads/singles/cmd/unix/bash_reverse_tcp",
        "payloads/singles/cmd/unix/python_reverse_tcp",
        "payloads/singles/cmd/multi/python_thin_stager",
        "payloads/singles/cmd/unix/curl_python_stager",
        "payloads/singles/cmd/unix/wget_python_stager",
        "payloads/singles/cmd/unix/curl_pipe_bash_stager",
        "payloads/singles/cmd/unix/python_urllib_stager",
        "payloads/singles/cmd/unix/bash_reverse_udp",
        "payloads/stagers/linux/x64/reverse_tcp_recv_stage",
    ),
    "windows_cmd": (
        "payloads/singles/cmd/windows/powershell_reverse_tcp",
        "payloads/singles/cmd/windows/powershell_reverse_https",
        "payloads/singles/cmd/windows/powershell_iex_stager",
        "payloads/singles/cmd/windows/certutil_exe_stager",
        "payloads/singles/cmd/windows/bitsadmin_exe_stager",
        "payloads/singles/cmd/windows/curl_exe_stager",
        "payloads/singles/cmd/windows/mshta_remote_stager",
        "payloads/singles/cmd/windows/regsvr32_sct_stager",
        "payloads/singles/cmd/windows/rundll32_js_stager",
        "payloads/singles/cmd/windows/wmic_xsl_stager",
        "payloads/singles/cmd/windows/msbuild_remote_stager",
        "payloads/singles/cmd/multi/python_thin_stager",
    ),
    "web_php": (
        "payloads/singles/cmd/php/reverse_tcp",
        "payloads/singles/cmd/unix/bash_reverse_tcp",
        "payloads/singles/cmd/multi/python_thin_stager",
        "payloads/singles/cmd/unix/curl_python_stager",
        "payloads/singles/cmd/unix/python_urllib_stager",
    ),
    "nodejs": (
        "payloads/singles/cmd/multi/nodejs_reverse_tcp",
        "payloads/singles/cmd/unix/python_reverse_tcp",
        "payloads/singles/cmd/unix/curl_python_stager",
    ),
    "meterpreter": (
        "payloads/singles/cmd/unix/python_meterpreter_reverse_tcp",
        "payloads/stagers/windows/x64/meterpreter_reverse_tcp",
        "payloads/singles/cmd/unix/zig_meterpreter_reverse_tcp",
    ),
    "covert": (
        "payloads/singles/cmd/multi/python_dns_reverse",
        "payloads/singles/cmd/multi/python_http_polling",
        "payloads/singles/cmd/multi/python_mqtt_reverse",
        "payloads/singles/cmd/unix/python_reverse_icmp",
        "payloads/singles/cmd/multi/python_slack_reverse",
        "payloads/singles/cmd/multi/python_reverse_udp",
    ),
    "database": (
        "payloads/singles/cmd/multi/python_postgresql_notify_agent",
        "payloads/singles/cmd/multi/mysql_bind_session",
        "payloads/singles/cmd/multi/postgresql_bind_session",
        "payloads/singles/cmd/multi/redis_bind_session",
        "payloads/singles/cmd/multi/mongodb_bind_session",
        "payloads/singles/cmd/multi/mssql_bind_session",
        "payloads/singles/cmd/multi/ldap_bind_session",
        "payloads/singles/cmd/multi/elasticsearch_bind_session",
    ),
    "ssh": (
        "payloads/singles/cmd/multi/python_reverse_ssh",
        "payloads/singles/cmd/multi/ssh_client_bind",
    ),
    "smb": (
        "payloads/singles/cmd/multi/smb_bind_session",
    ),
    "cloud": (
        "payloads/singles/cmd/multi/azure_run_command_bind",
        "payloads/singles/cmd/multi/gcp_compute_ssh_bind",
        "payloads/singles/cmd/multi/kubernetes_api_bind",
    ),
    "kubernetes": (
        "payloads/singles/cmd/multi/kubernetes_api_bind",
    ),
}

LISTENER_PAYLOAD_PAIRS: dict[str, str] = {
    "listeners/multi/reverse_tls": "payloads/singles/cmd/windows/powershell_reverse_https",
    "listeners/multi/reverse_icmp": "payloads/singles/cmd/unix/python_reverse_icmp",
    "listeners/multi/reverse_tcp": "payloads/singles/cmd/unix/bash_reverse_tcp",
    "listeners/multi/reverse_udp": "payloads/singles/cmd/multi/python_reverse_udp",
    "listeners/multi/reverse_tcp_staged": "payloads/stagers/linux/x64/reverse_tcp_recv_stage",
    "listeners/multi/reverse_http_polling": "payloads/singles/cmd/multi/python_http_polling",
    "listeners/multi/reverse_ssh": "payloads/singles/cmd/multi/python_reverse_ssh",
    "listeners/multi/reverse_quic": "payloads/singles/cmd/multi/python_reverse_quic",
    "listeners/multi/ssh_client": "payloads/singles/cmd/multi/ssh_client_bind",
    "listeners/multi/bind_tcp": "payloads/singles/cmd/unix/python_bind_tcp",
    "listeners/email/reverse_email": "payloads/singles/cmd/unix/python_reverse_email",
    "listeners/web/websocket": "payloads/singles/cmd/multi/python_reverse_websocket",
    "listeners/covert/dns": "payloads/singles/cmd/multi/python_dns_reverse",
    "listeners/database/postgresql_notify_shell": "payloads/singles/cmd/multi/python_postgresql_notify_agent",
    "listeners/database/postgresql": "payloads/singles/cmd/multi/postgresql_bind_session",
    "listeners/database/mysql": "payloads/singles/cmd/multi/mysql_bind_session",
    "listeners/database/redis": "payloads/singles/cmd/multi/redis_bind_session",
    "listeners/database/mongodb": "payloads/singles/cmd/multi/mongodb_bind_session",
    "listeners/database/mssql": "payloads/singles/cmd/multi/mssql_bind_session",
    "listeners/database/ldap": "payloads/singles/cmd/multi/ldap_bind_session",
    "listeners/database/elasticsearch": "payloads/singles/cmd/multi/elasticsearch_bind_session",
    "listeners/smb/client": "payloads/singles/cmd/multi/smb_bind_session",
    "listeners/azure/run_command": "payloads/singles/cmd/multi/azure_run_command_bind",
    "listeners/gcp/compute_ssh": "payloads/singles/cmd/multi/gcp_compute_ssh_bind",
    "listeners/container/kubernetes_api": "payloads/singles/cmd/multi/kubernetes_api_bind",
    "listeners/iot/reverse_mqtt_shell": "payloads/singles/cmd/multi/python_mqtt_reverse",
    "listeners/messaging/slack_socketmode": "payloads/singles/cmd/multi/python_slack_reverse",
    "listeners/aws/reverse_aws_sqs": "payloads/singles/cmd/multi/python_aws_sqs_reverse",
}

REQUIRES_HOST_STAGER: frozenset[str] = frozenset(
    path for paths in RECOMMENDED_BY_PROFILE.values() for path in paths if is_download_stager_path(path)
)


def recommend_payloads(platform: str = "", category: str = "") -> tuple[str, ...]:
    key = str(category or "").strip().lower()
    if key in RECOMMENDED_BY_PROFILE:
        return RECOMMENDED_BY_PROFILE[key]
    plat = str(platform or "").strip().lower()
    if plat in ("windows", "win"):
        return RECOMMENDED_BY_PROFILE["windows_cmd"]
    if plat in ("unix", "linux", "multi"):
        return RECOMMENDED_BY_PROFILE["unix_cmd"]
    if plat == "php":
        return RECOMMENDED_BY_PROFILE["web_php"]
    return RECOMMENDED_BY_PROFILE["unix_cmd"]


__all__ = [
    "BUILTIN_DELIVERY_MODES",
    "LISTENER_PAYLOAD_PAIRS",
    "RECOMMENDED_BY_PROFILE",
    "REQUIRES_HOST_STAGER",
    "is_download_stager_path",
    "is_nopayload_path",
    "normalize_nopayload_path",
    "recommend_payloads",
]
