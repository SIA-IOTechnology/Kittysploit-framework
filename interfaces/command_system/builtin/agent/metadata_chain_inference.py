#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Infer ``agent.chain`` / ``requires`` metadata from module path, tags, and family.

Used at runtime when on-disk ``__info__['agent']`` lacks chain blocks, and by
``metadata_annotator`` when upgrading module sources.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from interfaces.command_system.builtin.agent.chain_meta import normalize_chain_block

# (path_regex, chain_dict, optional requires_dict)
_CHAIN_RULES: Sequence[Tuple[re.Pattern[str], Dict[str, Any], Optional[Dict[str, Any]]]] = (
    (
        re.compile(r"(^|/)sqli_engine$|(^|/)sqli_scanner$|(^|/)sql_injection"),
        {
            "produces_capabilities": [
                "db_access",
                {"capability": "inj_param", "from_detail": "inj_param"},
                {"capability": "inj_path", "from_detail": "inj_path"},
                {"capability": "inj_method", "from_detail": "inj_method"},
            ],
            "suggested_followups": ["post/http/sqli_shell"],
        },
        {"risk_signals_any": ["sql", "sqli"], "min_params": 1},
    ),
    (
        re.compile(r"(^|/)lfi_fuzzer$|(^|/)lfi_detect$|(^|/)path_traversal"),
        {
            "produces_capabilities": [
                {"capability": "file_read", "from_detail": "lfi_path"},
                {"capability": "lfi_param", "from_detail": "lfi_param"},
            ],
            "suggested_followups": [
                "auxiliary/scanner/http/lfi_log_poison",
                "post/php/exploits/mail_sendmail_rce",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)lfi_log_poison$"),
        {
            "consumes_capabilities": ["file_read", "lfi_param"],
            "produces_capabilities": [
                {"capability": "poisoned_payload", "from_detail": "poison_payload"},
                {"capability": "log_file_path", "from_detail": "log_path"},
                {"capability": "rce", "from_detail": "rce_confirmed"},
            ],
            "option_bindings": {
                "parameter": "lfi_param",
                "log_path": "log_file_path",
                "php_payload": "poisoned_payload",
            },
            "suggested_followups": [
                "post/php/exploits/mail_sendmail_rce",
                "post/shell/multi/manage/spawn_reverse_shell",
            ],
        },
        {"capabilities_any": ["file_read", "lfi_param"]},
    ),
    (
        re.compile(r"(^|/)ssrf_scanner$|(^|/)ssrf_detect"),
        {
            "produces_capabilities": [
                {"capability": "ssrf_primitive", "from_detail": "ssrf_confirmed"},
                {"capability": "ssrf_param", "from_detail": "ssrf_param"},
            ],
            "suggested_followups": [
                "auxiliary/scanner/http/ssrf_cloud_metadata_harvest",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ssrf_cloud_metadata"),
        {
            "consumes_capabilities": ["ssrf_primitive", "ssrf_param"],
            "produces_capabilities": [
                "cloud_credentials",
                "cloud_identity",
            ],
            "option_bindings": {"parameter": "ssrf_param"},
        },
        {"capabilities_any": ["ssrf_primitive", "ssrf_param"]},
    ),
    (
        re.compile(r"(^|/)graphql_abuse$|(^|/)graphql_detect"),
        {
            "produces_capabilities": [
                {"capability": "graphql_endpoint", "from_detail": "graphql_path"},
            ],
            "suggested_followups": ["auxiliary/scanner/http/graphql_abuse"],
        },
        None,
    ),
    (
        re.compile(r"(^|/)admin_login_bruteforce$|(^|/)login_bruteforce"),
        {
            "produces_capabilities": [
                "credentials",
                "session_cookie",
                "authenticated_session",
            ],
            "suggested_followups": [
                "post/http/gather/authenticated_surface",
                "auxiliary/scanner/http/jwt_oauth_probe",
            ],
        },
        {"risk_signals_any": ["login_surface_detected", "login_form_detected"]},
    ),
    (
        re.compile(r"(^|/)login_page_detector$|(^|/)admin_panel_detect"),
        {
            "produces_capabilities": ["login_paths"],
            "suggested_followups": [
                "auxiliary/scanner/http/login/admin_login_bruteforce",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)generic_upload_probe$|(^|/)file_upload"),
        {
            "produces_capabilities": [
                {"capability": "upload_path", "from_detail": "upload_path"},
            ],
            "suggested_followups": [
                "post/shell/multi/manage/spawn_reverse_shell",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)sqli_shell$"),
        {
            "consumes_capabilities": ["db_access", "inj_param"],
            "produces_capabilities": ["shell", "rce"],
            "option_bindings": {
                "parameter": "inj_param",
                "path": "inj_path",
            },
        },
        {"capabilities_any": ["db_access", "inj_param"]},
    ),
    (
        re.compile(r"(^|/)session_acquire$"),
        {
            "produces_capabilities": ["shell", "authenticated_session"],
            "suggested_followups": [
                "post/shell/multi/gather/privesc_suggester",
                "post/shell/multi/manage/pivot_autoroute",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)modbus_identify$|(^|/)modbus_session_acquire"),
        {
            "produces_capabilities": ["ot_assets", "modbus_tcp"],
            "suggested_followups": [
                "post/ics/modbus/gather/map_registers",
                "post/ics/manage/modbus_write_register",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)s7comm_identify$|(^|/)s7comm_session_acquire"),
        {
            "produces_capabilities": ["ot_assets", "s7comm"],
            "suggested_followups": [
                "post/ics/manage/s7_read_db",
                "auxiliary/scanner/ics/s7_module_enum",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)dnp3_identify$|(^|/)dnp3_master_probe$|(^|/)dnp3_client$"),
        {
            "produces_capabilities": ["dnp3_access", "dnp3_dest", "ot_assets"],
            "suggested_followups": [
                "post/ics/dnp3/gather/read_points",
                "post/ics/dnp3/gather/integrity_dump",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)bacnet_whois$|(^|/)bacnet_client$"),
        {
            "produces_capabilities": ["ot_assets", "bacnet"],
            "suggested_followups": [
                "post/ics/bacnet/gather/object_inventory",
                "post/ics/bacnet/gather/read_property",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)iec104_interrogate$|(^|/)iec104_client$"),
        {
            "produces_capabilities": ["ot_assets", "iec104"],
            "suggested_followups": [
                "post/ics/iec104/gather/interrogation_dump",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)iec61850_mms_identify$|(^|/)iec61850_client$|"
            r"(^|/)iec61850/gather/(identify|directory_dump)$"
        ),
        {
            "produces_capabilities": ["ot_assets", "iec61850"],
            "suggested_followups": [
                "listeners/ics/iec61850_client",
                "post/ics/iec61850/gather/identify",
                "post/ics/iec61850/gather/directory_dump",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)mqtt_broker_identify$|(^|/)mqtt$"),
        {
            "produces_capabilities": ["mqtt_access", "ot_assets"],
            "suggested_followups": [
                "post/mqtt/gather/broker_audit",
                "post/mqtt/gather/topic_dump",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)coap_client$|(^|/)resource_enum$"),
        {
            "produces_capabilities": ["coap_access", "ot_assets"],
            "suggested_followups": [
                "post/coap/gather/resource_enum",
                "post/coap/gather/config_dump",
                "post/coap/gather/observe_dump",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)onvif_client$|(^|/)onvif_device_info$"),
        {
            "produces_capabilities": ["onvif_access", "ot_assets"],
            "suggested_followups": [
                "post/onvif/gather/media_streams",
                "post/onvif/gather/ptz_status",
                "post/onvif/gather/events_probe",
                "auxiliary/admin/http/camera/onvif_snapshot",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ssdp_detect$|(^|/)upnp_client$|(^|/)upnp_device_detect$"),
        {
            "produces_capabilities": ["upnp_access", "ot_assets"],
            "suggested_followups": [
                "listeners/iot/upnp_client",
                "post/upnp/gather/device_inventory",
                "post/upnp/gather/igd_portmap",
                "workflow/iot-discovery",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ble_scan$|(^|/)ble_gatt_client$|(^|/)bleedingtooth"),
        {
            "produces_capabilities": ["ble_discover", "ble_gatt_map", "ot_assets"],
            "suggested_followups": [
                "listeners/iot/ble_gatt_client",
                "post/ble/gather/services",
                "post/ble/gather/uart_probe",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ble/.*/(uart_probe|uart_exec|services|characteristics)$"),
        {
            "produces_capabilities": ["ble_uart_pivot", "ble_gatt_map", "ot_assets"],
            "suggested_followups": [
                "post/ble/gather/uart_probe",
                "post/ble/manage/uart_exec",
                "post/ble/manage/write_characteristic",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)mdns_detect$|(^|/)mdns_enum$"),
        {
            "produces_capabilities": ["ot_assets", "mdns_map"],
            "suggested_followups": [
                "scanner/udp/mdns_enum",
                "scanner/udp/matter_detect",
                "workflow/iot-discovery",
                "listeners/iot/mqtt",
                "listeners/iot/coap_client",
                "listeners/iot/onvif_client",
                "listeners/iot/rtsp_client",
                "listeners/iot/matter_client",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)firmware_arch_suggest$|(^|/)firmware_adaptive_payload$|(^|/)firmware_extractor_advanced$"
        ),
        {
            "produces_capabilities": ["payload_plan"],
            "suggested_followups": [
                "analysis/binary/firmware_adaptive_payload",
                "workflow/firmware-to-payload",
                "listeners/multi/adaptive_reverse_tcp",
                "listeners/multi/reverse_http_polling",
                "payloads/singles/cmd/unix/busybox_reverse_tcp",
                "payloads/singles/cmd/unix/busybox_http_polling",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)mqtt_broker_identify$"),
        {
            "produces_capabilities": ["mqtt_access", "ot_assets"],
            "suggested_followups": [
                "listeners/iot/mqtt",
                "post/mqtt/gather/topic_dump",
                "post/mqtt/gather/broker_audit",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)media_streams$|(^|/)onvif_snapshot$"),
        {
            "produces_capabilities": ["onvif_access", "file_read"],
            "suggested_followups": [
                "listeners/iot/rtsp_client",
                "post/rtsp/gather/describe_dump",
                "post/onvif/gather/events_probe",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)rtsp_detect$|(^|/)rtsp_client$|(^|/)rtsp/.*/(describe_dump|stream_probe)$"
        ),
        {
            "produces_capabilities": ["rtsp_access", "ot_assets"],
            "suggested_followups": [
                "listeners/iot/rtsp_client",
                "post/rtsp/gather/describe_dump",
                "post/rtsp/gather/stream_probe",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)matter_detect$|(^|/)matter_client$|"
            r"(^|/)matter/gather/(discover|device_inventory)$"
        ),
        {
            "produces_capabilities": ["matter_access", "ot_assets"],
            "suggested_followups": [
                "listeners/iot/matter_client",
                "post/matter/gather/discover",
                "post/matter/gather/device_inventory",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)observe_dump$|(^|/)config_dump$"),
        {
            "produces_capabilities": ["coap_access", "ot_assets"],
            "suggested_followups": [
                "post/coap/gather/observe_dump",
                "post/coap/manage/resource_write",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)python_mqtt_reverse$|(^|/)reverse_mqtt_shell$|(^|/)deploy_reverse_agent$"
            r"|(^|/)deploy_embedded_c2$|(^|/)busybox_http_polling$"
        ),
        {
            "produces_capabilities": ["shell", "c2_beacon", "mqtt_access"],
            "suggested_followups": [
                "listeners/iot/reverse_mqtt_shell",
                "listeners/multi/reverse_http_polling",
                "post/shell/linux/busybox/deploy_embedded_c2",
                "post/mqtt/gather/topic_dump",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)openwrt_|busybox/(firmware_info|dump_nvram|network_recon|deploy_embedded_c2)"),
        {
            "produces_capabilities": ["ot_assets", "file_read", "c2_beacon"],
            "suggested_followups": [
                "post/shell/linux/busybox/dump_nvram",
                "post/shell/linux/busybox/dump_dropbear_keys",
                "post/shell/linux/busybox/network_recon",
                "post/shell/linux/busybox/deploy_embedded_c2",
                "listeners/multi/reverse_http_polling",
            ],
        },
        {"capabilities_any": ["shell"]},
    ),
    (
        re.compile(r"(^|/)kerberoastable_users$"),
        {
            "produces_capabilities": ["kerberoast_targets", "ldap_access"],
            "suggested_followups": ["post/ldap/gather/asrep_roastable"],
        },
        {"capabilities_any": ["ldap_access"]},
    ),
    (
        re.compile(r"(^|/)asrep_roastable$"),
        {
            "produces_capabilities": ["asrep_targets", "credentials"],
        },
        {"capabilities_any": ["ldap_access"]},
    ),
    (
        re.compile(r"(^|/)privesc_suggester$|(^|/)suid_sgid_hunt$"),
        {
            "consumes_capabilities": ["shell"],
            "produces_capabilities": ["root"],
        },
        {"capabilities_any": ["shell"]},
    ),
    (
        re.compile(r"(^|/)copy_program_exec$|(^|/)cve_2019_9193_rce$"),
        {
            "consumes_capabilities": ["db_access"],
            "produces_capabilities": ["shell", "rce"],
        },
        {"capabilities_any": ["db_access"]},
    ),
    (
        re.compile(r"(^|/)exploits/.+_rce$|(^|/)exploits/.+/rce$"),
        {
            "produces_capabilities": ["rce", "shell"],
            "suggested_followups": [
                "post/shell/multi/gather/privesc_suggester",
                "post/shell/multi/manage/pivot_autoroute",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)post/shell/.+/persistence/"),
        {
            "consumes_capabilities": ["shell"],
            "produces_capabilities": ["root"],
        },
        {"capabilities_any": ["shell"]},
    ),
    (
        re.compile(r"(^|/)post/gcp/gather/whoami$"),
        {
            "produces_capabilities": ["cloud_identity", "cloud_credentials"],
            "suggested_followups": [
                "post/gcp/gather/iam_policy",
                "post/gcp/analyze/iam_privesc_paths",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)spring_actuator_detect$|(^|/)consul_detect$|(^|/)etcd_detect$"
        ),
        {
            "produces_capabilities": ["devops_panel", "misconfig_surface"],
            "suggested_followups": [
                "auxiliary/scanner/http/debug_info_leak",
                "scanner/cloud/kubernetes_api_detect",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)redis_unauth_write_detect$|(^|/)redis_info_detect$"),
        {
            "produces_capabilities": ["db_access", "redis_unauth"],
            "suggested_followups": [
                "post/redis/gather/enum_info",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)gitlab_detect$|(^|/)jenkins_detect$|(^|/)harbor_detect$|"
            r"(^|/)argocd_detect$|(^|/)portainer_detect$|(^|/)nexus_detect$|"
            r"(^|/)teamcity_detect$|(^|/)rancher_detect$|(^|/)bitbucket_detect$|"
            r"(^|/)graylog_detect$|(^|/)splunk_detect$|(^|/)clickhouse_detect$"
        ),
        {
            "produces_capabilities": ["devops_panel", "admin_surface"],
            "suggested_followups": [
                "auxiliary/scanner/http/login_page_detector",
                "scanner/http/swagger_detect",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(_unauth_|_verify$|_verify\.py$|unauth_write_detect$|unauth_detect$|"
            r"indices_verify$|public_access_detect$|gpp_password_hunter$)"
        ),
        {
            "produces_capabilities": ["verified_misconfig", "unauth_read"],
            "consumes_capabilities": ["devops_panel", "ai_panel", "network_service"],
            "suggested_followups": [
                "auxiliary/scanner/http/debug_info_leak",
                "scanner/http/sensitive_files_detect",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)kubelet_readonly_verify$|(^|/)docker_api_exposed$|"
            r"(^|/)k8s_dashboard_unauth_verify$|(^|/)adcs_web_enroll_detect$"
        ),
        {
            "produces_capabilities": ["k8s_misconfig", "cloud_exposure", "adcs_surface"],
            "suggested_followups": [
                "scanner/cloud/kubernetes_api_detect",
                "scanner/ldap/adcs_misconfig_scanner",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)ollama_detect$|(^|/)openwebui_detect$|(^|/)comfyui_detect$|"
            r"(^|/)mlflow_detect$|(^|/)langflow"
        ),
        {
            "produces_capabilities": ["ai_panel", "misconfig_surface"],
            "suggested_followups": [
                "scanner/http/ollama_api_verify",
                "scanner/http/openwebui_unauth_verify",
                "scanner/http/comfyui_unauth_verify",
                "scanner/http/mlflow_unauth_verify",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)okta_detect$|(^|/)auth0_detect$|(^|/)sharepoint_detect$|"
            r"(^|/)citrix_gateway_detect$"
        ),
        {
            "produces_capabilities": ["identity_surface", "enterprise_panel"],
            "suggested_followups": [
                "auxiliary/scanner/http/login_page_detector",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)log4j_header_detect$|(^|/)spring4shell_detect$"),
        {
            "produces_capabilities": ["java_vuln_signal", "cve_indicator"],
            "suggested_followups": [
                "scanner/http/spring_actuator_detect",
                "auxiliary/scanner/http/java_deserialization",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)openssh_banner_detect$|(^|/)ssh_hostkey$"),
        {
            "produces_capabilities": [
                "network_service",
                "service_identified",
                "remote_access",
            ],
            "suggested_followups": [
                "scanner/ssh/ssh_auth_methods",
                "scanner/ssh/ssh_empty_password_detect",
                "auxiliary/scanner/ssh/ssh_login_bruteforce",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ssh_auth_methods$"),
        {
            "produces_capabilities": [
                "service_identified",
                "ssh_auth_surface",
                "remote_access",
            ],
            "suggested_followups": [
                "scanner/ssh/ssh_empty_password_detect",
                "auxiliary/scanner/ssh/ssh_login_bruteforce",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ssh_empty_password_detect$"),
        {
            "produces_capabilities": [
                {"capability": "ssh_access", "from_detail": "username"},
                "authenticated_session",
            ],
            "suggested_followups": [
                "auxiliary/scanner/ssh/ssh_login_bruteforce",
                "post/shell/linux/gather/enum_system",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ssh_login_bruteforce$|(^|/)ssh_login$"),
        {
            "consumes_capabilities": ["service_identified", "ssh_auth_surface"],
            "produces_capabilities": [
                {"capability": "ssh_access", "from_detail": "username"},
                "authenticated_session",
                "shell",
            ],
            "suggested_followups": [
                "post/shell/linux/gather/enum_system",
                "post/shell/linux/gather/check_sudo",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)rdp_service_detect$|(^|/)winrm_detect$"),
        {
            "produces_capabilities": ["network_service", "remote_access"],
            "suggested_followups": [
                "auxiliary/scanner/tcp/winrm_auth_enum",
            ],
        },
        None,
    ),
    (
        re.compile(r"winrm_auth_enum"),
        {
            "produces_capabilities": ["winrm_access", "network_service"],
            "suggested_followups": [],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)ftp_banner_detect$|(^|/)ftp_syst_detect$|(^|/)ftp_feat_detect$"
        ),
        {
            "produces_capabilities": ["service_identified", "ftp_surface"],
            "suggested_followups": [
                "scanner/ftp/ftp_anonymous_login_detect",
                "auxiliary/scanner/ftp/ftp_enum",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ftp_anonymous_login_detect$"),
        {
            "produces_capabilities": [
                "anonymous_access",
                "ftp_surface",
                {"capability": "file_read", "from_detail": ""},
            ],
            "suggested_followups": ["auxiliary/scanner/ftp/ftp_enum"],
        },
        None,
    ),
    (
        re.compile(r"(^|/)ftp_enum$"),
        {
            "consumes_capabilities": ["ftp_surface", "anonymous_access"],
            "produces_capabilities": ["service_identified", "file_read"],
            "suggested_followups": [],
        },
        None,
    ),
    (
        re.compile(r"(^|/)mysql_info_detect$|(^|/)mysql_tls_detect$"),
        {
            "produces_capabilities": ["service_identified", "db_surface"],
            "suggested_followups": [
                "scanner/mysql/mysql_empty_password_detect",
                "auxiliary/scanner/mysql/mysql_login_bruteforce",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)mysql_empty_password_detect$"),
        {
            "produces_capabilities": [
                {"capability": "db_access", "from_detail": "username"},
                "authenticated_session",
            ],
            "suggested_followups": [
                "auxiliary/scanner/mysql/mysql_login_bruteforce",
                "post/mysql/gather/enum_databases",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)mysql_login_bruteforce$"),
        {
            "consumes_capabilities": ["service_identified", "db_surface"],
            "produces_capabilities": [
                {"capability": "db_access", "from_detail": "username"},
                "authenticated_session",
            ],
            "suggested_followups": [
                "post/mysql/gather/enum_users",
                "post/mysql/gather/enum_databases",
                "post/mysql/gather/check_mysql_hardening",
            ],
        },
        None,
    ),
    (
        re.compile(
            r"(^|/)postgresql_info_detect$|(^|/)postgresql_auth_method_detect$"
        ),
        {
            "produces_capabilities": [
                "service_identified",
                "db_surface",
                "pgsql_auth_surface",
            ],
            "suggested_followups": [
                "scanner/postgresql/postgresql_empty_password_detect",
                "auxiliary/scanner/postgresql/postgresql_login_bruteforce",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)postgresql_empty_password_detect$"),
        {
            "produces_capabilities": [
                {"capability": "db_access", "from_detail": "username"},
                "authenticated_session",
            ],
            "suggested_followups": [
                "auxiliary/scanner/postgresql/postgresql_login_bruteforce",
            ],
        },
        None,
    ),
    (
        re.compile(r"(^|/)postgresql_login_bruteforce$"),
        {
            "consumes_capabilities": ["service_identified", "pgsql_auth_surface"],
            "produces_capabilities": [
                {"capability": "db_access", "from_detail": "username"},
                "authenticated_session",
            ],
            "suggested_followups": [
                "post/postgresql/gather/enum_roles",
                "post/postgresql/gather/enum_databases",
                "post/postgresql/gather/check_postgresql_hardening",
            ],
        },
        None,
    ),
    (
        re.compile(r"smb_relay_surface"),
        {
            "produces_capabilities": ["smb_access"],
            "suggested_followups": [],
        },
        None,
    ),
    (
        re.compile(r"(^|/)crawler$"),
        {
            "produces_capabilities": ["endpoints"],
            "suggested_followups": ["auxiliary/scanner/http/security_headers"],
        },
        None,
    ),
    (
        re.compile(r"^auxiliary/scanner/http/"),
        {
            "produces_capabilities": ["endpoints"],
            "suggested_followups": [],
        },
        None,
    ),
)

_FAMILY_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "scanner": {
        "produces_capabilities": [],
        "suggested_followups": [],
    },
    "auxiliary/scanner": {
        "produces_capabilities": [],
        "suggested_followups": [],
    },
    "exploits": {
        "produces_capabilities": ["rce"],
        "suggested_followups": ["post/shell/multi/gather/privesc_suggester"],
    },
    "post": {
        "consumes_capabilities": ["shell"],
        "produces_capabilities": [],
    },
}


def _module_family(module_path: str) -> str:
    path = str(module_path or "").strip().lower()
    if path.startswith("auxiliary/scanner/"):
        return "auxiliary/scanner"
    if path.startswith("scanner/"):
        return "scanner"
    if path.startswith("exploits/") or path.startswith("exploit/"):
        return "exploits"
    if path.startswith("post/"):
        return "post"
    return path.split("/")[0] if "/" in path else "other"


def _tags_blob(info: Optional[Dict[str, Any]]) -> str:
    if not isinstance(info, dict):
        return ""
    tags = info.get("tags") or []
    if not isinstance(tags, (list, tuple)):
        return ""
    return " ".join(str(t).lower() for t in tags)


def infer_chain_metadata(
    module_path: str,
    info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a normalized chain block inferred from path/tags."""
    path = str(module_path or "").strip().lower()
    blob = f"{path} {_tags_blob(info)}"

    for pattern, chain, _requires in _CHAIN_RULES:
        if pattern.search(path) or pattern.search(blob.replace(" ", "/")):
            return normalize_chain_block(chain)

    family = _module_family(path)
    default = _FAMILY_DEFAULTS.get(family)
    if default:
        chain = dict(default)
        if "sqli" in blob or "sql" in blob:
            chain.setdefault("produces_capabilities", []).append("db_access")
        if "lfi" in blob or "traversal" in blob:
            chain.setdefault("produces_capabilities", []).extend([
                {"capability": "file_read", "from_detail": "lfi_path"},
                {"capability": "lfi_param", "from_detail": "lfi_param"},
            ])
        if "ssrf" in blob:
            chain.setdefault("produces_capabilities", []).append("ssrf_primitive")
        # OT caps only for ICS / protocol-named modules — never from substring noise
        if "/ics/" in path or "/modbus" in path:
            if "modbus" in path:
                chain.setdefault("produces_capabilities", []).extend(["ot_assets", "modbus_tcp"])
        if "/ics/" in path or "s7comm" in path or "/s7_" in path:
            if "s7comm" in path or "/s7_" in path or "siemens" in blob:
                chain.setdefault("produces_capabilities", []).extend(["ot_assets", "s7comm"])
        if "/ics/" in path and "dnp3" in path:
            chain.setdefault("produces_capabilities", []).extend(["ot_assets", "dnp3_access"])
        if "/ics/" in path and "bacnet" in path:
            chain.setdefault("produces_capabilities", []).extend(["ot_assets", "bacnet"])
        if "/ics/" in path and ("opcua" in path or "opc_ua" in path):
            chain.setdefault("produces_capabilities", []).extend(["ot_assets", "opcua"])
        if "/ics/" in path and "iec104" in path:
            chain.setdefault("produces_capabilities", []).extend(["ot_assets", "iec104"])
        if "/ics/" in path and ("iec61850" in path or "mms" in path):
            chain.setdefault("produces_capabilities", []).extend(["ot_assets", "iec61850"])
        if "rtsp" in path:
            chain.setdefault("produces_capabilities", []).extend(["ot_assets", "rtsp_access"])
        if "onvif" in path:
            chain.setdefault("produces_capabilities", []).extend(["ot_assets", "onvif_access"])
        if "matter" in path and "mattermost" not in path:
            chain.setdefault("produces_capabilities", []).extend(["ot_assets", "matter_access"])
        if family == "post" and "/gather/" in path:
            chain["consumes_capabilities"] = []
        return normalize_chain_block(chain)

    return normalize_chain_block({})


def infer_requires_metadata(
    module_path: str,
    info: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    path = str(module_path or "").strip().lower()
    blob = f"{path} {_tags_blob(info)}"
    for pattern, _chain, requires in _CHAIN_RULES:
        if requires and (pattern.search(path) or pattern.search(blob.replace(" ", "/"))):
            return dict(requires)
    family = _module_family(path)
    if family == "post" and "/exploits/" in path:
        return {"capabilities_any": ["db_access", "rce", "shell", "file_read"]}
    if family == "post" and "/manage/" in path and "/ics/" in path:
        caps = ["ot_assets"]
        if "modbus" in path:
            caps.append("modbus_tcp")
        if "s7" in path:
            caps.append("s7comm")
        if "dnp3" in path:
            caps.append("dnp3_access")
        if "bacnet" in path:
            caps.append("bacnet")
        if "iec104" in path:
            caps.append("iec104")
        if "iec61850" in path or "mms" in path:
            caps.append("iec61850")
        if "opcua" in path:
            caps.append("opcua")
        return {"capabilities_any": caps}
    return None


def chain_is_empty(chain: Optional[Dict[str, Any]]) -> bool:
    normalized = normalize_chain_block(chain)
    return not (
        normalized.get("produces_capabilities")
        or normalized.get("consumes_capabilities")
        or normalized.get("suggested_followups")
        or normalized.get("option_bindings")
    )


def enrich_agent_metadata(
    module_path: str,
    agent: Optional[Dict[str, Any]],
    info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Merge on-disk agent metadata with inferred chain/requires when absent.

    Returns a normalized agent dict suitable for the planner.
    """
    from interfaces.command_system.builtin.agent.agent_module_meta import normalize_agent_block
    from interfaces.command_system.builtin.agent.metadata_annotator import infer_agent_metadata

    if agent is None:
        base = infer_agent_metadata(module_path, info)
    else:
        base = dict(normalize_agent_block(agent) or infer_agent_metadata(module_path, info))

    existing_chain = normalize_chain_block(base.get("chain"))
    if chain_is_empty(existing_chain):
        inferred = infer_chain_metadata(module_path, info)
        if not chain_is_empty(inferred):
            base["chain"] = inferred

    requires = base.get("requires") if isinstance(base.get("requires"), dict) else {}
    if not requires.get("capabilities_any") and not requires.get("risk_signals_any"):
        inferred_req = infer_requires_metadata(module_path, info)
        if inferred_req:
            base["requires"] = {
                **{
                    "min_endpoints": 0,
                    "min_params": 0,
                    "tech_hints_any": [],
                    "risk_signals_any": [],
                    "auth_session": False,
                    "capabilities_any": [],
                    "capabilities_all": [],
                },
                **requires,
                **inferred_req,
            }

    if "cost" not in base or base.get("cost") == 1.0:
        family = _module_family(module_path)
        if family in {"exploits", "post"}:
            base["cost"] = 1.5
        elif "bruteforce" in module_path.lower() or "fuzzer" in module_path.lower():
            base["cost"] = 2.0
        else:
            base["cost"] = 1.0

    if "noise" not in base:
        low_noise = any(
            token in module_path.lower()
            for token in ("identify", "detect", "gather", "enum", "whoami")
        )
        base["noise"] = 0.35 if low_noise else 0.8

    if "value" not in base:
        high_value = any(
            token in module_path.lower()
            for token in ("sqli", "rce", "shell", "exploit", "session_acquire", "privesc")
        )
        base["value"] = 2.0 if high_value else 1.0

    from interfaces.command_system.builtin.agent.metadata_contract_inference import apply_extended_contract_fields

    base = apply_extended_contract_fields(module_path, base, info)
    return normalize_agent_block(base) or base
