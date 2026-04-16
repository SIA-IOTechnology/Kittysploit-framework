#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Centralized literals for the autonomous agent (CMS hints, auth surfaces, evidence phrases).

Adjust tuning here instead of hunting through workflow code.
"""

from __future__ import annotations

from typing import Dict, Final, FrozenSet, Tuple

# --- CMS & stack hints (blobs, specialization corpus, catalog notability) ---

CMS_HINT_TOKENS: Final[Tuple[str, ...]] = (
    "wordpress",
    "wp_",
    "wp-",
    "drupal",
    "joomla",
    "wp-content",
    "wp-includes",
    "wp-json",
    "xmlrpc",
    "drupal.settings",
    "sites/default",
    "joomla!",
    "com_content",
    "django",
    "flask",
    "fastapi",
    "python",
    "nodejs",
    "react",
    "angular",
    "grafana",
    "jenkins",
    "tomcat",
    "phpmyadmin",
    "api",
    "swagger",
    "graphql",
)

# Tokens scanned in result evidence blobs for AgentWorkflowCore._detect_specializations
CMS_SPECIALIZATION_BLOB_TOKENS: Final[Tuple[str, ...]] = (
    "wordpress",
    "drupal",
    "joomla",
    "django",
    "flask",
    "nodejs",
    "react",
    "angular",
    "grafana",
    "jenkins",
    "tomcat",
    "phpmyadmin",
    "api",
    "swagger",
)

WORDPRESS_BODY_FINGERPRINT_TOKENS: Final[Tuple[str, ...]] = ("wp-content", "wp-includes", "wordpress")

WORDPRESS_FORM_FIELD_TOKENS: Final[Tuple[str, ...]] = ("wp-submit", "user_login", "wordpress")

WORDPRESS_LANDING_PATH_MARKERS: Final[Tuple[str, ...]] = (
    "/wp-login.php",
    "/wp-json",
    "/xmlrpc.php",
    "/readme.html",
)

# Substrings for redirect / URL probes that suggest an auth or admin surface
AUTH_PATH_MARKERS: Final[Tuple[str, ...]] = (
    "login",
    "signin",
    "auth",
    "admin",
    "/login",
    "/auth",
    "/admin/login",
    "admin/login",
    "/wp-login.php",
    "wp-login.php",
)

DRUPAL_BLOB_MARKERS: Final[Tuple[str, ...]] = ("x-drupal-cache", "/sites/default/", "drupal.settings")

JOOMLA_BLOB_MARKERS: Final[Tuple[str, ...]] = ("joomla!", "com_content", "option=com_")

# Non-redirect HTTP statuses recorded as coarse risk signals (fingerprint pass)
HTTP_STATUS_RISK_SIGNALS: Final[Tuple[int, ...]] = (301, 302, 403, 429)

# Paths containing these substrings skip noisy post-auth chaining
DISALLOWED_POST_AUTH_TOKENS: Final[Tuple[str, ...]] = (
    "mail",
    "smtp",
    "newsletter",
    "sendgrid",
    "twilio",
    "ses_",
    "email_",
    "contact_form",
    "ticket",
    "helpdesk",
    "forum",
    "message_board",
    "chat_",
    "push_notif",
    "sms_",
    "mms_",
    "bulk_mail",
)

# Phrases in aggregated result text treated as explicit scanner evidence
POSITIVE_EVIDENCE_MARKERS: Final[Tuple[str, ...]] = (
    "detected",
    "found",
    "exposed",
    "enumerated",
    "authenticated as",
    "valid credentials",
    "login page detected",
    "login panel",
    "missing headers",
    "robots.txt exposed",
    "information leak",
    "version",
)

# Message substrings that indicate a negative / empty scanner outcome
NEGATIVE_EVIDENCE_MARKERS: Final[Tuple[str, ...]] = (
    "not detected",
    "found: 0",
    "found 0",
    "no vulnerabilities",
    "no cves",
    "misconfigurations found: 0",
    "paths found: 0",
    "exposed files found: 0",
)

# LLM / heuristic execution plan: allowed next_actions.type values
SAFE_FOLLOWUP_ACTION_TYPES: Final[FrozenSet[str]] = frozenset({
    "prioritize",
    "run_followup",
    "run_exploit",
    "skip",
})

# --- Additional shared literals (kept here to avoid drift) ---

# Positive-but-weak signals in free-text scanner message for _result_indicates_positive_detection
POSITIVE_SCAN_MESSAGE_MARKERS: Final[Tuple[str, ...]] = (
    "version detected",
    "plugin found",
    "login panel",
    "installed",
    "exposed",
    "missing headers",
    "sitemap",
    "robots.txt",
)

HTTP_REDIRECT_STATUSES: Final[Tuple[int, ...]] = (301, 302, 303, 307, 308)

# Keywords that make a module path notable in the capability catalog
NOTABLE_CATALOG_KEYWORDS: Final[Tuple[str, ...]] = (
    "rce",
    "injection",
    "xss",
    "sqli",
    "lfi",
    "ssrf",
    "xxe",
    "wordpress",
    "drupal",
    "joomla",
)

# Paths treated as pure technology detection (noise unless strong signal in message)
PURE_DETECTION_PATH_MARKERS: Final[Tuple[str, ...]] = (
    "scanner/http/wordpress_detect",
    "scanner/http/drupal_detect",
    "scanner/http/joomla_detect",
    "scanner/http/swagger_detect",
    "scanner/http/graphql_detect",
    "server_banner",
)

# Phrases that override pure-detection classification (real vuln / session)
STRONG_VULN_SIGNAL_PHRASES: Final[Tuple[str, ...]] = (
    "valid credentials",
    "authenticated as",
    "auth bypass",
    "rce",
    "command execution",
    "file read",
)

CMS_LOCK_NAMES: Final[Tuple[str, ...]] = ("wordpress", "drupal", "joomla")

# Cookie name substrings preferred when seeding session from auth_context["cookies"]
SESSION_COOKIE_NAME_MARKERS: Final[Tuple[str, ...]] = (
    "session",
    "phpsessid",
    "auth",
    "token",
    "connect.sid",
    "jsessionid",
    "aspxauth",
)

# Order for _select_best_login_path when multiple candidates exist
LOGIN_PATH_PRIORITY: Final[Tuple[str, ...]] = (
    "/login.php",
    "/login",
    "/admin/login",
    "/wp-login.php",
    "/signin",
    "/auth/login",
)

# Strategic campaign goals (short IDs — all planner decisions should key off these)
CAMPAIGN_GOAL_OBTAIN_AUTH: Final[str] = "obtain_auth"
CAMPAIGN_GOAL_POST_AUTH: Final[str] = "post_auth"
CAMPAIGN_GOAL_EXPLOIT: Final[str] = "exploit"
CAMPAIGN_GOAL_RECON: Final[str] = "recon"
CAMPAIGN_GOAL_SHELL_STOP: Final[str] = "shell_obtained"
# Backward-compatible aliases
CAMPAIGN_GOAL_LEVERAGE_AUTH: Final[str] = "post_auth"
CAMPAIGN_GOAL_CONTINUE_RECON: Final[str] = "recon"
CAMPAIGN_GOAL_OBTAIN_SHELL: Final[str] = "obtain_shell"
CAMPAIGN_GOAL_VERIFY_LEAK: Final[str] = "verify_possible_info_leak"

# run_followup paths demoted while AUTH-FIRST is active (generic recon / noise vs login chain)
AUTH_FIRST_DEPRIORITIZE_SUBSTRINGS: Final[Tuple[str, ...]] = (
    "spa_scanner",
    "security_headers",
    "sensitive_files",
    "debug_info",
    "robots",
    "cors_misconfig",
    "csp_bypass",
    "server_banner",
    "graphql_detect",
    "swagger_detect",
)

# Basenames → prior utility 0..1 for :mod:`module_context_memory` before any learned data
DEFAULT_MODULE_CONTEXT_PRIORS: Final[Dict[str, Dict[str, float]]] = {
    "login_detected_no_auth": {
        "admin_login_bruteforce": 0.9,
        "login_page_detector": 0.65,
        "simple_login_scanner": 0.55,
        "spa_scanner": 0.2,
        "security_headers_detect": 0.25,
        "sensitive_files_detect": 0.3,
    },
    "authenticated_session": {
        "crawler": 0.4,
        "xss_scanner": 0.55,
        "sql_injection": 0.55,
        "lfi_fuzzer": 0.5,
        "wp_plugin_scanner": 0.65,
        "wordpress_enum_user": 0.55,
    },
    "cms_stack_locked": {
        "wp_plugin_scanner": 0.72,
        "wordpress_detect": 0.55,
        "wordpress_enum_user": 0.58,
        "drupal_detect": 0.55,
        "joomla_detect": 0.55,
    },
    "cold_recon": {
        "crawler": 0.72,
        "swagger_detect": 0.55,
        "graphql_detect": 0.5,
        "server_banner": 0.6,
        "robots": 0.45,
    },
}
