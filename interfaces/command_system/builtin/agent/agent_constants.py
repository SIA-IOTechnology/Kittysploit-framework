#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Centralized literals for the autonomous agent (CMS hints, auth surfaces, evidence phrases).

Adjust tuning here instead of hunting through workflow code.
"""

from __future__ import annotations

from typing import Dict, Final, FrozenSet, Tuple

DEFAULT_AGENT_USER_AGENT: Final[str] = "KittysploitAgent/1.0 (+authorized-testing)"

SAFETY_PROFILE_NAMES: Final[Tuple[str, ...]] = ("safe", "discreet", "normal", "aggressive")

DISCREET_PROFILE_DEFAULT_MAX_MODULES: Final[int] = 18
DISCREET_PROFILE_DEFAULT_RECON_MODULES: Final[int] = 5
DISCREET_PROFILE_DEFAULT_REQUEST_BUDGET: Final[int] = 26
DISCREET_PROFILE_DEFAULT_DELAY_MIN: Final[float] = 0.7
DISCREET_PROFILE_DEFAULT_DELAY_MAX: Final[float] = 2.2
DISCREET_PROFILE_MAX_LLM_CALLS: Final[int] = 1

SAFE_PROFILE_BLOCKED_MODULE_SUBSTRINGS: Final[Tuple[str, ...]] = (
    "admin_login_bruteforce",
    "bruteforce",
    "credential",
    "password",
    "fuzzer",
    "write_access",
    "file_download",
    "/dos/ics/",
    "stop_cpu",
    "plc_control",
    "quantum_plc",
    "rpc_integer_overflow",
    "profinet_dcp_set_ip",
    "qconn_rce",
)

DISCREET_PROFILE_BLOCKED_MODULE_SUBSTRINGS: Final[Tuple[str, ...]] = (
    "api_fuzzer",
    "bypass_403",
    "bypass_404",
    "crawler",
    "directory_bruteforce",
    "fuzz",
    "fuzzer",
    "hop_proxy_generator",
    "smuggling",
    "spider",
    "write_access",
)

DISCREET_PROFILE_EXPENSIVE_MODULE_SUBSTRINGS: Final[Tuple[str, ...]] = (
    "admin_login_bruteforce",
    "bruteforce",
    "file_download",
    "password",
    "credential",
)

WAF_RISK_HTTP_STATUS_CODES: Final[Tuple[int, ...]] = (403, 406, 429)

# Prefer interfaces.command_system.builtin.agent.waf_signals for detection logic.
WAF_BODY_MARKERS: Final[Tuple[str, ...]] = (
    "captcha",
    "recaptcha",
    "hcaptcha",
    "access denied",
    "request blocked",
    "not acceptable",
    "too many requests",
    "rate limit",
    "cloudflare",
    "cf-chl",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "bot detection",
)

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
    "dvwa",
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
    "dvwa",
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

# Pre-auth DVWA fingerprints (Metasploitable2 index links, login page title, etc.)
DVWA_BLOB_MARKERS: Final[Tuple[str, ...]] = (
    "damn vulnerable web application",
    "/dvwa/",
    "dvwa/login.php",
    "dvwa security",
)

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
    "http_request",
    "surface_scan",
    "run_followup",
    "run_exploit",
    "run_post",
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
    "sqli_engine",
    "lfi",
    "ssrf",
    "xxe",
    "wordpress",
    "drupal",
    "joomla",
    "nextjs",
    "next.js",
    "next_js",
    "javascript",
    "client_js",
    "webhook",
    "secret",
    "actuator",
    "gitlab",
    "jira",
    "confluence",
    "harbor",
    "argocd",
    "traefik",
    "consul",
    "etcd",
    "log4j",
    "spring4shell",
    "prometheus",
    "portainer",
    "redis_unauth",
    "memcached",
    "kubernetes",
    "exchange",
    "owa",
)

# Preferred low-noise SQLi modules (scanner → post-exploitation chain).
HTTP_SQLI_SCANNER_MODULE: Final[str] = "auxiliary/scanner/http/sqli_engine"
HTTP_SQLI_SCANNER_MODULE_LEGACY: Final[str] = "auxiliary/scanner/http/sql_injection"
HTTP_SQLI_POST_MODULE: Final[str] = "post/http/sqli_shell"

# Paths treated as pure technology detection (noise unless strong signal in message)
PURE_DETECTION_PATH_MARKERS: Final[Tuple[str, ...]] = (
    "scanner/http/wordpress_detect",
    "scanner/http/drupal_detect",
    "scanner/http/joomla_detect",
    "scanner/http/swagger_detect",
    "scanner/http/graphql_detect",
    "scanner/http/gitlab_detect",
    "scanner/http/jira_detect",
    "scanner/http/confluence_detect",
    "scanner/http/jenkins_detect",
    "scanner/http/grafana_detect",
    "scanner/http/kibana_detect",
    "scanner/http/prometheus_detect",
    "scanner/http/portainer_detect",
    "scanner/http/harbor_detect",
    "scanner/http/argocd_detect",
    "scanner/http/nexus_detect",
    "scanner/http/sonarqube_detect",
    "scanner/http/teamcity_detect",
    "scanner/http/rancher_detect",
    "scanner/http/bitbucket_detect",
    "scanner/http/netlify_detect",
    "scanner/http/vercel_detect",
    "scanner/http/okta_detect",
    "scanner/http/auth0_detect",
    "scanner/ssh/openssh_banner_detect",
    "scanner/tcp/rdp_service_detect",
    "scanner/tcp/vnc_service_detect",
    "server_banner",
    "waf_fingerprint",
    "robots_txt_detect",
    "grpc_reflection_detect",
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

NEXTJS_HINT_TOKENS: Final[Tuple[str, ...]] = (
    "__next_data__",
    "/_next/",
    "/_next/static/",
    "next-route-announcer",
    "next-head-count",
    "nextjs",
    "next.js",
    "x-nextjs-cache",
    "x-nextjs-matched-path",
    "x-middleware-rewrite",
    "x-middleware-next",
)

CLIENT_JS_INTEL_MODULES: Final[Tuple[str, ...]] = (
    "auxiliary/osint/js_sourcemap_analyzer",
    "auxiliary/osint/js_endpoint_extractor",
    "auxiliary/osint/webhook_api_leak_analyzer",
    "auxiliary/osint/secret_leak_access_validator",
)

# ``agent --all``: extra module trees (beyond ``scanner/http`` + ``auxiliary/scanner/http``).
EXPANDED_SURFACE_MODULE_PREFIXES: Final[Tuple[str, ...]] = (
    "exploits/",
    "auxiliary/osint/",
    "scanner/cloud/",
    "scanner/ssh/",
    "scanner/tcp/",
    "scanner/udp/",
    "scanner/postgresql/",
    "scanner/redis/",
    "scanner/mongodb/",
    "scanner/mssql/",
    "scanner/mysql/",
    "scanner/cassandra/",
    "auxiliary/aws/",
    "auxiliary/azure/",
    "auxiliary/gcp/",
)

# Expanded recon: skip obviously invasive / follow-up modules in the first recon pass.
EXPANDED_SURFACE_RECON_SKIP_SUBSTR: Final[Tuple[str, ...]] = (
    "bruteforce",
    "_write_access",
    "file_download",
    "hop_proxy_generator",
)

# After OSINT / expanded modules: scan a bounded set of same-family hostnames (subdomains).
DERIVED_HOST_SCAN_MAX_HOSTS: Final[int] = 10
DERIVED_HOST_SCAN_MODULES_PER_HOST: Final[int] = 8

# Rapid HTTP probe before derived-host scans (--all / shell pivot).
DERIVED_HOST_PROBE_PATHS: Final[Tuple[str, ...]] = ("/", "/api", "/login")
DERIVED_HOST_LIVE_STATUSES: Final[Tuple[int, ...]] = (200, 301, 302, 401, 403)

# Subdomain hostname priority (higher score → scanned first).
SUBDOMAIN_PRIORITY_MARKERS: Final[Tuple[Tuple[str, int], ...]] = (
    ("api.", 40),
    ("admin.", 35),
    ("dev.", 30),
    ("staging.", 30),
    ("stage.", 28),
    ("login.", 25),
    ("auth.", 25),
    ("portal.", 20),
    ("app.", 15),
    ("internal.", 12),
    ("test.", 10),
    ("beta.", 10),
)

# obtain-shell macro loop: max extra module rounds after phased campaign.
SHELL_HUNTER_MACRO_MAX_ROUNDS: Final[int] = 12

# ``agent --all``: ordered passive intel before HTTP campaign (subdomains → identities).
EXPANDED_SURFACE_SUBDOMAIN_MODULES: Final[Tuple[str, ...]] = (
    "auxiliary/osint/domain_crtsh",
    "auxiliary/osint/domain_dns",
    "auxiliary/osint/domain_surface_mapper",
)

EXPANDED_SURFACE_IDENTITY_MODULES: Final[Tuple[str, ...]] = (
    "auxiliary/osint/email_pattern_harvester",
    "auxiliary/osint/identity_handle_hunter",
    "auxiliary/osint/persona_password_profiler",
    "auxiliary/osint/breach_exposure_score",
    "auxiliary/osint/saas_tenant_discovery",
    "auxiliary/osint/email_infra_pivot",
    "auxiliary/osint/advanced_exposed_credentials_detector",
)

EXPANDED_SURFACE_INTEL_MODULES: Final[Tuple[str, ...]] = (
    EXPANDED_SURFACE_SUBDOMAIN_MODULES + EXPANDED_SURFACE_IDENTITY_MODULES
)

EXPANDED_SURFACE_INTEL_MAX_MODULES: Final[int] = 6
EXPANDED_SURFACE_USERNAME_CANDIDATE_MAX: Final[int] = 24
EXPANDED_SURFACE_PASSWORD_CANDIDATE_MAX: Final[int] = 32
EXPANDED_SURFACE_BRUTEFORCE_MAX_ATTEMPTS: Final[int] = 36

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
        "sqli_engine": 0.72,
        "sql_injection": 0.45,
        "sqli_shell": 0.68,
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
