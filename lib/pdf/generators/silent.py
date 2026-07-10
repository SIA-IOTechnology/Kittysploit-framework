"""Silent callback PDF generators."""

from __future__ import annotations

import base64
import bz2
import os
import re
import zlib

from lib.pdf.obfuscation import ensure_scheme

def write_silent_dns_catalog_aa(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AA <<
       /WC << /S /URI /URI (''' + host + '''/test38-willclose) >>
       /WS << /S /URI /URI (''' + host + '''/test38-willsave) >>
       /DS << /S /URI /URI (''' + host + '''/test38-didsave) >>
     >>
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
    (Testcase: 'silent-dns'  ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000280 00000 n
0000000381 00000 n
0000000650 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
770
%%EOF
''')
