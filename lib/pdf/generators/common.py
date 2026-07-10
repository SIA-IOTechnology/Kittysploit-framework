"""Shared generator helpers."""

from __future__ import annotations

def _js_callback_pdf(filename, host, js_code, label):
    """Helper to generate a minimal PDF with a single JavaScript callback."""
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
      /JS(''' + js_code + ''')
      >>
  >>
>>''')
