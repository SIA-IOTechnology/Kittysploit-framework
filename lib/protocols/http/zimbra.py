#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic Zimbra SOAP / EWS HTTP helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from core.framework.base_module import BaseModule


class Zimbra(BaseModule):
    """Shared Zimbra Collaboration SOAP and EWS calls."""

    _SOAP_PATH = "/service/soap"
    _EWS_PATHS = ("/service/extension/zimbraews", "/EWS/Exchange.asmx")

    def _soap_envelope(self, body: str, auth_token: Optional[str] = None) -> str:
        ctx = ""
        if auth_token:
            ctx = (
                '<context xmlns="urn:zimbra">'
                f'<authToken>{auth_token}</authToken>'
                "</context>"
            )
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
            f"<soap:Header>{ctx}</soap:Header>"
            f"<soap:Body>{body}</soap:Body>"
            "</soap:Envelope>"
        )

    def zimbra_auth(self, account: str, password: str) -> Tuple[Optional[str], str]:
        body = (
            '<AuthRequest xmlns="urn:zimbraAccount">'
            f'<account by="name">{account}</account>'
            f"<password>{password}</password>"
            "</AuthRequest>"
        )
        resp = self.http_request(
            method="POST",
            path=self._SOAP_PATH,
            headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
            data=self._soap_envelope(body),
        )
        if not resp:
            return None, "no response"
        text = resp.text or ""
        match = re.search(r"<authToken[^>]*>([^<]+)</authToken>", text)
        if match:
            return match.group(1), text
        return None, text[:400]

    def zimbra_get_account_uuid(self, auth_token: str, account_name: str) -> Optional[str]:
        body = (
            '<GetAccountInfoRequest xmlns="urn:zimbraAccount">'
            f'<account by="name">{account_name}</account>'
            "</GetAccountInfoRequest>"
        )
        resp = self.http_request(
            method="POST",
            path=self._SOAP_PATH,
            headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
            data=self._soap_envelope(body, auth_token),
        )
        if not resp:
            return None
        match = re.search(r'<attr name="zimbraId">([^<]+)</attr>', resp.text or "")
        return match.group(1) if match else None

    def zimbra_save_draft_send(
        self,
        auth_token: str,
        *,
        from_addr: str,
        to_addr: str,
        subject: str,
        body_text: str,
    ) -> bool:
        body = (
            '<SaveDraftRequest xmlns="urn:zimbraMail" isDelegatedReq="1">'
            "<m>"
            f'<e t="t" a="{to_addr}"/>'
            f'<e t="f" a="{from_addr}"/>'
            f"<su>{subject}</su>"
            '<mp ct="text/plain"><content>' + body_text + "</content></mp>"
            "</m>"
            "</SaveDraftRequest>"
        )
        resp = self.http_request(
            method="POST",
            path=self._SOAP_PATH,
            headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
            data=self._soap_envelope(body, auth_token),
        )
        if not resp or int(resp.status_code) not in (200, 500):
            return False
        text = resp.text or ""
        return "SaveDraftResponse" in text or "sent" in text.lower()

    def zimbra_ews_find_item(
        self,
        username: str,
        password: str,
        folder_id: str,
        *,
        max_items: int = 5,
    ) -> Tuple[int, str]:
        import base64

        soap = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" '
            'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">'
            "<soap:Header>"
            '<t:RequestServerVersion Version="Exchange2010" />'
            "</soap:Header>"
            "<soap:Body>"
            '<m:FindItem Traversal="Shallow">'
            "<m:ItemShape><t:BaseShape>AllProperties</t:BaseShape>"
            "<t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape>"
            f'<m:IndexedPageItemView MaxEntriesReturned="{max_items}" Offset="0" BasePoint="End"/>'
            f'<m:ParentFolderIds><t:FolderId Id="{folder_id}"/></m:ParentFolderIds>'
            "</m:FindItem>"
            "</soap:Body></soap:Envelope>"
        )
        basic = base64.b64encode(f"{username}:{password}".encode()).decode()
        for path in self._EWS_PATHS:
            resp = self.http_request(
                method="POST",
                path=path,
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "Authorization": f"Basic {basic}",
                },
                data=soap,
            )
            if resp and int(resp.status_code) == 200:
                return int(resp.status_code), resp.text or ""
        return 0, ""