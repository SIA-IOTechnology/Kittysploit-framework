#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for Azure Run Command post modules."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from lib.protocols.oauth.entra_token import EntraTokenMixin

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.subscription import SubscriptionClient
    AZURE_AVAILABLE = True
except Exception:
    DefaultAzureCredential = ResourceManagementClient = SubscriptionClient = None
    AZURE_AVAILABLE = False


class AzurePostMixin(EntraTokenMixin):
    """Mixin providing Azure SDK helpers for azure_run_command sessions."""

    def _azure_require_sdk(self) -> None:
        if not AZURE_AVAILABLE:
            raise RuntimeError(
                "Azure SDK packages are missing. Install azure-identity, "
                "azure-mgmt-resource, and azure-mgmt-subscription."
            )

    def _session_id_value(self) -> str:
        if not hasattr(self, "session_id"):
            return ""
        session_id_attr = getattr(self, "session_id")
        if hasattr(session_id_attr, "value"):
            return str(session_id_attr.value or "").strip()
        return str(session_id_attr or "").strip()

    def _azure_session_data(self) -> Dict[str, Any]:
        session_id_value = self._session_id_value()
        if not session_id_value or not self.framework:
            return {}
        session = self.framework.session_manager.get_session(session_id_value)
        if not session or not session.data:
            return {}
        return dict(session.data)

    def _azure_subscription_id(self) -> str:
        return str(self._azure_session_data().get("subscription_id") or "").strip()

    def _azure_resource_group(self) -> str:
        return str(self._azure_session_data().get("resource_group") or "").strip()

    def _azure_vm_name(self) -> str:
        return str(self._azure_session_data().get("vm_name") or "").strip()

    def _azure_os_type(self) -> str:
        return str(self._azure_session_data().get("os_type") or "linux").strip().lower()

    def _azure_credential(self):
        self._azure_require_sdk()
        return DefaultAzureCredential()

    def _azure_whoami(self) -> Dict[str, Any]:
        self._azure_require_sdk()
        credential = self._azure_credential()
        token = credential.get_token("https://management.azure.com/.default")
        claims = self.entra_decode_jwt_claims(getattr(token, "token", "") or "")

        identity = {
            "subscription_id": self._azure_subscription_id(),
            "resource_group": self._azure_resource_group(),
            "vm_name": self._azure_vm_name(),
            "os_type": self._azure_os_type(),
            "tenant_id": claims.get("tid", ""),
            "object_id": claims.get("oid", ""),
            "app_id": claims.get("appid", ""),
            "upn": claims.get("upn", ""),
            "name": claims.get("name", ""),
            "unique_name": claims.get("unique_name", ""),
        }

        subscription_id = identity["subscription_id"]
        if subscription_id:
            try:
                sub_client = SubscriptionClient(credential)
                sub = sub_client.subscriptions.get(subscription_id)
                identity["subscription_name"] = getattr(sub, "display_name", "") or ""
                identity["subscription_state"] = str(getattr(sub, "state", "") or "")
            except Exception:
                pass

        return identity

    def _azure_list_resources(
        self,
        *,
        resource_group: str = "",
        filter_expr: str = "",
        max_items: int = 200,
    ) -> List[Dict[str, Any]]:
        self._azure_require_sdk()
        subscription_id = self._azure_subscription_id()
        if not subscription_id:
            return []

        credential = self._azure_credential()
        client = ResourceManagementClient(credential, subscription_id)
        resources: List[Dict[str, Any]] = []
        limit = max(1, int(max_items or 200))

        if resource_group:
            iterator = client.resources.list_by_resource_group(
                resource_group,
                filter=filter_expr or None,
            )
        else:
            iterator = client.resources.list(filter=filter_expr or None)

        for item in iterator:
            resources.append(
                {
                    "name": getattr(item, "name", ""),
                    "type": getattr(item, "type", ""),
                    "location": getattr(item, "location", ""),
                    "resource_group": (
                        str(getattr(item, "id", "") or "").split("/")[4]
                        if getattr(item, "id", None)
                        else resource_group
                    ),
                    "id": getattr(item, "id", ""),
                }
            )
            if len(resources) >= limit:
                break
        return resources
