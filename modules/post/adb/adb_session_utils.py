from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


def _get_session(framework, session_id: str):
    """Safely fetch a SessionData object."""
    if not framework or not session_id:
        return None

    session_manager = getattr(framework, "session_manager", None)
    if not session_manager:
        return None

    try:
        return session_manager.get_session(session_id)
    except Exception:
        return None


def _lookup_device_in_listener(listener, session_id: str):
    if not listener or not session_id:
        return None

    connections = getattr(listener, "_session_connections", None)
    if not connections:
        return None

    return connections.get(session_id)


def get_adb_device_info(
    framework, session_id: str
) -> Tuple[Optional[Any], Optional[str], Optional[int], Optional[Dict[str, Any]]]:
    """
    Resolve the ppadb device object for a session along with serial/port/session data.

    Returns:
        (device, serial, port, session_data_dict)
    """
    session = _get_session(framework, session_id)
    if not session:
        return None, None, None, None

    data: Dict[str, Any] = {}
    if getattr(session, "data", None) and isinstance(session.data, dict):
        data = session.data

    serial = data.get("adb_device_id") or getattr(session, "host", None)
    port = getattr(session, "port", None)

    listener_id = data.get("listener_id")
    device = None

    active_listeners = getattr(framework, "active_listeners", {}) if framework else {}
    if listener_id and isinstance(active_listeners, dict):
        device = _lookup_device_in_listener(active_listeners.get(listener_id), session_id)

    if not device:
        current_module = getattr(framework, "current_module", None)
        device = _lookup_device_in_listener(current_module, session_id)

    if not device:
        modules = getattr(framework, "modules", None)
        if isinstance(modules, dict):
            for module in modules.values():
                device = _lookup_device_in_listener(module, session_id)
                if device:
                    break

    return device, serial, port, data or None


def get_adb_device(framework, session_id: str):
    """Backward-compatible helper that only returns the device object."""
    device, _, _, _ = get_adb_device_info(framework, session_id)
    return device
