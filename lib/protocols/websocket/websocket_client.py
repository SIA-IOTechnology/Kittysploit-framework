#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import websocket
import ssl
from typing import Dict, Optional, Any, Union
import logging

from core.framework.option import OptString, OptPort, OptBool
from core.framework.base_module import BaseModule

logger = logging.getLogger(__name__)

class WebsocketTimeoutException(Exception):
    pass

class Websocket_client(BaseModule):
    """Advanced WebSocket client for Kittysploit modules"""

    target = OptString("", "Target URL, IP or hostname", True)
    port = OptPort(443, "Target port", True)
    path = OptString("/", "Target path", True)
    ssl = OptBool(True, "SSL enabled: true/false", True, advanced=True)
    timeout = OptPort(10, "Connection timeout in seconds", True, advanced=True)
    verify_ssl = OptBool(False, "Verify SSL certificates: true/false", False, advanced=True)
    
    def __init__(self, framework=None):
        super().__init__(framework)
        self.logger = logger
        self.ws = None
    
    def _to_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ('true', 'yes', 'y', '1', 'on')
        return bool(value)
    
    def ws_connect(self, path: Optional[str] = None, headers: Optional[Dict[str, str]] = None, **kwargs) -> websocket.WebSocket:
        def get_option_value(option):
            if hasattr(option, 'value'): return option.value
            if hasattr(option, '__get__'):
                try: return option.__get__(self, type(self))
                except: return option
            return option

        target = get_option_value(self.target) if hasattr(self, 'target') else get_option_value(getattr(self, 'rhost', ''))
        port = get_option_value(self.port) if hasattr(self, 'port') else get_option_value(getattr(self, 'rport', ''))
        
        if not target or not port:
            raise ValueError("target and port options must be set.")
            
        ssl_enabled = False
        if hasattr(self, 'ssl'):
            ssl_enabled = self._to_bool(get_option_value(self.ssl))
        elif int(port) == 443:
            ssl_enabled = True
            
        protocol = 'wss' if ssl_enabled else 'ws'
        
        path_str = path if path is not None else get_option_value(self.path)
        if not path_str.startswith("/"):
            path_str = "/" + path_str
            
        url = f"{protocol}://{target}:{port}{path_str}"
        
        verify_ssl = self._to_bool(get_option_value(self.verify_ssl)) if hasattr(self, 'verify_ssl') else False
        timeout = int(get_option_value(self.timeout)) if hasattr(self, 'timeout') else 10
        
        sslopt = {}
        if not verify_ssl:
            sslopt = {"cert_reqs": ssl.CERT_NONE}
            
        formatted_headers = []
        if headers:
            for k, v in headers.items():
                formatted_headers.append(f"{k}: {v}")
                
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"WS Connect: {url}")
            
        try:
            self.ws = websocket.create_connection(
                url,
                timeout=timeout,
                sslopt=sslopt,
                header=formatted_headers,
                **kwargs
            )
        except websocket.WebSocketTimeoutException:
            raise WebsocketTimeoutException("Connection timed out")
        return self.ws
        
    def ws_send(self, data: Union[str, bytes], opcode: str = "text"):
        if not self.ws:
            raise ValueError("WebSocket is not connected. Call ws_connect() first.")
        
        ws_opcode = websocket.ABNF.OPCODE_TEXT
        if opcode == "binary" or (isinstance(data, bytes) and opcode != "text"):
            ws_opcode = websocket.ABNF.OPCODE_BINARY
            
        self.ws.send(data, ws_opcode)
        
    def ws_recv(self) -> Union[str, bytes]:
        if not self.ws:
            raise ValueError("WebSocket is not connected. Call ws_connect() first.")
        try:
            return self.ws.recv()
        except websocket.WebSocketTimeoutException:
            raise WebsocketTimeoutException("Receive timed out")
        
    def ws_close(self):
        if self.ws:
            self.ws.close()
            self.ws = None
