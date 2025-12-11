import asyncio
import threading
import sys
import os
import importlib
from typing import Dict, List, Callable, Optional

try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
except ImportError as exc:
    raise ImportError("mitmproxy doit être installé (pip install mitmproxy)") from exc

from flow_manager import flow_manager
from plugins.base import InterceptionPlugin

# Note: Individual plugins are now in kittyproxy/plugins/ directory
# They are automatically loaded by InterceptionPluginManager._load_plugins()

class InterceptionPluginManager:
    """Manager for interception plugins"""
    def __init__(self):
        self.plugins: Dict[str, InterceptionPlugin] = {}
        self.plugins_dir = os.path.join(os.path.dirname(__file__), 'plugins')
        self._load_plugins()
    
    def _load_plugins(self):
        """Load all plugins from the plugins directory"""
        if not os.path.exists(self.plugins_dir):
            print(f"[WARNING] Plugins directory not found: {self.plugins_dir}")
            return
        
        # Add plugins directory to Python path
        if self.plugins_dir not in sys.path:
            sys.path.insert(0, self.plugins_dir)
        
        # Import all plugin modules
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                plugin_name = filename[:-3]  # Remove .py extension
                
                # Skip base.py
                if plugin_name == 'base':
                    continue
                
                try:
                    # Import the plugin module
                    module = importlib.import_module(f'plugins.{plugin_name}')
                    
                    # Find plugin classes in the module (classes that inherit from InterceptionPlugin)
                    import inspect
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, InterceptionPlugin) and 
                            obj != InterceptionPlugin):
                            # Instantiate and register the plugin
                            plugin_instance = obj()
                            self.register_plugin(plugin_instance)
                            print(f"[INFO] Loaded plugin: {plugin_instance.name}")
                            
                except Exception as e:
                    print(f"[ERROR] Failed to load plugin '{plugin_name}': {e}")
                    import traceback
                    traceback.print_exc()
    
    def register_plugin(self, plugin: InterceptionPlugin):
        """Register a plugin"""
        self.plugins[plugin.name] = plugin
    
    def get_plugin(self, name: str) -> Optional[InterceptionPlugin]:
        """Get a plugin by name"""
        return self.plugins.get(name)
    
    def get_all_plugins(self) -> List[Dict]:
        """Get all plugins as dictionaries"""
        return [
            {
                "name": plugin.name,
                "description": plugin.description,
                "enabled": plugin.enabled,
                "config": plugin.config
            }
            for plugin in self.plugins.values()
        ]
    
    def enable_plugin(self, name: str):
        """Enable a plugin"""
        if name in self.plugins:
            self.plugins[name].enabled = True
    
    def disable_plugin(self, name: str):
        """Disable a plugin"""
        if name in self.plugins:
            self.plugins[name].enabled = False
    
    def update_plugin_config(self, name: str, config: Dict):
        """Update plugin configuration"""
        if name in self.plugins:
            self.plugins[name].config.update(config)

# Global plugin manager
plugin_manager = InterceptionPluginManager()

class InterceptorAddon:
    def __init__(self, api_host=None, api_port=None):
        """Initialize the interceptor addon with optional API host/port to ignore"""
        self.api_host = api_host
        self.api_port = api_port
    
    def _is_api_request(self, flow):
        """Check if the request is to the API interface itself"""
        if not self.api_host or not self.api_port:
            return False
        
        try:
            # Get the request host and port
            request_host = flow.request.host
            request_port = flow.request.port
            
            # Check if it matches the API host and port
            if request_host == self.api_host and request_port == self.api_port:
                return True
            
            # Also check the URL in case host/port are not set correctly
            if hasattr(flow.request, 'url') and flow.request.url:
                url = flow.request.url
                if f"{self.api_host}:{self.api_port}" in url or url.startswith(f"http://{self.api_host}:{self.api_port}") or url.startswith(f"https://{self.api_host}:{self.api_port}"):
                    return True
            
            return False
        except:
            return False
    
    def request(self, flow):
        # Ignore requests to the API interface itself
        if self._is_api_request(flow):
            return
        
        # Add to flow manager immediately so it's visible
        flow_manager.add_flow(flow)
        
        # Process plugins
        for plugin in plugin_manager.plugins.values():
            if plugin.enabled:
                if plugin.process_request(flow):
                    # Block the request
                    flow.response = http.Response.make(403, b"Blocked by interception plugin")
                    return
        
        # Interception check (this blocks if enabled)
        flow_manager.intercept_request(flow)
    
    def response(self, flow):
        # Ignore responses to the API interface itself
        if self._is_api_request(flow):
            return
        
        # Process response plugins
        for plugin in plugin_manager.plugins.values():
            if plugin.enabled:
                plugin.process_response(flow)
        
        # Mettre à jour le flow dans le cache maintenant que la réponse est disponible
        flow_manager.add_flow(flow)
        
        # Record performance metrics
        from performance_monitor import performance_monitor
        performance_monitor.record_request(flow)
        
        # Notifier les collaborateurs du nouveau flow
        try:
            from api import broadcast_flow_to_collaborators
            broadcast_flow_to_collaborators(flow)
        except Exception as e:
            # Ignorer les erreurs de collaboration
            pass

class MitmProxyWrapper:
    def __init__(self, host="127.0.0.1", port=8080, api_host=None, api_port=None):
        self.host = host
        self.port = port
        self.api_host = api_host
        self.api_port = api_port
        self.master = None
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._async_run())

    async def _async_run(self):
        opts = options.Options(listen_host=self.host, listen_port=self.port)
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.master.addons.add(InterceptorAddon(api_host=self.api_host, api_port=self.api_port))
        try:
            await self.master.run()
        except asyncio.CancelledError:
            # Arrêt attendu
            pass
        except Exception as e:
            print(f"Mitmproxy error: {e}")

    def start(self):
        self.thread.start()
        print(f"Proxy started on {self.host}:{self.port}")

    def stop(self):
        if not self.loop:
            return
        
        async def _graceful_stop():
            # Arrêt mitmproxy si encore présent
            if self.master:
                try:
                    shutdown_result = self.master.shutdown()
                    if asyncio.iscoroutine(shutdown_result):
                        await shutdown_result
                except asyncio.CancelledError:
                    # Attendu si déjà en cours d'arrêt
                    pass
                except Exception as e:
                    print(f"[Proxy] Error during shutdown: {e}")
            # Annuler les tâches restantes (sans relancer d'exceptions)
            pending = [t for t in asyncio.all_tasks(loop=self.loop) if not t.done() and t is not asyncio.current_task()]
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            # Laisser l'event loop traiter les annulations
            await asyncio.sleep(0)
        
        try:
            fut = asyncio.run_coroutine_threadsafe(_graceful_stop(), self.loop)
            fut.result(timeout=3)
        except Exception as e:
            print(f"[Proxy] Graceful stop timeout/error: {e}")
        finally:
            try:
                self.loop.call_soon_threadsafe(self.loop.stop)
            except Exception:
                pass
        
        if self.thread.is_alive():
            self.thread.join(timeout=3)
