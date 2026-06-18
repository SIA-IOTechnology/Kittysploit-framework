#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Run command implementation
"""

import argparse
import socket
import time
from typing import Dict, List, Any, Optional
from interfaces.command_system.base_command import BaseCommand
from core.framework.option.base_option import Option as BaseOption
from core.output_handler import print_info, print_success, print_error, print_warning, print_empty

class RunCommand(BaseCommand):
    """Command to run the current module"""
    
    @property
    def name(self) -> str:
        return "run"
    
    @property
    def description(self) -> str:
        return "Execute the current module"
    
    @property
    def usage(self) -> str:
        return "run [--preview] [--background]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command executes the currently selected module. Make sure to set
all required options before running.

Options:
    --preview                 Show execution preview without running
    --background              Run module in background (for listeners)
    --yes, -y                 Skip destructive-action confirmation (scope)

Examples:
    run                       # Execute the current module
    run --preview             # Show execution preview
    run --background          # Run listener in background
        """
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Execute the current module",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        parser.add_argument(
            '--preview',
            action='store_true',
            help='Show execution preview without running'
        )
        
        parser.add_argument(
            '--background',
            action='store_true',
            help='Run module in background (for listeners)'
        )

        parser.add_argument(
            '--yes', '-y',
            action='store_true',
            help='Skip destructive-action confirmation prompt'
        )
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the run command"""
        plugin_manager = getattr(self.framework, 'plugin_manager', None)
        metasploit_plugin = plugin_manager.get_plugin("metasploit") if plugin_manager else None
        if metasploit_plugin and getattr(metasploit_plugin, "is_integrated_mode_active", lambda: False)():
            return metasploit_plugin.msf_run(args)

        try:
            parsed_args = self.parser.parse_args(args)
        except SystemExit:
            return True
        
        if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
            print_error("No module selected. Use 'use <module>' first.")
            return False
        
        module = self.framework.current_module

        # Preview is a pre-flight view: it must work even when required options
        # are missing, because reporting those gaps is part of the feature.
        if parsed_args.preview:
            self._show_execution_preview(module, background=parsed_args.background)
            return True
        
        try:
            # Check if all required options are set
            if not module.check_options():
                missing = module.get_missing_options()
                if missing:
                    print_error(f"Missing required options: {', '.join(missing)}")
                else:
                    print_error("Not all required options are set")
                print_info("Use 'show options' to see required options")
                return False

            scope_manager = getattr(self.framework, 'scope_manager', None)
            if scope_manager and not scope_manager.ensure_execution_permitted(
                module,
                skip_confirm=parsed_args.yes,
            ):
                return False
            
            # Vérifier la blacklist du Guardian avant l'exécution
            if hasattr(self.framework, 'guardian_manager') and self.framework.guardian_manager and self.framework.guardian_manager.enabled and self.framework.guardian_manager.verbose:
                print_info(f"[GUARDIAN DEBUG] Checking guardian - has guardian_manager: {hasattr(self.framework, 'guardian_manager')}")
                if hasattr(self.framework, 'guardian_manager'):
                    print_info(f"[GUARDIAN DEBUG] guardian_manager exists: {self.framework.guardian_manager is not None}")
                    if self.framework.guardian_manager:
                        print_info(f"[GUARDIAN DEBUG] guardian_manager.enabled: {self.framework.guardian_manager.enabled}")
                        print_info(f"[GUARDIAN DEBUG] blacklist size: {len(self.framework.guardian_manager.blacklist)}")
                        print_info(f"[GUARDIAN DEBUG] blacklist contents: {list(self.framework.guardian_manager.blacklist.keys())}")
            
            if hasattr(self.framework, 'guardian_manager') and self.framework.guardian_manager and self.framework.guardian_manager.enabled:
                target_ip = self.framework._extract_target_ip_from_module()
                if self.framework.guardian_manager.verbose:
                    print_info(f"[GUARDIAN DEBUG] Extracted target IP: {target_ip}")
                if target_ip:
                    # Vérifier si l'IP est dans la blacklist
                    is_blacklisted = target_ip in self.framework.guardian_manager.blacklist
                    if self.framework.guardian_manager.verbose:
                        print_info(f"[GUARDIAN DEBUG] Is {target_ip} in blacklist? {is_blacklisted}")
                    if is_blacklisted:
                        blacklist_entry = self.framework.guardian_manager.blacklist[target_ip]
                        reason = blacklist_entry.get('reason', 'Unknown reason')
                        timestamp = blacklist_entry.get('timestamp', 'Unknown')
                        
                        print_error(f"[GUARDIAN] Module execution BLOCKED: Target IP {target_ip} is blacklisted")
                        print_error(f"[GUARDIAN] Reason: {reason} (added: {timestamp})")
                        
                        # Créer une alerte Guardian via _create_alert pour mettre à jour les statistiques
                        alert = self.framework.guardian_manager._create_alert(
                            target=target_ip,
                            severity="CRITICAL",
                            issue=f"Module execution blocked: IP {target_ip} is blacklisted",
                            confidence=100.0,
                            recommendations=[
                                "Remove IP from blacklist if this is intentional",
                                "Verify target before removing from blacklist"
                            ],
                            evidence=[f"IP {target_ip} found in blacklist"]
                        )
                        # Marquer l'action comme prise
                        alert.auto_action_taken = True
                        alert.action_description = "Module execution blocked"
                        
                        return False
            
            # Check if module requires root privileges
            if module.requires_root:
                print_warning("This module requires root privileges")
                # In a real implementation, you might want to check actual privileges
            
            # Execute the module
            print_info(f"Executing module: {module.name}")
            print_info("=" * 50)
            
            # Check if it's a listener module
            if hasattr(module, 'type') and module.type == 'listener':
                # Check if run() method accepts background parameter
                import inspect
                run_signature = inspect.signature(module.run)
                accepts_background = 'background' in run_signature.parameters
                
                if parsed_args.background:
                    print_info("Listener module detected. Running in background mode.")
                    try:
                        # For background mode, use direct run() but still create session if result is a tuple
                        if accepts_background:
                            result = module.run(background=True)
                        else:
                            result = module.run()
                        
                        # If result is a tuple with (connection, target, port), create session automatically
                        if isinstance(result, tuple) and len(result) >= 3:
                            connection, target, port = result[0], result[1], result[2]
                            additional_data = result[3] if len(result) > 3 else {}
                            
                            # Create session automatically using listener's _create_session_from_connection_data
                            if hasattr(module, '_create_session_from_connection_data'):
                                session_id = module._create_session_from_connection_data(
                                    connection, target, port, additional_data
                                )
                                if session_id:
                                    print_success(f"Session {session_id} created automatically")
                                    # Convert result to boolean for command history
                                    success = True
                                else:
                                    print_error("Failed to create session automatically")
                                    success = False
                            else:
                                # Fallback: use run_with_auto_session if available
                                if hasattr(module, 'run_with_auto_session'):
                                    session_id = module.run_with_auto_session()
                                    success = bool(session_id) if session_id else False
                                else:
                                    success = False
                        # If result is a session ID (string), it's already created
                        elif isinstance(result, str) and result:
                            print_success(f"Session {result} created")
                            success = True
                        # Convert result to boolean for command history
                        else:
                            success = bool(result) if result is not None else False
                        
                        if success:
                            print_success("Listener started in background")
                            # Register as a background job
                            self._register_background_job(module)
                        else:
                            print_error("Failed to start listener in background")
                        return success
                    except Exception as e:
                        print_error(f"Error starting listener in background: {e}")
                        return False
                else:
                    print_info("Listener module detected. Press Ctrl+C to stop.")
                    try:
                        # Use run_with_auto_session for listeners to automatically create sessions
                        if hasattr(module, 'run_with_auto_session'):
                            result = module.run_with_auto_session()
                            
                            # If result is a session_id (string), automatically start interactive session
                            if isinstance(result, str) and result:
                                session_id = result
                                print_success(f"Session {session_id} created. Starting interactive shell...")
                                
                                # Automatically start interactive session
                                return self._start_interactive_session_for_listener(session_id)
                            
                            # Convert result to boolean for command history
                            success = bool(result) if result is not None else False
                            if success:
                                print_success("Module execution completed successfully")
                            else:
                                print_error("Module execution failed")
                            return success
                        else:
                            # Fallback to direct run() if run_with_auto_session is not available
                            if accepts_background:
                                result = module.run(background=False)
                            else:
                                result = module.run()
                            # Convert result to boolean for command history
                            success = bool(result) if result is not None else False
                            if success:
                                print_success("Module execution completed successfully")
                            else:
                                print_error("Module execution failed")
                            return success
                    except KeyboardInterrupt:
                        print_info("\n[!] Interrupted by user")
                        # Call shutdown method if available
                        if hasattr(module, 'shutdown'):
                            try:
                                module.shutdown()
                                print_info("Listener stopped gracefully")
                            except Exception as e:
                                print_warning(f"Error during shutdown: {e}")
                        return True
            else:
                # Check if it's a payload module
                is_payload = (hasattr(module, 'type') and module.type == 'payload') or \
                            (hasattr(module, 'TYPE_MODULE') and module.TYPE_MODULE == 'payload')
                
                if is_payload:
                    # For payloads, use generate() instead of run()
                    print_info("Payload module detected. Generating payload...")
                    try:
                        payload_result = module.generate()
                        if payload_result:
                            print_success("Payload generated successfully!")
                            print_info(f"Payload: {payload_result}")
                            return True
                        else:
                            print_error("Failed to generate payload")
                            return False
                    except Exception as e:
                        print_error(f"Error generating payload: {e}")
                        return False
                
                # Regular module execution
                if parsed_args.background:
                    print_info("Running module in background mode.")
                    try:
                        # Check if run() method accepts background parameter
                        import inspect
                        try:
                            run_signature = inspect.signature(module.run)
                            accepts_background = 'background' in run_signature.parameters
                        except (ValueError, TypeError):
                            # If signature inspection fails, assume no background parameter
                            accepts_background = False
                        
                        if accepts_background:
                            result = module.run(background=True)
                        else:
                            result = module.run()
                        # Convert result to boolean for command history
                        success = bool(result) if result is not None else False
                        if success:
                            print_success("Module started in background")
                            # Register as a background job
                            self._register_background_job(module)
                        else:
                            print_error("Failed to start module in background")
                        return success
                    except Exception as e:
                        print_error(f"Error starting module in background: {e}")
                        return False
                else:
                    result = module._exploit()
                    
                    # Convert result to boolean for command history
                    success = bool(result) if result is not None else False

                    # Scanner modules return False for "not detected"; that is not a run failure.
                    is_scanner = getattr(module, 'TYPE_MODULE', None) == 'scanner'
                    if is_scanner:
                        if getattr(module, '_scan_error', False):
                            print_error("Module execution failed.")
                            return False
                        if success:
                            print_success("Module execution completed successfully.")
                        else:
                            print_success("Module execution completed (scan finished).")
                        # Negative detection is not a CLI/command failure; only _scan_error is.
                        return True

                    if success:
                        print_success("Module execution completed successfully")
                    else:
                        print_error("Module execution failed")
                    
                    return success
            
        except Exception as e:
            print_error(f"Error executing module: {str(e)}")
            return False
    
    def _register_background_job(self, module):
        """Register a module as a background job"""
        try:
            from core.job_manager import global_job_manager
            
            # Generate job name based on module type and name
            job_name = f"{module.type} {module.name}"
            if hasattr(module, 'lhost') and hasattr(module, 'lport'):
                # For listeners, include host and port
                host = str(module.lhost.value)
                port = int(module.lport.value)
                job_name = f"{module.type} {module.name} on {host}:{port}"
            
            job_id = global_job_manager.add_job(
                name=job_name,
                description=f"{module.type} module: {module.name}",
                module=module
            )
            
            if job_id:
                print_success(f"Module registered as background job [ID: {job_id}]")
                # Store job_id in module for later reference
                if hasattr(module, 'job_id'):
                    module.job_id = job_id
            else:
                print_warning("Failed to register module as background job")
                
        except Exception as e:
            print_warning(f"Could not register module as background job: {e}")
    
    def _show_execution_preview(self, module, background: bool = False):
        """Show a non-executing pre-flight summary for the current module."""
        module_name = getattr(module, 'name', '') or self._module_path(module) or type(module).__name__
        module_type = self._module_type(module)
        missing_options = self._missing_options(module)
        target_entries = self._target_entries(module)
        target_option_names = self._target_option_names(module)
        payload_preview = self._payload_listener_preview(module)
        privilege_preview = self._privilege_preview(module)
        guardian_preview = self._guardian_preview(target_entries, target_option_names)
        scope_preview = self._scope_preview(module)

        print_empty()
        print_info("Execution Preview")
        print_info("=" * 50)
        print_info(f"Module: {module_name}")
        module_path = self._module_path(module)
        if module_path:
            print_info(f"Path: {module_path}")
        print_info(f"Type: {module_type}")
        print_info(f"Mode: {self._execution_mode(module, background)}")

        print_empty()
        print_info("Target")
        if target_entries:
            for name, value in target_entries:
                print_info(f"  {name}: {value}")
        elif target_option_names:
            print_warning("  No target value configured")
            print_info(f"  Target options: {', '.join(target_option_names)}")
        else:
            print_warning("  No target option detected")

        print_empty()
        print_info("Required Options")
        if missing_options:
            print_warning(f"  Missing: {', '.join(missing_options)}")
            print_info("  Ready: no")
        else:
            print_success("  Missing: none")
            print_info("  Ready: yes")

        print_empty()
        print_info("Payload / Listener")
        for line in payload_preview:
            print_info(f"  {line}")

        print_empty()
        print_info("Required Privileges")
        for line in privilege_preview:
            print_info(f"  {line}")

        print_empty()
        print_info("Engagement Scope")
        for level, line in scope_preview:
            if level == "error":
                print_error(f"  {line}")
            elif level == "warning":
                print_warning(f"  {line}")
            elif level == "success":
                print_success(f"  {line}")
            else:
                print_info(f"  {line}")

        print_empty()
        print_info("Guardian Scope")
        for level, line in guardian_preview:
            if level == "error":
                print_error(f"  {line}")
            elif level == "warning":
                print_warning(f"  {line}")
            elif level == "success":
                print_success(f"  {line}")
            else:
                print_info(f"  {line}")

        print_empty()
        if missing_options:
            print_warning("Preview only: execution would fail until required options are set.")
        elif any(level == "error" for level, _line in scope_preview):
            print_warning("Preview only: engagement scope would block execution.")
        elif any(level == "error" for level, _line in guardian_preview):
            print_warning("Preview only: Guardian would block execution for the current scope.")
        elif any(level == "warning" and "confirmation" in line for level, line in scope_preview):
            print_warning("Preview only: destructive-action confirmation would be required.")
        else:
            print_success("Preview complete: no required-option, scope, or Guardian blocker detected.")

    def _module_path(self, module) -> str:
        raw_path = str(getattr(module, '__module__', '') or '')
        if raw_path.startswith('modules.'):
            return raw_path[len('modules.'):].replace('.', '/')
        return raw_path.replace('.', '/') if raw_path else ''

    def _module_type(self, module) -> str:
        module_type = (
            getattr(module, 'type', None)
            or getattr(module, 'TYPE_MODULE', None)
            or getattr(module, '__info__', {}).get('type')
            or 'module'
        )
        return self._stringify(module_type).lower()

    def _execution_mode(self, module, background: bool = False) -> str:
        module_type = self._module_type(module)
        if module_type == 'payload':
            return 'generate payload'
        if module_type == 'listener':
            return 'start listener in background' if background else 'start listener'
        if background:
            return 'execute in background'
        return 'execute module'

    def _module_options(self, module) -> Dict[str, Any]:
        try:
            options = module.get_options() if hasattr(module, 'get_options') else {}
            return options or {}
        except Exception as exc:
            print_warning(f"Could not read module options for preview: {exc}")
            return {}

    def _option_descriptor(self, module, name: str):
        descriptor = getattr(type(module), name, None)
        return descriptor if isinstance(descriptor, BaseOption) else None

    def _option_display_value(self, module, name: str, default: Any = "") -> str:
        descriptor = self._option_descriptor(module, name)
        if descriptor:
            instance_data = getattr(descriptor, '_instance_values', {}).get(id(module), {}) or {}
            if 'display_value' in instance_data:
                return self._stringify(instance_data.get('display_value', ''))
            return self._stringify(getattr(descriptor, '_default_display_value', default))

        try:
            value = getattr(module, name)
        except Exception:
            value = default
        return self._stringify(value)

    def _missing_options(self, module) -> List[str]:
        try:
            if hasattr(module, 'get_missing_options'):
                return [str(item) for item in module.get_missing_options()]
        except Exception as exc:
            print_warning(f"Could not compute missing options with module helper: {exc}")

        missing = []
        for name, option_data in self._module_options(module).items():
            required = bool(option_data[1]) if len(option_data) > 1 else False
            if required and not self._is_set(self._option_display_value(module, name)):
                missing.append(str(name))
        return missing

    def _target_entries(self, module) -> List[tuple]:
        target_names = self._target_option_name_set()
        entries = []
        for name, option_data in self._module_options(module).items():
            if str(name).lower() not in target_names:
                continue
            default = option_data[0] if option_data else ""
            value = self._option_display_value(module, name, default)
            if self._is_set(value):
                entries.append((str(name), value))
        return entries

    def _target_option_names(self, module) -> List[str]:
        target_names = self._target_option_name_set()
        return [
            str(name)
            for name in self._module_options(module).keys()
            if str(name).lower() in target_names
        ]

    def _target_option_name_set(self) -> set:
        target_names = {
            'target', 'targets', 'rhost', 'rhosts', 'host', 'hosts', 'hostname',
            'ip', 'domain', 'url', 'uri', 'endpoint', 'base_url', 'target_url',
            'tcp_host', 'tcp_port', 'port', 'rport', 'path', 'ssl',
        }
        return target_names

    def _payload_listener_preview(self, module) -> List[str]:
        module_type = self._module_type(module)
        payload_path = self._payload_path(module)

        if module_type == 'listener':
            return self._listener_module_preview(module)

        if module_type == 'payload':
            return self._payload_module_preview(module, "Current module")

        lines = []
        if payload_path:
            lines.append(f"Payload: {payload_path}")
            payload_module = self._load_preview_module(payload_path)
            if payload_module:
                lines.extend(self._payload_module_preview(payload_module, None))
            elif str(payload_path).startswith("msf/"):
                lines.extend(self._metasploit_payload_preview(payload_path))
            else:
                lines.append("Listener: unavailable (payload metadata could not be loaded)")
        elif 'payload' in self._module_options(module):
            lines.append("Payload: not configured")
            if 'payload' in self._missing_options(module):
                lines.append("Listener: unavailable until payload is set")
            else:
                lines.append("Listener: none declared")
        else:
            lines.append("Payload: none")
            lines.append("Listener: none")

        disable_handler = self._option_display_value(module, 'disablePayloadHandler')
        if self._is_truthy(disable_handler):
            lines.append("Automatic handler: disabled by disablePayloadHandler")
        elif payload_path:
            lines.append("Automatic handler: enabled")
        return lines

    def _listener_module_preview(self, module) -> List[str]:
        lines = ["Payload: none (listener module)"]
        listener_name = getattr(module, 'name', '') or self._module_path(module) or type(module).__name__
        lines.append(f"Listener: {listener_name}")

        endpoint_parts = []
        for name in ('lhost', 'lport', 'rhost', 'rport', 'host', 'port', 'handler', 'session_type'):
            if name in self._module_options(module) or hasattr(type(module), name):
                value = self._option_display_value(module, name)
                if self._is_set(value):
                    endpoint_parts.append(f"{name}={value}")
        if endpoint_parts:
            lines.append(f"Listener options: {', '.join(endpoint_parts)}")
        return lines

    def _payload_module_preview(self, module, prefix: Optional[str]) -> List[str]:
        info = getattr(module, '__info__', {}) or {}
        lines = []
        if prefix:
            module_name = getattr(module, 'name', '') or info.get('name') or self._module_path(module)
            lines.append(f"{prefix}: {module_name}")

        listener = self._stringify(info.get('listener'))
        handler = self._stringify(info.get('handler'))
        session_type = self._stringify(info.get('session_type'))
        protocol = self._stringify(info.get('protocol'))

        lines.append(f"Listener: {listener or 'none declared'}")
        if handler:
            lines.append(f"Handler: {handler}")
        if session_type:
            lines.append(f"Session type: {session_type}")
        if protocol:
            lines.append(f"Protocol: {protocol}")
        return lines

    def _metasploit_payload_preview(self, payload_path: str) -> List[str]:
        plugin_manager = getattr(self.framework, 'plugin_manager', None)
        metasploit_plugin = plugin_manager.get_plugin("metasploit") if plugin_manager else None
        infer = getattr(metasploit_plugin, '_infer_msf_payload_metadata', None)
        if not infer:
            return ["Listener: metasploit/multi/handler", "Handler: inferred by Metasploit plugin"]
        try:
            metadata = infer(payload_path) or {}
        except Exception as exc:
            return [f"Listener: unavailable (Metasploit metadata error: {exc})"]
        return [
            f"Listener: {self._stringify(metadata.get('listener')) or 'metasploit/multi/handler'}",
            f"Handler: {self._stringify(metadata.get('handler')) or 'unknown'}",
            f"Session type: {self._stringify(metadata.get('session_type')) or 'unknown'}",
        ]

    def _payload_path(self, module) -> str:
        descriptor = self._option_descriptor(module, 'payload')
        if descriptor and hasattr(descriptor, '_instance_values'):
            instance_data = descriptor._instance_values.get(id(module), {}) or {}
            value = instance_data.get('value')
            if self._is_set(value):
                return self._stringify(value)

        info_payload = (getattr(module, '__info__', {}) or {}).get('payload')
        if isinstance(info_payload, dict):
            default = info_payload.get('default')
            if self._is_set(default):
                return self._stringify(default)
        elif self._is_set(info_payload):
            return self._stringify(info_payload)

        if descriptor:
            instance_data = getattr(descriptor, '_instance_values', {}).get(id(module), {}) or {}
            value = instance_data.get('display_value') or getattr(descriptor, '_default_display_value', '')
            if self._is_set(value):
                return self._stringify(value)
        return ""

    def _load_preview_module(self, module_path: str):
        module_loader = getattr(self.framework, 'module_loader', None)
        if not module_loader:
            return None
        try:
            return module_loader.load_module(
                module_path,
                load_only=True,
                framework=self.framework,
                silent=True,
            )
        except Exception:
            return None

    def _privilege_preview(self, module) -> List[str]:
        info = getattr(module, '__info__', {}) or {}
        requires_root = bool(getattr(module, 'requires_root', False) or info.get('requires_root', False))
        lines = []
        if requires_root:
            lines.append("Root/admin privileges required")
        else:
            lines.append("No root/admin requirement declared")

        for key in ('required_privileges', 'privileges_required', 'privileges', 'required_permissions'):
            value = info.get(key)
            if value:
                lines.append(f"{key}: {self._stringify(value)}")
        return lines

    def _guardian_preview(self, target_entries: List[tuple], target_option_names: List[str] = None) -> List[tuple]:
        guardian = getattr(self.framework, 'guardian_manager', None)
        if not guardian:
            return [("warning", "Guardian manager unavailable")]

        enabled = bool(getattr(guardian, 'enabled', False))
        blacklist = getattr(guardian, 'blacklist', {}) or {}
        whitelist = getattr(guardian, 'whitelist', set()) or set()
        lines = [
            ("info", f"Monitoring: {'enabled' if enabled else 'disabled'}"),
            ("info", f"Auto-action: {'enabled' if getattr(guardian, 'auto_action', False) else 'disabled'}"),
            ("info", f"Blacklist entries: {len(blacklist)}"),
        ]

        target_ip = None
        extractor = getattr(self.framework, '_extract_target_ip_from_module', None)
        if extractor:
            try:
                target_ip = extractor()
            except Exception:
                target_ip = None

        if target_ip:
            lines.append(("info", f"Execution target IP: {target_ip}"))
            if target_ip in blacklist:
                entry = blacklist[target_ip]
                reason = entry.get('reason', 'Unknown reason')
                timestamp = entry.get('timestamp', 'Unknown time')
                lines.append(("error", f"Status: BLOCKED by blacklist ({reason}, added {timestamp})"))
            elif target_ip in whitelist:
                lines.append(("success", "Status: allowed by Guardian whitelist"))
            elif enabled:
                lines.append(("success", "Status: allowed by current Guardian blacklist"))
            else:
                lines.append(("info", "Status: not enforced while Guardian is disabled"))
        elif target_entries:
            visible_targets = ", ".join(f"{name}={value}" for name, value in target_entries[:4])
            lines.append(("warning", f"Execution target IP: unresolved from options ({visible_targets})"))
            lines.append(("warning", "Status: IP blacklist cannot be evaluated without a concrete IP"))
        elif target_option_names:
            lines.append(("warning", f"Execution target IP: no concrete target value configured ({', '.join(target_option_names)})"))
            lines.append(("warning", "Status: IP blacklist cannot be evaluated until a target value is set"))
        else:
            lines.append(("warning", "Execution target IP: no target option in scope"))
        return lines

    def _scope_preview(self, module) -> List[tuple]:
        manager = getattr(self.framework, 'scope_manager', None)
        if not manager:
            return [("warning", "Scope manager unavailable")]
        return manager.preview_lines(module)

    def _stringify(self, value: Any) -> str:
        if value is None:
            return ""
        if hasattr(value, 'value'):
            return self._stringify(value.value)
        if hasattr(value, 'name') and not isinstance(value, str):
            return str(value.name).lower()
        if isinstance(value, (list, tuple, set)):
            return ", ".join(self._stringify(item) for item in value if self._stringify(item))
        return str(value)

    def _is_set(self, value: Any) -> bool:
        text = self._stringify(value).strip()
        return bool(text and text.lower() not in {'none', 'null'})

    def _is_truthy(self, value: Any) -> bool:
        text = self._stringify(value).strip().lower()
        return text in {'1', 'true', 'yes', 'y', 'on'}


    
    def _start_interactive_session_for_listener(self, session_id: str) -> bool:
        """Start an interactive session for a listener-created session"""
        try:
            if not hasattr(self.framework, 'shell_manager'):
                print_error("Shell manager not available")
                return False
            
            # Check if session exists
            session = self.framework.session_manager.get_session(session_id)
            if not session:
                print_error(f"Session not found: {session_id}")
                return False
            
            # Determine shell type based on session type
            session_type = session.session_type.lower() if session.session_type else "standard"
            if session_type == "ssh":
                shell_type = "ssh"
            elif session_type == "meterpreter":
                shell_type = "meterpreter"
            elif session_type in ("php", "http", "https"):
                shell_type = "php"
            elif session_type == "mysql":
                shell_type = "mysql"
            elif session_type == "postgresql":
                shell_type = "postgresql"
            elif session_type == "redis":
                shell_type = "redis"
            elif session_type == "ldap":
                shell_type = "ldap"
            elif session_type == "mongodb":
                shell_type = "mongodb"
            elif session_type == "elasticsearch":
                shell_type = "elasticsearch"
            elif session_type == "mssql":
                shell_type = "mssql"
            elif session_type == "ftp":
                shell_type = "ftp"
            elif session_type == "aws":
                # Check if it's a command executor or interactive shell
                session_data = session.data if hasattr(session, 'data') else {}
                if session_data and session_data.get('command_executor'):
                    shell_type = "aws_sqs_command"
                else:
                    shell_type = "aws_sqs"
            elif session_type == "android":
                shell_type = "android"
            elif session_type == "email":
                shell_type = "email"
            else:
                shell_type = "classic"
            
            # Create shell if it doesn't exist
            shell = self.framework.shell_manager.get_shell(session_id)
            if not shell:
                shell = self.framework.shell_manager.create_shell(
                    session_id=session_id,
                    shell_type=shell_type,
                    session_type=session_type,
                    framework=self.framework
                )
            
            if not shell:
                print_error(f"Failed to create shell for session {session_id}")
                return False
            
            # Set as active shell
            self.framework.shell_manager.set_active_shell(session_id)
            
            # Start interactive session
            print_info("Starting interactive session...")
            print_info("Type 'exit', 'back' or 'background' to return to main shell (session remains active), 'help' for shell commands")
            print_info("-" * 50)
            
            while True:
                try:
                    # Get shell prompt
                    prompt = shell.get_prompt()
                    command = input(prompt)
                    
                    if not command.strip():
                        continue
                    
                    # Handle special commands
                    if command.lower() in ['exit', 'back', 'background']:
                        print_info("Returning to main shell (session remains active)...")
                        break
                    elif command.lower() == 'help':
                        # Use shell's built-in help command if available
                        result = shell.execute_command('help')
                        if result.get('output'):
                            print_info(result['output'])
                        elif result.get('error'):
                            print_error(result['error'])
                        else:
                            # Fallback to simple help
                            self._show_shell_help(shell)
                        continue
                    
                    # Execute command in shell
                    result = shell.execute_command(command)
                    
                    # Check if result indicates interactive shell should start
                    if result and isinstance(result, dict) and result.get('interactive_shell'):
                        if hasattr(shell, 'start_interactive_shell_loop'):
                            # Don't display the output message, just start the loop directly
                            shell.start_interactive_shell_loop()
                            continue
                    
                    # Display output (only if not starting interactive shell)
                    if result and result.get('output'):
                        output = result['output']
                        # Ensure output ends with newline if it doesn't already
                        if output and not output.endswith('\n'):
                            output += '\n'
                        print_info(output)
                    
                    if result and result.get('error'):
                        print_error(result['error'])
                    
                    # Check if shell is still active
                    if not shell.is_active:
                        print_error("Shell has been deactivated")
                        break
                        
                except KeyboardInterrupt:
                    print_info("\nUse 'exit', 'back' or 'background' to return to main shell (session remains active)")
                    continue
                except EOFError:
                    print_info("\nReturning to main shell (session remains active)...")
                    break
            
            return True
            
        except Exception as e:
            print_error(f"Error starting interactive session: {str(e)}")
            return False
    
    def _show_shell_help(self, shell):
        """Show help for shell commands"""
        try:
            if hasattr(shell, 'get_available_commands'):
                commands = shell.get_available_commands()
                print_info("Available shell commands:")
                for cmd in commands:
                    print_info(f"  {cmd}")
            else:
                print_info("No help available for this shell type")
        except Exception as e:
            print_error(f"Error showing shell help: {str(e)}")
    
