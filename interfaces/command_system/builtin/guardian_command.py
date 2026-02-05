#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import time
import threading
from typing import Dict, List, Any, Optional
import logging

from core.output_handler import print_success, print_error, print_warning, print_info, print_empty
from interfaces.command_system.base_command import BaseCommand
from core.guardian_manager import GuardianManager

logger = logging.getLogger(__name__)

class GuardianCommand(BaseCommand):
    """Guardian command for anomaly detection and behavioral analysis"""
    
    @property
    def name(self) -> str:
        return "guardian"
    
    @property
    def description(self) -> str:
        return "Guardian - Behavioral analysis and anomaly detection for offensive operations"
    
    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        # Use the framework's guardian_manager instead of creating a new one
        # This ensures blacklist and settings are shared across the application
        if hasattr(self.framework, 'guardian_manager') and self.framework.guardian_manager:
            self.guardian_manager = self.framework.guardian_manager
        else:
            # Fallback: create a new one and attach it to the framework
            self.guardian_manager = GuardianManager()
            if self.framework:
                self.framework.guardian_manager = self.guardian_manager
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command parser"""
        parser = argparse.ArgumentParser(
            description="Guardian - Behavioral analysis and anomaly detection for offensive operations",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  guardian enable                    # Enable Guardian monitoring
  guardian disable                   # Disable Guardian monitoring
  guardian status                    # Show Guardian status and recent alerts
  guardian learn                     # Train Guardian on past operations
  guardian blacklist add 192.168.1.50  # Add host to blacklist
  guardian blacklist remove 192.168.1.50  # Remove host from blacklist
  guardian blacklist show            # Show blacklisted hosts
  guardian alerts                    # Show recent alerts
  guardian config                    # Show Guardian configuration
  guardian test 192.168.1.50        # Test host for anomalies
            """
        )
        
        subparsers = parser.add_subparsers(dest='action', help='Available actions')
        
        # Enable subcommand
        enable_parser = subparsers.add_parser('enable', help='Enable Guardian monitoring')
        enable_parser.add_argument('--verbose', action='store_true', help='Enable verbose monitoring')
        enable_parser.add_argument('--auto-action', action='store_true', help='Enable automatic protective actions')
        
        # Disable subcommand
        disable_parser = subparsers.add_parser('disable', help='Disable Guardian monitoring')
        
        # Status subcommand
        status_parser = subparsers.add_parser('status', help='Show Guardian status and recent alerts')
        
        # Learn subcommand
        learn_parser = subparsers.add_parser('learn', help='Train Guardian on past operations')
        learn_parser.add_argument('--operations', type=int, default=100, help='Number of past operations to analyze')
        
        # Blacklist subcommands
        blacklist_parser = subparsers.add_parser('blacklist', help='Manage blacklisted hosts')
        blacklist_subparsers = blacklist_parser.add_subparsers(dest='blacklist_action', help='Blacklist actions')
        
        blacklist_add_parser = blacklist_subparsers.add_parser('add', help='Add host to blacklist')
        blacklist_add_parser.add_argument('host', help='Host to blacklist')
        blacklist_add_parser.add_argument('--reason', help='Reason for blacklisting')
        
        blacklist_remove_parser = blacklist_subparsers.add_parser('remove', help='Remove host from blacklist')
        blacklist_remove_parser.add_argument('host', help='Host to remove from blacklist')
        
        blacklist_show_parser = blacklist_subparsers.add_parser('show', help='Show blacklisted hosts')
        
        # Alerts subcommand
        alerts_parser = subparsers.add_parser('alerts', help='Show recent alerts')
        alerts_parser.add_argument('--count', type=int, default=10, help='Number of alerts to show')
        
        # Config subcommand
        config_parser = subparsers.add_parser('config', help='Show Guardian configuration')
        
        # Test subcommand
        test_parser = subparsers.add_parser('test', help='Test host for anomalies')
        test_parser.add_argument('host', help='Host to test')
        test_parser.add_argument('--deep', action='store_true', help='Perform deep analysis')

        # Acknowledge subcommand
        ack_parser = subparsers.add_parser('ack', help='Mark a host as safe (acknowledge false positive)')
        ack_parser.add_argument('host', help='Host to acknowledge as safe')
        ack_parser.add_argument('--note', help='Optional operator note to store with the acknowledgement')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute Guardian command"""
        if not args:
            args = ['--help']
        
        try:
            parsed_args = self.parser.parse_args(args)
            
            if parsed_args.action == 'enable':
                return self._enable_guardian(parsed_args)
            elif parsed_args.action == 'disable':
                return self._disable_guardian()
            elif parsed_args.action == 'status':
                return self._show_status()
            elif parsed_args.action == 'learn':
                return self._learn_mode(parsed_args)
            elif parsed_args.action == 'blacklist':
                return self._manage_blacklist(parsed_args)
            elif parsed_args.action == 'alerts':
                return self._show_alerts(parsed_args)
            elif parsed_args.action == 'config':
                return self._show_config()
            elif parsed_args.action == 'test':
                return self._test_host(parsed_args)
            elif parsed_args.action == 'ack':
                return self._acknowledge_host(parsed_args)
            else:
                self.parser.print_help()
                return True
                
        except SystemExit:
            return True
        except Exception as e:
            print_error(f"Error executing Guardian command: {e}")
            return False
    
    def _enable_guardian(self, args):
        """Enable Guardian monitoring"""
        try:
            self.guardian_manager.enable(
                verbose=args.verbose,
                auto_action=args.auto_action
            )
            
            print_success("Guardian monitoring enabled")
            print_info("Monitoring your operations for anomalies...")
            
            if args.verbose:
                print_info("Verbose monitoring enabled")
            
            if args.auto_action:
                print_info("Automatic protective actions enabled")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to enable Guardian: {e}")
            return False
    
    def _disable_guardian(self):
        """Disable Guardian monitoring"""
        try:
            self.guardian_manager.disable()
            print_success("Guardian monitoring disabled")
            return True
            
        except Exception as e:
            print_error(f"Failed to disable Guardian: {e}")
            return False
    
    def _show_status(self):
        """Show Guardian status and recent alerts"""
        try:
            status = self.guardian_manager.get_status()

            print_empty()
            print_info("Guardian Protection Status")
            print_info("-------------------------")
            monitoring_state = "enabled" if status['enabled'] else "disabled"
            print_info(f"  Monitoring: {monitoring_state}")
            print_info(f"  Threats detected (24h): {status['threats_detected']}")
            print_info(f"  Alerts generated: {status['alerts_generated']}")
            print_info(f"  Auto-actions executed: {status['auto_actions']}")

            accuracy = getattr(self.guardian_manager, 'learned_patterns', {}).get('accuracy')
            if accuracy is not None:
                print_info(f"  Model accuracy: {accuracy}%")

            recent_threats = status.get('recent_threats', [])
            print_empty()
            if recent_threats:
                print_info("Recent threats:")
                for threat in recent_threats:
                    print_info(f"  [{threat['severity']}] {threat['description']} ({threat['time']})")
                    print_info(f"    {threat['details']}")
                    if threat.get('action'):
                        print_info(f"    Action: {threat['action']}")
                    print_empty()
            else:
                print_info("No threats recorded in the last 24 hours.")
                print_empty()

            return True
        except Exception as e:
            print_error(f"Failed to get Guardian status: {e}")
            return False

    def _learn_mode(self, args):
        """Train Guardian on past operations"""
        try:
            print_info("Guardian Learning Mode")
            print_info(f"Analyzing {args.operations} past operations...")
            print_info("Building threat detection model...")

            for i in range(3):
                time.sleep(0.5)
                print_info(f"Processing batch {i + 1}/3...")

            results = self.guardian_manager.learn(args.operations)

            print_empty()
            print_success("Updated detection baseline:")
            print_info(f"  Response time window: {results['normal_response_time']}")
            print_info(f"  Honeypot signatures tracked: {results['honeypot_signatures']}")
            print_info(f"  Deception patterns observed: {results['deception_patterns']}")
            print_info(f"  Unique threat issues logged: {results['blue_team_ttps']}")
            print_info(f"  Operations evaluated: {results['operations_used']}")
            print_empty()
            print_success(f"Guardian accuracy: {results['old_accuracy']}% -> {results['new_accuracy']}%")

            return True
        except Exception as e:
            print_error(f"Failed to train Guardian: {e}")
            return False

    def _acknowledge_host(self, args):
        """Mark a host as safe / false positive"""
        try:
            note = args.note or ""
            acknowledged = self.guardian_manager.acknowledge_host(args.host, note)
            if acknowledged:
                print_success(f"Host {args.host} acknowledged as safe")
                if note:
                    print_info(f"Note recorded: {note}")
                return True
            print_warning(f"No Guardian telemetry found for host {args.host}")
            return False
        except Exception as e:
            print_error(f"Failed to acknowledge host: {e}")
            return False
    
    def _manage_blacklist(self, args):
        """Manage blacklisted hosts"""
        try:
            if args.blacklist_action == 'add':
                self.guardian_manager.add_to_blacklist(args.host, args.reason)
                print_success(f"Host {args.host} added to blacklist")
                if args.reason:
                    print_info(f"Reason: {args.reason}")
                    
            elif args.blacklist_action == 'remove':
                self.guardian_manager.remove_from_blacklist(args.host)
                print_success(f"Host {args.host} removed from blacklist")
                
            elif args.blacklist_action == 'show':
                blacklist = self.guardian_manager.get_blacklist()
                if blacklist:
                    print_info("Blacklisted hosts:")
                    for host, info in blacklist.items():
                        print_info(f"  • {host} - {info.get('reason', 'No reason provided')}")
                else:
                    print_info("No hosts in blacklist")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to manage blacklist: {e}")
            return False
    
    def _show_alerts(self, args):
        """Show recent alerts"""
        try:
            alerts = self.guardian_manager.get_recent_alerts(args.count)
            if not alerts:
                print_info("No recent alerts")
                return True

            print_info(f"Recent alerts (last {args.count}):")
            print_empty()

            for alert in alerts:
                print_info(f"[{alert['severity']}] {alert['timestamp']}")
                print_info(f"   Target: {alert['target']}")
                print_info(f"   Issue: {alert['issue']}")
                print_info(f"   Confidence: {alert.get('confidence', 0):.1f}%")

                evidence = alert.get('evidence') or []
                if evidence:
                    print_info("   Evidence:")
                    for item in evidence:
                        print_info(f"     - {item}")

                recommendations = alert.get('recommendations') or []
                if recommendations:
                    print_info("   Recommendations:")
                    for rec in recommendations:
                        print_info(f"     - {rec}")

                if alert.get('auto_action_taken'):
                    action_desc = alert.get('action_description', 'automatic action executed')
                    print_info(f"   Auto-action: {action_desc}")

                print_empty()

            return True
        except Exception as e:
            print_error(f"Failed to get alerts: {e}")
            return False
    
    def _show_config(self):
        """Show Guardian configuration"""
        try:
            config = self.guardian_manager.get_config()
            
            print_info("Guardian Configuration:")
            print_empty()
            print_info(f"  Monitoring enabled: {config['enabled']}")
            print_info(f"  Verbose mode: {config['verbose']}")
            print_info(f"  Auto-actions: {config['auto_action']}")
            print_info(f"  Response time threshold: {config['response_time_threshold']}ms")
            print_info(f"  Honeypot confidence threshold: {config['honeypot_threshold']}%")
            print_info(f"  Learning mode: {config['learning_mode']}")
            print_info(f"  Blacklist size: {config['blacklist_size']}")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to get configuration: {e}")
            return False
    
    def _test_host(self, args):
        """Test host for anomalies"""
        try:
            print_info(f"Testing host {args.host} for anomalies...")
            
            if args.deep:
                print_info("Performing deep analysis...")
                time.sleep(2)
            
            # Simulate host testing
            result = self.guardian_manager.test_host(args.host, deep=args.deep)
            
            print_empty()
            print_info("=== GUARDIAN INVESTIGATION REPORT ===")
            print_empty()
            
            print_info("Behavioral Analysis:")
            for analysis in result['behavioral_analysis']:
                print_info(f"- {analysis}")
            
            print_empty()
            print_info("Network Context:")
            for context in result['network_context']:
                print_info(f"- {context}")
            
            print_empty()
            print_info(f"VERDICT: {result['confidence']}% confidence this is a {result['verdict']}")
            print_info(f"RECOMMENDATION: {result['recommendation']}")
            
            if result['auto_blacklist']:
                print_success(f"Host {args.host} added to blacklist automatically")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to test host: {e}")
            return False
    
    def get_subcommands(self) -> List[str]:
        """Get available subcommands for auto-completion"""
        return [
            'enable', 'disable', 'status', 'learn', 'blacklist', 
            'alerts', 'config', 'test', 'ack'
        ]
