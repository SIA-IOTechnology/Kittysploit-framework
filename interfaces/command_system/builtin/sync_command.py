from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import argparse
import threading

class SyncCommand(BaseCommand):
    """Command to synchronize modules between filesystem and database"""
    
    @property
    def name(self) -> str:
        return "sync"
    
    @property
    def description(self) -> str:
        return "Synchronize modules between filesystem and database"
    
    @property
    def usage(self) -> str:
        return "sync <action> [options]"
    
    def _create_parser(self):
        """Create argument parser for sync command"""
        parser = argparse.ArgumentParser(
            prog='sync',
            description='Synchronize modules between filesystem and database'
        )
        
        subparsers = parser.add_subparsers(dest='action', help='Available actions')
        
        # Start subcommand
        start_parser = subparsers.add_parser('start', help='Start background synchronization')
        start_parser.add_argument('--interval', type=int, default=300, 
                                help='Sync interval in seconds (default: 300)')
        
        # Stop subcommand
        stop_parser = subparsers.add_parser('stop', help='Stop background synchronization')
        
        # Now subcommand
        now_parser = subparsers.add_parser('now', help='Perform immediate synchronization')
        now_parser.add_argument('--force', action='store_true', 
                              help='Force synchronization even if already running')
        now_parser.add_argument('--background', '-b', action='store_true',
                              help='Run synchronization in background (returns control immediately)')
        
        # Status subcommand
        status_parser = subparsers.add_parser('status', help='Show synchronization status')
        
        # Stats subcommand
        stats_parser = subparsers.add_parser('stats', help='Show module statistics')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the sync command"""
        if not args:
            args = ['status']  # Default action
        
        try:
            parsed_args = self._create_parser().parse_args(args)
            
            if parsed_args.action == 'start':
                self._handle_start(parsed_args)
            elif parsed_args.action == 'stop':
                self._handle_stop()
            elif parsed_args.action == 'now':
                self._handle_now(parsed_args)
            elif parsed_args.action == 'status':
                self._handle_status()
            elif parsed_args.action == 'stats':
                self._handle_stats()
            else:
                print_error("Unknown action. Use 'sync --help' for usage information.")
                return False
                
        except SystemExit:
            return False
        except Exception as e:
            print_error(f"Error executing sync command: {e}")
            return False
        
        return True
    
    def _handle_start(self, args):
        """Handle start subcommand"""
        try:
            self.framework.start_module_sync(args.interval)
            print_success(f"Background module synchronization started (interval: {args.interval}s)")
        except Exception as e:
            print_error(f"Failed to start synchronization: {e}")
    
    def _handle_stop(self):
        """Handle stop subcommand"""
        try:
            self.framework.stop_module_sync()
            print_success("Background module synchronization stopped")
        except Exception as e:
            print_error(f"Failed to stop synchronization: {e}")
    
    def _handle_now(self, args):
        """Handle now subcommand"""
        try:
            if args.background:
                # Run in background thread
                def sync_background():
                    try:
                        # Use module_sync_manager directly to pass force parameter
                        if hasattr(self.framework, 'module_sync_manager') and self.framework.module_sync_manager:
                            stats = self.framework.module_sync_manager.sync_modules(force=args.force)
                            print_success("Module synchronization completed")
                            print_info(f"Added: {stats.get('added', 0)}")
                            print_info(f"Updated: {stats.get('updated', 0)}")
                            print_info(f"Removed: {stats.get('removed', 0)}")
                        else:
                            print_error("Module sync manager not available")
                    except Exception as e:
                        print_error(f"Failed to synchronize modules: {e}")
                
                # Check if already syncing
                if hasattr(self.framework, 'module_sync_manager') and self.framework.module_sync_manager:
                    if self.framework.module_sync_manager.is_syncing and not args.force:
                        print_warning("Synchronization already in progress. Use --force to override.")
                        return
                
                thread = threading.Thread(target=sync_background, daemon=True)
                thread.start()
                print_info("Module synchronization started in background...")
                print_info("Use 'sync status' to check progress")
            else:
                # Run synchronously (original behavior)
                print_info("Starting immediate module synchronization...")
                stats = self.framework.sync_modules_now()
                
                print_success("Module synchronization completed")
                print_info(f"Added: {stats.get('added', 0)}")
                print_info(f"Updated: {stats.get('updated', 0)}")
                print_info(f"Removed: {stats.get('removed', 0)}")
            
        except Exception as e:
            print_error(f"Failed to synchronize modules: {e}")
    
    def _handle_status(self):
        """Handle status subcommand"""
        try:
            status = self.framework.get_module_sync_status()
            
            print_info("Module Synchronization Status:")
            print_info(f"  Background Sync Active: {status.get('background_sync_active', False)}")
            print_info(f"  Currently Syncing: {status.get('is_syncing', False)}")
            print_info(f"  Sync Interval: {status.get('sync_interval', 0)} seconds")
            
            last_sync = status.get('last_sync')
            if last_sync:
                from datetime import datetime
                try:
                    # Try to parse and format the datetime nicely
                    if isinstance(last_sync, str):
                        dt = datetime.fromisoformat(last_sync.replace('Z', '+00:00'))
                    else:
                        dt = last_sync
                    # Format as relative time if recent, otherwise absolute
                    now = datetime.utcnow()
                    if isinstance(dt, datetime):
                        diff = (now - dt.replace(tzinfo=None)).total_seconds()
                        if diff < 60:
                            print_info(f"  Last Sync: {int(diff)} seconds ago")
                        elif diff < 3600:
                            print_info(f"  Last Sync: {int(diff/60)} minutes ago")
                        else:
                            print_info(f"  Last Sync: {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                    else:
                        print_info(f"  Last Sync: {last_sync}")
                except Exception:
                    print_info(f"  Last Sync: {last_sync}")
            else:
                print_info("  Last Sync: Never")
            
            # Show helpful message if currently syncing
            if status.get('is_syncing', False):
                print_info("")
                print_warning("Synchronization is currently in progress. Please wait...")
                
        except Exception as e:
            print_error(f"Failed to get sync status: {e}")
    
    def _handle_stats(self):
        """Handle stats subcommand"""
        try:
            stats = self.framework.get_module_stats_db()
            
            print_info("Module Statistics:")
            print_info(f"  Total Modules: {stats.get('total', 0)}")
            print_info(f"  Exploits: {stats.get('exploits', 0)}")
            print_info(f"  Auxiliary: {stats.get('auxiliary', 0)}")
            print_info(f"  Payloads: {stats.get('payloads', 0)}")
            print_info(f"  Listeners: {stats.get('listeners', 0)}")
            print_info(f"  Post: {stats.get('post', 0)}")
            print_info(f"  Scanner: {stats.get('scanner', 0)}")
            print_info(f"  Encoder: {stats.get('encoder', 0)}")
            
        except Exception as e:
            print_error(f"Failed to get module stats: {e}")
