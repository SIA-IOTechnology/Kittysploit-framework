#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
History Manager for secure command history storage in database
"""

import json
import os
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from core.models.models import CommandHistory
from core.output_handler import print_info, print_success, print_error, print_warning

class HistoryManager:
    """Manages encrypted command history in database"""
    
    def __init__(self, db_manager, workspace_id: Optional[int] = None, framework=None):
        self.db_manager = db_manager
        self.workspace_id = workspace_id
        self.user_id = None  # Will be set when user authenticates
        self.framework = framework  # Reference to framework for get_db_session
    
    def set_user_id(self, user_id: str):
        """Set the current user ID for history tracking"""
        self.user_id = user_id
    
    def add_command(self, command: str, args: List[str] = None, success: bool = True, session_id: str = None) -> bool:
        """Add a command to the encrypted history"""
        try:
            if self.framework:
                session = self.framework.get_db_session()
            else:
                session = self.db_manager.get_session("default")
            
            # Prepare arguments as JSON string
            args_json = json.dumps(args) if args else None
            
            # Create new history entry
            history_entry = CommandHistory(
                command=command,
                success=success,
                args=args_json,
                user_id=self.user_id,
                session_id=session_id,
                workspace_id=self.workspace_id
            )
            
            session.add(history_entry)
            session.commit()
            
            # Limit history to 100 entries to avoid database overload
            self._limit_history(max_entries=100)
            
            return True
                
        except Exception as e:
            print_error(f"Error adding command to history: {e}")
            return False
    
    def get_history(self, limit: int = 100, offset: int = 0, user_id: str = None, 
                   success_only: bool = False, search_term: str = None) -> List[Dict[str, Any]]:
        """Get command history with optional filtering"""
        try:
            if self.framework:
                session = self.framework.get_db_session()
            else:
                session = self.db_manager.get_session("default")
            
            query = session.query(CommandHistory)
            
            # Filter by workspace
            if self.workspace_id:
                query = query.filter(CommandHistory.workspace_id == self.workspace_id)
            
            # Filter by user
            if user_id:
                query = query.filter(CommandHistory.user_id == user_id)
            elif self.user_id:
                query = query.filter(CommandHistory.user_id == self.user_id)
            
            # Filter by success status
            if success_only:
                query = query.filter(CommandHistory.success == True)
            
            # Search in command text
            if search_term:
                query = query.filter(CommandHistory.command.contains(search_term))
            
            # Order by timestamp (newest first)
            query = query.order_by(CommandHistory.timestamp.desc())
            
            # Apply pagination
            query = query.offset(offset).limit(limit)
            
            # Convert to dictionaries
            history = []
            for entry in query.all():
                # Safely parse args JSON
                args_list = []
                if entry.args:
                    try:
                        # Check if args is already a list or dict (already deserialized)
                        if isinstance(entry.args, (list, dict)):
                            args_list = entry.args
                        elif isinstance(entry.args, str):
                            # Try to parse as JSON string
                            args_list = json.loads(entry.args)
                        else:
                            # If it's another type, convert to list
                            args_list = [entry.args] if entry.args else []
                    except (json.JSONDecodeError, ValueError, TypeError):
                        # If JSON is invalid or type error, use empty list
                        args_list = []
                
                history.append({
                    'id': entry.id,
                    'timestamp': entry.timestamp.isoformat(),
                    'command': entry.command,
                    'success': entry.success,
                    'args': args_list,
                    'user_id': entry.user_id,
                    'session_id': entry.session_id
                })
            
            return history
                
        except Exception as e:
            print_error(f"Error retrieving history: {e}")
            return []
    
    def _limit_history(self, max_entries: int = 100) -> int:
        """Limit the history to a maximum number of entries, keeping the most recent ones"""
        try:
            if self.framework:
                session = self.framework.get_db_session()
            else:
                session = self.db_manager.get_session("default")
            
            # Build base query with same filters as add_command
            base_query = session.query(CommandHistory)
            
            # Filter by workspace
            if self.workspace_id:
                base_query = base_query.filter(CommandHistory.workspace_id == self.workspace_id)
            
            # Filter by user
            if self.user_id:
                base_query = base_query.filter(CommandHistory.user_id == self.user_id)
            
            # Count total entries
            total_count = base_query.count()
            
            # If we exceed the limit, delete the oldest entries
            if total_count > max_entries:
                # Get IDs of entries to keep (most recent ones)
                entries_to_keep = base_query.order_by(
                    CommandHistory.timestamp.desc()
                ).limit(max_entries).with_entities(CommandHistory.id).all()
                
                keep_ids = [entry[0] for entry in entries_to_keep]
                
                # Rebuild query for deletion (with same filters)
                delete_query = session.query(CommandHistory)
                if self.workspace_id:
                    delete_query = delete_query.filter(CommandHistory.workspace_id == self.workspace_id)
                if self.user_id:
                    delete_query = delete_query.filter(CommandHistory.user_id == self.user_id)
                
                # Delete entries that are not in the keep list
                deleted_count = delete_query.filter(
                    ~CommandHistory.id.in_(keep_ids)
                ).delete(synchronize_session=False)
                
                session.commit()
                return deleted_count
            
            return 0
                
        except Exception as e:
            print_error(f"Error limiting history: {e}")
            return 0
    
    def clear_history(self, user_id: str = None, older_than_days: int = None) -> int:
        """Clear command history with optional filtering"""
        try:
            if self.framework:
                session = self.framework.get_db_session()
            else:
                session = self.db_manager.get_session("default")
            
            query = session.query(CommandHistory)
            
            # Filter by workspace
            if self.workspace_id:
                query = query.filter(CommandHistory.workspace_id == self.workspace_id)
            
            # Filter by user
            if user_id:
                query = query.filter(CommandHistory.user_id == user_id)
            elif self.user_id:
                query = query.filter(CommandHistory.user_id == self.user_id)
            
            # Filter by age
            if older_than_days:
                cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)
                query = query.filter(CommandHistory.timestamp < cutoff_date)
            
            # Count before deletion
            count = query.count()
            
            # Delete matching records
            query.delete(synchronize_session=False)
            session.commit()
            
            return count
                
        except Exception as e:
            print_error(f"Error clearing history: {e}")
            return 0
    
    def export_history(self, output_file: str, user_id: str = None, format: str = 'json') -> bool:
        """Export command history to file"""
        try:
            history = self.get_history(user_id=user_id)
            
            if format.lower() == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(history, f, indent=2, ensure_ascii=False)
            elif format.lower() == 'csv':
                import csv
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    if history:
                        writer = csv.DictWriter(f, fieldnames=history[0].keys())
                        writer.writeheader()
                        writer.writerows(history)
            else:
                print_error(f"Unsupported export format: {format}")
                return False
            
            print_success(f"History exported to {output_file}")
            return True
            
        except Exception as e:
            print_error(f"Error exporting history: {e}")
            return False
    
    def get_stats(self, user_id: str = None) -> Dict[str, Any]:
        """Get history statistics"""
        try:
            if self.framework:
                session = self.framework.get_db_session()
            else:
                session = self.db_manager.get_session("default")
            
            query = session.query(CommandHistory)
            
            # Filter by workspace
            if self.workspace_id:
                query = query.filter(CommandHistory.workspace_id == self.workspace_id)
            
            # Filter by user
            if user_id:
                query = query.filter(CommandHistory.user_id == user_id)
            elif self.user_id:
                query = query.filter(CommandHistory.user_id == self.user_id)
            
            total_commands = query.count()
            successful_commands = query.filter(CommandHistory.success == True).count()
            failed_commands = total_commands - successful_commands
            
            # Get most recent command
            most_recent = query.order_by(CommandHistory.timestamp.desc()).first()
            last_command_time = most_recent.timestamp.isoformat() if most_recent else None
            
            # Get most used commands
            from sqlalchemy import func
            command_counts = session.query(
                CommandHistory.command,
                func.count(CommandHistory.command).label('count')
            ).filter(
                CommandHistory.workspace_id == self.workspace_id if self.workspace_id else True
            ).group_by(CommandHistory.command).order_by(
                func.count(CommandHistory.command).desc()
            ).limit(10).all()
            
            most_used = [{'command': cmd, 'count': count} for cmd, count in command_counts]
            
            return {
                'total_commands': total_commands,
                'successful_commands': successful_commands,
                'failed_commands': failed_commands,
                'success_rate': (successful_commands / total_commands * 100) if total_commands > 0 else 0,
                'last_command_time': last_command_time,
                'most_used_commands': most_used
            }
                
        except Exception as e:
            print_error(f"Error getting history stats: {e}")
            return {}
