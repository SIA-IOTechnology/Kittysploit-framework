#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug Manager - Handles debug mode functionality for KittySploit framework
"""

import json
import time
import threading
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from core.output_handler import print_info, print_success, print_error, print_warning

# Try to import Flask, if not available, provide a fallback
try:
    from flask import Flask, render_template_string, jsonify, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print_warning("Flask not available. Web interface will not work. Install with: pip install flask")


class DebugAction:
    """Represents a debug action"""
    
    def __init__(self, action_type: str, description: str = "", data: Dict = None):
        self.id = str(uuid.uuid4())[:8]
        self.type = action_type
        self.description = description
        self.data = data or {}
        self.timestamp = datetime.utcnow()
        self.blocked = False
        self.executed = False
        self.result = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'type': self.type,
            'description': self.description,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'blocked': self.blocked,
            'executed': self.executed,
            'result': self.result
        }


class DebugManager:
    """Manages debug mode functionality"""
    
    def __init__(self):
        self.is_active = False
        self.debug_level = "info"
        self.output_destination = "console"
        self.output_file = None
        self.actions: List[DebugAction] = []
        self.blocked_actions: set = set()
        self.start_time = None
        self._lock = threading.Lock()
        self._web_server = None
        self._web_thread = None
        
    def start_debug_mode(self, level: str = "info", output: str = "console", output_file: str = None):
        """Start debug mode"""
        with self._lock:
            if self.is_active:
                print_warning("Debug mode is already active")
                return
            
            self.is_active = True
            self.debug_level = level
            self.output_destination = output
            self.output_file = output_file
            self.start_time = datetime.utcnow()
            
            print_success(f"Debug mode started (level: {level}, output: {output})")
    
    def stop_debug_mode(self):
        """Stop debug mode"""
        with self._lock:
            if not self.is_active:
                print_warning("Debug mode is not active")
                return
            
            self.is_active = False
            self._stop_web_server()
            print_success("Debug mode stopped")
    
    def get_status(self) -> Dict:
        """Get debug mode status"""
        with self._lock:
            return {
                'active': self.is_active,
                'level': self.debug_level,
                'output': self.output_destination,
                'actions_count': len(self.actions),
                'blocked_count': len(self.blocked_actions),
                'start_time': self.start_time.isoformat() if self.start_time else None
            }
    
    def add_action(self, action_type: str, description: str = "", data: Dict = None) -> str:
        """Add a debug action"""
        with self._lock:
            if not self.is_active:
                return None
            
            action = DebugAction(action_type, description, data)
            self.actions.append(action)
            
            # Log action
            self._log_action(f"Action added: {action.id} - {action_type}: {description}")
            
            return action.id
    
    def list_actions(self, filter_type: str = None, limit: int = 50) -> List[Dict]:
        """List debug actions"""
        with self._lock:
            actions = self.actions.copy()
            
            # Apply filter
            if filter_type:
                actions = [a for a in actions if a.type == filter_type]
            
            # Apply limit
            actions = actions[-limit:] if limit > 0 else actions
            
            return [action.to_dict() for action in actions]
    
    def execute_action(self, action_id: str) -> Any:
        """Execute a specific action"""
        with self._lock:
            action = self._find_action(action_id)
            if not action:
                print_error(f"Action {action_id} not found")
                return None
            
            if action.blocked:
                print_warning(f"Action {action_id} is blocked")
                return None
            
            # Simulate action execution
            action.executed = True
            action.result = f"Executed {action.type}: {action.description}"
            
            self._log_action(f"Action executed: {action_id}")
            return action.result
    
    def block_action(self, action_id: str) -> bool:
        """Block a specific action"""
        with self._lock:
            action = self._find_action(action_id)
            if not action:
                print_error(f"Action {action_id} not found")
                return False
            
            action.blocked = True
            self.blocked_actions.add(action_id)
            
            self._log_action(f"Action blocked: {action_id}")
            return True
    
    def unblock_action(self, action_id: str) -> bool:
        """Unblock a specific action"""
        with self._lock:
            action = self._find_action(action_id)
            if not action:
                print_error(f"Action {action_id} not found")
                return False
            
            action.blocked = False
            self.blocked_actions.discard(action_id)
            
            self._log_action(f"Action unblocked: {action_id}")
            return True
    
    def clear_actions(self) -> int:
        """Clear all debug actions"""
        with self._lock:
            count = len(self.actions)
            self.actions.clear()
            self.blocked_actions.clear()
            
            self._log_action(f"Cleared {count} actions")
            return count
    
    def export_actions(self, file_path: str) -> int:
        """Export actions to file"""
        with self._lock:
            try:
                data = {
                    'export_time': datetime.utcnow().isoformat(),
                    'actions': [action.to_dict() for action in self.actions]
                }
                
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2)
                
                count = len(self.actions)
                self._log_action(f"Exported {count} actions to {file_path}")
                return count
                
            except Exception as e:
                print_error(f"Failed to export actions: {e}")
                return 0
    
    def import_actions(self, file_path: str) -> int:
        """Import actions from file"""
        with self._lock:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                imported_actions = data.get('actions', [])
                count = 0
                
                for action_data in imported_actions:
                    action = DebugAction(
                        action_data['type'],
                        action_data['description'],
                        action_data.get('data', {})
                    )
                    action.id = action_data['id']
                    action.timestamp = datetime.fromisoformat(action_data['timestamp'])
                    action.blocked = action_data.get('blocked', False)
                    action.executed = action_data.get('executed', False)
                    action.result = action_data.get('result')
                    
                    self.actions.append(action)
                    count += 1
                
                self._log_action(f"Imported {count} actions from {file_path}")
                return count
                
            except Exception as e:
                print_error(f"Failed to import actions: {e}")
                return 0
    
    def launch_web_interface(self, host: str = "127.0.0.1", port: int = 8080) -> str:
        """Launch web debug interface"""
        if not FLASK_AVAILABLE:
            print_error("Flask is not available. Install with: pip install flask")
            return None
        
        try:
            if self._web_server is not None:
                print_warning("Web interface is already running")
                return f"http://{host}:{port}"
            
            self._web_server = Flask(__name__)
            self._setup_web_routes()
            
            # Start web server in a separate thread
            self._web_thread = threading.Thread(
                target=self._run_web_server,
                args=(host, port),
                daemon=True
            )
            self._web_thread.start()
            
            url = f"http://{host}:{port}"
            self._log_action(f"Web interface launched at {url}")
            return url
            
        except Exception as e:
            print_error(f"Failed to launch web interface: {e}")
            return None
    
    def _setup_web_routes(self):
        """Setup Flask routes for the web interface"""
        
        # HTML template for the debug interface
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>KittySploit — Debugger</title>
  <style>
    :root {
      --bg: #0b1020;
      --bg-elev: #111731;
      --panel: #151c3b;
      --panel-border: #263056;
      --text: #e7ecf5;
      --muted: #a9b1c7;
      --brand: #6ea8fe;
      --brand-2: #a78bfa;
      --ok: #3ac77a;
      --warn: #f4a261;
      --err: #ef5350;
      --chip: #22305f;
      --code: #0b132b;
      --shadow: 0 6px 20px rgba(0,0,0,.35);
      --radius-lg: 14px;
      --radius-md: 10px;
      --radius-sm: 8px;
      --topbar-h: 64px;
    }

    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      background: radial-gradient(1200px 600px at 20% -10%, rgba(110,168,254,.08), transparent 60%),
                  radial-gradient(900px 600px at 100% 10%, rgba(167,139,250,.08), transparent 60%),
                  var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
      line-height: 1.55;
    }

    /* Topbar */
    .topbar {
      position: sticky; top: 0; z-index: 50;
      display: flex; align-items: center; justify-content: space-between;
      padding: 16px 22px; margin: 0 0 22px 0;
      background: linear-gradient(180deg, rgba(21,28,59,.92), rgba(21,28,59,.75));
      backdrop-filter: blur(8px);
      border-bottom: 1px solid var(--panel-border);
      min-height: var(--topbar-h);
    }
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 700; }
    .brand-badge {
      width: 34px; height: 34px; border-radius: 10px;
      background: linear-gradient(135deg, var(--brand), var(--brand-2));
      display: grid; place-items: center; box-shadow: var(--shadow);
    }
    .brand-title { font-size: 18px; letter-spacing: .3px; }
    .status-chip { display: inline-flex; align-items: center; gap: 8px; padding: 6px 10px; border-radius: 999px; background: var(--chip); border: 1px solid var(--panel-border); font-size: 12px; color: var(--muted); }
    .dot { width: 8px; height: 8px; border-radius: 999px; }
    .dot.on { background: var(--ok); box-shadow: 0 0 10px rgba(58,199,122,.6); }
    .dot.off { background: var(--err); }

    /* Layout */
    .container { padding: 0 22px 28px; height: calc(100vh - var(--topbar-h) - 22px); }
    .grid { height: 100%; display: grid; grid-template-columns: 320px 1fr; gap: 22px; }
    @media (max-width: 1100px) { .grid { grid-template-columns: 1fr; } }

    /* Cards */
    .card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: var(--radius-lg); box-shadow: var(--shadow); }
    .card.full-height { height: 100%; display: flex; flex-direction: column; min-height: 0; }
    .card .hdr { padding: 14px 16px; border-bottom: 1px solid var(--panel-border); display: flex; align-items: center; justify-content: space-between; }
    .card .hdr h3 { margin: 0; font-size: 14px; letter-spacing: .6px; text-transform: uppercase; color: var(--muted); }
    .card .body { padding: 16px; }

    /* Stats */
    .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .stat { background: var(--bg-elev); border: 1px solid var(--panel-border); border-radius: var(--radius-md); padding: 14px; }
    .stat .n { font-size: 24px; font-weight: 800; }
    .stat .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }

    .n.ok { color: var(--ok); }
    .n.err { color: var(--err); }
    .n.blk { color: var(--warn); }

    /* Controls */
    .controls { display: flex; flex-direction: column; gap: 12px; }
    .field { display: flex; flex-direction: column; gap: 6px; }
    .label { font-size: 12px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); }
    .input, .select { background: var(--bg-elev); color: var(--text); border: 1px solid var(--panel-border); border-radius: var(--radius-sm); padding: 10px 12px; font-size: 14px; }
    .input:focus, .select:focus { outline: none; border-color: var(--brand); box-shadow: 0 0 0 3px rgba(110,168,254,.15); }

    .btnrow { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 6px; }
    .btn { display: inline-flex; align-items: center; gap: 8px; background: var(--bg-elev); color: var(--text); border: 1px solid var(--panel-border); border-radius: var(--radius-sm); padding: 10px 14px; font-weight: 700; font-size: 13px; cursor: pointer; transition: .2s ease; }
    .btn:hover { transform: translateY(-1px); box-shadow: var(--shadow); }
    .b-primary { background: linear-gradient(135deg, var(--brand), var(--brand-2)); border: none; }
    .b-danger { background: linear-gradient(135deg, #ef5350, #ff6d6a); border: none; }
    .b-warn { background: linear-gradient(135deg, #f4a261, #f7b267); border: none; }
    .b-ok { background: linear-gradient(135deg, #3ac77a, #30b06b); border: none; }

    /* Flow */
    .flow { overflow: auto; padding: 6px 10px 6px 6px; }
    .body.flow { flex: 1 1 auto; min-height: 0; }
    .flow::-webkit-scrollbar { width: 8px; }
    .flow::-webkit-scrollbar-thumb { background: #22305f; border-radius: 10px; }

    .entry { position: relative; border: 1px solid var(--panel-border); background: var(--bg-elev); border-radius: var(--radius-md); padding: 14px; margin: 12px 2px; }
    .entry::before { content: ''; position: absolute; left: -1px; top: 0; bottom: 0; width: 4px; border-radius: 6px 0 0 6px; background: var(--brand); }
    .entry.ok::before { background: var(--ok); }
    .entry.err::before { background: var(--err); }
    .entry.warn::before { background: var(--warn); }

    .row { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
    .id { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; background: var(--chip); border: 1px solid var(--panel-border); color: var(--brand-2); font-size: 12px; padding: 4px 8px; border-radius: 6px; }
    .type { background: var(--chip); border: 1px solid var(--panel-border); padding: 6px 10px; border-radius: 999px; font-size: 12px; text-transform: uppercase; letter-spacing: .4px; }
    .time { color: var(--muted); font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .desc { margin: 8px 0 10px; font-weight: 600; }
    .code { background: var(--code); border: 1px solid var(--panel-border); border-radius: var(--radius-sm); padding: 12px; font-size: 12.5px; color: var(--text); white-space: pre-wrap; overflow: auto; }
    .result { background: #0d1b2a; border: 1px solid #1f3b5e; border-radius: var(--radius-sm); padding: 12px; font-size: 12.5px; color: #8cffc6; white-space: pre-wrap; overflow: auto; margin-top: 8px; }
    .actions { display: flex; gap: 8px; margin-top: 10px; }

    .empty { text-align: center; color: var(--muted); padding: 40px 10px; }
    .spinner { width: 18px; height: 18px; border: 2px solid #2a365f; border-top-color: var(--brand); border-radius: 999px; animation: spin 1s linear infinite; display: inline-block; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <div class="brand-badge" aria-hidden="true">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4 12a8 8 0 1116 0 8 8 0 01-16 0z" fill="#fff" opacity=".15"/><path d="M7 13l4 4 6-8" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </div>
      <div class="brand-title">KittySploit Debugger</div>
    </div>
    <div id="top-status" class="status-chip"><span class="dot off"></span><span>Inactive</span></div>
  </header>

  <main class="container">
    <div class="grid">
      <section>
        <div class="card">
          <div class="hdr"><h3>Statistics</h3></div>
          <div class="body">
            <div class="stats">
              <div class="stat"><div class="n" id="total-actions">0</div><div class="l">Total</div></div>
              <div class="stat"><div class="n ok" id="success-actions">0</div><div class="l">Successful</div></div>
              <div class="stat"><div class="n err" id="error-actions">0</div><div class="l">Errors</div></div>
              <div class="stat"><div class="n blk" id="blocked-actions">0</div><div class="l">Blocked</div></div>
            </div>
          </div>
        </div>

        <div class="card" style="margin-top: 16px;">
          <div class="hdr"><h3>Controls</h3></div>
          <div class="body controls">
            <div class="field">
              <label class="label" for="filter-type">Filter by type</label>
              <select id="filter-type" class="select">
                <option value="">All</option>
                <option value="command_execute">Commands</option>
                <option value="module_load">Module Load</option>
                <option value="module_execute">Module Execute</option>
              </select>
            </div>
            <div class="field">
              <label class="label" for="limit">Show last</label>
              <input id="limit" class="input" type="number" value="20" min="1" max="100" />
            </div>
            <div class="btnrow">
              <button class="btn b-primary" onclick="refreshData()">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M21 12a9 9 0 10-3.3 6.9" stroke="#fff" stroke-width="2" stroke-linecap="round"/><path d="M21 3v7h-7" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>
                Refresh
              </button>
              <button class="btn b-danger" onclick="clearActions()">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3 6h18" stroke="#fff" stroke-width="2" stroke-linecap="round"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6m3-3h8a1 1 0 011 1v2H7V4a1 1 0 011-1z" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                Clear All
              </button>
            </div>
            <label style="display:flex;align-items:center;gap:10px;margin-top:6px;color:var(--muted);font-size:13px;">
              <input type="checkbox" id="auto-refresh" onchange="toggleAutoRefresh()" /> Auto-refresh (3s)
            </label>
          </div>
        </div>

        <div class="card" style="margin-top: 16px;">
          <div class="hdr"><h3>Status</h3></div>
          <div class="body" id="debug-status">
            <div class="empty"><span class="spinner"></span> Loading…</div>
          </div>
        </div>
      </section>

      <section>
        <div class="card full-height">
          <div class="hdr"><h3>Command Flow</h3></div>
          <div class="body flow" id="command-flow">
            <div class="empty"><span class="spinner"></span> Loading command flow…</div>
          </div>
        </div>
      </section>
    </div>
  </main>

  <script>
    let autoRefreshInterval = null;

    function refreshData() {
      fetch('/api/status')
        .then(r => r.json())
        .then(data => {
          const top = document.getElementById('top-status');
          if (data.active) { top.innerHTML = '<span class="dot on"></span><span>Active</span>'; } else { top.innerHTML = '<span class="dot off"></span><span>Inactive</span>'; }

          const statusHtml = `
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
              <div><span style="color:var(--muted);">Level</span><div style="font-weight:700;">${data.level}</div></div>
              <div><span style="color:var(--muted);">Output</span><div style="font-weight:700;">${data.output}</div></div>
              <div><span style="color:var(--muted);">Started</span><div style="font-weight:700;">${data.start_time ? new Date(data.start_time).toLocaleString() : 'N/A'}</div></div>
              <div><span style="color:var(--muted);">Actions</span><div style="font-weight:700;">${data.actions_count}</div></div>
            </div>`;
          document.getElementById('debug-status').innerHTML = statusHtml;
        });

      const filterType = document.getElementById('filter-type').value;
      const limit = document.getElementById('limit').value;
      fetch(`/api/actions?filter=${filterType}&limit=${limit}`)
        .then(r => r.json())
        .then(actions => {
          updateStatistics(actions);
          updateCommandFlow(actions);
        });
    }

    function updateStatistics(actions) {
      const total = actions.length;
      const success = actions.filter(a => a.executed && !a.blocked).length;
      const errors = actions.filter(a => /error|failed/i.test(a.type)).length;
      const blocked = actions.filter(a => a.blocked).length;

      document.getElementById('total-actions').textContent = total;
      document.getElementById('success-actions').textContent = success;
      document.getElementById('error-actions').textContent = errors;
      document.getElementById('blocked-actions').textContent = blocked;
    }

    function groupActionsByCommand(actions) {
      const map = new Map();
      for (const a of actions) {
        const key = (a.data && (a.data.command || a.data.module_path)) || a.type || 'unknown';
        if (!map.has(key)) map.set(key, []);
        map.get(key).push(a);
      }
      const groups = Array.from(map.entries()).map(([command, acts]) => ({ command, actions: acts }));
      groups.sort((g1, g2) => new Date(g2.actions[g2.actions.length-1].timestamp) - new Date(g1.actions[g1.actions.length-1].timestamp));
      return groups;
    }

    function updateCommandFlow(actions) {
      const flow = document.getElementById('command-flow');
      if (!actions.length) {
        flow.innerHTML = `<div class="empty">No commands yet — try running something in KittySploit.</div>`;
        return;
      }
      const groups = groupActionsByCommand(actions);
      flow.innerHTML = groups.map(renderCommandGroup).join('');
    }

    function renderCommandGroup(group) {
      const latest = group.actions[group.actions.length - 1];
      const hasError = group.actions.some(a => /error|failed/i.test(a.type));
      const isSuccess = group.actions.some(a => a.executed && !a.blocked);
      const klass = hasError ? 'err' : (isSuccess ? 'ok' : '');
      const ts = latest.timestamp ? new Date(latest.timestamp).toLocaleString() : '';

      return `
        <div class="entry ${klass}">
          <div class="row">
            <span class="id">${latest.id}</span>
            <span class="type">${group.command}</span>
            <span class="time">${ts}</span>
          </div>
          <div class="desc">${latest.description || ''}</div>
          ${renderActionData(latest)}
          ${renderActionResults(group.actions)}
          <div class="actions">
            <button class="btn b-ok" onclick="executeAction('${latest.id}')">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 12h14M12 5l7 7-7 7" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>
              Execute
            </button>
            ${latest.blocked
              ? `<button class="btn b-warn" onclick="unblockAction('${latest.id}')">Unblock</button>`
              : `<button class="btn b-danger" onclick="blockAction('${latest.id}')">Block</button>`}
          </div>
        </div>`;
    }

    function renderActionData(action) {
      if (!action.data || !Object.keys(action.data).length) return '';
      const pretty = JSON.stringify(action.data, null, 2);
      return `<div class="code"><strong style="color:var(--muted);">Input</strong>
${pretty}</div>`;
    }

    function renderActionResults(actions) {
      const results = actions.filter(a => a.result);
      if (!results.length) return '';
      const latest = results[results.length - 1];
      return `<div class="result"><strong style="color:#9af2c7;">Result</strong>
${latest.result}</div>`;
    }

    function executeAction(id) {
      fetch(`/api/actions/${id}/execute`, { method: 'POST' })
        .then(r => r.json())
        .then(d => { if (d.success) { notify('Action executed', 'ok'); refreshData(); } else { notify('Execution failed: '+d.error, 'err'); } });
    }
    function blockAction(id) {
      fetch(`/api/actions/${id}/block`, { method: 'POST' })
        .then(r => r.json())
        .then(d => { if (d.success) { notify('Action blocked', 'warn'); refreshData(); } else { notify('Block failed: '+d.error, 'err'); } });
    }
    function unblockAction(id) {
      fetch(`/api/actions/${id}/unblock`, { method: 'POST' })
        .then(r => r.json())
        .then(d => { if (d.success) { notify('Action unblocked', 'ok'); refreshData(); } else { notify('Unblock failed: '+d.error, 'err'); } });
    }
    function clearActions() {
      if (!confirm('Clear all actions?')) return;
      fetch('/api/actions/clear', { method: 'POST' })
        .then(r => r.json())
        .then(d => { if (d.success) { notify(`Cleared ${d.count} actions`, 'ok'); refreshData(); } else { notify('Clear failed: '+d.error, 'err'); } });
    }
    function toggleAutoRefresh() {
      const c = document.getElementById('auto-refresh');
      if (c.checked) { autoRefreshInterval = setInterval(refreshData, 3000); }
      else if (autoRefreshInterval) { clearInterval(autoRefreshInterval); autoRefreshInterval = null; }
    }
    function notify(msg, type) {
      const n = document.createElement('div');
      n.style.cssText = `position:fixed;top:18px;right:18px;padding:10px 14px;border-radius:10px;color:#fff;font-weight:700;z-index:1000;box-shadow:${getComputedStyle(document.documentElement).getPropertyValue('--shadow')}`;
      n.style.background = type==='ok' ? '#30b06b' : type==='warn' ? '#f4a261' : '#ef5350';
      n.textContent = msg; document.body.appendChild(n); setTimeout(()=>n.remove(), 2800);
    }

    refreshData();
  </script>
</body>
</html>

        """
        
        @self._web_server.route('/')
        def index():
            return render_template_string(html_template)
        
        @self._web_server.route('/api/status')
        def api_status():
            return jsonify(self.get_status())
        
        @self._web_server.route('/api/actions')
        def api_actions():
            filter_type = request.args.get('filter', '')
            limit = int(request.args.get('limit', 50))
            return jsonify(self.list_actions(filter_type or None, limit))
        
        @self._web_server.route('/api/actions/<action_id>/execute', methods=['POST'])
        def api_execute_action(action_id):
            try:
                result = self.execute_action(action_id)
                return jsonify({'success': True, 'result': result})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self._web_server.route('/api/actions/<action_id>/block', methods=['POST'])
        def api_block_action(action_id):
            try:
                success = self.block_action(action_id)
                return jsonify({'success': success})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self._web_server.route('/api/actions/<action_id>/unblock', methods=['POST'])
        def api_unblock_action(action_id):
            try:
                success = self.unblock_action(action_id)
                return jsonify({'success': success})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self._web_server.route('/api/actions/clear', methods=['POST'])
        def api_clear_actions():
            try:
                count = self.clear_actions()
                return jsonify({'success': True, 'count': count})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self._web_server.route('/api/actions/test', methods=['POST'])
        def api_create_test_actions():
            try:
                count = self.create_test_actions(5)
                return jsonify({'success': True, 'count': count})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
    
    def _run_web_server(self, host: str, port: int):
        """Run the Flask web server"""
        try:
            import logging
            # Disable Flask logging
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)
            
            # Run Flask server silently
            self._web_server.run(
                host=host, 
                port=port, 
                debug=False, 
                use_reloader=False,
                threaded=True
            )
        except Exception as e:
            print_error(f"Web server error: {e}")
    
    def _stop_web_server(self):
        """Stop the web server"""
        if self._web_server is not None:
            # Flask doesn't have a built-in way to stop the server
            # We'll just clear the reference
            self._web_server = None
            self._web_thread = None
    
    def _find_action(self, action_id: str) -> Optional[DebugAction]:
        """Find action by ID"""
        for action in self.actions:
            if action.id == action_id:
                return action
        return None
    
    def _is_action_blocked(self, action_id: str) -> bool:
        """Check if an action is blocked"""
        return action_id in self.blocked_actions
    
    def _log_action(self, message: str):
        """Log debug action"""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        
        if self.output_destination in ["console", "both"]:
            print_info(log_message)
        
        if self.output_destination in ["file", "both"] and self.output_file:
            try:
                with open(self.output_file, 'a') as f:
                    f.write(log_message + "\n")
            except Exception as e:
                print_error(f"Failed to write to debug log file: {e}")
