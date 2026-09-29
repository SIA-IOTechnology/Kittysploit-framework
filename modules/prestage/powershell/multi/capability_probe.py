#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Dict

from kittysploit import *


class Module(Prestage):
    PRESTAGE_ID = "capability_probe"

    __info__ = {
        "name": "Capability Probe (PowerShell)",
        "description": (
            "Detect OS, architecture, runtime, privileges, writable directory, "
            "and network capabilities before callback"
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "platform": Platform.MULTI,
        "languages": ["powershell"],
        "dependencies": [],
        "tags": ["recon", "prestage", "offline", "powershell"],
    }

    def generate_powershell(self, context: Dict[str, Any] = None) -> str:
        return """
$ErrorActionPreference='SilentlyContinue'
function _KittyProbeWritableDir {
  $candidates=@()
  if($env:TEMP){ $candidates += $env:TEMP }
  if($env:TMP){ $candidates += $env:TMP }
  try { $candidates += [IO.Path]::GetTempPath() } catch {}
  try { $candidates += (Get-Location).Path } catch {}
  if(-not $_kittyIsWindows){ $candidates += @('/tmp','/var/tmp','/dev/shm') }
  $seen=@{}
  foreach($path in $candidates){
    if([string]::IsNullOrWhiteSpace($path) -or $seen.ContainsKey($path)){ continue }
    $seen[$path]=$true
    try {
      [IO.Directory]::CreateDirectory($path)|Out-Null
      $probe=[IO.Path]::Combine($path,'.kitty_probe')
      [IO.File]::WriteAllText($probe,'ok')
      Remove-Item $probe -Force -ErrorAction Stop
      return $path
    } catch {}
  }
  return ''
}
function _KittyProbePrivileges {
  $info=@{ elevated=$false; user=''; uid=$null; gid=$null }
  try {
    if(-not $_kittyIsWindows){
      $id=(id -u 2>$null)
      if($id){ $info.uid=[int]$id; if($info.uid -eq 0){ $info.elevated=$true } }
      $info.user=(whoami 2>$null)
    } else {
      $info.user=$env:USERNAME
      if(-not $info.user){ $info.user=(whoami 2>$null) }
      try {
        $wp=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $info.elevated=$wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
      } catch {}
    }
  } catch {}
  return $info
}
function _KittyProbeNetwork {
  $net=@{ socket=$false; dns=$false; tcp_outbound=$false; hostname=''; ips=@(); proxy=@{} }
  try { $net.hostname=[System.Net.Dns]::GetHostName() } catch {}
  try {
    $rows=[System.Net.Dns]::GetHostAddresses($net.hostname)
    $net.ips=@($rows | ForEach-Object { $_.IPAddressToString } | Sort-Object -Unique)
    $net.dns=$true
  } catch {
    try {
      $net.ips=@([System.Net.IPAddress]::Loopback.ToString())
    } catch {}
  }
  try {
    $client=New-Object System.Net.Sockets.TcpClient
    $iar=$client.BeginConnect('127.0.0.1',1,$null,$null)
    if($iar.AsyncWaitHandle.WaitOne(1000,$false)){
      try { $client.EndConnect($iar)|Out-Null } catch {}
    }
    $net.socket=$true
    $net.tcp_outbound=$true
    $client.Close()
  } catch {
    $net.socket=$true
    if($_.Exception.Message -match 'refused|unreachable|actively|timeout'){
      $net.tcp_outbound=$true
    }
  }
  foreach($key in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')){
    $val=[Environment]::GetEnvironmentVariable($key)
    if($val){ $net.proxy[$key.ToLower()]=$val }
  }
  return $net
}
$_kittyIsWindows=($env:OS -eq 'Windows_NT')
if($PSVersionTable.PSVersion.Major -ge 6){
  if($IsLinux){ $_kittyIsWindows=$false; $_kittyOsName='Linux' }
  elseif($IsMacOS){ $_kittyIsWindows=$false; $_kittyOsName='Darwin' }
  elseif($IsWindows){ $_kittyIsWindows=$true; $_kittyOsName='Windows' }
}
if(-not $_kittyOsName){
  if($_kittyIsWindows){ $_kittyOsName='Windows' } else { $_kittyOsName='Unix' }
}
$_kittyOsRelease=''
$_kittyOsVersion=''
if($_kittyIsWindows){
  $_kittyWinOs=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
  if($_kittyWinOs){
    $_kittyOsRelease=[string]$_kittyWinOs.Version
    $_kittyOsVersion=[string]$_kittyWinOs.Caption
  }
} else {
  try {
    if(Test-Path '/etc/os-release'){
      $_kittyOsRelease=((Get-Content '/etc/os-release' | Where-Object { $_ -match '^VERSION_ID=' }) -replace '^VERSION_ID=','' -replace '"','')
      $_kittyOsVersion=((Get-Content '/etc/os-release' | Where-Object { $_ -match '^PRETTY_NAME=' }) -replace '^PRETTY_NAME=','' -replace '"','')
    }
  } catch {}
  if(-not $_kittyOsRelease){ $_kittyOsRelease=(uname -r 2>$null) }
}
$global:_kitty_capability_probe=@{
  os=@{
    name=$_kittyOsName
    release=$_kittyOsRelease
    version=$_kittyOsVersion
  }
  arch=$env:PROCESSOR_ARCHITECTURE
  runtime=@{
    language='powershell'
    version=$PSVersionTable.PSVersion.ToString()
    edition=$PSVersionTable.PSEdition
    executable=$PSHOME
  }
  privileges=_KittyProbePrivileges
  writable_dir=_KittyProbeWritableDir
  network=_KittyProbeNetwork
}
""".strip()
