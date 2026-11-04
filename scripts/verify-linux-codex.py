import json,pathlib,urllib.request,time,shlex
root=pathlib.Path.home(); env={}
for line in (root/'.config/rli-remote/gateway.env').read_text().splitlines():
 if '=' in line and not line.startswith('#'):
  k,v=line.split('=',1); env[k]=shlex.split(v)[0]
headers={'Authorization':'Bearer '+pathlib.Path(env['RLI_MCP_TOKEN_FILE']).read_text().strip(),'Content-Type':'application/json'}
def rpc(name,args):
 q={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}}
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8743/mcp',data=json.dumps(q).encode(),headers=headers),timeout=20) as r: x=json.load(r)
 if x.get('error'): raise RuntimeError(x['error'])
 return x['result']
j=rpc('codex.job.submit',{'prompt':'Reply exactly AI_RELAY_LINUX_CODEX_OK. Do not use tools.','workdir':str(root/'rli-remote')})
for i in range(180):
 r=rpc('codex.job.status',{'job_id':j['id']})
 if r['status'] in ('completed','failed','canceled'): break
 time.sleep(1)
assert r['status']=='completed',(r['status'],r.get('error'))
log=rpc('codex.job.log',{'job_id':j['id'],'tail_bytes':32000})
assert 'AI_RELAY_LINUX_CODEX_OK' in str(log)
print('deployed Linux real Codex job: PASS; job='+j['id'])
