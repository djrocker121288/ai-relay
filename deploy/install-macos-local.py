#!/usr/bin/env python3
"""Install and enroll a persistent, authenticated loopback gateway and agent."""
import argparse, json, os, pathlib, platform, plistlib, secrets, shutil, subprocess, time, urllib.request
p=argparse.ArgumentParser(); p.add_argument('--bin-dir',type=pathlib.Path,required=True); a=p.parse_args()
base=pathlib.Path.home()/'.local/ai-relay'; base.mkdir(mode=0o700,parents=True,exist_ok=True); base.chmod(0o700)
suffix={'arm64':'arm64','x86_64':'amd64'}[platform.machine()]; uid=os.getuid(); domain=f'gui/{uid}'; launch=pathlib.Path.home()/'Library/LaunchAgents'
for name in ('gateway','agent'):
    label=f'com.ai-relay.{name}'
    subprocess.run(['launchctl','bootout',f'{domain}/{label}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    shutil.copy2(a.bin_dir/f'ai-relay-{name}-darwin-{suffix}',base/f'ai-relay-{name}'); (base/f'ai-relay-{name}').chmod(0o755)
for name in ('mcp','admin'):
    f=base/f'{name}.token'
    if not f.exists():
        fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as out: out.write(secrets.token_urlsafe(32))
    if f.is_symlink() or f.stat().st_mode & 0o077: raise RuntimeError('unsafe credential permissions')
env={'PATH':'/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','AI_RELAY_MCP_TOKEN_FILE':str(base/'mcp.token'),'AI_RELAY_MCP_ADMIN_TOKEN_FILE':str(base/'admin.token')}
# Do not silently select a potentially stale system Codex binary. The
# operator may point the service at the already-authorized current CLI; if it
# is omitted, the gateway's normal PATH lookup remains in effect.
codex_bin=os.environ.get('AI_RELAY_CODEX_BIN','').strip()
if codex_bin:
    env['AI_RELAY_CODEX_BIN']=codex_bin
def install(name,args):
    label=f'com.ai-relay.{name}'; f=launch/f'{label}.plist'
    for stream in ('stdout','stderr'):
        log=base/f'{name}.{stream}.log'; log.touch(exist_ok=True); log.chmod(0o600)
    cfg={'Label':label,'ProgramArguments':[str(base/f'ai-relay-{name}')]+args,'WorkingDirectory':str(base),'EnvironmentVariables':env,'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':10,'StandardOutPath':str(base/f'{name}.stdout.log'),'StandardErrorPath':str(base/f'{name}.stderr.log')}
    with f.open('wb') as out: plistlib.dump(cfg,out)
    f.chmod(0o600); subprocess.run(['plutil','-lint',str(f)],check=True)
    subprocess.run(['launchctl','bootstrap',domain,str(f)],check=True)
install('gateway',['-listen','127.0.0.1:8743','-state',str(base/'state')])
for i in range(30):
    try:
        urllib.request.urlopen('http://127.0.0.1:8743/healthz',timeout=2).close(); break
    except OSError: time.sleep(1)
else: raise RuntimeError('gateway health deadline exceeded')
cred=base/'agent.cred'
if not cred.exists():
    req=urllib.request.Request('http://127.0.0.1:8743/v1/enroll',method='PUT',headers={'Authorization':'Bearer '+(base/'admin.token').read_text()})
    with urllib.request.urlopen(req,timeout=5) as r: token=json.load(r)['token']
    f=base/'enroll.token'; fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as out: out.write(token)
    try: subprocess.run([str(base/'ai-relay-agent'),'-gateway','http://127.0.0.1:8743','-credential-file',str(cred),'-enroll-token-file',str(f),'-once'],check=True,timeout=45,stdout=subprocess.DEVNULL)
    finally: f.unlink(missing_ok=True)
install('agent',['-gateway','http://127.0.0.1:8743','-credential-file',str(cred)])
print('Persistent loopback gateway and enrolled agent installed. No secrets printed.')
