#!/bin/sh
set -eu
# Agent-only installation: an existing gateway and enrolled credential are required.
prefix=${AI_RELAY_PREFIX:-"$HOME/.local/ai-relay"}
gateway=${AI_RELAY_GATEWAY:-http://127.0.0.1:8743}
credential=${AI_RELAY_CREDENTIAL_FILE:-"$prefix/agent.cred"}
test -f "$credential" || { echo "An enrolled AI_RELAY_CREDENTIAL_FILE is required. For a complete local gateway use install-macos-local.py." >&2; exit 1; }
case "$(uname -m)" in arm64) suffix=arm64;; x86_64) suffix=amd64;; *) echo 'unsupported architecture' >&2; exit 2;; esac
source_agent=${AI_RELAY_AGENT_BINARY:-"ai-relay-agent-darwin-$suffix"}
test -f "$source_agent" || source_agent=ai-relay-agent
test -f "$source_agent" || { echo 'agent binary missing' >&2; exit 1; }
export AI_RELAY_INSTALL_PREFIX="$prefix" AI_RELAY_INSTALL_GATEWAY="$gateway" AI_RELAY_INSTALL_CREDENTIAL="$credential" AI_RELAY_INSTALL_BINARY="$source_agent"
python3 - <<'PYTHON'
import os,pathlib,plistlib,shutil,subprocess
from urllib.parse import urlparse
b=pathlib.Path(os.environ['AI_RELAY_INSTALL_PREFIX']).expanduser().resolve(); b.mkdir(parents=True,exist_ok=True); b.chmod(0o700)
c=pathlib.Path(os.environ['AI_RELAY_INSTALL_CREDENTIAL']).expanduser().resolve()
if not c.is_file() or c.stat().st_mode & 0o077: raise RuntimeError('credential must be a protected regular file')
gateway=urlparse(os.environ['AI_RELAY_INSTALL_GATEWAY'])
if gateway.scheme not in ('http','https') or not gateway.netloc: raise RuntimeError('gateway must be an absolute HTTP(S) URL')
if gateway.scheme == 'http' and gateway.hostname not in ('localhost','127.0.0.1','::1'): raise RuntimeError('remote gateways require HTTPS')
source=pathlib.Path(os.environ['AI_RELAY_INSTALL_BINARY']).resolve(); target=b/'ai-relay-agent'
if source!=target: shutil.copy2(source,target)
target.chmod(0o755)
label='com.ai-relay.agent'; dest=pathlib.Path.home()/'Library/LaunchAgents'/f'{label}.plist'; dest.parent.mkdir(parents=True,exist_ok=True)
config={'Label':label,'ProgramArguments':[str(target),'-gateway',os.environ['AI_RELAY_INSTALL_GATEWAY'],'-credential-file',str(c)],'WorkingDirectory':str(b),'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'},'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':10,'StandardOutPath':str(b/'agent.stdout.log'),'StandardErrorPath':str(b/'agent.stderr.log')}
with dest.open('wb') as f: plistlib.dump(config,f)
dest.chmod(0o600); subprocess.run(['plutil','-lint',str(dest)],check=True)
print('Configured enrolled agent. Load the plist with launchctl bootstrap in the logged-in GUI domain.')
PYTHON
