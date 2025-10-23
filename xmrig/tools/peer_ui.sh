#!/usr/bin/env bash
set -euo pipefail

HOST=127.0.0.1
PORT=8082
PEER_PORT=""
WATCH=0

usage() {
  echo "Usage: $(basename "$0") [-h host] [-p port] [--peer-port port] [--watch seconds]";
}

while (( "$#" )); do
  case "$1" in
    -h|--host) HOST=$2; shift 2;;
    -p|--port) PORT=$2; shift 2;;
    --peer-port) PEER_PORT=$2; shift 2;;
    --watch) WATCH=$2; shift 2;;
    -?|--help) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1;;
  esac
done

human_bytes() {
  local b=$1 u=(B KB MB GB TB PB) i=0
  while (( b >= 1024 && i < ${#u[@]}-1 )); do b=$((b/1024)); ((i++)); done
  echo "$b ${u[$i]}"
}

get_pid_for_port() {
  local port=$1
  ss -ltnp 2>/dev/null | awk -v p=":$port" 'index($4,p){print $0}' | awk -F 'pid=' '{print $2}' | awk -F, '{print $1}' | head -n1
}

get_user_from_pid() {
  local pid=$1
  if [[ -r /proc/$pid/cmdline ]]; then
    tr '\0' ' ' < /proc/$pid/cmdline | awk '{for(i=1;i<=NF;i++){if($i=="-u"){print $(i+1); exit}}}'
    return 0
  fi
  echo "unknown"
}

render_once() {
  local summary backends peer_sum pid user token
  summary=$(curl -s --max-time 2 "http://$HOST:$PORT/2/summary" || echo '{}')
  backends=$(curl -s --max-time 2 "http://$HOST:$PORT/2/backends" || echo '[]')
  if [[ -n "$PEER_PORT" ]]; then
    peer_sum=$(curl -s --max-time 2 "http://$HOST:$PEER_PORT/2/summary" || echo '{}')
  else
    peer_sum='{}'
  fi
  pid=$(get_pid_for_port "$PORT" || true)
  user="unknown"; [[ -n "${pid:-}" ]] && user=$(get_user_from_pid "$pid")
  token="$user"; [[ "$token" == *:* ]] && token="${token%%:*}"

  python3 - "$PORT" "$user" "$token" <<PY
import json, sys
summary = json.loads('''$summary''')
backends = json.loads('''$backends''')
peer_summary = json.loads('''$peer_sum''')
port = sys.argv[1]
user = sys.argv[2]
token = sys.argv[3]

cpu = summary.get('cpu', {})
res = summary.get('resources', {}).get('memory', {})
conn = summary.get('connection', {})
peer = summary.get('peer_server', {})
peer_alt = peer_summary.get('peer_server', {}) if isinstance(peer_summary, dict) else {}
if peer_alt and peer_alt.get('enabled'):
    peer = peer_alt
hr = summary.get('hashrate', {})

algo = summary.get('algo') or conn.get('algo') or '-'
pool = conn.get('pool') or '-'
ht = hr.get('total') or [0,0,0]
h10 = float(ht[0] or 0)
h60 = float(ht[1] or 0)

free_b = int(res.get('free') or 0)
total_b = int(res.get('total') or 0)

# Dataset approximation for RandomX
if str(algo).startswith('rx'):
    dataset_mb = 2336
else:
    dataset_mb = 0

remote = None
for b in backends:
    if b.get('type') == 'remote':
        remote = b; break

remote_enabled = bool(remote and remote.get('enabled'))
remote_status = remote.get('status') if remote else '-'
remotes_connected = 0
if remote and isinstance(remote.get('remotes'), list):
    remotes_connected = sum(1 for r in remote['remotes'] if r.get('connected'))

cpu_backend = None
for b in backends:
    if b.get('type') == 'cpu' and b.get('enabled'):
        cpu_backend = b; break

threads = cpu_backend.get('threads', []) if cpu_backend else []

print("== XMRig CLI UI ==")
print(f"Host: 127.0.0.1:{port}  |  Algo: {algo}  |  Pool: {pool}")
print(f"User: {user}  |  Token: {token}  |  CPU: {cpu.get('brand','-')}  |  Threads: {cpu.get('threads','-')}")
print(f"Total Hashrate: {h10:.2f} H/s (10s), {h60:.2f} H/s (60s)")
free_gb = free_b / (1024**3)
total_gb = total_b / (1024**3)
print(f"Dataset: {dataset_mb} MB  |  RAM: {free_gb:.2f} GB free / {total_gb:.2f} GB total")
print(f"Peer: enabled={peer.get('enabled', False)} bind={peer.get('bind','-')} port={peer.get('port','-')} conns={peer.get('connections',0)}")
print(f"Remote: enabled={remote_enabled} status={remote_status} remotes_connected={remotes_connected}")
print()

if threads:
    print("PROCESSORS")
    print("Idx  Aff  Int  Hashrate(10s)  Hashrate(60s)")
    for idx,t in enumerate(threads):
        hr = t.get('hashrate') or [0,0,0]
        print(f"{idx:>3}  {str(t.get('affinity','-')):>3}  {str(t.get('intensity','-')):>3}  {float(hr[0] or 0):>12.2f}  {float(hr[1] or 0):>12.2f}")
PY
}

if [[ "$WATCH" -gt 0 ]]; then
  while true; do
    clear || true
    render_once || true
    sleep "$WATCH"
  done
else
  render_once
fi
