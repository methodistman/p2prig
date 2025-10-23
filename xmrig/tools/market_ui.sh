#!/usr/bin/env bash
set -euo pipefail
HOSTPORT="${1:-${XMRIG_API:-127.0.0.1:8080}}"
BASE="http://${HOSTPORT}"

curl -sS "${BASE}/2/summary" | python3 - <<'PY'
import sys, json
j=json.load(sys.stdin)
m=j.get('market',{})
print("=== Market Summary ===")
print(f"enabled: {m.get('enabled')}  role: {m.get('role')}  price_per_khash: {m.get('price_per_khash')}  capacity_khash: {m.get('capacity_khash')}  lease_ms: {m.get('lease_ms')}  fee_bps: {m.get('fee_bps')}")
print(f"offers: {m.get('offers')}  leases_active: {m.get('leases_active')}  last_price: {m.get('last_price')}  clearing_price: {m.get('clearing_price')}")
PY

curl -sS "${BASE}/2/backends" | python3 - <<'PY'
import sys, json
j=json.load(sys.stdin)
arr=j if isinstance(j, list) else []
print("\n=== Remote Backends (market) ===")
for b in arr:
  if b.get('type')!='remote':
    continue
  mk=b.get('market',{})
  print(f"backend: remote  enabled={b.get('enabled')} status={b.get('status')} max_price={mk.get('max_price_per_khash')} lease_ms={mk.get('lease_ms')} offers={mk.get('connected_offers')}")
  rem=b.get('remotes',[])
  if rem:
    for r in rem:
      rmk=r.get('market',{})
      print(f"  - {r.get('host')}:{r.get('port')} connected={r.get('connected')} lease_supported={rmk.get('lease_supported')} eff_batch={r.get('effective_batch')} job_id={r.get('job_id')}")
PY
