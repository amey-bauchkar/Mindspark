import requests, time, json, sys

rid = sys.argv[1] if len(sys.argv) > 1 else '344594ac-6e53-4391-87de-6b580e1501a2'
for _ in range(90):
    r = requests.get(f'http://localhost:8000/api/reports/{rid}/status').json()
    stage = r.get('stage', '')
    pct = r.get('progress', 0)
    print(f"[{pct:3}%] {stage}")
    if stage == 'done' or r.get('error'):
        break
    time.sleep(1)

if r.get('error'):
    print('ERROR:', r['error'])
    sys.exit(1)

print('\n--- REPORT SUMMARY ---')
rpt = requests.get(f'http://localhost:8000/api/reports/{rid}').json()
s = rpt.get('summary', {})
print(f"INCIDENT: {s.get('incident',0)}")
print(f"ACT_NOW:  {s.get('act_now',0)}")
print(f"UPGRADE:  {s.get('upgrade',0)}")
print(f"MONITOR:  {s.get('monitor',0)}")
print(f"REVIEW:   {s.get('review',0)}")
print(f"CANNOT:   {s.get('cannot_assess',0)}")
print(f"NKF:      {s.get('no_known_finding',0)}")
print(f"TOTAL:    {s.get('total_packages',0)}")
print(f"ECOSYSTEM: {s.get('ecosystem','')}")
print(f"BADGE:    {s.get('data_badge','')}")
print('\n--- DECISIONS ---')
for d in rpt.get('decisions', []):
    print(f"  [{d['verdict']}] {d['name']}@{d['version']} — {d['what'][:60]}")
