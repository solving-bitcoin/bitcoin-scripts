#!/usr/bin/env python3
"""Offline independent table transcription, output, witness and source checks."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

root=Path(__file__).resolve().parents[2]
path=Path(sys.argv[1]) if len(sys.argv)>1 else root/'research/damm-finite-state/metrics.json'
r=json.loads(path.read_text())
ref=(root/'research/damm-finite-state/reference/DammQuasigroupTable.cs').read_bytes()
assert hashlib.sha256(ref).hexdigest()=='b5be157bdbc16daf91a1caf75911cc648ac108488a878909a8b1e22cd75ceaf2'
body=re.search(r'_quasigroupTable\s*=\s*\[(.*?)\];',ref.decode('utf-8-sig'),re.S).group(1)
flat=[int(x) for x in re.findall(r'\d+',body)]
assert len(flat)==100
q=[flat[i:i+10] for i in range(0,100,10)]
for p in ['src/arithmetic/u4/damm/mod.rs','research/damm-finite-state/baseline.rs']:
 text=(root/p).read_text();actual=ast.literal_eval(re.search(r'const Q:.*?=\s*(\[.*?\]);',text,re.S).group(1));assert actual==q
assert all(sorted(row)==list(range(10)) for row in q)
assert all(sorted(q[a][b] for a in range(10))==list(range(10)) for b in range(10))
assert all(q[a][a]==0 for a in range(10))
assert all((q[q[c][x]][y]==q[q[c][y]][x])==(x==y) for c in range(10) for x in range(10) for y in range(10))
for p,h in r['source_sha256'].items():
 assert hashlib.sha256((root/p).read_bytes()).hexdigest()==h,p
 if r['source_revision']!='0'*40:
  assert re.fullmatch('[a-f0-9]{40}',r['source_revision'])
  b=subprocess.check_output(['git','show',f"{r['source_revision']}:{p}"],cwd=root)
  assert hashlib.sha256(b).hexdigest()==h,p
for row in r['rows']:
 n=row['n'];pattern=row['digit_pattern'];digits=[0 if pattern=='zeros' else 9 if pattern=='nines' else (7*i+3)%10 for i in range(n)]
 state=0
 for d in digits:state=q[state][d]
 assert row['expected_digit']==state
 assert row['witness_bytes']==(1 if n<253 else 3)+sum(5 if row['encoding']=='four-byte-alias' else 1+(d!=0) for d in digits)
 assert row['data_items']==n and row['hint_items']==0 and row['hint_bytes']==0
 for key in ['fragment','leaf']:
  a=row[key];assert a['compile_options']==('ALL' if a['raw_bytes']<=32768 else 'NONE')
  assert a['validation_weight_charged']==0
  if a['error'] is not None:assert a['error']=='StackSize' and a['max_stack_items']==1001
print(f"Pinned upstream table, source bindings and {len(r['rows'])} configurations verified; no C# execution or Core claim.")
meta=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1'],cwd=root))
for name,key in [('bitcoin-script','compiler_source'),('bitcoin-scriptexec','interpreter_source')]:
 sources={p['source'] for p in meta['packages'] if p['name']==name}
 assert sources=={r[key]},(name,sources,r[key])
def compact(n):
 return bytes([n]) if n<253 else b'\xfd'+n.to_bytes(2,'little')
def encode(items):
 return compact(len(items))+b''.join(compact(len(x))+x for x in items)
for c in r['compositions']:
 targets=[4,7,9]*10
 targets=targets[:c['repeat_count']]
 assert c['expected_digits']==targets
 inputs=[]
 for target in targets:
  digits=[0]*31+[q[0].index(target)]
  state=0
  for d in digits:state=q[state][d]
  assert state==target
  inputs.extend(b'' if d==0 else bytes([d]) for d in digits)
 assert c['data_items']==32*c['repeat_count'] and c['hint_items']==0 and c['hint_bytes']==0
 raw=encode(inputs)
 assert c['witness_bytes']==len(raw)
 assert c['witness_sha256']==hashlib.sha256(raw).hexdigest()
 assert c['expected_output_sha256']==hashlib.sha256(encode([bytes([x]) for x in targets])).hexdigest()
 assert c['fragment']['script_bytes']==c['component_bytes_sum']+c['composition_optimizer_delta']
 for key in ['fragment','leaf']:
  a=c[key]
  assert a['compile_options']==('ALL' if a['raw_bytes']<=32768 else 'NONE')
  if a['error'] is None:assert a['max_stack_items']==c['data_items']+104
  else:assert a['error']=='StackSize' and a['max_stack_items']==1001
print(f"Cargo provenance and {len(r['compositions'])} preloaded independent compositions verified.")

for b in r['resident_breakdowns']:
 n=b['digit_count']
 assert b['table_setup_bytes']==(100 if n else 0)
 assert b['initial_state_bytes']==1
 assert b['table_cleanup_and_state_restore_bytes']==(52 if n else 0)
 assert b['component_bytes_sum']==sum(b[k] for k in ['table_setup_bytes','initial_state_bytes','validated_query_and_routing_bytes','table_cleanup_and_state_restore_bytes'])
 assert b['whole_script_bytes']==b['component_bytes_sum']+b['whole_optimizer_delta']
 row=next(x for x in r['rows'] if x['algorithm']=='resident' and x['n']==n)
 assert b['whole_script_bytes']==row['fragment']['script_bytes']
print('Resident lifecycle components and whole-policy deltas verified.')
