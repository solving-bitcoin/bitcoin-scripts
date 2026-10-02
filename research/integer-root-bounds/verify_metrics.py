#!/usr/bin/env python3
"""Independent math.isqrt, witness serialization and immutable source bindings."""
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

root=Path(__file__).resolve().parents[2]
r=json.loads((Path(sys.argv[1]) if len(sys.argv)>1 else root/'research/integer-root-bounds/metrics.json').read_text())
num=lambda n: b'' if n==0 else n.to_bytes((n.bit_length()+7)//8,'little')+(b'\0' if n.bit_length()%8==0 else b'')
compact=lambda n:bytes([n]) if n<253 else b'\xfd'+n.to_bytes(2,'little')
encode=lambda items:compact(len(items))+b''.join(compact(len(x))+x for x in items)
sha=lambda b:hashlib.sha256(b).hexdigest()
for path,h in r['source_sha256'].items():
 assert sha((root/path).read_bytes())==h,path
 if r['source_revision']!='0'*40:
  assert sha(subprocess.check_output(['git','show',f"{r['source_revision']}:{path}"],cwd=root))==h,path
meta=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1'],cwd=root))
for name,key in [('bitcoin-script','compiler_source'),('bitcoin-scriptexec','interpreter_source')]:
 assert {p['source'] for p in meta['packages'] if p['name']==name}=={r[key]}
for x in r['rows']:
 q=math.isqrt(x['input']);assert x['expected_root']==q
 b=num(x['input']) if x['encoding']=='canonical' else bytes([1,0,0,0])
 w=encode([b]);assert x['witness_bytes']==len(w) and x['witness_sha256']==sha(w)
 assert x['data_items']==1 and x['hint_items']==0 and x['hint_bytes']==0
 assert x['expected_output_sha256']==sha(encode([num(q)]))
 assert x['fragment']['output_sha256']==x['expected_output_sha256'] and x['fragment']['error'] is None
 assert x['leaf']['clean_success'] is True and x['leaf']['output_sha256']==sha(encode([b'\1']))
 for k in ['fragment','leaf']:
  a=x[k];assert a['compile_options']==('ALL' if a['raw_bytes']<=32768 else 'NONE');assert a['validation_weight_charged']==0
for x in r['compositions']:
 maximum=2**x['bit_count']-1;n=x['repeat_count']
 d=[min([0,1,2,3,16,65535,0x13579b,maximum][i%8],maximum) for i in range(n)]
 e=[math.isqrt(y) for y in d];assert x['expected_roots']==e
 w=encode([num(y) for y in d]);assert x['witness_bytes']==len(w) and x['witness_sha256']==sha(w)
 assert x['data_items']==n and x['hint_items']==0 and x['hint_bytes']==0
 assert x['expected_output_sha256']==sha(encode([num(y) for y in e]))
 assert x['fragment']['script_bytes']==x['component_bytes_sum']+x['whole_policy_delta']
 for k in ['fragment','leaf']:
  a=x[k];assert a['compile_options']==('ALL' if a['raw_bytes']<=32768 else 'NONE');assert a['validation_weight_charged']==0
  if n<=996:assert a['error'] is None and a['max_stack_items']==n+4
  else:assert a['error']=='StackSize' and a['max_stack_items']==1001
 if n<=996:
  assert x['fragment']['output_sha256']==x['expected_output_sha256']
  assert x['leaf']['clean_success'] is True
print(f"Independent math.isqrt (Python {platform.python_version()}), {len(r['rows'])} scalar rows / {len(r['compositions'])} compositions and source/Cargo/witness bindings verified; no Core or relay claim.")

for f in r['family_contracts']:
 assert f['bit_count']==16 and f['data_items']==1 and f['hint_items']==0 and f['hint_bytes']==0
 assert f['maximum_control_root']==math.isqrt(f['maximum_control_input'])==255
 assert f['maximum_control_witness_sha256']==sha(encode([num(65535)]))
 assert f['fragment']['error'] is None and f['fragment']['output_sha256']==sha(encode([num(255)]))
 assert f['leaf']['clean_success'] is True
 alias=f['alias_control_artifact'];assert alias['local_policy']['error']=='MinimalData'
 if f['canonical_input']:assert alias['error']=='EqualVerify' and alias['output_sha256'] is None
 else:assert alias['error'] is None and alias['output_sha256']==sha(encode([num(1)]))
print('Four exact shared-family artifacts, canonicality contracts and Policy alias outcomes verified.')
