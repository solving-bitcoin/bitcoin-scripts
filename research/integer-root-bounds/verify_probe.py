#!/usr/bin/env python3
"""Independent exact-integer oracle and current/immutable source verification."""
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

root=Path(__file__).resolve().parents[2]
r=json.loads((Path(sys.argv[1]) if len(sys.argv)>1 else root/'research/integer-root-bounds/initial-probe.json').read_text())
num=lambda n: b'' if n==0 else n.to_bytes((n.bit_length()+7)//8,'little')+(b'\0' if n.bit_length()%8==0 else b'')
for path,h in r['source_sha256'].items():
 assert hashlib.sha256((root/path).read_bytes()).hexdigest()==h,path
 if r['source_revision']!='0'*40:
  b=subprocess.check_output(['git','show',f"{r['source_revision']}:{path}"],cwd=root)
  assert hashlib.sha256(b).hexdigest()==h,path
digest=hashlib.sha256(b''.join(math.isqrt(x).to_bytes(4,'little') for x in range(65536))).hexdigest()
for c in r['contracts']:
 assert c['exhaustive_16bit_inputs']==65536 and c['root_u32le_sha256']==digest
 for f in c['frontiers']:
  assert f['data_items']==f['caller_main_items']+f['caller_alt_items']+1 and f['hint_items']==0
  assert f['artifact']['error'] is None and f['artifact']['max_stack_items']==1000
  assert f['artifact']['output_items']==f['data_items']
cases=set()
for q in range(math.isqrt(2**31-1)+1):
 sq=q*q;cases.add(sq)
 if sq:cases.add(sq-1)
 cases.add(min((q+1)**2-1,2**31-1))
assert r['restoring31_boundary_cases']==len(cases)
assert r['restoring31_input_root_u32le_sha256']==hashlib.sha256(b''.join(x.to_bytes(4,'little')+math.isqrt(x).to_bytes(4,'little') for x in sorted(cases))).hexdigest()
for x in r['rows']:
 q=math.isqrt(x['input']);assert x['expected_root']==q
 w=b'\1'+bytes([len(num(x['input']))])+num(x['input'])
 assert x['witness_bytes']==len(w) and x['witness_sha256']==hashlib.sha256(w).hexdigest()
 assert x['data_items']==1 and x['hint_items']==0 and x['hint_bytes']==0
 assert x['fragment']['output_hex']==[num(q).hex()] and x['fragment']['error'] is None
 assert x['leaf']['output_hex']==['01'] and x['leaf']['clean_success'] is True
 for key in ['fragment','leaf']:
  a=x[key];assert a['compile_options']==('ALL' if a['raw_bytes']<=32768 else 'NONE');assert a['validation_weight_charged']==0
meta=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1'],cwd=root))
for name,key in [('bitcoin-script','compiler_source'),('bitcoin-scriptexec','interpreter_source')]:
 assert {p['source'] for p in meta['packages'] if p['name']==name}=={r[key]}
print(f"Independent math.isqrt oracle: Python {platform.python_version()}; 2*65536 scalar inputs, {len(cases)} 31-bit endpoints and {len(r['rows'])} measured rows verified. No Core/relay claim.")
