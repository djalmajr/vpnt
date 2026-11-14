#!/usr/bin/env python3
"""Build the local graphical askpass adapter; never install or invoke sudo."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
if sys.platform!='darwin' or os.getuid()==0 or os.geteuid()==0:
    raise SystemExit('Build on macOS as an ordinary user')
catalogs=ROOT/'ui/src/locales/native.json'
data=catalogs.read_bytes()
parsed=json.loads(data)
auth={'authTitle','authPrompt','authConfirm','authCancel'}
expected=auth|{'unresponsiveTitle','unresponsiveBody'}
assert set(parsed)=={'pt-BR','en-US'}
assert all(set(c)==expected and all(isinstance(v,str) and v for v in c.values()) for c in parsed.values())
# Embed only the fields this adapter consumes after validating the shared catalog.
data=json.dumps({locale:{key:catalog[key] for key in sorted(auth)} for locale,catalog in parsed.items()},ensure_ascii=False).encode()
output=ROOT/'target/debug/vpnt-askpass'
output.parent.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='vpnt-askpass-',dir=output.parent) as directory:
    temporary=Path(directory)
    (temporary/'native-catalogs.h').write_text('static const unsigned char vpnt_native_catalogs[] = {'+','.join(map(str,data))+'};\n')
    binary=temporary/'vpnt-askpass'
    subprocess.run(['/usr/bin/clang','-fobjc-arc','-fblocks','-Wall','-Wextra','-Werror','-O2','-mmacosx-version-min=13.0','-I',str(temporary),str(ROOT/'scripts/macos/askpass.m'),'-framework','AppKit','-o',str(binary)],check=True)
    # A direct call must reject before displaying UI or returning a password.
    result=subprocess.run([str(binary),'untrusted-parent'],capture_output=True,timeout=5)
    assert result.returncode==1 and result.stdout==b'' and result.stderr==b''
    os.replace(binary,output)
print(output.relative_to(ROOT))
