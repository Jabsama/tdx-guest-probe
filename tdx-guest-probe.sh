#!/usr/bin/env bash
# tdx-guest-probe: what an Intel TDX guest can, and cannot, observe about its
# own confidential-computing state. Written after DDRop (14 Sept 2026), where
# two of the three demonstrated attacks only work when the host runs TDX in
# the default "logical integrity" mode and are blocked by the optional
# "cryptographic integrity" mode. That setting lives on the host (TME-MK), so
# this script collects everything a guest CAN see and says plainly what it
# cannot. No provider-specific code: kernel interfaces and cpuid only.
#
#   ssh -p <port> ubuntu@<ip> 'bash -s' < tdx-guest-probe.sh
#
# Optional: if a voltage-verify bundle.json is in $HOME, its TDX quote is
# parsed too (td_attributes: DEBUG bit and friends).
set -u
cd "$HOME"

echo "== kernel and TDX guest device"
uname -r; ls -l /dev/tdx_guest 2>&1

echo "== dmesg: tdx / tme / integrity / memory encryption"
sudo dmesg 2>/dev/null | grep -iE "tdx|tme|mktme|integrit|memory encryption" | head -20 || echo "(dmesg not accessible)"

echo "== cpuinfo flags"
grep -m1 -oE "\b(tme|tdx_guest|pconfig|sgx)\b" /proc/cpuinfo | sort -u | tr '\n' ' '; echo

echo "== cpuid: leaf 7 (TME) and leaf 0x21 (TDX)"
sudo modprobe cpuid 2>/dev/null
python3 - <<'PY'
import os, struct
def cpuid(leaf, sub=0):
    try:
        fd = os.open('/dev/cpu/0/cpuid', os.O_RDONLY)
        os.lseek(fd, (sub << 32) | leaf, 0)
        d = os.read(fd, 16); os.close(fd)
        return struct.unpack('IIII', d)
    except Exception as e:
        return None, str(e)
r = cpuid(7, 0)
print('leaf 7    :', 'TME(ecx.13)=%d' % ((r[2] >> 13) & 1) if r[0] is not None else 'not accessible ' + r[1])
r = cpuid(0x21, 0)
if r[0] is not None:
    print('leaf 0x21 : vendor =', struct.pack('III', r[1], r[3], r[2]).decode(errors='replace'), '| eax =', r[0])
else:
    print('leaf 0x21 : not accessible', r[1])
PY

echo "== TD report through configfs TSM (kernel >= 6.7)"
if [ -d /sys/kernel/config/tsm/report ]; then
  sudo mkdir -p /sys/kernel/config/tsm/report/probe 2>/dev/null
  printf '%064d' 0 | sudo tee /sys/kernel/config/tsm/report/probe/inblob >/dev/null 2>&1
  sudo cat /sys/kernel/config/tsm/report/probe/outblob 2>/dev/null > /tmp/quote.bin && echo "quote: $(stat -c %s /tmp/quote.bin) bytes"
  sudo rmdir /sys/kernel/config/tsm/report/probe 2>/dev/null
else
  echo "(no /sys/kernel/config/tsm/report)"
fi

echo "== TD attributes (from bundle.json if present, else /tmp/quote.bin)"
python3 - <<'PY'
import json, base64, struct, os
q = None
if os.path.exists('bundle.json'):
    b = json.load(open('bundle.json'))
    def find(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k.lower() in ('quote', 'tdx_quote', 'quote_b64') and isinstance(v, str) and len(v) > 1000: return v
                r = find(v)
                if r: return r
        if isinstance(o, list):
            for v in o:
                r = find(v)
                if r: return r
    s = find(b)
    if s:
        try: q = base64.b64decode(s)
        except Exception: q = None
if q is None and os.path.exists('/tmp/quote.bin'):
    q = open('/tmp/quote.bin', 'rb').read()
if not q:
    print('no quote to parse'); raise SystemExit
# Quote v4: 48-byte header, then the 584-byte TD report body
hdr = q[:48]; body = q[48:48 + 584]
ver = struct.unpack('<H', hdr[:2])[0]
print('quote version :', ver, '| size :', len(q))
seam_attr = body[112:120]; td_attr = body[120:128]; xfam = body[128:136]
a = struct.unpack('<Q', td_attr)[0]
print('seam_attributes :', seam_attr.hex())
print('td_attributes   : 0x%016x  (DEBUG=%d SEPT_VE_DISABLE=%d PKS=%d KL=%d PERFMON=%d)' % (a, a & 1, (a >> 28) & 1, (a >> 30) & 1, (a >> 31) & 1, (a >> 63) & 1))
print('xfam            :', xfam.hex())
print('tee_tcb_svn     :', body[0:16].hex())
print("NOTE: the memory integrity mode (logical vs cryptographic, TME-MK) is a host platform setting; there is no documented field for it in the TD report. What is printed above is everything a guest can observe.")
PY
