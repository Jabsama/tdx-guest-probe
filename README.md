# tdx-guest-probe

One shell script that prints everything an Intel TDX guest can observe about its own
confidential-computing state, and says plainly what it cannot.

Written the week DDRop was published (14 September 2026). Two of the three attacks demonstrated
against TDX only work when the host runs the default *logical integrity* mode and are blocked by the
optional *cryptographic integrity* mode. That setting is a host platform choice (TME-MK). A tenant
renting a "confidential" VM naturally asks: *can I tell which mode my host runs?* The honest answer,
measured rather than assumed, is **no**, and this script shows exactly where the visibility stops.

## What it prints

- kernel version and whether `/dev/tdx_guest` exists
- `dmesg` lines mentioning TDX, TME, memory encryption, integrity
- `cpuinfo` flags (`tdx_guest`, `tme`, `pconfig`, `sgx`)
- `cpuid` leaf 7 (TME bit) and leaf 0x21 (TDX vendor string)
- a fresh TD report through the kernel's standard configfs TSM interface (`/sys/kernel/config/tsm/report`, kernel 6.7+)
- the quote's `td_attributes` (DEBUG, SEPT_VE_DISABLE, PKS, KL, PERFMON), `xfam`, `tee_tcb_svn`, parsed from a `voltage-verify` `bundle.json` if one is present, else from the fresh quote

and then one line saying that the memory integrity mode is not a documented field of the TD report
and is therefore not observable from inside the guest.

## Use

```bash
ssh -p <port> ubuntu@<vm-ip> 'bash -s' < tdx-guest-probe.sh
```

No provider-specific code. It reads Linux kernel interfaces and `cpuid` only, so it runs the same on
any TDX guest: a cloud VM, a bare-metal TDX host, a lab machine.

## Example output (VoltageGPU Confidential VM, RTX PRO 6000 Blackwell, 17 September 2026)

```
== kernel and TDX guest device
6.8.0-110-generic
crw------- 1 root root 10, 122 ... /dev/tdx_guest
== dmesg: tdx / tme / integrity / memory encryption
[    0.000000] tdx: Guest detected
[   10.848643] Memory Encryption Features active: Intel TDX
[   32.003287] systemd[1]: Detected confidential virtualization tdx
== TD report through configfs TSM (kernel >= 6.7)
quote: 5247 bytes
== TD attributes
quote version : 4 | size : 5247
td_attributes   : 0x0000000010000000  (DEBUG=0 SEPT_VE_DISABLE=1 PKS=0 KL=0 PERFMON=0)
tee_tcb_svn     : 05030400...
NOTE: the memory integrity mode (logical vs cryptographic, TME-MK) is a host platform setting; ...
```

So a tenant can confirm that TDX is active, that the Trust Domain is **not** in debug mode (the bit
the second DDRop attack flips), and that the quote comes from the stock kernel interface. A tenant
cannot confirm the integrity mode. Any provider claiming it without naming the host setting is
telling you something they cannot see from the guest either.

## Related

- Dated, re-verifiable attestation bundles: https://github.com/Jabsama/confidential-gpu-attestation-evidence
- Verifier for those bundles: https://github.com/Jabsama/voltage-verify
- The write-up: https://voltagegpu.com/blog/ddrop-tdx-physical-attacks-what-it-means-if-you-rent-confidential-gpus

## License

MIT. Copyright 2026 VOLTAGE EI.
