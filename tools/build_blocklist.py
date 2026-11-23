#!/usr/bin/env python3
"""
build_blocklist.py - turn ad/tracker blocklists into blocklist.bin for ESPHole32.

Accepts hosts files ("0.0.0.0 ads.example.com"), plain domain lists and
Adblock-style lists ("||ads.example.com^"), from URLs or local files.

Examples
  python build_blocklist.py                      # default list (StevenBlack)
  python build_blocklist.py --preset big         # StevenBlack + HaGeZi Multi
  python build_blocklist.py my_list.txt https://example.com/hosts.txt
  python build_blocklist.py --allow allow.txt    # never block these

Output: blocklist.bin  -> upload it from the ESPHole32 dashboard.

File format (must match src/dnslogic.h):
  16-byte header: b"ESPH", uint32 version=1, uint32 count, uint32 reserved (little-endian)
  then `count` sorted 40-bit FNV-1a hashes of the domains, 5 bytes each, big-endian.
"""
import argparse
import re
import struct
import sys
import urllib.request

PRESETS = {
    "default": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ],
    "big": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt",
    ],
}

# Partition is 0x220000 bytes (see partitions.csv)
CAPACITY = (0x220000 - 16) // 5
MASK40 = (1 << 40) - 1
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
        "ip6-loopback", "0.0.0.0", "ip6-allnodes", "ip6-allrouters"}


def fnv40(domain: str) -> int:
    h = 0xCBF29CE484222325
    for b in domain.encode("ascii", "ignore"):
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h & MASK40


def read_source(src: str) -> str:
    if src.startswith(("http://", "https://")):
        print(f"  downloading {src}", file=sys.stderr)
        req = urllib.request.Request(src, headers={"User-Agent": "ESPHole32-builder"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read().decode("utf-8", "ignore")
    with open(src, encoding="utf-8", errors="ignore") as f:
        return f.read()


def parse(text: str):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line or line.startswith(("!", "[", "@@")):
            continue
        if line.startswith("||"):                      # adblock: ||domain^
            line = line[2:].split("^", 1)[0].split("$", 1)[0]
        else:
            parts = line.split()
            if len(parts) >= 2 and re.match(r"^[0-9a-f.:]+$", parts[0]):  # hosts: IP domain
                line = parts[1]
            elif len(parts) == 1:
                line = parts[0]
            else:
                continue
        line = line.strip(".")
        if line.startswith("*."):
            line = line[2:]
        if line in SKIP or not DOMAIN_RE.match(line):
            continue
        yield line


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="*", help="URLs or files (default: --preset default)")
    ap.add_argument("--preset", choices=PRESETS, help="use a built-in set of list URLs")
    ap.add_argument("--allow", action="append", default=[], help="file of domains never to block")
    ap.add_argument("-o", "--output", default="blocklist.bin")
    a = ap.parse_args()

    sources = list(a.sources)
    if a.preset or not sources:
        sources += PRESETS[a.preset or "default"]

    domains = set()
    for s in sources:
        before = len(domains)
        domains.update(parse(read_source(s)))
        print(f"  {s}: +{len(domains) - before:,} domains", file=sys.stderr)

    allow = set()
    for f in a.allow:
        allow.update(parse(read_source(f)))
    domains -= allow

    # The ESP32 also blocks every subdomain of a listed domain, so drop entries
    # whose parent is already listed - saves flash.
    def has_listed_parent(d):
        p = d.split(".")
        return any(".".join(p[i:]) in domains for i in range(1, len(p) - 1))

    pruned = {d for d in domains if not has_listed_parent(d)}
    print(f"Unique domains: {len(domains):,}  after removing covered subdomains: {len(pruned):,}", file=sys.stderr)

    hashes = {}
    collisions = 0
    for d in pruned:
        h = fnv40(d)
        if h in hashes and hashes[h] != d:
            collisions += 1
        hashes[h] = d
    keys = sorted(hashes)

    if len(keys) > CAPACITY:
        print(f"WARNING: {len(keys):,} domains exceeds capacity {CAPACITY:,}; truncating.", file=sys.stderr)
        keys = keys[:CAPACITY]

    with open(a.output, "wb") as f:
        f.write(b"ESPH" + struct.pack("<III", 1, len(keys), 0))
        for h in keys:
            f.write(h.to_bytes(5, "big"))

    print(f"Wrote {a.output}: {len(keys):,} domains, {16 + 5 * len(keys):,} bytes, "
          f"{collisions} hash collisions", file=sys.stderr)
    if allow:
        print("Note: allow-listed domains are removed here, but a parent domain on the list still blocks them -"
              " add them to the dashboard allow list too.", file=sys.stderr)


if __name__ == "__main__":
    main()
