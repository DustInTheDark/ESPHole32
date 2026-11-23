// dnslogic.h - pure C++ DNS helpers (no Arduino dependencies, so they can be
// unit-tested on a PC). Used by the ESPHole32 firmware.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace dns {

// ---------------------------------------------------------------------------
// Hashing: 64-bit FNV-1a over the lower-case domain, truncated to 40 bits.
// MUST match tools/build_blocklist.py exactly.
// ---------------------------------------------------------------------------
static const uint64_t HASH_MASK = 0xFFFFFFFFFFULL;  // 40 bits

inline uint64_t fnv40(const char* s, size_t len) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = (uint8_t)s[i];
    if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
    h ^= c;
    h *= 0x100000001b3ULL;
  }
  return h & HASH_MASK;
}
inline uint64_t fnv40(const char* s) { return fnv40(s, strlen(s)); }

// 5-byte big-endian entry -> integer (big-endian keeps byte order == numeric order)
inline uint64_t decode40(const uint8_t* b) {
  return ((uint64_t)b[0] << 32) | ((uint64_t)b[1] << 24) | ((uint64_t)b[2] << 16) |
         ((uint64_t)b[3] << 8) | (uint64_t)b[4];
}

// ---------------------------------------------------------------------------
// Blocklist file header (16 bytes, little-endian fields), followed by
// `count` sorted 5-byte big-endian hashes.
// ---------------------------------------------------------------------------
static const uint8_t BL_MAGIC[4] = {'E', 'S', 'P', 'H'};
static const uint32_t BL_VERSION = 1;
static const size_t BL_HEADER = 16;
static const size_t BL_ENTRY = 5;

inline uint32_t rd32le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Returns entry count if header valid, or -1.
inline long parseHeader(const uint8_t* h, size_t capacityBytes) {
  if (memcmp(h, BL_MAGIC, 4) != 0) return -1;
  if (rd32le(h + 4) != BL_VERSION) return -1;
  uint32_t count = rd32le(h + 8);
  if (BL_HEADER + (uint64_t)count * BL_ENTRY > capacityBytes) return -1;
  return (long)count;
}

// Binary search. `readEntry(index, out5)` fetches one 5-byte entry.
template <typename ReadFn>
bool sortedContains(uint32_t count, uint64_t h, ReadFn readEntry) {
  uint32_t lo = 0, hi = count;
  uint8_t buf[5];
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (!readEntry(mid, buf)) return false;
    uint64_t v = decode40(buf);
    if (v == h) return true;
    if (v < h) lo = mid + 1; else hi = mid;
  }
  return false;
}

// ---------------------------------------------------------------------------
// DNS packet handling
// ---------------------------------------------------------------------------
static const size_t HDR = 12;
static const uint16_t TYPE_A = 1;
static const uint16_t TYPE_AAAA = 28;
static const uint16_t TYPE_HTTPS = 65;

inline uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
inline void wr16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }

struct Question {
  char name[256];   // lower-case, no trailing dot ("" for root)
  uint16_t qtype;
  uint16_t qclass;
  int end;          // offset just after the first question
};

// True if this is a standard query (QR=0, OPCODE=0) with >=1 question that
// we parsed successfully.
inline bool parseQuery(const uint8_t* p, int len, Question& q) {
  if (len < (int)HDR + 5) return false;
  if (p[2] & 0x80) return false;              // QR=1 -> it's a response
  if (((p[2] >> 3) & 0x0F) != 0) return false; // OPCODE != QUERY
  if (rd16(p + 4) < 1) return false;           // QDCOUNT
  int i = HDR, n = 0;
  while (true) {
    if (i >= len) return false;
    uint8_t l = p[i++];
    if (l == 0) break;
    if (l & 0xC0) return false;                // no compression expected in question
    if (i + l > len) return false;
    if (n + l + 1 > 253) return false;
    if (n) q.name[n++] = '.';
    for (int k = 0; k < l; k++) {
      char c = (char)p[i + k];
      if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
      q.name[n++] = c;
    }
    i += l;
  }
  q.name[n] = 0;
  if (i + 4 > len) return false;
  q.qtype = rd16(p + i);
  q.qclass = rd16(p + i + 2);
  q.end = i + 4;
  return true;
}

// Build a "blocked" answer: A -> 0.0.0.0, AAAA -> ::, anything else -> NODATA.
// `out` must hold at least q.end + 28 bytes. Returns length.
inline int buildBlocked(const uint8_t* query, const Question& q, uint8_t* out, uint32_t ttl = 60) {
  memcpy(out, query, q.end);
  out[2] = 0x80 | (query[2] & 0x79);  // QR=1, keep OPCODE + RD
  out[3] = 0x80;                      // RA=1, RCODE=0
  wr16(out + 4, 1);                   // QDCOUNT
  wr16(out + 8, 0);                   // NSCOUNT
  wr16(out + 10, 0);                  // ARCOUNT (drop EDNS OPT)
  int n = q.end;
  uint16_t an = 0;
  if (q.qclass == 1 && (q.qtype == TYPE_A || q.qtype == TYPE_AAAA)) {
    uint16_t rdlen = q.qtype == TYPE_A ? 4 : 16;
    out[n++] = 0xC0; out[n++] = 0x0C;          // name -> pointer to question
    wr16(out + n, q.qtype); n += 2;
    wr16(out + n, 1); n += 2;                  // class IN
    out[n++] = ttl >> 24; out[n++] = ttl >> 16; out[n++] = ttl >> 8; out[n++] = ttl;
    wr16(out + n, rdlen); n += 2;
    memset(out + n, 0, rdlen); n += rdlen;     // 0.0.0.0 / ::
    an = 1;
  }
  wr16(out + 6, an);
  return n;
}

// Build an error response (e.g. SERVFAIL=2) for a query. Returns length.
inline int buildError(const uint8_t* query, const Question& q, uint8_t rcode, uint8_t* out) {
  memcpy(out, query, q.end);
  out[2] = 0x80 | (query[2] & 0x79);
  out[3] = 0x80 | (rcode & 0x0F);
  wr16(out + 4, 1); wr16(out + 6, 0); wr16(out + 8, 0); wr16(out + 10, 0);
  return q.end;
}

// Call fn(suffix) for "a.b.example.com", "b.example.com", "example.com".
// Stops before a bare TLD. Returns true as soon as fn returns true.
template <typename Fn>
bool anySuffix(const char* name, Fn fn) {
  const char* s = name;
  while (*s) {
    const char* dot = strchr(s, '.');
    if (!dot) break;            // s is a single label (TLD) - don't test it
    if (fn(s)) return true;
    s = dot + 1;
  }
  // single-label names (e.g. "localhost") are tested once as-is
  if (s == name && *s) return fn(s);
  return false;
}

}  // namespace dns
