#pragma once
// Phase 1 offline super-admin license verification (admin app / virule.exe only).
//
// Looks for an Ed25519-signed license file:
//   1. path in env var VIRULE_SUPERADMIN_LICENSE (if set and non-empty)
//   2. else the Phase-1 fixed dev path (kFallbackLicensePath below)
// Phase 1 deliberately does NOT look next to virule.exe.
//
// The license is JSON: { "payload": {...}, "signature": "<base64 Ed25519 sig>" }.
// The signature is over the CANONICALIZED payload, exactly as the generator
// (VIRULE_SECURITY/tools/license/make_license.py) produces it:
//   json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
// i.e. keys sorted byte-wise, no whitespace, UTF-8, non-ASCII unescaped.
//
// Unlock requires ALL of:
//   - signature verifies against the embedded PUBLIC key
//   - payload.product     == "VIRULE_ADMIN"
//   - payload.entitlement == "SUPER_ADMIN"
//   - payload.features contains "SUPER_ADMIN"
//   - payload.expires is null, OR parses as UTC and now(UTC) < expires
// Any missing/unreadable/malformed/expired/forged license => locked (false).
// Never throws out of IsSuperAdminUnlocked(); never prompts; no password.
//
// SECURITY: only the PUBLIC key is embedded here. The private key lives with
// the generator tool and must never be referenced by, shipped with, or
// committed to this application. Do not log the resolved license path.
//
// Ed25519 verification is a verify-only subset of TweetNaCl 20140427
// (D. J. Bernstein et al., public domain, https://tweetnacl.cr.yp.to) —
// kept byte-faithful apart from C++ const-initializer requirements.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace virule::core::super_admin {
namespace detail {

// ======================= Ed25519 verify (TweetNaCl subset) =================
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4018 4146 4244 4245 4267) // signed/unsigned + narrowing in reference code
#endif
#define FOR(i, n) for (i = 0; i < n; ++i)
#define sv static void

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];

static const gf
  gf0 = {0},
  gf1 = {1},
  D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static u64 dl64(const u8 *x)
{
  u64 i,u=0;
  FOR(i,8) u=(u<<8)|x[i];
  return u;
}

sv ts64(u8 *x,u64 u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}

static int vn(const u8 *x,const u8 *y,int n)
{
  u32 i,d = 0;
  FOR(i,n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

static int crypto_verify_32(const u8 *x,const u8 *y)
{
  return vn(x,y,32);
}

sv set25519(gf r, const gf a)
{
  int i;
  FOR(i,16) r[i]=a[i];
}

sv car25519(gf o)
{
  int i;
  i64 c;
  FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

sv sel25519(gf p,gf q,int b)
{
  i64 t,i,c=~(b-1);
  FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

sv pack25519(u8 *o,const gf n)
{
  int i,j,b;
  gf m,t;
  FOR(i,16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int neq25519(const gf a, const gf b)
{
  u8 c[32],d[32];
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

static u8 par25519(const gf a)
{
  u8 d[32];
  pack25519(d,a);
  return d[0]&1;
}

sv unpack25519(gf o, const u8 *n)
{
  int i;
  FOR(i,16) o[i]=n[2*i]+((i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

sv A(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]+b[i];
}

sv Z(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]-b[i];
}

sv M(gf o,const gf a,const gf b)
{
  i64 i,j,t[31];
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

sv S(gf o,const gf a)
{
  M(o,a,a);
}

sv inv25519(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

sv pow2523(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

static u64 R(u64 x,int c) { return (x >> c) | (x << (64 - c)); }
static u64 Ch(u64 x,u64 y,u64 z) { return (x & y) ^ (~x & z); }
static u64 Maj(u64 x,u64 y,u64 z) { return (x & y) ^ (x & z) ^ (y & z); }
static u64 Sigma0(u64 x) { return R(x,28) ^ R(x,34) ^ R(x,39); }
static u64 Sigma1(u64 x) { return R(x,14) ^ R(x,18) ^ R(x,41); }
static u64 sigma0(u64 x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
static u64 sigma1(u64 x) { return R(x,19) ^ R(x,61) ^ (x >> 6); }

static const u64 K[80] =
{
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static int crypto_hashblocks(u8 *x,const u8 *m,u64 n)
{
  u64 z[8],b[8],a[8],w[16],t;
  int i,j;

  FOR(i,8) z[i] = a[i] = dl64(x + 8 * i);

  while (n >= 128) {
    FOR(i,16) w[i] = dl64(m + 8 * i);

    FOR(i,80) {
      FOR(j,8) b[j] = a[j];
      t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
      b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
      b[3] += t;
      FOR(j,8) a[(j+1)%8] = b[j];
      if (i%16 == 15)
        FOR(j,16)
          w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
    }

    FOR(i,8) { a[i] += z[i]; z[i] = a[i]; }

    m += 128;
    n -= 128;
  }

  FOR(i,8) ts64(x+8*i,z[i]);

  return n;
}

static const u8 iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

static int crypto_hash(u8 *out,const u8 *m,u64 n)
{
  u8 h[64],x[256];
  u64 i,b = n;

  FOR(i,64) h[i] = iv[i];

  crypto_hashblocks(h,m,n);
  m += n;
  n &= 127;
  m -= n;

  FOR(i,256) x[i] = 0;
  FOR(i,n) x[i] = m[i];
  x[n] = 128;

  n = 256-128*(n<112);
  x[n-9] = b >> 61;
  ts64(x+n-8,b<<3);
  crypto_hashblocks(h,x,n);

  FOR(i,64) out[i] = h[i];

  return 0;
}

sv add(gf p[4],gf q[4])
{
  gf a,b,c,d,t,e,f,g,h;

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

sv cswap(gf p[4],gf q[4],u8 b)
{
  int i;
  FOR(i,4)
    sel25519(p[i],q[i],b);
}

sv pack(u8 *r,gf p[4])
{
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

sv scalarmult(gf p[4],gf q[4],const u8 *s)
{
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    u8 b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  }
}

sv scalarbase(gf p[4],const u8 *s)
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

sv modL(u8 *r,i64 x[64])
{
  i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  FOR(j,32) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  FOR(j,32) x[j] -= carry * L[j];
  FOR(i,32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

sv reduce(u8 *r)
{
  i64 x[64],i;
  FOR(i,64) x[i] = (u64) r[i];
  FOR(i,64) r[i] = 0;
  modL(r,x);
}

static int unpackneg(gf r[4],const u8 p[32])
{
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
  return 0;
}

static int crypto_sign_open(u8 *m,u64 *mlen,const u8 *sm,u64 n,const u8 *pk)
{
  int i;
  u8 t[32],h[64];
  gf p[4],q[4];

  *mlen = -1;
  if (n < 64) return -1;

  if (unpackneg(q,pk)) return -1;

  FOR(i,n) m[i] = sm[i];
  FOR(i,32) m[i+32] = pk[i];
  crypto_hash(h,m,n);
  reduce(h);
  scalarmult(p,q,h);

  scalarbase(q,sm + 32);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm, t)) {
    FOR(i,n) m[i] = 0;
    return -1;
  }

  FOR(i,n) m[i] = sm[i + 64];
  *mlen = n;
  return 0;
}

#undef FOR
#undef sv
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
// ===================== end TweetNaCl subset =================================

// Embedded Ed25519 PUBLIC key (raw 32 bytes) — extracted from the generator's
// public_key.pem (SPKI). Safe to embed; verification-only.
inline const unsigned char* license_public_key() {
    static const unsigned char k[32] = {
        0x2D, 0x14, 0x83, 0x3C, 0xBA, 0xAF, 0x55, 0xC2,
        0xF5, 0xCD, 0xFF, 0x6A, 0x85, 0xD2, 0x0D, 0x36,
        0xB0, 0x89, 0x4A, 0x0F, 0xE0, 0x0B, 0x0E, 0xD6,
        0x6C, 0xC8, 0xFE, 0xB2, 0x08, 0xBB, 0x70, 0x70,
    };
    return k;
}

// Phase-1 fixed fallback path (dev machine). Checked only when the env var
// VIRULE_SUPERADMIN_LICENSE is missing/empty. Never printed to logs.
inline const wchar_t* kFallbackLicensePath =
    L"D:\\Dropbox\\Dropbox\\development\\VIRULE_SECURITY\\tools\\license\\superadmin.lic";

// ----------------------- minimal JSON (parse + canonicalize) ---------------
// Just enough JSON to load the license document and re-serialize the payload
// exactly like the generator's canonicalizer (sorted keys, no whitespace,
// UTF-8, non-ASCII left unescaped). Numbers are preserved as written — the
// license payload uses only strings / null / arrays of strings, and the
// generator emits plain integers if a number is ever added.
struct JsonValue {
    enum class Type { Null, Boolean, Number, String, Array, Object };
    Type type = Type::Null;
    bool boolean = false;
    std::string number_raw; // numeric token exactly as written
    std::string str;        // decoded string bytes (UTF-8)
    std::vector<JsonValue> items;                            // Array
    std::vector<std::pair<std::string, JsonValue>> members;  // Object (dup keys: last wins)

    const JsonValue* find(const char* key) const {
        for (const auto& m : members)
            if (m.first == key) return &m.second;
        return nullptr;
    }
};

inline void json_skip_ws(const std::string& s, size_t& i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
}

inline void json_append_utf8(std::string& out, unsigned int cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

inline bool json_parse_hex4(const std::string& s, size_t& i, unsigned int& out) {
    if (i + 4 > s.size()) return false;
    out = 0;
    for (int k = 0; k < 4; ++k) {
        const char c = s[i + k];
        unsigned int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') v = 10 + (c - 'A');
        else return false;
        out = (out << 4) | v;
    }
    i += 4;
    return true;
}

inline bool json_parse_string(const std::string& s, size_t& i, std::string& out) {
    if (i >= s.size() || s[i] != '"') return false;
    ++i;
    out.clear();
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '"') { ++i; return true; }
        if (c == '\\') {
            ++i;
            if (i >= s.size()) return false;
            const char e = s[i++];
            switch (e) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    unsigned int cp = 0;
                    if (!json_parse_hex4(s, i, cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        // high surrogate: require \uDC00-\uDFFF to follow
                        if (i + 1 >= s.size() || s[i] != '\\' || s[i + 1] != 'u') return false;
                        i += 2;
                        unsigned int lo = 0;
                        if (!json_parse_hex4(s, i, lo)) return false;
                        if (lo < 0xDC00 || lo > 0xDFFF) return false;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return false; // lone low surrogate
                    }
                    json_append_utf8(out, cp);
                    break;
                }
                default: return false;
            }
        } else if (c < 0x20) {
            return false; // raw control char inside string
        } else {
            out.push_back(static_cast<char>(c));
            ++i;
        }
    }
    return false; // unterminated
}

inline bool json_parse_value(const std::string& s, size_t& i, JsonValue& out, int depth);

inline bool json_parse_object(const std::string& s, size_t& i, JsonValue& out, int depth) {
    ++i; // consume '{'
    out.type = JsonValue::Type::Object;
    json_skip_ws(s, i);
    if (i < s.size() && s[i] == '}') { ++i; return true; }
    for (;;) {
        json_skip_ws(s, i);
        std::string key;
        if (!json_parse_string(s, i, key)) return false;
        json_skip_ws(s, i);
        if (i >= s.size() || s[i] != ':') return false;
        ++i;
        json_skip_ws(s, i);
        JsonValue v;
        if (!json_parse_value(s, i, v, depth)) return false;
        // Duplicate keys: last one wins (mirrors Python's json.loads into dict).
        bool replaced = false;
        for (auto& m : out.members) {
            if (m.first == key) { m.second = std::move(v); replaced = true; break; }
        }
        if (!replaced) out.members.emplace_back(std::move(key), std::move(v));
        json_skip_ws(s, i);
        if (i >= s.size()) return false;
        if (s[i] == ',') { ++i; continue; }
        if (s[i] == '}') { ++i; return true; }
        return false;
    }
}

inline bool json_parse_array(const std::string& s, size_t& i, JsonValue& out, int depth) {
    ++i; // consume '['
    out.type = JsonValue::Type::Array;
    json_skip_ws(s, i);
    if (i < s.size() && s[i] == ']') { ++i; return true; }
    for (;;) {
        json_skip_ws(s, i);
        JsonValue v;
        if (!json_parse_value(s, i, v, depth)) return false;
        out.items.emplace_back(std::move(v));
        json_skip_ws(s, i);
        if (i >= s.size()) return false;
        if (s[i] == ',') { ++i; continue; }
        if (s[i] == ']') { ++i; return true; }
        return false;
    }
}

inline bool json_parse_value(const std::string& s, size_t& i, JsonValue& out, int depth) {
    if (depth > 32) return false;
    json_skip_ws(s, i);
    if (i >= s.size()) return false;
    const char c = s[i];
    if (c == '{') return json_parse_object(s, i, out, depth + 1);
    if (c == '[') return json_parse_array(s, i, out, depth + 1);
    if (c == '"') { out.type = JsonValue::Type::String; return json_parse_string(s, i, out.str); }
    if (s.compare(i, 4, "null") == 0)  { out.type = JsonValue::Type::Null; i += 4; return true; }
    if (s.compare(i, 4, "true") == 0)  { out.type = JsonValue::Type::Boolean; out.boolean = true;  i += 4; return true; }
    if (s.compare(i, 5, "false") == 0) { out.type = JsonValue::Type::Boolean; out.boolean = false; i += 5; return true; }
    // Number token: capture as written (validated loosely; preserved verbatim).
    if (c == '-' || (c >= '0' && c <= '9')) {
        const size_t start = i;
        if (s[i] == '-') ++i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
        if (i < s.size() && s[i] == '.') {
            ++i;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
        }
        if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
            ++i;
            if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
        }
        if (i == start || (i == start + 1 && s[start] == '-')) return false;
        out.type = JsonValue::Type::Number;
        out.number_raw = s.substr(start, i - start);
        return true;
    }
    return false;
}

// Serialize a string the way Python json.dumps(ensure_ascii=False) does:
// escape only ", \ and control chars (<0x20, with the short forms where they
// exist); pass all other bytes through untouched.
inline void json_canonical_string(std::string& out, const std::string& s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

// Canonical serialization matching make_license.py's canonicalize():
// sorted keys (byte-wise UTF-8 == code-point order, same as Python's str sort),
// separators (",", ":"), no whitespace.
inline void json_canonical_serialize(const JsonValue& v, std::string& out) {
    switch (v.type) {
        case JsonValue::Type::Null:    out += "null"; break;
        case JsonValue::Type::Boolean: out += (v.boolean ? "true" : "false"); break;
        case JsonValue::Type::Number:  out += v.number_raw; break;
        case JsonValue::Type::String:  json_canonical_string(out, v.str); break;
        case JsonValue::Type::Array: {
            out.push_back('[');
            for (size_t k = 0; k < v.items.size(); ++k) {
                if (k) out.push_back(',');
                json_canonical_serialize(v.items[k], out);
            }
            out.push_back(']');
            break;
        }
        case JsonValue::Type::Object: {
            std::vector<const std::pair<std::string, JsonValue>*> sorted;
            sorted.reserve(v.members.size());
            for (const auto& m : v.members) sorted.push_back(&m);
            std::stable_sort(sorted.begin(), sorted.end(),
                [](const auto* a, const auto* b) { return a->first < b->first; });
            out.push_back('{');
            for (size_t k = 0; k < sorted.size(); ++k) {
                if (k) out.push_back(',');
                json_canonical_string(out, sorted[k]->first);
                out.push_back(':');
                json_canonical_serialize(sorted[k]->second, out);
            }
            out.push_back('}');
            break;
        }
    }
}

// ----------------------------- base64 (strict) -----------------------------
inline bool b64_decode_strict(const std::string& in, std::vector<unsigned char>& out) {
    out.clear();
    if (in.empty() || (in.size() % 4) != 0) return false;
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.reserve((in.size() / 4) * 3);
    for (size_t i = 0; i < in.size(); i += 4) {
        int pad = 0;
        int v[4] = {};
        for (int j = 0; j < 4; ++j) {
            const char c = in[i + j];
            if (c == '=') {
                if (i + 4 != in.size() || j < 2) return false;
                ++pad;
                v[j] = 0;
            } else {
                if (pad) return false;
                v[j] = val(c);
                if (v[j] < 0) return false;
            }
        }
        const unsigned u = (static_cast<unsigned>(v[0]) << 18) |
                           (static_cast<unsigned>(v[1]) << 12) |
                           (static_cast<unsigned>(v[2]) << 6) |
                            static_cast<unsigned>(v[3]);
        out.push_back(static_cast<unsigned char>((u >> 16) & 0xFF));
        if (pad < 2) out.push_back(static_cast<unsigned char>((u >> 8) & 0xFF));
        if (pad < 1) out.push_back(static_cast<unsigned char>(u & 0xFF));
    }
    return true;
}

// --------------------------- expiry (UTC) ----------------------------------
// Accepts "YYYY-MM-DD" or "YYYY-MM-DD[T ]HH:MM:SS", optional trailing "Z".
// Anything else is treated as unparseable (=> license invalid, locked).
inline bool parse_expires_utc(const std::string& s, std::time_t& out) {
    auto digits = [&](size_t pos, int count, int& v) -> bool {
        v = 0;
        if (pos + count > s.size()) return false;
        for (int k = 0; k < count; ++k) {
            const char c = s[pos + k];
            if (c < '0' || c > '9') return false;
            v = v * 10 + (c - '0');
        }
        return true;
    };
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    if (!digits(0, 4, y) || s.size() < 10 || s[4] != '-' || !digits(5, 2, mo) ||
        s[7] != '-' || !digits(8, 2, d))
        return false;
    size_t pos = 10;
    if (pos < s.size() && (s[pos] == 'T' || s[pos] == ' ')) {
        ++pos;
        if (!digits(pos, 2, h) || pos + 8 > s.size() || s[pos + 2] != ':' ||
            !digits(pos + 3, 2, mi) || s[pos + 5] != ':' || !digits(pos + 6, 2, se))
            return false;
        pos += 8;
    }
    if (pos < s.size() && s[pos] == 'Z') ++pos;
    if (pos != s.size()) return false;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return false;

    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = se;
    const std::time_t t = _mkgmtime(&tm); // UTC
    if (t == static_cast<std::time_t>(-1)) return false;
    out = t;
    return true;
}

// --------------------------- verification ----------------------------------
inline bool evaluate_super_admin_unlock() {
    // 1) Resolve the license path: env var first, else the Phase-1 fixed path.
    std::wstring path;
    {
        wchar_t* env = nullptr;
        size_t env_len = 0;
        if (_wdupenv_s(&env, &env_len, L"VIRULE_SUPERADMIN_LICENSE") == 0 && env) {
            if (env[0] != L'\0') path = env;
            std::free(env);
        }
    }
    if (path.empty()) path = kFallbackLicensePath;

    // 2) Read the file (bounded; missing/unreadable/oversized => locked).
    std::string text;
    {
        std::ifstream f(std::filesystem::path(path), std::ios::binary | std::ios::ate);
        if (!f) return false;
        const std::streamoff sz = f.tellg();
        if (sz <= 0 || sz > 64 * 1024) return false;
        text.resize(static_cast<size_t>(sz));
        f.seekg(0);
        if (!f.read(text.data(), sz)) return false;
    }
    // Tolerate a UTF-8 BOM (hand-edited files).
    if (text.size() >= 3 &&
        static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF)
        text.erase(0, 3);

    // 3) Parse { "payload": {...}, "signature": "base64" }.
    JsonValue doc;
    {
        size_t i = 0;
        if (!json_parse_value(text, i, doc, 0)) return false;
        json_skip_ws(text, i);
        if (i != text.size()) return false; // trailing garbage
    }
    if (doc.type != JsonValue::Type::Object) return false;
    const JsonValue* payload = doc.find("payload");
    const JsonValue* signature = doc.find("signature");
    if (!payload || payload->type != JsonValue::Type::Object) return false;
    if (!signature || signature->type != JsonValue::Type::String) return false;

    // 4) Re-canonicalize the payload exactly like the generator, decode the
    //    signature, and verify Ed25519 against the embedded public key.
    std::string canon;
    json_canonical_serialize(*payload, canon);

    std::vector<unsigned char> sig;
    if (!b64_decode_strict(signature->str, sig) || sig.size() != 64) return false;

    {
        const size_t n = 64 + canon.size();
        std::vector<unsigned char> sm(n);
        std::memcpy(sm.data(), sig.data(), 64);
        std::memcpy(sm.data() + 64, canon.data(), canon.size());
        std::vector<unsigned char> m(n);
        u64 mlen = 0;
        if (crypto_sign_open(m.data(), &mlen, sm.data(), static_cast<u64>(n),
                             license_public_key()) != 0)
            return false;
    }

    // 5) Entitlement checks on the (now signature-verified) payload.
    const JsonValue* product = payload->find("product");
    if (!product || product->type != JsonValue::Type::String || product->str != "VIRULE_ADMIN")
        return false;
    const JsonValue* entitlement = payload->find("entitlement");
    if (!entitlement || entitlement->type != JsonValue::Type::String ||
        entitlement->str != "SUPER_ADMIN")
        return false;
    const JsonValue* features = payload->find("features");
    if (!features || features->type != JsonValue::Type::Array) return false;
    {
        bool has_super_admin = false;
        for (const auto& f : features->items) {
            if (f.type == JsonValue::Type::String && f.str == "SUPER_ADMIN") {
                has_super_admin = true;
                break;
            }
        }
        if (!has_super_admin) return false;
    }
    // expires: null => perpetual; string => must parse as UTC and be in the future.
    const JsonValue* expires = payload->find("expires");
    if (expires && expires->type != JsonValue::Type::Null) {
        if (expires->type != JsonValue::Type::String) return false;
        std::time_t exp = 0;
        if (!parse_expires_utc(expires->str, exp)) return false;
        if (std::time(nullptr) >= exp) return false;
    }

    return true;
}

} // namespace detail

// True iff a valid super-admin license was found and verified. Evaluated once
// per process (first call) and cached; never throws, never prompts, and never
// logs the license path.
inline bool IsSuperAdminUnlocked() {
    static const bool unlocked = detail::evaluate_super_admin_unlock();
    return unlocked;
}

} // namespace virule::core::super_admin
