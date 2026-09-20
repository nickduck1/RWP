/*
 * ============================================================================
 * RRKDHT.c — Production Rotating Rendezvous Kademlia DHT (single-file C port)
 * ============================================================================
 *
 * A function-for-function, logic-for-logic C port of RRKDHT.py
 * (Production Rotating Rendezvous Kademlia Distributed Hash Table with
 * RWP protocol support, epoch-based key rotation, and production features).
 *
 * Every Python class, method, module-level function and constant is ported:
 *
 *   Config                 -> CFG_* constants / config_get_max_neighbors()
 *   create_ed25519_key_pair-> create_ed25519_key_pair()
 *   generate_peer_id       -> generate_peer_id()
 *   digest                 -> digest()
 *   EpochManager           -> EpochManager_*
 *   MessageType            -> MessageType (enum + message_type_value())
 *   Message                -> Message
 *   NodeInfo               -> NodeInfo (+ NodeInfo_is_expired)
 *   SecureMessaging        -> SecureMessaging_*
 *   Node                   -> Node_*
 *   NodeHeap               -> NodeHeap_*
 *   SearchResult           -> SearchResult
 *   NodeSearch             -> NodeSearch_*
 *   RWPProtocolHandler     -> folded into RWPDHTHandler_* (only subclass is
 *                             ever instantiated in the Python code)
 *   RRKDHTProtocol         -> RRKDHTProtocol_* (includes RPCProtocol base:
 *                             msgpack UDP RPC, _outstanding map, timeouts)
 *   KBucket                -> KBucket_*
 *   TableTraverser         -> TableTraverser_*
 *   RoutingTable           -> RoutingTable_*
 *   RPCFindResponse        -> RPCFindResponse_*
 *   SpiderCrawl            -> SpiderCrawl_* / NodeSpiderCrawl_*
 *   gather_dict            -> gather_dict()
 *   shared_prefix          -> shared_prefix()
 *   bytes_to_bit_string    -> bytes_to_bit_string()
 *   RRKDHT                 -> RRKDHT_* (every method, incl. the duplicated
 *                             _synchronized_heartbeat_check: in Python the
 *                             second definition shadows the first; both are
 *                             kept here, the second one is the live one)
 *   RWPDHTHandler          -> RWPDHTHandler_*
 *
 * Concurrency model: Python asyncio is emulated with pthreads.
 *   - asyncio.ensure_future(coro)        -> detached pthread
 *   - asyncio.gather(*tasks)             -> one pthread per task + join
 *   - loop.call_later(delay, cb)         -> global timer scheduler thread
 *   - asyncio.sleep(t)                   -> nanosleep
 *   - RPC future / wait_for(timeout)     -> pthread mutex + cond timedwait
 *
 * Wire compatibility with the Python implementation is preserved:
 *   - UDP RPC: rpcudp 5.x framing  \\x00|\\x01 + 20-byte msgid + msgpack
 *   - RWP TCP: "RWP/1.0" request/response, JSON bodies, base64 envelopes
 *   - Encryption: X25519 + HKDF-SHA256('rrdht-encryption') + ChaCha20-Poly1305
 *   - State files: Python pickle (protocol 0 written, protocols 0-5 read)
 *
 * Build:
 *   gcc -O2 -Wall -o rrkdht RRKDHT.c -lcrypto -lpthread -lm
 *
 * (OpenSSL >= 3.0 required for Ed25519/X25519/HKDF/ChaCha20-Poly1305.)
 * ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <stdatomic.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

/* ============================================================================
 * LOGGING (mirrors python logging; Python hardcodes
 * logging.getLogger("RRKDHT").setLevel(logging.DEBUG), so default here is
 * DEBUG too — override with env RRKDHT_LOG_LEVEL)
 * ============================================================================ */

typedef enum { LL_DEBUG = 10, LL_INFO = 20, LL_WARNING = 30, LL_ERROR = 40 } LogLevel;

static LogLevel g_log_level = LL_DEBUG;
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;

static const char *level_name(LogLevel l) {
    switch (l) {
        case LL_DEBUG:   return "DEBUG";
        case LL_INFO:    return "INFO";
        case LL_WARNING: return "WARNING";
        default:         return "ERROR";
    }
}

static void log_emit(LogLevel lvl, const char *fmt, ...) {
    if (lvl < g_log_level) return;
    pthread_mutex_lock(&g_log_mu);
    fprintf(stderr, "%s:RRKDHT:", level_name(lvl));
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
    pthread_mutex_unlock(&g_log_mu);
}

#define log_debug(...)   log_emit(LL_DEBUG, __VA_ARGS__)
#define log_info(...)    log_emit(LL_INFO, __VA_ARGS__)
#define log_warning(...) log_emit(LL_WARNING, __VA_ARGS__)
#define log_error(...)   log_emit(LL_ERROR, __VA_ARGS__)

static void log_init_from_env(void) {
    const char *e = getenv("RRKDHT_LOG_LEVEL");
    if (!e) return;
    if (!strcasecmp(e, "DEBUG"))   g_log_level = LL_DEBUG;
    else if (!strcasecmp(e, "INFO"))    g_log_level = LL_INFO;
    else if (!strcasecmp(e, "WARNING")) g_log_level = LL_WARNING;
    else if (!strcasecmp(e, "ERROR"))   g_log_level = LL_ERROR;
}

/* ============================================================================
 * SMALL UTILITIES
 * ============================================================================ */

/* When true (set via the --no-publish CLI flag), this node participates in
 * the DHT for lookups/routing purposes only and never publishes its own
 * rendezvous key. Intended for lookup-only clients that don't host content
 * and therefore have nothing for anyone to find. */
static bool g_no_self_publish = false;
static bool g_require_sigs = false;

/* ==================== PRODUCTION HARDENING ==================== */
/* Rate limiting + thread/connection caps + memory check macro */

#define MAX_UDP_PER_SEC        50    /* max RPC messages per IP per second */
#define MAX_RWP_PER_SEC        20    /* max RWP connections per IP per second */
#define MAX_HANDLER_THREADS    64    /* max concurrent request-handler threads */
#define MAX_RWP_CONNECTIONS    20    /* max concurrent RWP TCP connections */
#define SYBIL_MAX_NODES_PER_IP 20    /* distinct node IDs allowed per source IP
                                        (NAT tradeoff: >20 devices behind one
                                        public IP get capped; raise if needed) */
#define RATE_TABLE_SIZE        256   /* per-IP rate tracking slots */

typedef struct {
    char ip[16];
    int64_t window_start;
    int count;
} RateEntry;

static RateEntry g_rate_table[RATE_TABLE_SIZE];
static pthread_mutex_t g_rate_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_rate_next = 0;

static _Atomic int g_handler_threads = 0;   /* active request-handler threads */
static _Atomic int g_rwp_connections = 0;   /* active RWP TCP connections */

/* Thread guard: wraps a thread function and decrements a counter
 * on exit, regardless of how the thread terminates. */
typedef struct {
    void *(*fn)(void *);
    void *arg;
    _Atomic int *counter;
} ThreadGuardCtx;

static void *thread_guard(void *arg) {
    ThreadGuardCtx *g = arg;
    void *result = g->fn(g->arg);
    atomic_fetch_sub(g->counter, 1);
    free(g);
    return result;
}

/* Check if an IP is within rate limits. Returns true if allowed. */
static bool rate_check(const char *ip, int max_per_sec) {
    pthread_mutex_lock(&g_rate_mu);
    int64_t now = (int64_t)time(NULL);

    for (int i = 0; i < RATE_TABLE_SIZE; i++) {
        if (g_rate_table[i].count > 0 && strcmp(g_rate_table[i].ip, ip) == 0) {
            if (now - g_rate_table[i].window_start >= 1) {
                g_rate_table[i].window_start = now;
                g_rate_table[i].count = 0;
            }
            g_rate_table[i].count++;
            bool ok = g_rate_table[i].count <= max_per_sec;
            pthread_mutex_unlock(&g_rate_mu);
            if (!ok) {
                log_warning("Rate limit: %s exceeded %d msg/s (count=%d)",
                            ip, max_per_sec, g_rate_table[i].count);
            }
            return ok;
        }
    }

    /* New IP — round-robin insert (evicts the oldest entry) */
    int slot = g_rate_next++ % RATE_TABLE_SIZE;
    snprintf(g_rate_table[slot].ip, sizeof(g_rate_table[slot].ip), "%s", ip);
    g_rate_table[slot].window_start = now;
    g_rate_table[slot].count = 1;
    pthread_mutex_unlock(&g_rate_mu);
    return true;
}

/* Safe memory allocation with NULL check */
#define SAFE_CALLOC(type, count) ({ \
    type *_p = calloc(count, sizeof(type)); \
    if (!_p) { \
        log_error("FATAL: calloc(%zu, %zu) failed at %s:%d", \
                  (size_t)count, sizeof(type), __FILE__, __LINE__); \
    } \
    _p; \
})

#define SAFE_MALLOC(size) ({ \
    void *_p = malloc(size); \
    if (!_p) { \
        log_error("FATAL: malloc(%zu) failed at %s:%d", \
                  (size_t)(size), __FILE__, __LINE__); \
    } \
    _p; \
})
/* ==================== END HARDENING ==================== */

static double now_time(void) {                 /* time.time() */
    struct timeval tv; gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static double now_mono(void) {                 /* time.monotonic() */
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void py_sleep(double secs) {            /* asyncio.sleep / time.sleep */
    if (secs <= 0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)secs;
    ts.tv_nsec = (long)((secs - (double)ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
}

static void rand_bytes(uint8_t *out, size_t n) { RAND_bytes(out, (int)n); }

static double py_uniform(double a, double b) { /* random.uniform(a, b) */
    uint64_t r; rand_bytes((uint8_t *)&r, sizeof(r));
    double u = ((double)(r >> 11)) * (1.0 / 9007199254740992.0); /* [0,1) */
    return a + (b - a) * u;
}

static char *xstrdup(const char *s) {
    if (!s) return NULL;
    char *d = malloc(strlen(s) + 1);
    if (d) strcpy(d, s);
    return d;
}

static char *hex_encode(const uint8_t *data, size_t len) {   /* bytes.hex() */
    char *out = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
    return out;
}

static bool hex_decode(const char *hex, uint8_t *out, size_t out_len) { /* bytes.fromhex() */
    size_t hlen = strlen(hex);
    if (hlen != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

/* Python str.startswith helper */
static bool starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) return false;
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* ============================================================================
 * u256 — fixed 256-bit unsigned integer (little-endian limbs).
 * Node IDs are 160-bit; Kademlia bucket ranges go up to 2**160, so 256 bits
 * covers every value the Python code computes with arbitrary-precision ints.
 * ============================================================================ */

typedef struct { uint64_t w[4]; } u256;   /* w[0] = least significant */

static u256 u256_zero(void) { u256 v; memset(&v, 0, sizeof(v)); return v; }

static bool u256_is_zero(u256 a) {
    return (a.w[0] | a.w[1] | a.w[2] | a.w[3]) == 0;
}

static u256 u256_from_u64(uint64_t x) { u256 v = u256_zero(); v.w[0] = x; return v; }

/* int(node_id.hex(), 16): big-endian 20 bytes -> integer */
static u256 u256_from_bytes_be20(const uint8_t b[20]) {
    u256 v = u256_zero();
    for (int i = 0; i < 20; i++) {
        int byte_index = 19 - i;                 /* little-endian byte position */
        v.w[byte_index / 8] |= (uint64_t)b[i] << (8 * (byte_index % 8));
    }
    return v;
}

static u256 u256_pow2(int bit) {               /* 2**bit */
    u256 v = u256_zero();
    v.w[bit / 64] = 1ULL << (bit % 64);
    return v;
}

static int u256_cmp(u256 a, u256 b) {
    for (int i = 3; i >= 0; i--) {
        if (a.w[i] < b.w[i]) return -1;
        if (a.w[i] > b.w[i]) return 1;
    }
    return 0;
}

static bool u256_eq(u256 a, u256 b) { return u256_cmp(a, b) == 0; }
static bool u256_lt(u256 a, u256 b) { return u256_cmp(a, b) < 0; }
static bool u256_le(u256 a, u256 b) { return u256_cmp(a, b) <= 0; }
static bool u256_gt(u256 a, u256 b) { return u256_cmp(a, b) > 0; }

static u256 u256_xor(u256 a, u256 b) {
    u256 v;
    for (int i = 0; i < 4; i++) v.w[i] = a.w[i] ^ b.w[i];
    return v;
}

static u256 u256_add(u256 a, u256 b) {
    u256 v;
    unsigned __int128 carry = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 s = (unsigned __int128)a.w[i] + b.w[i] + carry;
        v.w[i] = (uint64_t)s;
        carry = s >> 64;
    }
    return v;
}

static u256 u256_sub(u256 a, u256 b) {
    u256 v;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t bi = b.w[i] + borrow;
        v.w[i] = a.w[i] - bi;
        borrow = (a.w[i] < bi) ? 1 : 0;
    }
    return v;
}

static u256 u256_shr1(u256 a) {                /* a >> 1 (for //2 midpoint) */
    u256 v;
    for (int i = 0; i < 4; i++) {
        v.w[i] = (a.w[i] >> 1) | ((i < 3) ? (a.w[i + 1] << 63) : 0);
    }
    return v;
}

/* inverse of u256_from_bytes_be20: integer -> big-endian 20 bytes */
static void u256_to_bytes_be20(u256 a, uint8_t out[20]) {
    for (int i = 0; i < 20; i++) {
        int byte_index = 19 - i;
        out[i] = (uint8_t)(a.w[byte_index / 8] >> (8 * (byte_index % 8)));
    }
}

static int u256_bitlen(u256 a) {
    for (int i = 3; i >= 0; i--) {
        if (a.w[i]) {
            for (int b = 63; b >= 0; b--)
                if (a.w[i] & (1ULL << b)) return i * 64 + b + 1;
        }
    }
    return 0;
}

/* random.randint(0, max) inclusive, via bitmasking + rejection sampling
 * (unbiased, and since max's bit length bounds the mask, at least ~50%
 * of draws are accepted per attempt) */
static u256 u256_rand_below_incl(u256 max) {
    if (u256_is_zero(max)) return u256_zero();
    int bits = u256_bitlen(max);
    int nbytes = (bits + 7) / 8;
    int extra_bits = nbytes * 8 - bits;
    u256 r;
    do {
        uint8_t buf[32] = {0};
        rand_bytes(buf, nbytes);
        if (extra_bits > 0) buf[nbytes - 1] &= (uint8_t)(0xFF >> extra_bits);
        r = u256_zero();
        for (int i = 0; i < nbytes; i++) r.w[i / 8] |= (uint64_t)buf[i] << (8 * (i % 8));
    } while (u256_lt(max, r));
    return r;
}

/* random.randint(*bucket.range): uniform random id within [lo, hi] inclusive */
static u256 u256_rand_in_range(u256 lo, u256 hi) {
    u256 width = u256_sub(hi, lo);
    return u256_add(lo, u256_rand_below_incl(width));
}


/* decimal string (Python str(int)) — caller frees */
static char *u256_to_dec(u256 a) {
    if (u256_is_zero(a)) return xstrdup("0");
    char tmp[80]; int pos = 0;
    u256 v = a;
    while (!u256_is_zero(v)) {
        /* divmod by 10 */
        u256 q = u256_zero();
        uint64_t rem = 0;
        for (int i = 3; i >= 0; i--) {
            unsigned __int128 cur = ((unsigned __int128)rem << 64) | v.w[i];
            q.w[i] = (uint64_t)(cur / 10);
            rem = (uint64_t)(cur % 10);
        }
        tmp[pos++] = (char)('0' + rem);
        v = q;
    }
    char *out = malloc(pos + 1);
    for (int i = 0; i < pos; i++) out[i] = tmp[pos - 1 - i];
    out[pos] = '\0';
    return out;
}

/* f"{value:#x}" — "0x" + lowercase hex without leading zeros — caller frees */
static char *u256_to_hex0x(u256 a) {
    if (u256_is_zero(a)) return xstrdup("0x0");
    char buf[3 + 64 + 1];
    strcpy(buf, "0x");
    bool started = false;
    int pos = 2;
    for (int i = 3; i >= 0; i--) {
        if (!started) {
            if (a.w[i] == 0) continue;
            pos += sprintf(buf + pos, "%llx", (unsigned long long)a.w[i]);
            started = true;
        } else {
            pos += sprintf(buf + pos, "%016llx", (unsigned long long)a.w[i]);
        }
    }
    return xstrdup(buf);
}

/* ============================================================================
 * StrBuf — growable string builder
 * ============================================================================ */

typedef struct { char *buf; size_t len, cap; } StrBuf;

static void sb_init(StrBuf *sb) {
    sb->cap = 256; sb->len = 0;
    sb->buf = malloc(sb->cap); sb->buf[0] = '\0';
}

static void sb_grow(StrBuf *sb, size_t need) {
    if (sb->len + need + 1 > sb->cap) {
        while (sb->len + need + 1 > sb->cap) sb->cap *= 2;
        sb->buf = realloc(sb->buf, sb->cap);
    }
}

static void sb_addn(StrBuf *sb, const char *data, size_t n) {
    sb_grow(sb, n);
    memcpy(sb->buf + sb->len, data, n);
    sb->len += n; sb->buf[sb->len] = '\0';
}

static void sb_add(StrBuf *sb, const char *s) { sb_addn(sb, s, strlen(s)); }

static void sb_addc(StrBuf *sb, char c) { sb_addn(sb, &c, 1); }

static void sb_addf(StrBuf *sb, const char *fmt, ...) {
    char tmp[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    sb_add(sb, tmp);
}

static char *sb_steal(StrBuf *sb) { char *r = sb->buf; sb->buf = NULL; return r; }
static void sb_free(StrBuf *sb) { free(sb->buf); sb->buf = NULL; }

/* ============================================================================
 * base64 (RFC 4648, standard alphabet, with padding) — matches base64.b64*
 * ============================================================================ */

static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i+1] << 8) | data[i+2];
        out[j++] = B64T[(v >> 18) & 63]; out[j++] = B64T[(v >> 12) & 63];
        out[j++] = B64T[(v >> 6) & 63];  out[j++] = B64T[v & 63];
    }
    if (i < len) {
        uint32_t v = (uint32_t)data[i] << 16;
        int rem = (int)(len - i);
        if (rem == 2) v |= (uint32_t)data[i+1] << 8;
        out[j++] = B64T[(v >> 18) & 63];
        out[j++] = B64T[(v >> 12) & 63];
        out[j++] = (rem == 2) ? B64T[(v >> 6) & 63] : '=';
        out[j++] = '=';
    }
    out[j] = '\0';
    return out;
}

static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static uint8_t *b64_decode(const char *s, size_t *out_len) {
    size_t len = strlen(s);
    uint8_t *out = malloc(len * 3 / 4 + 4);
    size_t j = 0;
    int acc = 0, nbits = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '=' || s[i] == '\n' || s[i] == '\r') continue;
        int v = b64_val((unsigned char)s[i]);
        if (v < 0) { free(out); return NULL; }
        acc = (acc << 6) | v; nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            out[j++] = (uint8_t)((acc >> nbits) & 0xFF);
        }
    }
    *out_len = j;
    return out;
}

/* ============================================================================
 * JSON — value model + parser + serializer.
 * Serialization matches Python json.dumps() defaults: separators ", " / ": ",
 * ensure_ascii-style escaping of control characters.
 * ============================================================================ */

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;

typedef struct JVal {
    JType t;
    bool b;
    double num;
    bool is_int;          /* print without decimal point (Python int) */
    char *rawnum;         /* exact integer literal for big ints (optional) */
    char *s;              /* J_STR */
    struct JVal **items; size_t nitems, capitems;  /* J_ARR */
    char **keys; struct JVal **vals; size_t npairs, cappairs; /* J_OBJ */
} JVal;

static JVal *j_new(JType t) {
    JVal *v = SAFE_CALLOC(JVal, 1);
    if (!v) return NULL;
    v->t = t;
    return v;
}

static JVal *j_null(void)  { return j_new(J_NULL); }
static JVal *j_bool(bool b){ JVal *v = j_new(J_BOOL); v->b = b; return v; }
static JVal *j_num(double n){ JVal *v = j_new(J_NUM); v->num = n; v->is_int = false; return v; }
static JVal *j_int(int64_t n){ JVal *v = j_new(J_NUM); v->num = (double)n; v->is_int = true; return v; }
static JVal *j_str(const char *s){ JVal *v = j_new(J_STR); v->s = xstrdup(s ? s : ""); return v; }
static JVal *j_arr(void)   { return j_new(J_ARR); }
static JVal *j_obj(void)   { return j_new(J_OBJ); }

/* exact big-integer literal (Python unbounded int -> JSON) */
static JVal *j_rawnum(const char *decimal) {
    JVal *v = j_new(J_NUM);
    v->rawnum = xstrdup(decimal);
    return v;
}

static JVal *j_u256(u256 x) {
    char *dec = u256_to_dec(x);
    JVal *v = j_rawnum(dec);
    free(dec);
    return v;
}

static void j_free(JVal *v) {
    if (!v) return;
    free(v->rawnum);
    if (v->t == J_STR) free(v->s);
    if (v->t == J_ARR) {
        for (size_t i = 0; i < v->nitems; i++) j_free(v->items[i]);
        free(v->items);
    }
    if (v->t == J_OBJ) {
        for (size_t i = 0; i < v->npairs; i++) { free(v->keys[i]); j_free(v->vals[i]); }
        free(v->keys); free(v->vals);
    }
    free(v);
}

static void j_arr_add(JVal *arr, JVal *item) {
    if (arr->nitems == arr->capitems) {
        arr->capitems = arr->capitems ? arr->capitems * 2 : 8;
        arr->items = realloc(arr->items, arr->capitems * sizeof(JVal *));
    }
    arr->items[arr->nitems++] = item;
}

static void j_obj_set(JVal *obj, const char *key, JVal *val) {
    for (size_t i = 0; i < obj->npairs; i++) {
        if (!strcmp(obj->keys[i], key)) {
            j_free(obj->vals[i]);
            obj->vals[i] = val;
            return;
        }
    }
    if (obj->npairs == obj->cappairs) {
        obj->cappairs = obj->cappairs ? obj->cappairs * 2 : 8;
        obj->keys = realloc(obj->keys, obj->cappairs * sizeof(char *));
        obj->vals = realloc(obj->vals, obj->cappairs * sizeof(JVal *));
    }
    obj->keys[obj->npairs] = xstrdup(key);
    obj->vals[obj->npairs] = val;
    obj->npairs++;
}

static JVal *j_obj_get(const JVal *obj, const char *key) {
    if (!obj || obj->t != J_OBJ) return NULL;
    for (size_t i = 0; i < obj->npairs; i++)
        if (!strcmp(obj->keys[i], key)) return obj->vals[i];
    return NULL;
}

/* dict.get(key, default) helpers */
static bool j_obj_has(const JVal *obj, const char *key) { return j_obj_get(obj, key) != NULL; }

static const char *j_get_str(const JVal *obj, const char *key) {
    JVal *v = j_obj_get(obj, key);
    return (v && v->t == J_STR) ? v->s : NULL;
}

static double j_get_num(const JVal *obj, const char *key, double dflt) {
    JVal *v = j_obj_get(obj, key);
    return (v && v->t == J_NUM) ? v->num : dflt;
}

static bool j_get_bool(const JVal *obj, const char *key, bool dflt) {
    JVal *v = j_obj_get(obj, key);
    if (v && v->t == J_BOOL) return v->b;
    if (v && v->t == J_NUM) return v->num != 0;
    return dflt;
}

static JVal *j_deepcopy(const JVal *v) {
    if (!v) return NULL;
    JVal *c = j_new(v->t);
    c->b = v->b; c->num = v->num; c->is_int = v->is_int;
    if (v->rawnum) c->rawnum = xstrdup(v->rawnum);
    if (v->t == J_STR) c->s = xstrdup(v->s);
    if (v->t == J_ARR)
        for (size_t i = 0; i < v->nitems; i++) j_arr_add(c, j_deepcopy(v->items[i]));
    if (v->t == J_OBJ)
        for (size_t i = 0; i < v->npairs; i++) j_obj_set(c, v->keys[i], j_deepcopy(v->vals[i]));
    return c;
}

/* --- serializer (Python json.dumps style) --- */

static void j_print_rec(const JVal *v, StrBuf *sb) {
    switch (v->t) {
        case J_NULL: sb_add(sb, "null"); break;
        case J_BOOL: sb_add(sb, v->b ? "true" : "false"); break;
        case J_NUM: {
            if (v->rawnum) { sb_add(sb, v->rawnum); break; }
            if (v->is_int) {
                sb_addf(sb, "%lld", (long long)v->num);
            } else if (isnan(v->num)) {
                sb_add(sb, "NaN");
            } else if (isinf(v->num)) {
                sb_add(sb, v->num > 0 ? "Infinity" : "-Infinity");
            } else {
                char tmp[64];
                /* repr()-style shortest round trip approximation */
                snprintf(tmp, sizeof(tmp), "%.17g", v->num);
                /* trim to shortest form that round-trips */
                for (int prec = 1; prec <= 17; prec++) {
                    char cand[64];
                    snprintf(cand, sizeof(cand), "%.*g", prec, v->num);
                    if (strtod(cand, NULL) == v->num) { strcpy(tmp, cand); break; }
                }
                /* Python floats always carry a decimal point or exponent */
                if (!strchr(tmp, '.') && !strchr(tmp, 'e') && !strchr(tmp, 'E') &&
                    !strchr(tmp, 'n') /* inf/nan already handled */)
                    strcat(tmp, ".0");
                sb_add(sb, tmp);
            }
            break;
        }
        case J_STR: {
            sb_add(sb, "\"");
            for (const unsigned char *p = (const unsigned char *)v->s; *p; p++) {
                switch (*p) {
                    case '"':  sb_add(sb, "\\\""); break;
                    case '\\': sb_add(sb, "\\\\"); break;
                    case '\b': sb_add(sb, "\\b"); break;
                    case '\f': sb_add(sb, "\\f"); break;
                    case '\n': sb_add(sb, "\\n"); break;
                    case '\r': sb_add(sb, "\\r"); break;
                    case '\t': sb_add(sb, "\\t"); break;
                    default:
                        if (*p < 0x20) sb_addf(sb, "\\u%04x", *p);
                        else sb_addn(sb, (const char *)p, 1);
                }
            }
            sb_add(sb, "\"");
            break;
        }
        case J_ARR:
            sb_add(sb, "[");
            for (size_t i = 0; i < v->nitems; i++) {
                if (i) sb_add(sb, ", ");
                j_print_rec(v->items[i], sb);
            }
            sb_add(sb, "]");
            break;
        case J_OBJ:
            sb_add(sb, "{");
            for (size_t i = 0; i < v->npairs; i++) {
                if (i) sb_add(sb, ", ");
                JVal k = { .t = J_STR, .s = v->keys[i] };
                j_print_rec(&k, sb);
                sb_add(sb, ": ");
                j_print_rec(v->vals[i], sb);
            }
            sb_add(sb, "}");
            break;
    }
}

static char *j_dumps(const JVal *v) {
    StrBuf sb; sb_init(&sb);
    j_print_rec(v, &sb);
    return sb_steal(&sb);
}

/* --- parser (robust recursive descent, json.loads equivalent) --- */

typedef struct { const char *p; bool ok; } JParser;

static void j_skip_ws(JParser *ps) {
    while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r') ps->p++;
}

static JVal *j_parse_value(JParser *ps, int depth);

static bool j_parse_hex4(JParser *ps, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = ps->p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return false;
    }
    ps->p += 4;
    *out = v;
    return true;
}

static void j_utf8_encode(StrBuf *sb, unsigned cp) {
    char tmp[4]; int n = 0;
    if (cp < 0x80) tmp[n++] = (char)cp;
    else if (cp < 0x800) {
        tmp[n++] = (char)(0xC0 | (cp >> 6));
        tmp[n++] = (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        tmp[n++] = (char)(0xE0 | (cp >> 12));
        tmp[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[n++] = (char)(0x80 | (cp & 0x3F));
    } else {
        tmp[n++] = (char)(0xF0 | (cp >> 18));
        tmp[n++] = (char)(0x80 | ((cp >> 12) & 0x3F));
        tmp[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[n++] = (char)(0x80 | (cp & 0x3F));
    }
    sb_addn(sb, tmp, n);
}

static char *j_parse_string_raw(JParser *ps) {
    if (*ps->p != '"') { ps->ok = false; return NULL; }
    ps->p++;
    StrBuf sb; sb_init(&sb);
    while (*ps->p && *ps->p != '"') {
        if (*ps->p == '\\') {
            ps->p++;
            switch (*ps->p) {
                case '"': sb_addn(&sb, "\"", 1); ps->p++; break;
                case '\\': sb_addn(&sb, "\\", 1); ps->p++; break;
                case '/': sb_addn(&sb, "/", 1); ps->p++; break;
                case 'b': sb_addn(&sb, "\b", 1); ps->p++; break;
                case 'f': sb_addn(&sb, "\f", 1); ps->p++; break;
                case 'n': sb_addn(&sb, "\n", 1); ps->p++; break;
                case 'r': sb_addn(&sb, "\r", 1); ps->p++; break;
                case 't': sb_addn(&sb, "\t", 1); ps->p++; break;
                case 'u': {
                    ps->p++;
                    unsigned cp;
                    if (!j_parse_hex4(ps, &cp)) { ps->ok = false; sb_free(&sb); return NULL; }
                    if (cp >= 0xD800 && cp <= 0xDBFF && ps->p[0] == '\\' && ps->p[1] == 'u') {
                        ps->p += 2;
                        unsigned lo;
                        if (j_parse_hex4(ps, &lo) && lo >= 0xDC00 && lo <= 0xDFFF)
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    j_utf8_encode(&sb, cp);
                    break;
                }
                default: ps->ok = false; sb_free(&sb); return NULL;
            }
        } else {
            sb_addn(&sb, ps->p, 1);
            ps->p++;
        }
    }
    if (*ps->p != '"') { ps->ok = false; sb_free(&sb); return NULL; }
    ps->p++;
    return sb_steal(&sb);
}

static JVal *j_parse_value(JParser *ps, int depth) {
    if (depth > 200 || !ps->ok) { ps->ok = false; return NULL; }
    j_skip_ws(ps);
    char c = *ps->p;
    if (c == '{') {
        ps->p++;
        JVal *obj = j_obj();
        j_skip_ws(ps);
        if (*ps->p == '}') { ps->p++; return obj; }
        while (ps->ok) {
            j_skip_ws(ps);
            char *key = j_parse_string_raw(ps);
            if (!key) break;
            j_skip_ws(ps);
            if (*ps->p != ':') { free(key); ps->ok = false; break; }
            ps->p++;
            JVal *val = j_parse_value(ps, depth + 1);
            if (!val) { free(key); j_free(obj); return NULL; }
            j_obj_set(obj, key, val);
            free(key);
            j_skip_ws(ps);
            if (*ps->p == ',') { ps->p++; continue; }
            if (*ps->p == '}') { ps->p++; return obj; }
            ps->ok = false;
        }
        j_free(obj);
        return NULL;
    }
    if (c == '[') {
        ps->p++;
        JVal *arr = j_arr();
        j_skip_ws(ps);
        if (*ps->p == ']') { ps->p++; return arr; }
        while (ps->ok) {
            JVal *val = j_parse_value(ps, depth + 1);
            if (!val) { j_free(arr); return NULL; }
            j_arr_add(arr, val);
            j_skip_ws(ps);
            if (*ps->p == ',') { ps->p++; continue; }
            if (*ps->p == ']') { ps->p++; return arr; }
            ps->ok = false;
        }
        j_free(arr);
        return NULL;
    }
    if (c == '"') {
        char *s = j_parse_string_raw(ps);
        if (!s) return NULL;
        JVal *v = j_new(J_STR); v->s = s;
        return v;
    }
    if (!strncmp(ps->p, "true", 4))  { ps->p += 4; return j_bool(true); }
    if (!strncmp(ps->p, "false", 5)) { ps->p += 5; return j_bool(false); }
    if (!strncmp(ps->p, "null", 4))  { ps->p += 4; return j_null(); }
    if (!strncmp(ps->p, "NaN", 3))   { ps->p += 3; return j_num(NAN); }
    if (!strncmp(ps->p, "Infinity", 8))  { ps->p += 8; return j_num(INFINITY); }
    if (!strncmp(ps->p, "-Infinity", 9)) { ps->p += 9; return j_num(-INFINITY); }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char *end;
        double d = strtod(ps->p, &end);
        if (end == ps->p) { ps->ok = false; return NULL; }
        bool is_int = true;
        for (const char *q = ps->p; q < end; q++)
            if (*q == '.' || *q == 'e' || *q == 'E') { is_int = false; break; }
        ps->p = end;
        JVal *v = j_num(d);
        v->is_int = is_int;
        return v;
    }
    ps->ok = false;
    return NULL;
}

static JVal *j_loads(const char *text) {
    if (!text) return NULL;
    JParser ps = { .p = text, .ok = true };
    JVal *v = j_parse_value(&ps, 0);
    j_skip_ws(&ps);
    if (!ps.ok || !v) { j_free(v); return NULL; }
    return v;
}

/* ============================================================================
 * MessagePack — minimal but complete packer/unpacker for the types used by
 * rpcudp (umsgpack): nil, bool, int, float, str, bin, array, map.
 * Python str -> str family, Python bytes -> bin family (use_bin_type=True).
 * ============================================================================ */

typedef enum { M_NIL, M_BOOL, M_INT, M_UINT, M_FLOAT, M_STR, M_BIN, M_ARR, M_MAP } MType;

typedef struct MVal {
    MType t;
    bool b;
    int64_t i;
    uint64_t u;
    double f;
    char *str;                 /* M_STR (utf-8, NUL-terminated) */
    uint8_t *bin; size_t blen; /* M_BIN */
    struct MVal **items; size_t nitems; /* M_ARR / M_MAP (map: key,val,key,val...) */
} MVal;

static MVal *m_new(MType t) { MVal *v = calloc(1, sizeof(MVal)); v->t = t; return v; }
static MVal *m_nil(void) { return m_new(M_NIL); }
static MVal *m_bool(bool b) { MVal *v = m_new(M_BOOL); v->b = b; return v; }
static MVal *m_int(int64_t i) { MVal *v = m_new(M_INT); v->i = i; return v; }
static MVal *m_str(const char *s) { MVal *v = m_new(M_STR); v->str = xstrdup(s); return v; }
static MVal *m_bin(const uint8_t *data, size_t len) {
    MVal *v = m_new(M_BIN);
    v->bin = malloc(len ? len : 1);
    memcpy(v->bin, data, len);
    v->blen = len;
    return v;
}
static MVal *m_arr(void) { return m_new(M_ARR); }

static void m_arr_add(MVal *arr, MVal *item) {
    arr->items = realloc(arr->items, (arr->nitems + 1) * sizeof(MVal *));
    arr->items[arr->nitems++] = item;
}

static void m_free(MVal *v) {
    if (!v) return;
    free(v->str); free(v->bin);
    if (v->t == M_ARR || v->t == M_MAP)
        for (size_t i = 0; i < v->nitems; i++) m_free(v->items[i]);
    free(v->items);
    free(v);
}

/* --- packer --- */

static void mp_u8(StrBuf *sb, uint8_t v)  { sb_addn(sb, (char *)&v, 1); }
static void mp_be16(StrBuf *sb, uint16_t v) { uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v }; sb_addn(sb, (char *)b, 2); }
static void mp_be32(StrBuf *sb, uint32_t v) { uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v }; sb_addn(sb, (char *)b, 4); }
static void mp_be64(StrBuf *sb, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8 * i));
    sb_addn(sb, (char *)b, 8);
}

static void mp_pack_rec(const MVal *v, StrBuf *sb) {
    switch (v->t) {
        case M_NIL:  mp_u8(sb, 0xc0); break;
        case M_BOOL: mp_u8(sb, v->b ? 0xc3 : 0xc2); break;
        case M_INT: {
            int64_t i = v->i;
            if (i >= 0) {
                if (i < 128) mp_u8(sb, (uint8_t)i);                       /* positive fixint */
                else if (i <= 0xFF) { mp_u8(sb, 0xcc); mp_u8(sb, (uint8_t)i); }
                else if (i <= 0xFFFF) { mp_u8(sb, 0xcd); mp_be16(sb, (uint16_t)i); }
                else if (i <= 0xFFFFFFFFLL) { mp_u8(sb, 0xce); mp_be32(sb, (uint32_t)i); }
                else { mp_u8(sb, 0xcf); mp_be64(sb, (uint64_t)i); }
            } else {
                if (i >= -32) mp_u8(sb, (uint8_t)(i & 0xFF));             /* negative fixint */
                else if (i >= -128) { mp_u8(sb, 0xd0); mp_u8(sb, (uint8_t)(i & 0xFF)); }
                else if (i >= -32768) { mp_u8(sb, 0xd1); mp_be16(sb, (uint16_t)(i & 0xFFFF)); }
                else if (i >= -2147483648LL) { mp_u8(sb, 0xd2); mp_be32(sb, (uint32_t)(i & 0xFFFFFFFFULL)); }
                else { mp_u8(sb, 0xd3); mp_be64(sb, (uint64_t)i); }
            }
            break;
        }
        case M_UINT:
            if (v->u < 128) mp_u8(sb, (uint8_t)v->u);
            else if (v->u <= 0xFF) { mp_u8(sb, 0xcc); mp_u8(sb, (uint8_t)v->u); }
            else if (v->u <= 0xFFFF) { mp_u8(sb, 0xcd); mp_be16(sb, (uint16_t)v->u); }
            else if (v->u <= 0xFFFFFFFFULL) { mp_u8(sb, 0xce); mp_be32(sb, (uint32_t)v->u); }
            else { mp_u8(sb, 0xcf); mp_be64(sb, v->u); }
            break;
        case M_FLOAT: {
            mp_u8(sb, 0xcb);
            uint64_t bits; memcpy(&bits, &v->f, 8);
            mp_be64(sb, bits);
            break;
        }
        case M_STR: {
            size_t n = v->str ? strlen(v->str) : 0;
            if (n < 32) mp_u8(sb, (uint8_t)(0xa0 | n));
            else if (n <= 0xFF) { mp_u8(sb, 0xd9); mp_u8(sb, (uint8_t)n); }
            else if (n <= 0xFFFF) { mp_u8(sb, 0xda); mp_be16(sb, (uint16_t)n); }
            else { mp_u8(sb, 0xdb); mp_be32(sb, (uint32_t)n); }
            if (n) sb_addn(sb, v->str, n);
            break;
        }
        case M_BIN: {
            if (v->blen <= 0xFF) { mp_u8(sb, 0xc4); mp_u8(sb, (uint8_t)v->blen); }
            else if (v->blen <= 0xFFFF) { mp_u8(sb, 0xc5); mp_be16(sb, (uint16_t)v->blen); }
            else { mp_u8(sb, 0xc6); mp_be32(sb, (uint32_t)v->blen); }
            sb_addn(sb, (char *)v->bin, v->blen);
            break;
        }
        case M_ARR: {
            if (v->nitems < 16) mp_u8(sb, (uint8_t)(0x90 | v->nitems));
            else if (v->nitems <= 0xFFFF) { mp_u8(sb, 0xdc); mp_be16(sb, (uint16_t)v->nitems); }
            else { mp_u8(sb, 0xdd); mp_be32(sb, (uint32_t)v->nitems); }
            for (size_t k = 0; k < v->nitems; k++) mp_pack_rec(v->items[k], sb);
            break;
        }
        case M_MAP: {
            size_t pairs = v->nitems / 2;
            if (pairs < 16) mp_u8(sb, (uint8_t)(0x80 | pairs));
            else if (pairs <= 0xFFFF) { mp_u8(sb, 0xde); mp_be16(sb, (uint16_t)pairs); }
            else { mp_u8(sb, 0xdf); mp_be32(sb, (uint32_t)pairs); }
            for (size_t k = 0; k < v->nitems; k++) mp_pack_rec(v->items[k], sb);
            break;
        }
    }
}

static void mp_pack(const MVal *v, uint8_t **out, size_t *out_len) {
    StrBuf sb; sb_init(&sb);
    mp_pack_rec(v, &sb);
    *out = (uint8_t *)sb_steal(&sb);
    *out_len = sb.len;
}

/* --- unpacker --- */

typedef struct { const uint8_t *d; size_t len, pos; bool ok; } MParser;

static bool mp_need(MParser *ps, size_t n) {
    if (ps->pos + n > ps->len) { ps->ok = false; return false; }
    return true;
}

static uint8_t mp_r8(MParser *ps)  { if (!mp_need(ps, 1)) return 0; return ps->d[ps->pos++]; }
static uint16_t mp_r16(MParser *ps) { if (!mp_need(ps, 2)) return 0; uint16_t v = ((uint16_t)ps->d[ps->pos] << 8) | ps->d[ps->pos+1]; ps->pos += 2; return v; }
static uint32_t mp_r32(MParser *ps) { if (!mp_need(ps, 4)) return 0; uint32_t v = ((uint32_t)ps->d[ps->pos] << 24) | ((uint32_t)ps->d[ps->pos+1] << 16) | ((uint32_t)ps->d[ps->pos+2] << 8) | ps->d[ps->pos+3]; ps->pos += 4; return v; }
static uint64_t mp_r64(MParser *ps) { if (!mp_need(ps, 8)) return 0; uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | ps->d[ps->pos+i]; ps->pos += 8; return v; }

static MVal *mp_unpack_rec(MParser *ps, int depth) {
    if (depth > 100 || !ps->ok) { ps->ok = false; return NULL; }
    if (!mp_need(ps, 1)) return NULL;
    uint8_t c = mp_r8(ps);
    if (c <= 0x7f) { MVal *v = m_new(M_UINT); v->u = c; v->i = c; return v; }   /* pos fixint */
    if (c >= 0xe0) { MVal *v = m_int((int8_t)c); return v; }                    /* neg fixint */
    if ((c & 0xe0) == 0xa0) {                                                   /* fixstr */
        size_t n = c & 0x1f;
        if (!mp_need(ps, n)) return NULL;
        MVal *v = m_new(M_STR);
        v->str = malloc(n + 1); memcpy(v->str, ps->d + ps->pos, n); v->str[n] = '\0';
        ps->pos += n;
        return v;
    }
    if ((c & 0xf0) == 0x90) {                                                   /* fixarray */
        size_t n = c & 0x0f;
        MVal *v = m_arr();
        for (size_t i = 0; i < n; i++) {
            MVal *it = mp_unpack_rec(ps, depth + 1);
            if (!it) { m_free(v); return NULL; }
            m_arr_add(v, it);
        }
        return v;
    }
    if ((c & 0xf0) == 0x80) {                                                   /* fixmap */
        size_t n = c & 0x0f;
        MVal *v = m_new(M_MAP);
        for (size_t i = 0; i < n * 2; i++) {
            MVal *it = mp_unpack_rec(ps, depth + 1);
            if (!it) { m_free(v); return NULL; }
            m_arr_add(v, it);
        }
        return v;
    }
    switch (c) {
        case 0xc0: return m_nil();
        case 0xc2: return m_bool(false);
        case 0xc3: return m_bool(true);
        case 0xc4: { size_t n = mp_r8(ps);  if (!mp_need(ps, n)) return NULL; MVal *v = m_bin(ps->d + ps->pos, n); ps->pos += n; return v; }
        case 0xc5: { size_t n = mp_r16(ps); if (!mp_need(ps, n)) return NULL; MVal *v = m_bin(ps->d + ps->pos, n); ps->pos += n; return v; }
        case 0xc6: { size_t n = mp_r32(ps); if (!mp_need(ps, n)) return NULL; MVal *v = m_bin(ps->d + ps->pos, n); ps->pos += n; return v; }
        case 0xca: { uint32_t b = mp_r32(ps); float f; memcpy(&f, &b, 4); /* big-endian read */
                     uint32_t host = ((b & 0xFF) << 24) | ((b & 0xFF00) << 8) | ((b >> 8) & 0xFF00) | ((b >> 24) & 0xFF);
                     /* mp_r64/mp_r32 already assemble big-endian correctly */
                     memcpy(&f, &b, 4); (void)host;
                     MVal *v = m_new(M_FLOAT); v->f = f; return v; }
        case 0xcb: { uint64_t b = mp_r64(ps); double d; memcpy(&d, &b, 8); MVal *v = m_new(M_FLOAT); v->f = d; return v; }
        case 0xcc: { MVal *v = m_new(M_UINT); v->u = mp_r8(ps);  v->i = (int64_t)v->u; return v; }
        case 0xcd: { MVal *v = m_new(M_UINT); v->u = mp_r16(ps); v->i = (int64_t)v->u; return v; }
        case 0xce: { MVal *v = m_new(M_UINT); v->u = mp_r32(ps); v->i = (int64_t)v->u; return v; }
        case 0xcf: { MVal *v = m_new(M_UINT); v->u = mp_r64(ps); v->i = (int64_t)v->u; return v; }
        case 0xd0: return m_int((int8_t)mp_r8(ps));
        case 0xd1: return m_int((int16_t)mp_r16(ps));
        case 0xd2: return m_int((int32_t)mp_r32(ps));
        case 0xd3: return m_int((int64_t)mp_r64(ps));
        case 0xd9: { size_t n = mp_r8(ps);  if (!mp_need(ps, n)) return NULL; MVal *v = m_new(M_STR); v->str = malloc(n + 1); memcpy(v->str, ps->d + ps->pos, n); v->str[n] = 0; ps->pos += n; return v; }
        case 0xda: { size_t n = mp_r16(ps); if (!mp_need(ps, n)) return NULL; MVal *v = m_new(M_STR); v->str = malloc(n + 1); memcpy(v->str, ps->d + ps->pos, n); v->str[n] = 0; ps->pos += n; return v; }
        case 0xdb: { size_t n = mp_r32(ps); if (!mp_need(ps, n)) return NULL; MVal *v = m_new(M_STR); v->str = malloc(n + 1); memcpy(v->str, ps->d + ps->pos, n); v->str[n] = 0; ps->pos += n; return v; }
        case 0xdc: case 0xdd: {
            size_t n = (c == 0xdc) ? mp_r16(ps) : mp_r32(ps);
            MVal *v = m_arr();
            for (size_t i = 0; i < n; i++) {
                MVal *it = mp_unpack_rec(ps, depth + 1);
                if (!it) { m_free(v); return NULL; }
                m_arr_add(v, it);
            }
            return v;
        }
        case 0xde: case 0xdf: {
            size_t n = (c == 0xde) ? mp_r16(ps) : mp_r32(ps);
            MVal *v = m_new(M_MAP);
            for (size_t i = 0; i < n * 2; i++) {
                MVal *it = mp_unpack_rec(ps, depth + 1);
                if (!it) { m_free(v); return NULL; }
                m_arr_add(v, it);
            }
            return v;
        }
        default:
            ps->ok = false;
            return NULL;
    }
}

static MVal *mp_unpack(const uint8_t *data, size_t len) {
    MParser ps = { .d = data, .len = len, .pos = 0, .ok = true };
    MVal *v = mp_unpack_rec(&ps, 0);
    if (!ps.ok || !v) { m_free(v); return NULL; }
    return v;
}

/* convenience accessors */
static bool m_is_intlike(const MVal *v) { return v && (v->t == M_INT || v->t == M_UINT); }
static int64_t m_as_int(const MVal *v) { return v->t == M_UINT ? (int64_t)v->u : v->i; }
/* bin or str -> bytes view (rpcudp func names arrive as str, node ids as bin) */
static bool m_as_bytes(const MVal *v, const uint8_t **ptr, size_t *len) {
    if (!v) return false;
    if (v->t == M_BIN) { *ptr = v->bin; *len = v->blen; return true; }
    if (v->t == M_STR) { *ptr = (const uint8_t *)v->str; *len = strlen(v->str); return true; }
    return false;
}

/* ============================================================================
 * Pickle — minimal reader (protocols 0-5) and writer (protocol 0) covering
 * the value kinds used by RRKDHT.save_state(): dict/str/int/bool/None/list/
 * tuple. Files written here load fine in Python (pickle.load autodetects).
 * ============================================================================ */

typedef enum { P_NONE, P_BOOL, P_INT, P_STR, P_LIST, P_TUPLE, P_DICT } PType;

typedef struct PVal {
    PType t;
    bool b;
    long long i;
    char *s;
    struct PVal **items; size_t n;      /* LIST/TUPLE */
    char **keys; struct PVal **vals; size_t np; /* DICT */
} PVal;

static PVal *p_new(PType t) { PVal *v = calloc(1, sizeof(PVal)); v->t = t; return v; }
static PVal *p_none(void) { return p_new(P_NONE); }
static PVal *p_bool(bool b) { PVal *v = p_new(P_BOOL); v->b = b; return v; }
static PVal *p_int(long long i) { PVal *v = p_new(P_INT); v->i = i; return v; }
static PVal *p_str(const char *s) { PVal *v = p_new(P_STR); v->s = xstrdup(s); return v; }
static PVal *p_list(void) { return p_new(P_LIST); }
static PVal *p_dict(void) { return p_new(P_DICT); }

static void p_list_add(PVal *l, PVal *it) {
    l->items = realloc(l->items, (l->n + 1) * sizeof(PVal *));
    l->items[l->n++] = it;
}

static void p_dict_set(PVal *d, const char *key, PVal *val) {
    for (size_t i = 0; i < d->np; i++)
        if (!strcmp(d->keys[i], key)) { d->vals[i] = val; return; }
    d->keys = realloc(d->keys, (d->np + 1) * sizeof(char *));
    d->vals = realloc(d->vals, (d->np + 1) * sizeof(PVal *));
    d->keys[d->np] = xstrdup(key);
    d->vals[d->np] = val;
    d->np++;
}

static PVal *p_dict_get(const PVal *d, const char *key) {
    if (!d || d->t != P_DICT) return NULL;
    for (size_t i = 0; i < d->np; i++)
        if (!strcmp(d->keys[i], key)) return d->vals[i];
    return NULL;
}

static void p_free(PVal *v) {
    if (!v) return;
    free(v->s);
    if (v->t == P_LIST || v->t == P_TUPLE) {
        for (size_t i = 0; i < v->n; i++) p_free(v->items[i]);
        free(v->items);
    }
    if (v->t == P_DICT) {
        for (size_t i = 0; i < v->np; i++) { free(v->keys[i]); p_free(v->vals[i]); }
        free(v->keys); free(v->vals);
    }
    free(v);
}

/* --- pickle writer (protocol 2, binary opcodes — matches modern Python's
 * default pickle.dump protocol; the C reader already accepts protocols 0-5,
 * so round-tripping with itself and with Python is unaffected) --- */

static void pkl_put_u32le(StrBuf *sb, uint32_t v) {
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    sb_addn(sb, (char *)b, 4);
}

/* Minimal little-endian two's-complement encoding of a signed 64-bit value,
 * matching Python pickle's encode_long() (0 encodes as zero bytes). */
static int pkl_encode_long(long long i, uint8_t out[9]) {
    if (i == 0) return 0;
    bool neg = i < 0;
    uint64_t bits = (uint64_t)i;
    uint8_t bytes[8];
    for (int k = 0; k < 8; k++) bytes[k] = (uint8_t)(bits >> (8 * k));
    int len = 8;
    while (len > 1) {
        uint8_t msb = bytes[len - 1], next = bytes[len - 2];
        if (neg) { if (msb == 0xFF && (next & 0x80)) { len--; continue; } }
        else     { if (msb == 0x00 && !(next & 0x80)) { len--; continue; } }
        break;
    }
    memcpy(out, bytes, len);
    return len;
}

static void pkl_dump_rec(const PVal *v, StrBuf *sb) {
    switch (v->t) {
        case P_NONE: sb_add(sb, "N"); break;
        case P_BOOL: sb_add(sb, v->b ? "\x88" : "\x89"); break;   /* NEWTRUE / NEWFALSE */
        case P_INT: {
            long long i = v->i;
            if (i >= 0 && i <= 0xff) {                            /* BININT1 */
                uint8_t b[2] = { 'K', (uint8_t)i };
                sb_addn(sb, (char *)b, 2);
            } else if (i >= 0 && i <= 0xffff) {                   /* BININT2 */
                uint8_t b[3] = { 'M', (uint8_t)i, (uint8_t)(i >> 8) };
                sb_addn(sb, (char *)b, 3);
            } else if (i >= INT32_MIN && i <= INT32_MAX) {        /* BININT */
                uint8_t b[5] = { 'J', (uint8_t)i, (uint8_t)((uint32_t)i >> 8),
                                  (uint8_t)((uint32_t)i >> 16), (uint8_t)((uint32_t)i >> 24) };
                sb_addn(sb, (char *)b, 5);
            } else {                                              /* LONG1 */
                uint8_t buf[9];
                int n = pkl_encode_long(i, buf);
                uint8_t hdr[2] = { (uint8_t)0x8a, (uint8_t)n };
                sb_addn(sb, (char *)hdr, 2);
                sb_addn(sb, (char *)buf, n);
            }
            break;
        }
        case P_STR: {
            /* BINUNICODE: 'X' + 4-byte LE utf8-length + utf8 bytes
             * (all state strings are ASCII, so len(bytes) == strlen) */
            size_t len = strlen(v->s);
            sb_add(sb, "X");
            pkl_put_u32le(sb, (uint32_t)len);
            sb_addn(sb, v->s, len);
            break;
        }
        case P_LIST:
            sb_add(sb, "]");                     /* EMPTY_LIST */
            if (v->n) {
                sb_add(sb, "(");                 /* MARK */
                for (size_t i = 0; i < v->n; i++) pkl_dump_rec(v->items[i], sb);
                sb_add(sb, "e");                 /* APPENDS */
            }
            break;
        case P_TUPLE:
            if (v->n == 0) { sb_add(sb, ")"); break; }             /* EMPTY_TUPLE */
            if (v->n <= 3) {
                for (size_t i = 0; i < v->n; i++) pkl_dump_rec(v->items[i], sb);
                sb_add(sb, v->n == 1 ? "\x85" : v->n == 2 ? "\x86" : "\x87"); /* TUPLE1/2/3 */
                break;
            }
            sb_add(sb, "(");                     /* MARK */
            for (size_t i = 0; i < v->n; i++) pkl_dump_rec(v->items[i], sb);
            sb_add(sb, "t");                     /* TUPLE */
            break;
        case P_DICT:
            sb_add(sb, "}");                     /* EMPTY_DICT */
            if (v->np) {
                sb_add(sb, "(");                 /* MARK */
                for (size_t i = 0; i < v->np; i++) {
                    PVal k = { .t = P_STR, .s = v->keys[i] };
                    pkl_dump_rec(&k, sb);
                    pkl_dump_rec(v->vals[i], sb);
                }
                sb_add(sb, "u");                 /* SETITEMS */
            }
            break;
    }
}

static uint8_t *pkl_dump(const PVal *v, size_t *out_len) {
    StrBuf sb; sb_init(&sb);
    sb_add(&sb, "\x80\x02");                     /* PROTO 2 */
    pkl_dump_rec(v, &sb);
    sb_add(&sb, ".");                            /* STOP */
    *out_len = sb.len;
    return (uint8_t *)sb_steal(&sb);
}

/* --- pickle reader: small stack machine over the opcode subset --- */

typedef struct {
    PVal **stack; size_t n, cap;
    size_t *marks; size_t nmarks, capmarks; /* stack of MARK positions */
    PVal **memo; size_t nmemo, capmemo;
} PklVM;

static void vm_mark_push(PklVM *vm, size_t idx) {
    vm->marks = realloc(vm->marks, (vm->nmarks + 1) * sizeof(size_t));
    vm->marks[vm->nmarks++] = idx;
}

static size_t vm_mark_pop(PklVM *vm) {
    if (!vm->nmarks) return (size_t)-1;
    return vm->marks[--vm->nmarks];
}

static size_t vm_mark_top(PklVM *vm) {
    return vm->nmarks ? vm->marks[vm->nmarks - 1] : (size_t)-1;
}

static void vm_push(PklVM *vm, PVal *v) {
    vm->stack = realloc(vm->stack, (vm->n + 1) * sizeof(PVal *));
    vm->stack[vm->n++] = v;
}

static PVal *vm_pop(PklVM *vm) { return vm->n ? vm->stack[--vm->n] : NULL; }

static void vm_memo_put(PklVM *vm, size_t idx, PVal *v) {
    if (idx >= vm->capmemo) {
        size_t nc = vm->capmemo ? vm->capmemo : 16;
        while (nc <= idx) nc *= 2;
        vm->memo = realloc(vm->memo, nc * sizeof(PVal *));
        for (size_t i = vm->capmemo; i < nc; i++) vm->memo[i] = NULL;
        vm->capmemo = nc;
    }
    vm->memo[idx] = v;
    if (idx >= vm->nmemo) vm->nmemo = idx + 1;
}

/* unescape a protocol-0 STRING payload between quotes */
static char *pkl_unescape(const uint8_t *d, size_t len) {
    StrBuf sb; sb_init(&sb);
    for (size_t i = 0; i < len; i++) {
        if (d[i] == '\\' && i + 1 < len) {
            i++;
            switch (d[i]) {
                case 'n': sb_addn(&sb, "\n", 1); break;
                case 'r': sb_addn(&sb, "\r", 1); break;
                case 't': sb_addn(&sb, "\t", 1); break;
                case '\\': sb_addn(&sb, "\\", 1); break;
                case '\'': sb_addn(&sb, "'", 1); break;
                case '"': sb_addn(&sb, "\"", 1); break;
                case 'x':
                    if (i + 2 < len) {
                        unsigned v; sscanf((const char *)d + i + 1, "%2x", &v);
                        char c = (char)v; sb_addn(&sb, &c, 1);
                        i += 2;
                    }
                    break;
                default: sb_addn(&sb, (const char *)d + i, 1);
            }
        } else sb_addn(&sb, (const char *)d + i, 1);
    }
    return sb_steal(&sb);
}

static PVal *pkl_load(const uint8_t *d, size_t len) {
    PklVM vm = {0};
    size_t pos = 0;
    bool ok = true;
    PVal *result = NULL;

    while (ok && pos < len) {
        uint8_t op = d[pos++];
        switch (op) {
            case 0x80: /* PROTO */ pos++; break;
            case 0x95: /* FRAME */ pos += 8; break;
            case '(':  /* MARK */
                vm_push(&vm, NULL);            /* marker placeholder */
                vm_mark_push(&vm, vm.n - 1);   /* remember its index */
                break;
            case 'N': vm_push(&vm, p_none()); break;
            case 0x88: vm_push(&vm, p_bool(true)); break;   /* NEWTRUE */
            case 0x89: vm_push(&vm, p_bool(false)); break;  /* NEWFALSE */
            case 'I': { /* INT (text, until \n) */
                char buf[64]; size_t k = 0;
                while (pos < len && d[pos] != '\n' && k < 63) buf[k++] = (char)d[pos++];
                buf[k] = 0; pos++;
                if (!strcmp(buf, "01")) vm_push(&vm, p_bool(true));
                else if (!strcmp(buf, "00")) vm_push(&vm, p_bool(false));
                else vm_push(&vm, p_int(strtoll(buf, NULL, 10)));
                break;
            }
            case 'J': { /* BININT */
                if (pos + 4 > len) { ok = false; break; }
                int32_t v; memcpy(&v, d + pos, 4); pos += 4;
                vm_push(&vm, p_int(v));
                break;
            }
            case 'K': { if (pos >= len) { ok = false; break; } vm_push(&vm, p_int(d[pos++])); break; } /* BININT1 */
            case 'M': { /* BININT2 */
                if (pos + 2 > len) { ok = false; break; }
                uint16_t v = (uint16_t)d[pos] | ((uint16_t)d[pos+1] << 8); pos += 2;
                vm_push(&vm, p_int(v));
                break;
            }
            case 0x8a: { /* LONG1: 1-byte length + little-endian two's-complement bytes */
                if (pos >= len) { ok = false; break; }
                size_t n = d[pos++];
                if (pos + n > len) { ok = false; break; }
                long long v = 0;
                if (n > 0) {
                    uint64_t bits = 0;
                    for (size_t i = 0; i < n && i < 8; i++) bits |= (uint64_t)d[pos + i] << (8 * i);
                    bool neg = (n <= 8) && (d[pos + n - 1] & 0x80);
                    if (neg && n < 8) {
                        for (size_t i = n; i < 8; i++) bits |= (uint64_t)0xFF << (8 * i);
                    }
                    v = (long long)bits;
                }
                pos += n;
                vm_push(&vm, p_int(v));
                break;
            }
            case 'S': { /* STRING '...'\n */
                if (pos >= len) { ok = false; break; }
                char quote = (char)d[pos++];
                size_t start = pos;
                while (pos < len) {
                    if (d[pos] == '\\') { pos += 2; continue; }
                    if (d[pos] == (uint8_t)quote) break;
                    pos++;
                }
                char *s = pkl_unescape(d + start, pos - start);
                pos++; /* closing quote */
                if (pos < len && d[pos] == '\n') pos++;
                PVal *v = p_new(P_STR); v->s = s;
                vm_push(&vm, v);
                break;
            }
            case 'U': { /* SHORT_BINSTRING */
                if (pos >= len) { ok = false; break; }
                size_t n = d[pos++];
                if (pos + n > len) { ok = false; break; }
                char *s = malloc(n + 1); memcpy(s, d + pos, n); s[n] = 0; pos += n;
                PVal *v = p_new(P_STR); v->s = s;
                vm_push(&vm, v);
                break;
            }
            case 'T': case 'X': { /* BINSTRING / BINUNICODE */
                if (pos + 4 > len) { ok = false; break; }
                uint32_t n; memcpy(&n, d + pos, 4); pos += 4;
                if (pos + n > len) { ok = false; break; }
                char *s = malloc(n + 1); memcpy(s, d + pos, n); s[n] = 0; pos += n;
                PVal *v = p_new(P_STR); v->s = s;
                vm_push(&vm, v);
                break;
            }
            case 0x8c: { /* SHORT_BINUNICODE */
                if (pos >= len) { ok = false; break; }
                size_t n = d[pos++];
                if (pos + n > len) { ok = false; break; }
                char *s = malloc(n + 1); memcpy(s, d + pos, n); s[n] = 0; pos += n;
                PVal *v = p_new(P_STR); v->s = s;
                vm_push(&vm, v);
                break;
            }
            case ']': vm_push(&vm, p_list()); break;         /* EMPTY_LIST */
            case ')': vm_push(&vm, p_new(P_TUPLE)); break;   /* EMPTY_TUPLE */
            case '}': vm_push(&vm, p_dict()); break;         /* EMPTY_DICT */
            case 'l': case 't': { /* LIST / TUPLE from MARK */
                size_t mark = vm_mark_pop(&vm);
                if (mark == (size_t)-1 || mark >= vm.n) { ok = false; break; }
                PVal *c = p_new(op == 'l' ? P_LIST : P_TUPLE);
                for (size_t i = mark + 1; i < vm.n; i++) p_list_add(c, vm.stack[i]);
                vm.n = mark;  /* pop items + marker */
                vm_push(&vm, c);
                break;
            }
            case 'd': { /* DICT from MARK */
                size_t mark = vm_mark_pop(&vm);
                if (mark == (size_t)-1 || mark >= vm.n) { ok = false; break; }
                PVal *c = p_dict();
                for (size_t i = mark + 1; i + 1 < vm.n; i += 2) {
                    if (vm.stack[i]->t != P_STR) { ok = false; break; }
                    p_dict_set(c, vm.stack[i]->s, vm.stack[i + 1]);
                }
                vm.n = mark;
                vm_push(&vm, c);
                break;
            }
            case 0x85: case 0x86: case 0x87: { /* TUPLE1/2/3 */
                int n = op - 0x84;
                if (vm.n < (size_t)n) { ok = false; break; }
                PVal *c = p_new(P_TUPLE);
                for (int i = n; i > 0; i--) p_list_add(c, vm.stack[vm.n - i]);
                vm.n -= (size_t)n;
                vm_push(&vm, c);
                break;
            }
            case 'a': { /* APPEND */
                if (vm.n < 2) { ok = false; break; }
                PVal *it = vm_pop(&vm);
                PVal *lst = vm.stack[vm.n - 1];
                if (!lst || (lst->t != P_LIST && lst->t != P_TUPLE)) { ok = false; break; }
                p_list_add(lst, it);
                break;
            }
            case 'e': { /* APPENDS: extend list below mark with items above */
                size_t mark = vm_mark_pop(&vm);
                if (mark == (size_t)-1 || mark >= vm.n || mark < 1) { ok = false; break; }
                PVal *lst = vm.stack[mark - 1];
                if (!lst || lst->t != P_LIST) { ok = false; break; }
                for (size_t i = mark + 1; i < vm.n; i++) p_list_add(lst, vm.stack[i]);
                vm.n = mark;
                break;
            }
            case 's': { /* SETITEM */
                if (vm.n < 3) { ok = false; break; }
                PVal *val = vm_pop(&vm);
                PVal *key = vm_pop(&vm);
                PVal *dct = vm.stack[vm.n - 1];
                if (!dct || dct->t != P_DICT || !key || key->t != P_STR) { ok = false; break; }
                p_dict_set(dct, key->s, val);
                break;
            }
            case 'u': { /* SETITEMS */
                size_t mark = vm_mark_pop(&vm);
                if (mark == (size_t)-1 || mark >= vm.n || mark < 1) { ok = false; break; }
                PVal *dct = vm.stack[mark - 1];
                if (!dct || dct->t != P_DICT) { ok = false; break; }
                for (size_t i = mark + 1; i + 1 < vm.n; i += 2) {
                    if (vm.stack[i]->t != P_STR) { ok = false; break; }
                    p_dict_set(dct, vm.stack[i]->s, vm.stack[i + 1]);
                }
                vm.n = mark;
                break;
            }
            case 'q': { /* BINPUT */
                if (pos >= len || vm.n < 1) { ok = false; break; }
                vm_memo_put(&vm, d[pos++], vm.stack[vm.n - 1]);
                break;
            }
            case 'r': { /* LONG_BINPUT */
                if (pos + 4 > len || vm.n < 1) { ok = false; break; }
                uint32_t idx; memcpy(&idx, d + pos, 4); pos += 4;
                vm_memo_put(&vm, idx, vm.stack[vm.n - 1]);
                break;
            }
            case 0x94: { /* MEMOIZE */
                if (vm.n < 1) { ok = false; break; }
                vm_memo_put(&vm, vm.nmemo, vm.stack[vm.n - 1]);
                break;
            }
            case 'h': { /* BINGET */
                if (pos >= len) { ok = false; break; }
                uint8_t idx = d[pos++];
                if (idx >= vm.nmemo || !vm.memo[idx]) { ok = false; break; }
                vm_push(&vm, vm.memo[idx]);
                break;
            }
            case 'j': { /* LONG_BINGET */
                if (pos + 4 > len) { ok = false; break; }
                uint32_t idx; memcpy(&idx, d + pos, 4); pos += 4;
                if (idx >= vm.nmemo || !vm.memo[idx]) { ok = false; break; }
                vm_push(&vm, vm.memo[idx]);
                break;
            }
            case '.': /* STOP */
                result = vm_pop(&vm);
                pos = len;
                break;
            default:
                ok = false;
                break;
        }
    }

    free(vm.stack);
    free(vm.memo);
    free(vm.marks);
    if (!ok) { p_free(result); return NULL; }
    return result;
}

/* ============================================================================
 * ASYNCIO EMULATION LAYER
 *   Future          <-> asyncio.Future (set_result / done / cancelled / wait)
 *   timer scheduler <-> loop.call_later(delay, cb, arg) returning a cancelable
 *                       TimerHandle (mirrors asyncio.TimerHandle.cancel())
 *   ensure_future   <-> detached pthread running the coroutine body
 *   parallel_gather <-> asyncio.gather(*tasks, return_exceptions=...)
 * ============================================================================ */

typedef enum { FUT_PENDING = 0, FUT_DONE = 1, FUT_CANCELLED = 2 } FutState;

typedef struct Future {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    FutState state;
    void *result;                 /* owned by caller-side convention */
} Future;

static Future *future_new(void) {
    Future *f = calloc(1, sizeof(Future));
    pthread_mutex_init(&f->mu, NULL);
    pthread_cond_init(&f->cv, NULL);
    f->state = FUT_PENDING;
    return f;
}

static void future_free(Future *f) {
    if (!f) return;
    pthread_mutex_destroy(&f->mu);
    pthread_cond_destroy(&f->cv);
    free(f);
}

static void future_set_result(Future *f, void *result) {
    pthread_mutex_lock(&f->mu);
    if (f->state == FUT_PENDING) {
        f->result = result;
        f->state = FUT_DONE;
        pthread_cond_broadcast(&f->cv);
    }
    pthread_mutex_unlock(&f->mu);
}

static bool future_cancel(Future *f) {
    pthread_mutex_lock(&f->mu);
    bool ok = (f->state == FUT_PENDING);
    if (ok) {
        f->state = FUT_CANCELLED;
        pthread_cond_broadcast(&f->cv);
    }
    pthread_mutex_unlock(&f->mu);
    return ok;
}

static bool future_done(Future *f) {
    pthread_mutex_lock(&f->mu);
    bool d = (f->state == FUT_DONE);
    pthread_mutex_unlock(&f->mu);
    return d;
}

static bool future_cancelled(Future *f) {
    pthread_mutex_lock(&f->mu);
    bool c = (f->state == FUT_CANCELLED);
    pthread_mutex_unlock(&f->mu);
    return c;
}

/* returns: 0 = done, 1 = cancelled, 2 = timeout (asyncio.TimeoutError) */
static int future_wait(Future *f, double timeout, void **result_out) {
    pthread_mutex_lock(&f->mu);
    if (f->state == FUT_PENDING) {
        if (timeout < 0) {
            while (f->state == FUT_PENDING) pthread_cond_wait(&f->cv, &f->mu);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (time_t)timeout;
            ts.tv_nsec += (long)((timeout - (double)(time_t)timeout) * 1e9);
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            while (f->state == FUT_PENDING) {
                if (pthread_cond_timedwait(&f->cv, &f->mu, &ts) == ETIMEDOUT) break;
            }
        }
    }
    int rc;
    if (f->state == FUT_DONE) { *result_out = f->result; rc = 0; }
    else if (f->state == FUT_CANCELLED) rc = 1;
    else rc = 2;
    pthread_mutex_unlock(&f->mu);
    return rc;
}

/* --- timer scheduler (loop.call_later) --- */

typedef void (*TimerCb)(void *arg);

typedef struct TimerEntry {
    uint64_t id;
    double due;                   /* monotonic */
    TimerCb cb;
    void *arg;
    bool cancelled;
} TimerEntry;

typedef struct {
    TimerEntry **heap;            /* min-heap by due */
    size_t n, cap;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    uint64_t next_id;
    pthread_t thread;
    bool started;
} TimerSched;

static TimerSched g_timers = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER };

static void ts_swap(TimerEntry **a, TimerEntry **b) { TimerEntry *t = *a; *a = *b; *b = t; }

static void ts_sift_up(TimerSched *s, size_t i) {
    while (i > 0) {
        size_t p = (i - 1) / 2;
        if (s->heap[p]->due <= s->heap[i]->due) break;
        ts_swap(&s->heap[p], &s->heap[i]);
        i = p;
    }
}

static void ts_sift_down(TimerSched *s, size_t i) {
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, m = i;
        if (l < s->n && s->heap[l]->due < s->heap[m]->due) m = l;
        if (r < s->n && s->heap[r]->due < s->heap[m]->due) m = r;
        if (m == i) break;
        ts_swap(&s->heap[m], &s->heap[i]);
        i = m;
    }
}

static void *timer_thread_main(void *unused) {
    (void)unused;
    TimerSched *s = &g_timers;
    pthread_mutex_lock(&s->mu);
    for (;;) {
        while (s->n == 0) pthread_cond_wait(&s->cv, &s->mu);
        double now = now_mono();
        TimerEntry *top = s->heap[0];
        if (top->due > now) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            double wait = top->due - now;
            ts.tv_sec += (time_t)wait;
            ts.tv_nsec += (long)((wait - (double)(time_t)wait) * 1e9);
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            pthread_cond_timedwait(&s->cv, &s->mu, &ts);
            continue;
        }
        /* pop */
        s->heap[0] = s->heap[--s->n];
        ts_sift_down(s, 0);
        pthread_mutex_unlock(&s->mu);
        if (!top->cancelled && top->cb) top->cb(top->arg);
        free(top);
        pthread_mutex_lock(&s->mu);
    }
    return NULL;
}

static void timer_sched_init(void) {
    TimerSched *s = &g_timers;
    pthread_mutex_lock(&s->mu);
    if (!s->started) {
        s->started = true;
        s->next_id = 1;
        pthread_create(&s->thread, NULL, timer_thread_main, NULL);
        pthread_detach(s->thread);
    }
    pthread_mutex_unlock(&s->mu);
}

/* loop.call_later(delay, callback, arg) -> TimerHandle (uint64 id, 0 = none) */
static uint64_t call_later(double delay, TimerCb cb, void *arg) {
    timer_sched_init();
    TimerSched *s = &g_timers;
    pthread_mutex_lock(&s->mu);
    TimerEntry *e = calloc(1, sizeof(TimerEntry));
    e->id = s->next_id++;
    e->due = now_mono() + delay;
    e->cb = cb;
    e->arg = arg;
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 16;
        s->heap = realloc(s->heap, s->cap * sizeof(TimerEntry *));
    }
    s->heap[s->n] = e;
    ts_sift_up(s, s->n);
    s->n++;
    pthread_cond_signal(&s->cv);
    pthread_mutex_unlock(&s->mu);
    return e->id;
}

/* TimerHandle.cancel() */
static void timer_cancel(uint64_t id) {
    if (!id) return;
    TimerSched *s = &g_timers;
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->n; i++)
        if (s->heap[i]->id == id) { s->heap[i]->cancelled = true; break; }
    pthread_mutex_unlock(&s->mu);
}

/* --- ensure_future: detached thread running a coroutine body --- */

typedef void *(*CoroFn)(void *arg);

static void *ensure_future_trampoline(void *ctx) {
    void **pair = (void **)ctx;
    CoroFn fn = (CoroFn)pair[0];
    void *arg = pair[1];
    free(pair);
    fn(arg);
    return NULL;
}

static void ensure_future(CoroFn fn, void *arg) {
    void **pair = malloc(2 * sizeof(void *));
    pair[0] = (void *)fn;
    pair[1] = arg;
    pthread_t t;
    if (pthread_create(&t, NULL, ensure_future_trampoline, pair) == 0)
        pthread_detach(t);
    else { free(pair); fn(arg); }
}

/* --- asyncio.gather emulation: run N tasks on N threads, join all --- */

typedef struct {
    CoroFn fn;
    void *arg;
    void *result;
} GatherTask;

static void *gather_worker(void *ctx) {
    GatherTask *t = ctx;
    t->result = t->fn(t->arg);
    return NULL;
}

static void parallel_gather(GatherTask *tasks, size_t n) {
    if (n == 0) return;
    pthread_t *tids = malloc(n * sizeof(pthread_t));
    size_t spawned = 0;
    for (size_t i = 0; i < n; i++) {
        if (pthread_create(&tids[i], NULL, gather_worker, &tasks[i]) == 0) spawned++;
        else { tasks[i].result = tasks[i].fn(tasks[i].arg); tids[i] = 0; }
    }
    for (size_t i = 0; i < n; i++)
        if (tids[i]) pthread_join(tids[i], NULL);
    free(tids);
}

/* ============================================================================
 * CRYPTOGRAPHY (OpenSSL) — mirrors the `cryptography` package usage:
 *   Ed25519 signing keys, X25519 exchange keys, HKDF-SHA256, ChaCha20-Poly1305
 * ============================================================================ */

/* create_ed25519_key_pair() -> (private_key, public_key) as EVP_PKEY* */
static EVP_PKEY *create_ed25519_private_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) return NULL;
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) > 0)
        EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* generate_peer_id(public_key): sha256 of raw 32-byte public key, hexdigest */
static char *generate_peer_id(EVP_PKEY *public_key) {
    uint8_t raw[32]; size_t rawlen = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(public_key, raw, &rawlen) <= 0) return NULL;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(raw, rawlen, hash);
    return hex_encode(hash, SHA256_DIGEST_LENGTH);
}

/* digest(string): SHA-1 digest (20 bytes). If input is text it is UTF-8
 * encoded first — identical to the Python helper. */
static void digest(const void *data, size_t len, uint8_t out[20]) {
    SHA1((const uint8_t *)data, len, out);
}

static void digest_str(const char *s, uint8_t out[20]) { digest(s, strlen(s), out); }

/* PEM serialization helpers (serialization.Encoding.PEM formats) */
static char *pem_public_key(EVP_PKEY *pub) {          /* SubjectPublicKeyInfo */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pub);
    BUF_MEM *b; BIO_get_mem_ptr(bio, &b);
    char *s = malloc(b->length + 1);
    memcpy(s, b->data, b->length); s[b->length] = 0;
    BIO_free(bio);
    return s;
}

static char *pem_private_key(EVP_PKEY *priv) {        /* PKCS8, NoEncryption */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, priv, NULL, NULL, 0, NULL, NULL);
    BUF_MEM *b; BIO_get_mem_ptr(bio, &b);
    char *s = malloc(b->length + 1);
    memcpy(s, b->data, b->length); s[b->length] = 0;
    BIO_free(bio);
    return s;
}

static EVP_PKEY *load_pem_public_key(const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return k;
}

static EVP_PKEY *load_pem_private_key(const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return k;
}

static EVP_PKEY *create_x25519_private_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return NULL;
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) > 0)
        EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* X25519 exchange -> 32-byte shared secret */
static bool x25519_exchange(EVP_PKEY *priv, EVP_PKEY *peer_pub, uint8_t out[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return false;
    size_t outlen = 32;
    bool ok = EVP_PKEY_derive_init(ctx) > 0 &&
              EVP_PKEY_derive_set_peer(ctx, peer_pub) > 0 &&
              EVP_PKEY_derive(ctx, out, &outlen) > 0 && outlen == 32;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/* HKDF-SHA256(length=32, salt=NULL, info=b'rrdht-encryption') */
static bool hkdf_rrdht(const uint8_t shared[32], uint8_t out[32]) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return false;
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) { EVP_KDF_free(kdf); return false; }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)shared, 32),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)"rrdht-encryption", 16),
        OSSL_PARAM_construct_end()
    };
    bool ok = EVP_KDF_derive(kctx, out, 32, params) > 0;
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok;
}

/* ChaCha20Poly1305.encrypt(nonce, data, None) -> ciphertext||tag */
static uint8_t *chacha_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *data, size_t len, size_t *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    uint8_t *out = malloc(len + 16);
    int outl = 0, tmplen = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) > 0 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0 &&
              EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) > 0 &&
              EVP_EncryptUpdate(ctx, out, &outl, data, (int)len) > 0 &&
              EVP_EncryptFinal_ex(ctx, out + outl, &tmplen) > 0 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out + outl + tmplen) > 0;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(out); return NULL; }
    *out_len = (size_t)(outl + tmplen) + 16;
    return out;
}

/* ChaCha20Poly1305.decrypt(nonce, ciphertext||tag, None) */
static uint8_t *chacha_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *data, size_t len, size_t *out_len) {
    if (len < 16) return NULL;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    size_t ct_len = len - 16;
    const uint8_t *tag = data + ct_len;
    uint8_t *out = malloc(ct_len + 1);
    int outl = 0, tmplen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) > 0 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0 &&
              EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) > 0 &&
              EVP_DecryptUpdate(ctx, out, &outl, data, (int)ct_len) > 0 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) > 0 &&
              EVP_DecryptFinal_ex(ctx, out + outl, &tmplen) > 0;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(out); return NULL; }
    *out_len = (size_t)(outl + tmplen);
    out[*out_len] = 0;
    return out;
}

/* ============================================================================
 * CONFIGURATION AND CONSTANTS (class Config)
 * ============================================================================ */

#define CFG_EPOCH_DURATION            300     /* 5 minutes */
#define CFG_OVERLAP_DURATION          300     /* 5 minutes */
#define CFG_REPLICATION_FACTOR        3
#define CFG_HEARTBEAT_INTERVAL        10
#define CFG_FAILURE_TIMEOUT           30
#define CFG_DEFAULT_TTL               86400   /* 24 hours */
#define CFG_QUORUM_SIZE               2
#define CFG_ANTI_ENTROPY_INTERVAL     600
#define CFG_RWP_TIMEOUT               10.0
#define CFG_MAX_MESSAGE_SIZE          65536
#define CFG_SEARCH_TIMEOUT            30.0
#define CFG_SEARCH_PARALLELISM        3
#define CFG_NODE_ID_BITS              160     /* SHA-1 produces 160-bit ids */
#define CFG_MIN_RESPONSIBLE_NODES     1
#define CFG_RESPONSIBLE_CHECK_INTERVAL 180
#define CFG_MAX_REJOIN_ATTEMPTS       5
#define CFG_MAX_IDENTITY_REGENERATIONS 3
#define CFG_REJOIN_VERIFICATION_WAIT  2

/* Config.get_max_neighbors(ksize) = ksize * NODE_ID_BITS */
static int config_get_max_neighbors(int ksize) { return ksize * CFG_NODE_ID_BITS; }

/* ============================================================================
 * FORWARD DECLARATIONS OF THE MAIN STRUCTURES
 * ============================================================================ */

typedef struct Node Node;
typedef struct NodeHeap NodeHeap;
typedef struct KBucket KBucket;
typedef struct RoutingTable RoutingTable;
typedef struct RRKDHTProtocol RRKDHTProtocol;
typedef struct RWPDHTHandler RWPDHTHandler;
typedef struct RRKDHT RRKDHT;
typedef struct EpochManager EpochManager;
typedef struct SecureMessaging SecureMessaging;
typedef struct NodeInfo NodeInfo;

/* Python `None` port/IP representation: NULL ip, -1 port */
#define PORT_NONE (-1)

/* --- Python set[bytes] equivalent (20-byte node ids) --- */

typedef struct { uint8_t (*ids)[20]; size_t n, cap; } IdSet;

static void idset_init(IdSet *s) { memset(s, 0, sizeof(*s)); }

static bool idset_contains(const IdSet *s, const uint8_t id[20]) {
    for (size_t i = 0; i < s->n; i++)
        if (!memcmp(s->ids[i], id, 20)) return true;
    return false;
}

static bool idset_add(IdSet *s, const uint8_t id[20]) {   /* returns true if newly added */
    if (idset_contains(s, id)) return false;
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 8;
        s->ids = realloc(s->ids, s->cap * 20);
    }
    memcpy(s->ids[s->n++], id, 20);
    return true;
}

static void idset_discard(IdSet *s, const uint8_t id[20]) {
    for (size_t i = 0; i < s->n; i++)
        if (!memcmp(s->ids[i], id, 20)) {
            memmove(s->ids[i], s->ids[s->n - 1], 20);
            s->n--;
            return;
        }
}

static void idset_clear(IdSet *s) { s->n = 0; }
static void idset_free(IdSet *s) { free(s->ids); s->ids = NULL; s->n = s->cap = 0; }

/* --- Python list[Node] equivalent --- */

typedef struct { Node **v; size_t n, cap; } NodeList;

static void nodelist_init(NodeList *l) { memset(l, 0, sizeof(*l)); }

static void nodelist_add(NodeList *l, Node *node) {
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 8;
        l->v = realloc(l->v, l->cap * sizeof(Node *));
    }
    l->v[l->n++] = node;
}

static void nodelist_remove_at(NodeList *l, size_t i) {
    if (i >= l->n) return;
    memmove(&l->v[i], &l->v[i + 1], (l->n - i - 1) * sizeof(Node *));
    l->n--;
}

static bool nodelist_remove(NodeList *l, Node *node) {
    for (size_t i = 0; i < l->n; i++)
        if (l->v[i] == node) { nodelist_remove_at(l, i); return true; }
    return false;
}

static void nodelist_free(NodeList *l) { free(l->v); l->v = NULL; l->n = l->cap = 0; }

/* --- Python OrderedDict[bytes, Node] equivalent --- */

typedef struct { uint8_t (*keys)[20]; Node **vals; size_t n, cap; } ODict;

static void odict_init(ODict *d) { memset(d, 0, sizeof(*d)); }

static Node *odict_get(const ODict *d, const uint8_t id[20]) {
    for (size_t i = 0; i < d->n; i++)
        if (!memcmp(d->keys[i], id, 20)) return d->vals[i];
    return NULL;
}

/* dict[key] = value (in-place, keeps position if key exists) */
static void odict_set(ODict *d, const uint8_t id[20], Node *node) {
    for (size_t i = 0; i < d->n; i++)
        if (!memcmp(d->keys[i], id, 20)) { d->vals[i] = node; return; }
    if (d->n == d->cap) {
        d->cap = d->cap ? d->cap * 2 : 8;
        d->keys = realloc(d->keys, d->cap * 20);
        d->vals = realloc(d->vals, d->cap * sizeof(Node *));
    }
    memcpy(d->keys[d->n], id, 20);
    d->vals[d->n] = node;
    d->n++;
}

static bool odict_del(ODict *d, const uint8_t id[20]) {
    for (size_t i = 0; i < d->n; i++)
        if (!memcmp(d->keys[i], id, 20)) {
            memmove(&d->keys[i], &d->keys[i + 1], (d->n - i - 1) * 20);
            memmove(&d->vals[i], &d->vals[i + 1], (d->n - i - 1) * sizeof(Node *));
            d->n--;
            return true;
        }
    return false;
}

/* OrderedDict.popitem() -> pops LAST item; popitem(last=False) -> FIRST */
static Node *odict_popitem(ODict *d, bool last) {
    if (!d->n) return NULL;
    size_t i = last ? d->n - 1 : 0;
    Node *v = d->vals[i];
    memmove(&d->keys[i], &d->keys[i + 1], (d->n - i - 1) * 20);
    memmove(&d->vals[i], &d->vals[i + 1], (d->n - i - 1) * sizeof(Node *));
    d->n--;
    return v;
}

static void odict_free(ODict *d) { free(d->keys); free(d->vals); memset(d, 0, sizeof(*d)); }

/* ============================================================================
 * EPOCH MANAGEMENT (class EpochManager)
 * ============================================================================ */

struct EpochManager {
    int epoch_duration;
    int overlap_duration;
    int64_t epoch_start;             /* fixed start time (Unix timestamp) */
};

static EpochManager *EpochManager_new(int epoch_duration, int overlap_duration) {
    EpochManager *em = calloc(1, sizeof(EpochManager));
    em->epoch_duration = epoch_duration > 0 ? epoch_duration : CFG_EPOCH_DURATION;
    em->overlap_duration = overlap_duration > 0 ? overlap_duration : CFG_OVERLAP_DURATION;
    em->epoch_start = 1704067200;    /* 2024-01-01T00:00:00Z */
    return em;
}

/* get_current_epoch(): int((time.time() - epoch_start) // epoch_duration) */
static int64_t EpochManager_get_current_epoch(EpochManager *em) {
    return (int64_t)floor((now_time() - (double)em->epoch_start) / (double)em->epoch_duration);
}

/* get_storage_epochs(): [current] */
static size_t EpochManager_get_storage_epochs(EpochManager *em, int64_t **out) {
    *out = malloc(sizeof(int64_t));
    (*out)[0] = EpochManager_get_current_epoch(em);
    return 1;
}

/* get_retrieval_epochs(): [current, current-1] — FIX #2 (display only:
 * the lookup enforces this itself now; this keeps the `debug` output
 * consistent with actual behavior) */
static size_t EpochManager_get_retrieval_epochs(EpochManager *em, int64_t **out) {
    int64_t current = EpochManager_get_current_epoch(em);
    *out = malloc(2 * sizeof(int64_t));
    (*out)[0] = current;
    (*out)[1] = current - 1;
    return 2;
}

/* ============================================================================
 * RWP PROTOCOL COMPONENTS (MessageType, Message, NodeInfo)
 * ============================================================================ */

typedef enum {
    MT_PING, MT_PONG, MT_NODE_INFO, MT_NODE_INFO_RESPONSE,
    MT_FIND_NODE, MT_HEARTBEAT, MT_DHT_GET, MT_DHT_SET, MT_VERIFY
} MessageType;

static const char *message_type_value(MessageType t) {
    switch (t) {
        case MT_PING:               return "ping";
        case MT_PONG:               return "pong";
        case MT_NODE_INFO:          return "node_info";
        case MT_NODE_INFO_RESPONSE: return "node_info_response";
        case MT_FIND_NODE:          return "find_node";
        case MT_VERIFY:             return "verify_neighbor";
        case MT_HEARTBEAT:          return "heartbeat";
        case MT_DHT_GET:            return "dht_get";
        case MT_DHT_SET:            return "dht_set";
    }
    return "?";
}

/* MessageType(value) — raises ValueError in Python; returns false here */
static bool message_type_from_value(const char *s, MessageType *out) {
    for (int i = MT_PING; i <= MT_DHT_SET; i++)
        if (!strcmp(s, message_type_value((MessageType)i))) { *out = (MessageType)i; return true; }
    return false;
}

/* @dataclass Message */
typedef struct Message {
    MessageType type;
    char *sender_id;
    JVal *payload;                 /* Dict[str, Any] */
    double timestamp;              /* default_factory=time.time */
    char *message_id;              /* default_factory=lambda: os.urandom(16).hex() */
} Message;

static Message *Message_new(MessageType type, const char *sender_id, JVal *payload) {
    Message *m = calloc(1, sizeof(Message));
    m->type = type;
    m->sender_id = xstrdup(sender_id);
    m->payload = payload;
    m->timestamp = now_time();
    uint8_t rnd[16]; rand_bytes(rnd, 16);
    m->message_id = hex_encode(rnd, 16);
    return m;
}

/* @dataclass NodeInfo */
struct NodeInfo {
    char *node_id;
    char *ip;
    int port;
    int rwp_port;
    char *rendezvous_key;
    char *signing_public_key;      /* PEM */
    char *exchange_public_key;     /* PEM */
    int64_t epoch;
    double timestamp;
};

/* is_expired(max_age=3600) */
static bool NodeInfo_is_expired(NodeInfo *ni, int max_age) {
    if (max_age <= 0) max_age = 3600;
    return now_time() - ni->timestamp > (double)max_age;
}

/* ============================================================================
 * SECURE MESSAGING (class SecureMessaging)
 * ============================================================================ */

struct SecureMessaging {
    EVP_PKEY *signing_private_key;   /* Ed25519 */
    EVP_PKEY *signing_public_key;    /* Ed25519 */
    EVP_PKEY *exchange_private_key;  /* X25519, generated in __init__ */
    EVP_PKEY *exchange_public_key;   /* X25519 */
};

static SecureMessaging *SecureMessaging_new(EVP_PKEY *signing_private_key, EVP_PKEY *signing_public_key) {
    SecureMessaging *sm = calloc(1, sizeof(SecureMessaging));
    sm->signing_private_key = signing_private_key;
    sm->signing_public_key = signing_public_key;
    sm->exchange_private_key = create_x25519_private_key();
    /* public key derived from private (same EVP_PKEY object carries both;
     * keep an explicit reference for clarity, mirroring .public_key()) */
    sm->exchange_public_key = sm->exchange_private_key;
    return sm;
}

/* Frees the exchange keypair this SecureMessaging owns (generated in _new).
 * Does NOT free signing_private_key/signing_public_key — those are supplied
 * by the caller (RRKDHT) and freed by whoever owns node identity. */
static void SecureMessaging_free(SecureMessaging *sm) {
    if (!sm) return;
    if (sm->exchange_private_key) EVP_PKEY_free(sm->exchange_private_key);
    free(sm);
}

/* encrypt_message(message, recipient_exchange_public_key) -> nonce+ciphertext
 * `message` is a JVal dict; returns bytes or NULL (exception path in Python). */
static uint8_t *SecureMessaging_encrypt_message(SecureMessaging *sm, JVal *message,
                                                EVP_PKEY *recipient_exchange_public_key,
                                                size_t *out_len) {
    uint8_t shared[32], key[32];
    if (!x25519_exchange(sm->exchange_private_key, recipient_exchange_public_key, shared)) {
        log_error("Encryption failed: X25519 exchange");
        return NULL;
    }
    if (!hkdf_rrdht(shared, key)) {
        log_error("Encryption failed: HKDF");
        return NULL;
    }
    uint8_t nonce[12]; rand_bytes(nonce, 12);   /* os.urandom(12) */
    char *msg = j_dumps(message);               /* json.dumps(message, default=...) */
    size_t ct_len;
    uint8_t *ct = chacha_encrypt(key, nonce, (uint8_t *)msg, strlen(msg), &ct_len);
    free(msg);
    if (!ct) {
        log_error("Encryption failed: ChaCha20Poly1305");
        return NULL;
    }
    uint8_t *out = malloc(12 + ct_len);         /* nonce + ciphertext */
    memcpy(out, nonce, 12);
    memcpy(out + 12, ct, ct_len);
    free(ct);
    *out_len = 12 + ct_len;
    return out;
}

/* decrypt_message(encrypted_data, sender_exchange_public_key) -> JVal dict */
static JVal *SecureMessaging_decrypt_message(SecureMessaging *sm, const uint8_t *encrypted_data,
                                             size_t encrypted_len, EVP_PKEY *sender_exchange_public_key) {
    if (encrypted_len < 12 + 16) {
        log_error("Decryption failed: message too short");
        return NULL;
    }
    uint8_t shared[32], key[32];
    if (!x25519_exchange(sm->exchange_private_key, sender_exchange_public_key, shared)) {
        log_error("Decryption failed: X25519 exchange");
        return NULL;
    }
    if (!hkdf_rrdht(shared, key)) {
        log_error("Decryption failed: HKDF");
        return NULL;
    }
    size_t pt_len;
    uint8_t *pt = chacha_decrypt(key, encrypted_data /*nonce*/, encrypted_data + 12,
                                 encrypted_len - 12, &pt_len);
    if (!pt) {
        log_error("Decryption failed: ChaCha20Poly1305 tag mismatch");
        return NULL;
    }
    JVal *msg = j_loads((char *)pt);
    free(pt);
    if (!msg) log_error("Decryption failed: invalid JSON");
    return msg;
}

/* ============================================================================
 * NODE CLASSES (class Node)
 * ============================================================================ */

struct Node {
    uint8_t id[20];                /* node id bytes (SHA-1 space) */
    char *ip;                      /* NULL = None */
    int port;                      /* PORT_NONE = None */
    int rwp_port;                  /* PORT_NONE = None */
    char *rendezvous_key;          /* NULL = None */
    u256 long_id;                  /* int(node_id.hex(), 16) */
    double last_seen;
    int failed_pings;
    double last_confirmed_as_neighbor;
};

static Node *Node_new_full(const uint8_t node_id[20], const char *ip, int port,
                           int rwp_port, const char *rendezvous_key) {
    Node *n = calloc(1, sizeof(Node));
    memcpy(n->id, node_id, 20);
    n->ip = xstrdup(ip);
    n->port = port;
    n->rwp_port = rwp_port;
    n->rendezvous_key = xstrdup(rendezvous_key);
    n->long_id = u256_from_bytes_be20(node_id);
    n->last_seen = now_time();
    n->failed_pings = 0;
    n->last_confirmed_as_neighbor = now_time();
    return n;
}

static Node *Node_new(const uint8_t node_id[20]) {
    return Node_new_full(node_id, NULL, PORT_NONE, PORT_NONE, NULL);
}

/* Nodes are never freed — mirrors Python GC-managed shared references:
 * the same Node object is shared between buckets, heaps, search results. */

/* same_home_as(node) */
static bool Node_same_home_as(Node *a, Node *b) {
    bool ip_eq = (a->ip == NULL && b->ip == NULL) || (a->ip && b->ip && !strcmp(a->ip, b->ip));
    return ip_eq && a->port == b->port;
}

/* distance_to(node): long_id ^ node.long_id */
static u256 Node_distance_to(Node *a, Node *b) { return u256_xor(a->long_id, b->long_id); }

/* get_rwp_url(content="") */
static char *Node_get_rwp_url(Node *n, const char *content) {
    if (!n->rendezvous_key) return NULL;
    StrBuf sb; sb_init(&sb);
    sb_addf(&sb, "rwp://%s/%s", n->rendezvous_key, content ? content : "");
    return sb_steal(&sb);
}

/* touch() */
static void Node_touch(Node *n) {
    n->last_seen = now_time();
    n->failed_pings = 0;
}

/* confirm_as_neighbor() */
static void Node_confirm_as_neighbor(Node *n) { n->last_confirmed_as_neighbor = now_time(); }

/* is_stale(timeout=Config.FAILURE_TIMEOUT) */
static bool Node_is_stale(Node *n, double timeout) {
    if (timeout <= 0) timeout = CFG_FAILURE_TIMEOUT;
    return now_time() - n->last_seen > timeout;
}

/* __eq__: identity by node id bytes */
static bool Node_eq(Node *a, Node *b) { return a && b && !memcmp(a->id, b->id, 20); }

/* __str__: f"{ip}:{port}(rwp:{rwp_port})" — None prints as "None" */
static char *Node_str(Node *n) {
    StrBuf sb; sb_init(&sb);
    if (n->ip) sb_add(&sb, n->ip); else sb_add(&sb, "None");
    if (n->port == PORT_NONE) sb_add(&sb, ":None"); else sb_addf(&sb, ":%d", n->port);
    if (n->rwp_port == PORT_NONE) sb_add(&sb, "(rwp:None)"); else sb_addf(&sb, "(rwp:%d)", n->rwp_port);
    return sb_steal(&sb);
}

/* __repr__: repr([long_id, ip, port, rwp_port, rendezvous_key]) */
/* Python repr() of a bytes object: b'...' with \x escapes for non-printables */
static char *py_bytes_repr(const uint8_t *b, size_t n) {
    StrBuf sb; sb_init(&sb);
    sb_add(&sb, "b'");
    for (size_t i = 0; i < n; i++) {
        uint8_t c = b[i];
        if (c == '\\') sb_add(&sb, "\\\\");
        else if (c == '\'') sb_add(&sb, "\\'");
        else if (c == '\n') sb_add(&sb, "\\n");
        else if (c == '\r') sb_add(&sb, "\\r");
        else if (c == '\t') sb_add(&sb, "\\t");
        else if (c >= 32 && c < 127) sb_addc(&sb, (char)c);
        else sb_addf(&sb, "\\x%02x", c);
    }
    sb_add(&sb, "'");
    return sb_steal(&sb);
}

static char *Node_repr(Node *n) {
    StrBuf sb; sb_init(&sb);
    char *dec = u256_to_dec(n->long_id);
    sb_addf(&sb, "[%s, ", dec);
    free(dec);
    if (n->ip) sb_addf(&sb, "'%s'", n->ip); else sb_add(&sb, "None");
    if (n->port == PORT_NONE) sb_add(&sb, ", None"); else sb_addf(&sb, ", %d", n->port);
    if (n->rwp_port == PORT_NONE) sb_add(&sb, ", None"); else sb_addf(&sb, ", %d", n->rwp_port);
    if (n->rendezvous_key) sb_addf(&sb, ", '%s'", n->rendezvous_key); else sb_add(&sb, ", None");
    sb_add(&sb, "]");
    return sb_steal(&sb);
}

/* ============================================================================
 * class NodeHeap — heap of nodes ordered by distance to a given node.
 * (Python heapq on (distance, node) tuples; distance collisions on distinct
 * 160-bit ids are practically impossible, so a distance-sorted list is
 * behaviorally identical.)
 * ============================================================================ */

typedef struct { u256 dist; Node *node; uint64_t seq; } HeapEntry;

struct NodeHeap {
    Node *node;                    /* reference node (distances measured to it) */
    HeapEntry *heap; size_t n, cap;
    IdSet contacted;
    int maxsize;
    uint64_t seq_counter;
};

static NodeHeap *NodeHeap_new(Node *node, int maxsize) {
    NodeHeap *h = calloc(1, sizeof(NodeHeap));
    h->node = node;
    h->maxsize = maxsize;
    idset_init(&h->contacted);
    return h;
}

static void nodeheap_insert_sorted(NodeHeap *h, u256 dist, Node *node) {
    if (h->n == h->cap) {
        h->cap = h->cap ? h->cap * 2 : 16;
        h->heap = realloc(h->heap, h->cap * sizeof(HeapEntry));
    }
    size_t i = h->n++;
    h->heap[i].dist = dist;
    h->heap[i].node = node;
    h->heap[i].seq = h->seq_counter++;
    /* bubble up to keep sorted by (dist, insertion seq) */
    while (i > 0) {
        HeapEntry *cur = &h->heap[i], *prev = &h->heap[i - 1];
        int c = u256_cmp(prev->dist, cur->dist);
        if (c < 0 || (c == 0 && prev->seq < cur->seq)) break;
        HeapEntry tmp = *prev; *prev = *cur; *cur = tmp;
        i--;
    }
}

/* push(nodes): add nodes not already present (membership by id) */
static bool NodeHeap_contains(NodeHeap *h, Node *node) {   /* __contains__ */
    for (size_t i = 0; i < h->n; i++)
        if (Node_eq(h->heap[i].node, node)) return true;
    return false;
}

static void NodeHeap_push(NodeHeap *h, NodeList *nodes) {
    for (size_t i = 0; i < nodes->n; i++) {
        Node *n = nodes->v[i];
        if (!NodeHeap_contains(h, n))
            nodeheap_insert_sorted(h, Node_distance_to(h->node, n), n);
    }
}

static void NodeHeap_push_one(NodeHeap *h, Node *n) {
    if (!NodeHeap_contains(h, n))
        nodeheap_insert_sorted(h, Node_distance_to(h->node, n), n);
}

/* remove(peers): drop entries whose node id is in peers */
static void NodeHeap_remove(NodeHeap *h, IdSet *peers) {
    if (!peers->n) return;
    size_t w = 0;
    for (size_t i = 0; i < h->n; i++)
        if (!idset_contains(peers, h->heap[i].node->id))
            h->heap[w++] = h->heap[i];
    h->n = w;
}

/* get_node(node_id) */
static Node *NodeHeap_get_node(NodeHeap *h, const uint8_t node_id[20]) {
    for (size_t i = 0; i < h->n; i++)
        if (!memcmp(h->heap[i].node->id, node_id, 20)) return h->heap[i].node;
    return NULL;
}

/* __len__ = min(len(heap), maxsize) */
static size_t NodeHeap_len(NodeHeap *h) {
    return h->n < (size_t)h->maxsize ? h->n : (size_t)h->maxsize;
}

/* __iter__: nsmallest(maxsize) — heap is kept sorted, take first maxsize */
static size_t NodeHeap_iter(NodeHeap *h, Node **out, size_t out_max) {
    size_t n = NodeHeap_len(h);
    if (n > out_max) n = out_max;
    for (size_t i = 0; i < n; i++) out[i] = h->heap[i].node;
    return n;
}

/* get_ids() over the (truncated) iteration view */
static IdSet NodeHeap_get_ids_set(NodeHeap *h) {
    IdSet s; idset_init(&s);
    size_t n = NodeHeap_len(h);
    for (size_t i = 0; i < n; i++) idset_add(&s, h->heap[i].node->id);
    return s;
}

/* get_ids() as ordered list of ids (comparison in SpiderCrawl uses equality) */
static size_t NodeHeap_get_ids(NodeHeap *h, uint8_t (*out)[20], size_t out_max) {
    size_t n = NodeHeap_len(h);
    if (n > out_max) n = out_max;
    for (size_t i = 0; i < n; i++) memcpy(out[i], h->heap[i].node->id, 20);
    return n;
}

/* mark_contacted(node) */
static void NodeHeap_mark_contacted(NodeHeap *h, Node *node) { idset_add(&h->contacted, node->id); }

/* popleft() -> pop closest node or NULL */
static Node *NodeHeap_popleft(NodeHeap *h) {
    if (NodeHeap_len(h) == 0) return NULL;
    Node *n = h->heap[0].node;
    memmove(&h->heap[0], &h->heap[1], (h->n - 1) * sizeof(HeapEntry));
    h->n--;
    return n;
}

/* get_uncontacted(): nodes in iteration view not yet contacted */
static NodeList NodeHeap_get_uncontacted(NodeHeap *h) {
    NodeList l; nodelist_init(&l);
    size_t n = NodeHeap_len(h);
    for (size_t i = 0; i < n; i++)
        if (!idset_contains(&h->contacted, h->heap[i].node->id))
            nodelist_add(&l, h->heap[i].node);
    return l;
}

/* have_contacted_all() */
static bool NodeHeap_have_contacted_all(NodeHeap *h) {
    NodeList l = NodeHeap_get_uncontacted(h);
    bool all = l.n == 0;
    nodelist_free(&l);
    return all;
}

/* ============================================================================
 * ROUTING TABLE CLASSES (KBucket, TableTraverser, RoutingTable)
 * ============================================================================ */

struct KBucket {
    u256 range_lo, range_hi;         /* self.range = (rangeLower, rangeUpper) */
    ODict nodes;                     /* OrderedDict[id, Node] */
    ODict replacement_nodes;         /* OrderedDict[id, Node] */
    double last_updated;             /* monotonic */
    int ksize;
    int max_replacement_nodes;       /* ksize * replacementNodeFactor */
};

/* utility functions shared_prefix / bytes_to_bit_string (module level in .py) */

static char *bytes_to_bit_string(const uint8_t *bites, size_t n) {
    char *out = malloc(n * 8 + 1);
    for (size_t i = 0; i < n; i++)
        for (int b = 7; b >= 0; b--)
            out[i * 8 + (7 - b)] = (bites[i] >> b) & 1 ? '1' : '0';
    out[n * 8] = '\0';
    return out;
}

/* shared prefix length of equal-length strings (Python shared_prefix()) */
static size_t shared_prefix_len(char **args, size_t nargs) {
    if (!nargs) return 0;
    size_t minlen = strlen(args[0]);
    for (size_t i = 1; i < nargs; i++) {
        size_t l = strlen(args[i]);
        if (l < minlen) minlen = l;
    }
    size_t i = 0;
    while (i < minlen) {
        char c = args[0][i];
        bool same = true;
        for (size_t k = 1; k < nargs; k++)
            if (args[k][i] != c) { same = false; break; }
        if (!same) break;
        i++;
    }
    return i;
}

static KBucket *KBucket_new(u256 rangeLower, u256 rangeUpper, int ksize, int replacementNodeFactor) {
    KBucket *b = calloc(1, sizeof(KBucket));
    b->range_lo = rangeLower;
    b->range_hi = rangeUpper;
    odict_init(&b->nodes);
    odict_init(&b->replacement_nodes);
    b->last_updated = now_mono();            /* touch_last_updated() */
    b->ksize = ksize;
    if (replacementNodeFactor <= 0) replacementNodeFactor = 5;
    b->max_replacement_nodes = ksize * replacementNodeFactor;
    return b;
}

static void KBucket_touch_last_updated(KBucket *b) { b->last_updated = now_mono(); }

/* get_nodes() -> list copy (caller frees list, not nodes) */
static NodeList KBucket_get_nodes(KBucket *b) {
    NodeList l; nodelist_init(&l);
    for (size_t i = 0; i < b->nodes.n; i++) nodelist_add(&l, b->nodes.vals[i]);
    return l;
}

static size_t KBucket_len(KBucket *b) { return b->nodes.n; }              /* __len__ */
static Node *KBucket_get(KBucket *b, const uint8_t id[20]) { return odict_get(&b->nodes, id); } /* __getitem__ */
static bool KBucket_has_in_range(KBucket *b, Node *n) {                   /* has_in_range */
    return u256_le(b->range_lo, n->long_id) && u256_le(n->long_id, b->range_hi);
}
static bool KBucket_is_new_node(KBucket *b, Node *n) { return !odict_get(&b->nodes, n->id); }
static Node *KBucket_head(KBucket *b) { return b->nodes.n ? b->nodes.vals[0] : NULL; } /* head() */

/* add_node(): true if added/updated in main dict, false if relegated to
 * replacement nodes (bucket full). Exact port including duplicate handling. */
static bool KBucket_add_node(KBucket *b, Node *node) {
    Node *existing = odict_get(&b->nodes, node->id);
    if (existing) {
        /* update existing node with new information */
        if (existing != node) {
            free(existing->ip); existing->ip = xstrdup(node->ip);
            existing->port = node->port;
            existing->rwp_port = node->rwp_port;
            free(existing->rendezvous_key); existing->rendezvous_key = xstrdup(node->rendezvous_key);
        }
        Node_touch(existing);
        /* move to end (most recently seen) */
        odict_del(&b->nodes, node->id);
        odict_set(&b->nodes, node->id, existing);
        return true;
    }
    /* check for duplicate by address (ip:port combination) */
    for (size_t i = 0; i < b->nodes.n; i++) {
        Node *en = b->nodes.vals[i];
        bool ip_eq = (en->ip == NULL && node->ip == NULL) ||
                     (en->ip && node->ip && !strcmp(en->ip, node->ip));
        if (ip_eq && en->port == node->port) {
            char *ips = node->ip ? node->ip : "None";
            log_debug("Found duplicate address %s:%d, updating existing node", ips, node->port);
            if (en != node) {
                free(en->ip); en->ip = xstrdup(node->ip);
                en->port = node->port;
                en->rwp_port = node->rwp_port;
                free(en->rendezvous_key); en->rendezvous_key = xstrdup(node->rendezvous_key);
            }
            Node_touch(en);
            return true;
        }
    }
    if (KBucket_len(b) < (size_t)b->ksize) {
        odict_set(&b->nodes, node->id, node);
        return true;
    }
    /* bucket full -> replacement nodes */
    odict_del(&b->replacement_nodes, node->id);
    odict_set(&b->replacement_nodes, node->id, node);
    while (b->replacement_nodes.n > (size_t)b->max_replacement_nodes)
        odict_popitem(&b->replacement_nodes, false);  /* popitem(last=False) */
    return false;
}

/* split() -> (one, two), redistributing nodes + replacement nodes */
static void KBucket_split(KBucket *b, KBucket **one_out, KBucket **two_out) {
    u256 sum = u256_add(b->range_lo, b->range_hi);
    u256 midpoint = u256_shr1(sum);                        /* (lo + hi) // 2 */
    KBucket *one = KBucket_new(b->range_lo, midpoint, b->ksize, 5);
    KBucket *two = KBucket_new(u256_add(midpoint, u256_from_u64(1)), b->range_hi, b->ksize, 5);
    /* chain(nodes.values(), replacement_nodes.values()) */
    for (int pass = 0; pass < 2; pass++) {
        ODict *d = pass == 0 ? &b->nodes : &b->replacement_nodes;
        for (size_t i = 0; i < d->n; i++) {
            Node *n = d->vals[i];
            KBucket *target = u256_le(n->long_id, midpoint) ? one : two;
            KBucket_add_node(target, n);
        }
    }
    *one_out = one;
    *two_out = two;
}

/* remove_node() */
static void KBucket_remove_node(KBucket *b, Node *node) {
    odict_del(&b->replacement_nodes, node->id);
    if (odict_del(&b->nodes, node->id)) {
        if (b->replacement_nodes.n) {
            Node *nn = odict_popitem(&b->replacement_nodes, true);   /* popitem() */
            /* need the id too — re-set under the node's own id */
            odict_set(&b->nodes, nn->id, nn);
        }
    }
}

/* depth(): length of shared prefix of node id bit strings */
static int KBucket_depth(KBucket *b) {
    if (!b->nodes.n) return 0;      /* Python would raise ValueError on min();
                                       unreachable in practice (only called on full buckets) */
    char **bits = malloc(b->nodes.n * sizeof(char *));
    for (size_t i = 0; i < b->nodes.n; i++) bits[i] = bytes_to_bit_string(b->nodes.vals[i]->id, 20);
    size_t d = shared_prefix_len(bits, b->nodes.n);
    for (size_t i = 0; i < b->nodes.n; i++) free(bits[i]);
    free(bits);
    return (int)d;
}

/* --- TableTraverser --- */

typedef struct {
    NodeList current_nodes;          /* list; pop() takes the LAST element */
    KBucket **left_buckets; size_t nleft;    /* buckets[:index], pop() takes LAST */
    KBucket **right_buckets; size_t nright;  /* buckets[index+1:], pop(0) takes FIRST */
    size_t right_pos;
    bool left;
} TableTraverser;

static void TableTraverser_init(TableTraverser *t, RoutingTable *table, Node *startNode);
/* (defined after RoutingTable) */

static Node *TableTraverser_next(TableTraverser *t) {   /* __next__; NULL = StopIteration */
    if (t->current_nodes.n) {
        Node *n = t->current_nodes.v[t->current_nodes.n - 1];
        t->current_nodes.n--;
        return n;
    }
    if (t->left && t->nleft) {
        KBucket *b = t->left_buckets[--t->nleft];
        nodelist_free(&t->current_nodes);
        t->current_nodes = KBucket_get_nodes(b);
        t->left = false;
        return TableTraverser_next(t);
    }
    if (t->right_pos < t->nright) {
        KBucket *b = t->right_buckets[t->right_pos++];
        nodelist_free(&t->current_nodes);
        t->current_nodes = KBucket_get_nodes(b);
        t->left = true;
        return TableTraverser_next(t);
    }
    return NULL;
}

static void TableTraverser_free(TableTraverser *t) {
    nodelist_free(&t->current_nodes);
    free(t->left_buckets);
    free(t->right_buckets);
}

/* --- RoutingTable --- */

struct RoutingTable {
    Node *node;                      /* our own node */
    RRKDHTProtocol *protocol;
    int ksize;
    int max_neighbors;               /* Config.get_max_neighbors(ksize) */
    KBucket **buckets; size_t nbuckets, capbuckets;
    pthread_mutex_t mu;              /* recursive — guards the table (GIL role) */
};

static void RoutingTable_lock(RoutingTable *t) { pthread_mutex_lock(&t->mu); }
static void RoutingTable_unlock(RoutingTable *t) { pthread_mutex_unlock(&t->mu); }

/* flush(): buckets = [KBucket(0, 2**160, ksize)] */
static void RoutingTable_flush(RoutingTable *t) {
    for (size_t i = 0; i < t->nbuckets; i++) {
        odict_free(&t->buckets[i]->nodes);
        odict_free(&t->buckets[i]->replacement_nodes);
        free(t->buckets[i]);
    }
    t->nbuckets = 0;
    t->buckets[t->nbuckets++] = KBucket_new(u256_zero(), u256_pow2(160), t->ksize, 5);
}

static RoutingTable *RoutingTable_new(RRKDHTProtocol *protocol, int ksize, Node *node) {
    RoutingTable *t = calloc(1, sizeof(RoutingTable));
    t->node = node;
    t->protocol = protocol;
    t->ksize = ksize;
    t->max_neighbors = config_get_max_neighbors(ksize);
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&t->mu, &attr);
    pthread_mutexattr_destroy(&attr);
    t->capbuckets = 8;
    t->buckets = malloc(t->capbuckets * sizeof(KBucket *));
    RoutingTable_flush(t);
    return t;
}

/* get_bucket_for(node) */
static int RoutingTable_get_bucket_for(RoutingTable *t, Node *node) {
    log_info("Finding bucket");
    for (size_t i = 0; i < t->nbuckets; i++)
        if (u256_lt(node->long_id, t->buckets[i]->range_hi)) return (int)i;
    return (int)t->nbuckets - 1;     /* fallback: last bucket */
}

static void TableTraverser_init(TableTraverser *tr, RoutingTable *table, Node *startNode) {
    int index = RoutingTable_get_bucket_for(table, startNode);
    KBucket_touch_last_updated(table->buckets[index]);
    tr->current_nodes = KBucket_get_nodes(table->buckets[index]);
    tr->nleft = (size_t)index;
    tr->left_buckets = malloc((tr->nleft ? tr->nleft : 1) * sizeof(KBucket *));
    for (size_t i = 0; i < tr->nleft; i++) tr->left_buckets[i] = table->buckets[i];
    tr->nright = table->nbuckets - (size_t)index - 1;
    tr->right_buckets = malloc((tr->nright ? tr->nright : 1) * sizeof(KBucket *));
    for (size_t i = 0; i < tr->nright; i++) tr->right_buckets[i] = table->buckets[index + 1 + i];
    tr->right_pos = 0;
    tr->left = true;
}

/* split_bucket(index) */
static void RoutingTable_split_bucket(RoutingTable *t, int index) {
    KBucket *one, *two;
    KBucket_split(t->buckets[index], &one, &two);
    odict_free(&t->buckets[index]->nodes);
    odict_free(&t->buckets[index]->replacement_nodes);
    free(t->buckets[index]);
    t->buckets[index] = one;
    if (t->nbuckets == t->capbuckets) {
        t->capbuckets *= 2;
        t->buckets = realloc(t->buckets, t->capbuckets * sizeof(KBucket *));
    }
    memmove(&t->buckets[index + 2], &t->buckets[index + 1],
            (t->nbuckets - (size_t)index - 1) * sizeof(KBucket *));
    t->buckets[index + 1] = two;
    t->nbuckets++;
}

/* lonely_buckets(): not updated in over an hour */
static size_t RoutingTable_lonely_buckets_list(RoutingTable *t, KBucket ***out) {
    double hrago = now_mono() - 3600;
    size_t n = 0;
    KBucket **res = malloc(t->nbuckets * sizeof(KBucket *));
    for (size_t i = 0; i < t->nbuckets; i++)
        if (t->buckets[i]->last_updated < hrago) res[n++] = t->buckets[i];
    *out = res;
    return n;
}

static size_t RoutingTable_lonely_buckets_count(RoutingTable *t) {
    KBucket **l;
    size_t n = RoutingTable_lonely_buckets_list(t, &l);
    free(l);
    return n;
}

/* remove_contact(node) */
static void RoutingTable_remove_contact(RoutingTable *t, Node *node) {
    RoutingTable_lock(t);
    int index = RoutingTable_get_bucket_for(t, node);
    KBucket_remove_node(t->buckets[index], node);
    RoutingTable_unlock(t);
}

/* is_new_node(node) */
static bool RoutingTable_is_new_node(RoutingTable *t, Node *node) {
    RoutingTable_lock(t);
    int index = RoutingTable_get_bucket_for(t, node);
    bool r = KBucket_is_new_node(t->buckets[index], node);
    RoutingTable_unlock(t);
    return r;
}

/* _find_existing_node(target_node): by ID first (per bucket), then by address */
static Node *RoutingTable_find_existing_node(RoutingTable *t, Node *target) {
    for (size_t i = 0; i < t->nbuckets; i++) {
        Node *existing = KBucket_get(t->buckets[i], target->id);
        if (existing) return existing;
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        Node *found = NULL;
        for (size_t j = 0; j < nl.n; j++) {
            Node *n = nl.v[j];
            bool ip_eq = (n->ip == NULL && target->ip == NULL) ||
                         (n->ip && target->ip && !strcmp(n->ip, target->ip));
            if (ip_eq && n->port == target->port) { found = n; break; }
        }
        nodelist_free(&nl);
        if (found) return found;
    }
    return NULL;
}

/* get_total_neighbor_count() */
static int RoutingTable_get_total_neighbor_count(RoutingTable *t) {
    int total = 0;
    for (size_t i = 0; i < t->nbuckets; i++) total += (int)KBucket_len(t->buckets[i]);
    return total;
}

/* is_at_neighbor_limit() */
static bool RoutingTable_is_at_neighbor_limit(RoutingTable *t) {
    return RoutingTable_get_total_neighbor_count(t) >= t->max_neighbors;
}

/* get_neighbors_by_distance(target_node_id=None, k=None) */
static NodeList RoutingTable_get_neighbors_by_distance(RoutingTable *t, const uint8_t target_id[20], int k) {
    if (k <= 0) k = t->ksize;
    uint8_t tid[20];
    if (target_id) memcpy(tid, target_id, 20); else memcpy(tid, t->node->id, 20);
    Node *target = Node_new(tid);
    typedef struct { u256 d; Node *n; } DN;
    DN *all = NULL; size_t n = 0, cap = 0;
    for (size_t i = 0; i < t->nbuckets; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++) {
            if (n == cap) { cap = cap ? cap * 2 : 16; all = realloc(all, cap * sizeof(DN)); }
            all[n].d = Node_distance_to(target, nl.v[j]);
            all[n].n = nl.v[j];
            n++;
        }
        nodelist_free(&nl);
    }
    /* sort by distance (stable) */
    for (size_t i = 1; i < n; i++) {
        DN key = all[i]; size_t j = i;
        while (j > 0 && u256_gt(all[j - 1].d, key.d)) { all[j] = all[j - 1]; j--; }
        all[j] = key;
    }
    NodeList out; nodelist_init(&out);
    for (size_t i = 0; i < n && (int)i < k; i++) nodelist_add(&out, all[i].n);
    free(all);
    free(target->ip); free(target->rendezvous_key); free(target); /* local temp node */
    return out;
}

/* should_accept_new_neighbor(node) */
static bool RoutingTable_should_accept_new_neighbor(RoutingTable *t, Node *node) {
    int current_total = RoutingTable_get_total_neighbor_count(t);
    if (current_total < t->max_neighbors) return true;

    int index = RoutingTable_get_bucket_for(t, node);
    KBucket *bucket = t->buckets[index];
    if (KBucket_len(bucket) < (size_t)bucket->ksize) return true;

    u256 furthest_distance = u256_zero();
    Node *furthest_node = NULL;
    for (size_t i = 0; i < t->nbuckets; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++) {
            u256 d = Node_distance_to(t->node, nl.v[j]);
            if (u256_gt(d, furthest_distance)) { furthest_distance = d; furthest_node = nl.v[j]; }
        }
        nodelist_free(&nl);
    }
    u256 new_node_distance = Node_distance_to(t->node, node);
    if (u256_lt(new_node_distance, furthest_distance)) {
        if (furthest_node) {
            RoutingTable_remove_contact(t, furthest_node);
            log_info("Replaced furthest neighbor %s:%d with closer node %s:%d "
                     "(limit: %d, current: %d)",
                     furthest_node->ip, furthest_node->port, node->ip, node->port,
                     t->max_neighbors, current_total);
        }
        return true;
    }
    log_debug("Rejected node %s:%d - at limit %d and not closer than furthest neighbor",
              node->ip, node->port, t->max_neighbors);
    return false;
}

/* find_neighbors(node, k=None, exclude=None) */
static NodeList RoutingTable_find_neighbors(RoutingTable *t, Node *node, int k, Node *exclude) {
    RoutingTable_lock(t);
    if (k <= 0) k = t->ksize;
    typedef struct { u256 d; Node *n; uint64_t seq; } DN;
    DN *heap = NULL; size_t n = 0, cap = 0;
    IdSet seen; idset_init(&seen);
    TableTraverser tr;
    TableTraverser_init(&tr, t, node);
    Node *neighbor;
    uint64_t seq = 0;
    while ((neighbor = TableTraverser_next(&tr)) != NULL) {
        if (idset_contains(&seen, neighbor->id)) continue;
        bool notexcluded = !exclude || !Node_same_home_as(neighbor, exclude);
        if (notexcluded) {
            if (n == cap) { cap = cap ? cap * 2 : 16; heap = realloc(heap, cap * sizeof(DN)); }
            heap[n].d = Node_distance_to(node, neighbor);
            heap[n].n = neighbor;
            heap[n].seq = seq++;
            n++;
            idset_add(&seen, neighbor->id);
        }
        if ((int)n == k) break;
    }
    TableTraverser_free(&tr);
    idset_free(&seen);
    /* heapq.nsmallest(k, nodes) — heap already <= k; sort by (distance, seq) */
    for (size_t i = 1; i < n; i++) {
        DN key = heap[i]; size_t j = i;
        while (j > 0 && (u256_gt(heap[j - 1].d, key.d) ||
                         (u256_eq(heap[j - 1].d, key.d) && heap[j - 1].seq > key.seq))) {
            heap[j] = heap[j - 1]; j--;
        }
        heap[j] = key;
    }
    NodeList out; nodelist_init(&out);
    for (size_t i = 0; i < n; i++) nodelist_add(&out, heap[i].n);
    free(heap);
    RoutingTable_unlock(t);
    return out;
}

/* get_stale_nodes() */
static NodeList RoutingTable_get_stale_nodes(RoutingTable *t) {
    NodeList out; nodelist_init(&out);
    RoutingTable_lock(t);
    for (size_t i = 0; i < t->nbuckets; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++)
            if (Node_is_stale(nl.v[j], 0)) nodelist_add(&out, nl.v[j]);
        nodelist_free(&nl);
    }
    RoutingTable_unlock(t);
    return out;
}

/* remove_stale_nodes() */
static int RoutingTable_remove_stale_nodes(RoutingTable *t) {
    int removed_count = 0;
    IdSet seen_ids; idset_init(&seen_ids);
    RoutingTable_lock(t);
    for (size_t i = 0; i < t->nbuckets; i++) {
        NodeList to_remove; nodelist_init(&to_remove);
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++) {
            Node *node = nl.v[j];
            if (idset_contains(&seen_ids, node->id)) {
                nodelist_add(&to_remove, node);
                char *hex = hex_encode(node->id, 20);
                log_warning("Removing duplicate node by ID: %s:%d (ID: %.16s...)",
                            node->ip, node->port, hex);
                free(hex);
            } else {
                idset_add(&seen_ids, node->id);
                if (node->failed_pings >= 3 || Node_is_stale(node, CFG_FAILURE_TIMEOUT * 2.0)) {
                    nodelist_add(&to_remove, node);
                    char *hex = hex_encode(node->id, 20);
                    log_info("Removing stale node: %s:%d (ID: %.16s...), failed_pings=%d, last_seen=%ds",
                             node->ip, node->port, hex, node->failed_pings,
                             (int)(now_time() - node->last_seen));
                    free(hex);
                }
            }
        }
        for (size_t j = 0; j < to_remove.n; j++) {
            KBucket_remove_node(t->buckets[i], to_remove.v[j]);
            removed_count++;
        }
        nodelist_free(&to_remove);
        nodelist_free(&nl);
    }
    RoutingTable_unlock(t);
    idset_free(&seen_ids);
    if (removed_count > 0)
        log_info("Removed %d nodes (stale or duplicates) from routing table", removed_count);
    return removed_count;
}

/* get_detailed_routing_info() -> JVal dict (mirrors the Python dict) */
static JVal *RoutingTable_get_detailed_routing_info(RoutingTable *t) {
    RoutingTable_lock(t);
    JVal *info = j_obj();
    int total_nodes = 0, total_replacement = 0, stale_nodes = 0, failed_nodes = 0;
    JVal *buckets_arr = j_arr();
    JVal *distribution = j_obj();
    size_t lonely = RoutingTable_lonely_buckets_count(t);

    for (size_t i = 0; i < t->nbuckets; i++) {
        KBucket *b = t->buckets[i];
        NodeList nodes = KBucket_get_nodes(b);
        JVal *bucket_nodes = j_arr();
        int stale_count = 0, failed_count = 0;
        for (size_t j = 0; j < nodes.n; j++) {
            Node *node = nodes.v[j];
            JVal *ni = j_obj();
            char *hex = hex_encode(node->id, 20);
            j_obj_set(ni, "id", j_str(hex)); free(hex);
            j_obj_set(ni, "long_id", j_u256(node->long_id));
            j_obj_set(ni, "ip", node->ip ? j_str(node->ip) : j_null());
            j_obj_set(ni, "port", node->port == PORT_NONE ? j_null() : j_int(node->port));
            j_obj_set(ni, "rwp_port", node->rwp_port == PORT_NONE ? j_null() : j_int(node->rwp_port));
            j_obj_set(ni, "rendezvous_key", node->rendezvous_key ? j_str(node->rendezvous_key) : j_null());
            j_obj_set(ni, "last_seen", j_num(node->last_seen));
            j_obj_set(ni, "seconds_since_seen", j_int((int64_t)(now_time() - node->last_seen)));
            j_obj_set(ni, "failed_pings", j_int(node->failed_pings));
            j_obj_set(ni, "is_stale", j_bool(Node_is_stale(node, 0)));
            j_obj_set(ni, "distance_to_self", j_u256(Node_distance_to(t->node, node)));
            j_arr_add(bucket_nodes, ni);
            if (Node_is_stale(node, 0)) stale_count++;
            if (node->failed_pings > 0) failed_count++;
        }
        JVal *repl_arr = j_arr();
        for (size_t j = 0; j < b->replacement_nodes.n; j++) {
            Node *node = b->replacement_nodes.vals[j];
            JVal *ri = j_obj();
            char *hex = hex_encode(node->id, 20);
            j_obj_set(ri, "id", j_str(hex)); free(hex);
            j_obj_set(ri, "ip", node->ip ? j_str(node->ip) : j_null());
            j_obj_set(ri, "port", node->port == PORT_NONE ? j_null() : j_int(node->port));
            j_obj_set(ri, "rwp_port", node->rwp_port == PORT_NONE ? j_null() : j_int(node->rwp_port));
            j_obj_set(ri, "last_seen", j_num(node->last_seen));
            j_obj_set(ri, "seconds_since_seen", j_int((int64_t)(now_time() - node->last_seen)));
            j_arr_add(repl_arr, ri);
        }
        JVal *bi = j_obj();
        j_obj_set(bi, "index", j_int((int64_t)i));
        char *lo = u256_to_hex0x(b->range_lo), *hi = u256_to_hex0x(b->range_hi);
        StrBuf rs; sb_init(&rs);
        sb_addf(&rs, "%s - %s", lo, hi);
        j_obj_set(bi, "range", j_str(rs.buf));
        sb_free(&rs); free(lo); free(hi);
        u256 size = u256_add(u256_sub(b->range_hi, b->range_lo), u256_from_u64(1));
        j_obj_set(bi, "range_size", j_u256(size));
        j_obj_set(bi, "node_count", j_int((int64_t)nodes.n));
        j_obj_set(bi, "replacement_count", j_int((int64_t)b->replacement_nodes.n));
        j_obj_set(bi, "max_nodes", j_int(b->ksize));
        j_obj_set(bi, "last_updated", j_num(b->last_updated));
        j_obj_set(bi, "seconds_since_update", j_int((int64_t)(now_mono() - b->last_updated)));
        bool is_lonely = b->last_updated < now_mono() - 3600;
        j_obj_set(bi, "is_lonely", j_bool(is_lonely));
        j_obj_set(bi, "stale_nodes", j_int(stale_count));
        j_obj_set(bi, "failed_nodes", j_int(failed_count));
        j_obj_set(bi, "nodes", bucket_nodes);
        j_obj_set(bi, "replacement_nodes", repl_arr);
        j_arr_add(buckets_arr, bi);

        total_nodes += (int)nodes.n;
        total_replacement += (int)b->replacement_nodes.n;
        stale_nodes += stale_count;
        failed_nodes += failed_count;

        char cntbuf[32]; snprintf(cntbuf, sizeof(cntbuf), "%zu", nodes.n);
        JVal *dv = j_obj_get(distribution, cntbuf);
        j_obj_set(distribution, cntbuf, j_int(dv ? (int64_t)dv->num + 1 : 1));
        nodelist_free(&nodes);
    }

    j_obj_set(info, "total_buckets", j_int((int64_t)t->nbuckets));
    j_obj_set(info, "total_nodes", j_int(total_nodes));
    j_obj_set(info, "total_replacement_nodes", j_int(total_replacement));
    j_obj_set(info, "max_neighbors", j_int(t->max_neighbors));
    j_obj_set(info, "ksize", j_int(t->ksize));
    j_obj_set(info, "lonely_buckets", j_int((int64_t)lonely));
    j_obj_set(info, "buckets", buckets_arr);
    j_obj_set(info, "node_distribution", distribution);
    j_obj_set(info, "stale_nodes", j_int(stale_nodes));
    j_obj_set(info, "failed_nodes", j_int(failed_nodes));
    RoutingTable_unlock(t);
    return info;
}

/* analyze_routing_health() -> JVal dict */
static JVal *RoutingTable_analyze_routing_health(RoutingTable *t) {
    JVal *ri = RoutingTable_get_detailed_routing_info(t);
    double total_nodes = j_get_num(ri, "total_nodes", 0);
    double stale_nodes = j_get_num(ri, "stale_nodes", 0);
    double failed_nodes = j_get_num(ri, "failed_nodes", 0);
    double lonely = j_get_num(ri, "lonely_buckets", 0);
    double nbuckets = j_get_num(ri, "total_buckets", 1);

    JVal *report = j_obj();
    j_obj_set(report, "overall_health", j_str("GOOD"));
    JVal *issues = j_arr();
    JVal *recs = j_arr();
    JVal *metrics = j_obj();
    j_obj_set(metrics, "fill_ratio", j_num(total_nodes / (nbuckets * t->ksize)));
    j_obj_set(metrics, "stale_ratio", j_num(stale_nodes / (total_nodes > 1 ? total_nodes : 1)));
    j_obj_set(metrics, "failed_ratio", j_num(failed_nodes / (total_nodes > 1 ? total_nodes : 1)));
    j_obj_set(metrics, "lonely_ratio", j_num(lonely / nbuckets));
    j_obj_set(report, "issues", issues);
    j_obj_set(report, "recommendations", recs);
    j_obj_set(report, "metrics", metrics);

    char buf[128];
    if (total_nodes < 10) {
        j_arr_add(issues, j_str("Very few neighbors - network connectivity may be poor"));
        j_arr_add(recs, j_str("Try bootstrapping with more nodes"));
        j_obj_set(report, "overall_health", j_str("POOR"));
    }
    double stale_ratio = j_get_num(metrics, "stale_ratio", 0);
    if (stale_ratio > 0.3) {
        snprintf(buf, sizeof(buf), "High stale node ratio: %.2f%%", stale_ratio * 100);
        j_arr_add(issues, j_str(buf));
        j_arr_add(recs, j_str("Increase heartbeat frequency or reduce failure timeout"));
        if (!strcmp(j_get_str(report, "overall_health"), "GOOD"))
            j_obj_set(report, "overall_health", j_str("FAIR"));
    }
    double failed_ratio = j_get_num(metrics, "failed_ratio", 0);
    if (failed_ratio > 0.2) {
        snprintf(buf, sizeof(buf), "High failed node ratio: %.2f%%", failed_ratio * 100);
        j_arr_add(issues, j_str(buf));
        j_arr_add(recs, j_str("Review network connectivity and node reliability"));
        if (!strcmp(j_get_str(report, "overall_health"), "GOOD"))
            j_obj_set(report, "overall_health", j_str("FAIR"));
    }
    double lonely_ratio = j_get_num(metrics, "lonely_ratio", 0);
    if (lonely_ratio > 0.5) {
        snprintf(buf, sizeof(buf), "Many lonely buckets: %.2f%%", lonely_ratio * 100);
        j_arr_add(issues, j_str(buf));
        j_arr_add(recs, j_str("Perform more frequent routing table refreshes"));
        if (!strcmp(j_get_str(report, "overall_health"), "GOOD"))
            j_obj_set(report, "overall_health", j_str("FAIR"));
    }
    j_free(ri);
    return report;
}

/* print_routing_table(show_empty_buckets=False, show_replacement_nodes=False) */
static void RoutingTable_print(RoutingTable *t, bool show_empty_buckets, bool show_replacement_nodes) {
    JVal *ri = RoutingTable_get_detailed_routing_info(t);
    char *self_hex = hex_encode(t->node->id, 20);
    printf("\n================================================================================\n");
    printf("ROUTING TABLE DEBUG - Node ID: %s\n", self_hex);
    printf("================================================================================\n");
    printf("Max Neighbors: %d | KSize: %d\n", (int)j_get_num(ri, "max_neighbors", 0), (int)j_get_num(ri, "ksize", 0));
    printf("Total Buckets: %d\n", (int)j_get_num(ri, "total_buckets", 0));
    printf("Total Nodes: %d\n", (int)j_get_num(ri, "total_nodes", 0));
    printf("Total Replacement Nodes: %d\n", (int)j_get_num(ri, "total_replacement_nodes", 0));
    printf("Lonely Buckets: %d\n", (int)j_get_num(ri, "lonely_buckets", 0));
    printf("Stale Nodes: %d\n", (int)j_get_num(ri, "stale_nodes", 0));
    printf("Failed Nodes: %d\n", (int)j_get_num(ri, "failed_nodes", 0));
    free(self_hex);

    printf("\nBucket Fill Distribution:\n");
    JVal *dist = j_obj_get(ri, "node_distribution");
    if (dist) {
        /* sorted(routing_info['node_distribution'].items()) — numeric key order */
        for (size_t a = 0; a < dist->npairs; a++)
            for (size_t b = a + 1; b < dist->npairs; b++)
                if (atoi(dist->keys[a]) > atoi(dist->keys[b])) {
                    char *tk = dist->keys[a]; dist->keys[a] = dist->keys[b]; dist->keys[b] = tk;
                    JVal *tv = dist->vals[a]; dist->vals[a] = dist->vals[b]; dist->vals[b] = tv;
                }
        for (size_t k = 0; k < dist->npairs; k++)
            printf("  %s nodes: %d buckets\n", dist->keys[k], (int)dist->vals[k]->num);
    }

    printf("\n%-6s %-35s %-6s %-5s %-8s %-10s\n", "Bucket", "Range", "Nodes", "Repl", "Updated", "Status");
    printf("--------------------------------------------------------------------------------\n");

    JVal *buckets = j_obj_get(ri, "buckets");
    if (buckets) {
        for (size_t i = 0; i < buckets->nitems; i++) {
            JVal *bi = buckets->items[i];
            int node_count = (int)j_get_num(bi, "node_count", 0);
            if (!show_empty_buckets && node_count == 0) continue;
            StrBuf status; sb_init(&status);
            if (j_get_bool(bi, "is_lonely", false)) sb_add(&status, "LONELY");
            int stale = (int)j_get_num(bi, "stale_nodes", 0);
            int failed = (int)j_get_num(bi, "failed_nodes", 0);
            if (stale > 0) sb_addf(&status, "%sSTALE(%d)", status.len ? "," : "", stale);
            if (failed > 0) sb_addf(&status, "%sFAILED(%d)", status.len ? "," : "", failed);
            const char *status_str = status.len ? status.buf : "OK";
            const char *range_str = j_get_str(bi, "range");
            char range_trunc[36];
            if (strlen(range_str) > 33) {
                memcpy(range_trunc, range_str, 30);
                memcpy(range_trunc + 30, "...", 4);   /* includes NUL */
            } else snprintf(range_trunc, sizeof(range_trunc), "%s", range_str);
            printf("%-6d %-35s %-6d %-5d %-8d %-10s\n",
                   (int)j_get_num(bi, "index", 0), range_trunc, node_count,
                   (int)j_get_num(bi, "replacement_count", 0),
                   (int)j_get_num(bi, "seconds_since_update", 0), status_str);
            sb_free(&status);

            JVal *nodes = j_obj_get(bi, "nodes");
            if (node_count > 0 && nodes) {
                for (size_t j = 0; j < nodes->nitems; j++) {
                    JVal *node = nodes->items[j];
                    StrBuf st; sb_init(&st);
                    if (j_get_bool(node, "is_stale", false)) sb_add(&st, " [STALE]");
                    int fp = (int)j_get_num(node, "failed_pings", 0);
                    if (fp > 0) sb_addf(&st, " [FAILED:%d]", fp);
                    const char *id = j_get_str(node, "id");
                    const char *ip = j_get_str(node, "ip");
                    JVal *portv = j_obj_get(node, "port");
                    JVal *rwpv = j_obj_get(node, "rwp_port");
                    char portbuf[16], rwpbuf[16];
                    if (portv && portv->t == J_NUM) snprintf(portbuf, sizeof(portbuf), "%d", (int)portv->num);
                    else snprintf(portbuf, sizeof(portbuf), "None");
                    if (rwpv && rwpv->t == J_NUM) snprintf(rwpbuf, sizeof(rwpbuf), "%d", (int)rwpv->num);
                    else snprintf(rwpbuf, sizeof(rwpbuf), "None");
                    printf("       └─ %s:%s (RWP:%s) ID:%.16s... Seen:%ds%s\n",
                           ip ? ip : "None", portbuf, rwpbuf, id ? id : "?",
                           (int)j_get_num(node, "seconds_since_seen", 0), st.buf);
                    sb_free(&st);
                }
            }
            JVal *repl = j_obj_get(bi, "replacement_nodes");
            if (show_replacement_nodes && repl && repl->nitems) {
                printf("       Replacement nodes:\n");
                for (size_t j = 0; j < repl->nitems; j++) {
                    JVal *node = repl->items[j];
                    const char *id = j_get_str(node, "id");
                    const char *ip = j_get_str(node, "ip");
                    JVal *portv = j_obj_get(node, "port");
                    char portbuf[16];
                    if (portv && portv->t == J_NUM) snprintf(portbuf, sizeof(portbuf), "%d", (int)portv->num);
                    else snprintf(portbuf, sizeof(portbuf), "None");
                    printf("         └─ %s:%s ID:%.16s... Seen:%ds\n",
                           ip ? ip : "None", portbuf, id ? id : "?",
                           (int)j_get_num(node, "seconds_since_seen", 0));
                }
            }
        }
    }
    printf("================================================================================\n\n");
    j_free(ri);
}

/* add_contact(node) — duplicate prevention, neighbor limits, enhanced logging */
static void RRKDHTProtocol_call_ping_async(Node *head, RRKDHTProtocol *proto); /* fwd */

static void RoutingTable_add_contact(RoutingTable *t, Node *node) {
    RoutingTable_lock(t);
    if (Node_eq(node, t->node)) {
        log_debug("Skipping self-node: %s:%d", node->ip, node->port);
        RoutingTable_unlock(t);
        return;
    }
    Node *existing_node = RoutingTable_find_existing_node(t, node);
    if (existing_node) {
        log_debug("Updating existing node %s:%d with new info from %s:%d",
                  existing_node->ip, existing_node->port, node->ip, node->port);
        bool new_is_loopback = node->ip && (starts_with(node->ip, "127.") || !strcmp(node->ip, "localhost"));
        bool ex_is_loopback = existing_node->ip &&
            (starts_with(existing_node->ip, "127.") || !strcmp(existing_node->ip, "localhost"));
        if (existing_node != node) {   /* self-update is a no-op (Python semantics) */
            if (new_is_loopback && !ex_is_loopback) {
                log_debug("Ignoring loopback IP update; keeping existing non-loopback IP %s", existing_node->ip);
            } else {
                free(existing_node->ip);
                existing_node->ip = xstrdup(node->ip);
                log_debug("Updated IP to %s", node->ip);
            }
            if (node->port > 0) existing_node->port = node->port;  /* if node.port: */
            existing_node->rwp_port = node->rwp_port;
            free(existing_node->rendezvous_key);
            existing_node->rendezvous_key = xstrdup(node->rendezvous_key);
        }
        Node_touch(existing_node);
        RoutingTable_unlock(t);
        return;
    }
    if (!RoutingTable_should_accept_new_neighbor(t, node)) {
        log_debug("At neighbor limit (%d), rejecting distant node: %s:%d",
                  t->max_neighbors, node->ip, node->port);
        RoutingTable_unlock(t);
        return;
    }
    int current_count = RoutingTable_get_total_neighbor_count(t);
    if (current_count >= t->max_neighbors) {
        NodeList all = RoutingTable_get_neighbors_by_distance(t, NULL, 0);
        if (all.n) {
            Node *farthest = all.v[all.n - 1];
            log_debug("Removing farthest node %s:%d to add closer %s:%d",
                      farthest->ip, farthest->port, node->ip, node->port);
            RoutingTable_remove_contact(t, farthest);
        }
        nodelist_free(&all);
    }
    char *hex = hex_encode(node->id, 20);
    log_debug("Adding new contact: %s:%d (RWP: %d) ID: %s (limit: %d, current: %d)",
              node->ip, node->port, node->rwp_port, hex, t->max_neighbors, current_count);
    free(hex);
    Node_touch(node);
    int index = RoutingTable_get_bucket_for(t, node);
    KBucket *bucket = t->buckets[index];

    if (KBucket_add_node(bucket, node)) {
        int new_count = RoutingTable_get_total_neighbor_count(t);
        log_info("Successfully added node to routing table: %s:%d (RWP: %d) - Total neighbors: %d/%d",
                 node->ip, node->port, node->rwp_port, new_count, t->max_neighbors);
        RoutingTable_unlock(t);
        return;
    }

    if (KBucket_has_in_range(bucket, t->node) || KBucket_depth(bucket) % 5 != 0) {
        log_debug("Splitting bucket %d to accommodate new node", index);
        RoutingTable_split_bucket(t, index);
        RoutingTable_unlock(t);
        RoutingTable_add_contact(t, node);        /* recursive retry */
    } else {
        log_debug("Node added to replacement nodes in bucket %d", index);
        Node *head = KBucket_head(bucket);
        RoutingTable_unlock(t);
        if (head) RRKDHTProtocol_call_ping_async(head, t->protocol); /* asyncio.ensure_future(call_ping) */
    }
}

/* ============================================================================
 * SHARED MAP TYPES USED BY RRKDHT SERVER STATE
 * ============================================================================ */

/* failed_nodes: dict[node_id bytes -> int] */
typedef struct { uint8_t (*keys)[20]; int *vals; size_t n, cap; } IdIntMap;

static void idint_init(IdIntMap *m) { memset(m, 0, sizeof(*m)); }

static int idint_get(IdIntMap *m, const uint8_t id[20], int dflt) {
    for (size_t i = 0; i < m->n; i++)
        if (!memcmp(m->keys[i], id, 20)) return m->vals[i];
    return dflt;
}

static void idint_set(IdIntMap *m, const uint8_t id[20], int v) {
    for (size_t i = 0; i < m->n; i++)
        if (!memcmp(m->keys[i], id, 20)) { m->vals[i] = v; return; }
    if (m->n == m->cap) {
        m->cap = m->cap ? m->cap * 2 : 8;
        m->keys = realloc(m->keys, m->cap * 20);
        m->vals = realloc(m->vals, m->cap * sizeof(int));
    }
    memcpy(m->keys[m->n], id, 20);
    m->vals[m->n] = v;
    m->n++;
}

static bool idint_pop(IdIntMap *m, const uint8_t id[20]) {
    for (size_t i = 0; i < m->n; i++)
        if (!memcmp(m->keys[i], id, 20)) {
            memmove(&m->keys[i], &m->keys[i + 1], (m->n - i - 1) * 20);
            memmove(&m->vals[i], &m->vals[i + 1], (m->n - i - 1) * sizeof(int));
            m->n--;
            return true;
        }
    return false;
}

/* possible_responsibles: dict[node_id -> {'node', 'last_contact', 'verified'}] */
typedef struct { Node *node; double last_contact; bool verified; int fail_count; } ResponsibleInfo;

typedef struct { uint8_t (*keys)[20]; ResponsibleInfo *vals; size_t n, cap; } RespMap;

static void respmap_init(RespMap *m) { memset(m, 0, sizeof(*m)); }

static ResponsibleInfo *respmap_get(RespMap *m, const uint8_t id[20]) {
    for (size_t i = 0; i < m->n; i++)
        if (!memcmp(m->keys[i], id, 20)) return &m->vals[i];
    return NULL;
}

static void respmap_set(RespMap *m, const uint8_t id[20], ResponsibleInfo v) {
    ResponsibleInfo *e = respmap_get(m, id);
    if (e) { *e = v; return; }
    if (m->n == m->cap) {
        m->cap = m->cap ? m->cap * 2 : 8;
        m->keys = realloc(m->keys, m->cap * 20);
        m->vals = realloc(m->vals, m->cap * sizeof(ResponsibleInfo));
    }
    memcpy(m->keys[m->n], id, 20);
    m->vals[m->n] = v;
    m->n++;
}

static bool respmap_del(RespMap *m, const uint8_t id[20]) {
    for (size_t i = 0; i < m->n; i++)
        if (!memcmp(m->keys[i], id, 20)) {
            memmove(&m->keys[i], &m->keys[i + 1], (m->n - i - 1) * 20);
            memmove(&m->vals[i], &m->vals[i + 1], (m->n - i - 1) * sizeof(ResponsibleInfo));
            m->n--;
            return true;
        }
    return false;
}

static void respmap_clear(RespMap *m) { m->n = 0; }

/* _rendezvous_storage: dict[key_hash bytes -> value dict (JVal)] */
typedef struct { uint8_t (*keys)[20]; JVal **vals; size_t n, cap; pthread_mutex_t mu; } StorageMap;

static void storage_init(StorageMap *m) { memset(m, 0, sizeof(*m)); pthread_mutex_init(&m->mu, NULL); }

static JVal *storage_get(StorageMap *m, const uint8_t id[20]) {
    JVal *r = NULL;
    pthread_mutex_lock(&m->mu);
    for (size_t i = 0; i < m->n; i++)
        if (!memcmp(m->keys[i], id, 20)) { r = m->vals[i]; break; }
    pthread_mutex_unlock(&m->mu);
    return r;
}

static void storage_set(StorageMap *m, const uint8_t id[20], JVal *v) {
    pthread_mutex_lock(&m->mu);
    for (size_t i = 0; i < m->n; i++)
        if (!memcmp(m->keys[i], id, 20)) { j_free(m->vals[i]); m->vals[i] = v; pthread_mutex_unlock(&m->mu); return; }
    if (m->n == m->cap) {
        m->cap = m->cap ? m->cap * 2 : 8;
        m->keys = realloc(m->keys, m->cap * 20);
        m->vals = realloc(m->vals, m->cap * sizeof(JVal *));
    }
    memcpy(m->keys[m->n], id, 20);
    m->vals[m->n] = v;
    m->n++;
    pthread_mutex_unlock(&m->mu);
}

static bool storage_del(StorageMap *m, const uint8_t id[20]) {
    bool found = false;
    pthread_mutex_lock(&m->mu);
    for (size_t i = 0; i < m->n; i++)
        if (!memcmp(m->keys[i], id, 20)) {
            j_free(m->vals[i]);
            memmove(&m->keys[i], &m->keys[i + 1], (m->n - i - 1) * 20);
            memmove(&m->vals[i], &m->vals[i + 1], (m->n - i - 1) * sizeof(JVal *));
            m->n--;
            found = true;
            break;
        }
    pthread_mutex_unlock(&m->mu);
    return found;
}

/* ============================================================================
 * SOCKET HELPERS
 * ============================================================================ */

static int resolve_ipv4(const char *host, struct in_addr *out) {
    if (!host) return -1;           /* Node.ip can legitimately be None/NULL;
                                        Python's socket calls would raise here,
                                        which the RPC layer catches and treats
                                        as a failed call — mirror that as a
                                        clean failure instead of UB in inet_pton */
    if (inet_pton(AF_INET, host, out) == 1) return 0;
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

/* socket.socket().connect((ip, port)) with timeout — returns fd or -1 */
static int tcp_connect_timeout(const char *ip, int port, double timeout_sec) {
    struct in_addr addr;
    if (resolve_ipv4(ip, &addr) != 0) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    /* non-blocking connect + select for timeout (socket.settimeout semantics) */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr = addr;
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc < 0) {
        fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
        struct timeval tv = { .tv_sec = (time_t)timeout_sec,
                              .tv_usec = (suseconds_t)((timeout_sec - (time_t)timeout_sec) * 1e6) };
        rc = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0) { close(fd); return -1; }
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err) { close(fd); return -1; }
    }
    fcntl(fd, F_SETFL, flags);   /* back to blocking */
    return fd;
}

/* socket.settimeout(t) on a connected TCP socket (recv timeout) */
static void tcp_set_recv_timeout(int fd, double sec) {
    struct timeval tv = { .tv_sec = (time_t)sec,
                          .tv_usec = (suseconds_t)((sec - (time_t)sec) * 1e6) };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static void tcp_set_send_timeout(int fd, double sec) {
    struct timeval tv = { .tv_sec = (time_t)sec,
                          .tv_usec = (suseconds_t)((sec - (time_t)sec) * 1e6) };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* ============================================================================
 * THE THREE TOP-LEVEL STRUCTS (RRKDHTProtocol / RWPDHTHandler / RRKDHT)
 * Method implementations follow in Python file order.
 * ============================================================================ */

/* --- RPC call result: mirrors the (happened, data) future result --- */
typedef struct {
    bool happened;
    MVal *data;                    /* unpacked response (owned) */
    int status;                    /* 0 = completed (future resolved, even (False,None)),
                                      2 = outer asyncio.wait_for TimeoutError */
} RpcResult;

#define RPC_STATUS_COMPLETED 0
#define RPC_STATUS_TIMEOUT   2

/* _outstanding[msg_id] = (future, timeout_handle) */
typedef struct {
    uint8_t mid[20];
    Future *fut;
    uint64_t timer_id;
    bool used;
} Outstanding;

struct RRKDHTProtocol {
    /* --- RPCProtocol (rpcudp) base --- */
    int sockfd;                    /* transport (UDP socket) */
    volatile bool transport_open;
    pthread_t recv_thread;
    double wait_timeout;           /* RPCProtocol(wait_timeout=5) */
    Outstanding *outstanding; size_t n_out, cap_out;
    pthread_mutex_t out_mu;
    /* --- RRKDHTProtocol --- */
    RoutingTable *router;
    Node *source_node;
    EpochManager *epoch_manager;
    RWPDHTHandler *rwp_handler;
    int ksize;
    atomic_bool learning_enabled;   /* toggled by search thread, read by RPC receiver threads */
    RRKDHT *server_ref;
};

struct RWPDHTHandler {
    /* RWPProtocolHandler.__init__ */
    char *node_id;                 /* hex string */
    SecureMessaging *messaging;
    EpochManager *epoch_manager;
    char *rendezvous_key;
    /* node_info_cache: dict["ip:port" -> NodeInfo] with cache_lock (RLock) */
    struct { char **keys; NodeInfo **vals; size_t n, cap; } cache;
    pthread_mutex_t cache_lock;    /* threading.RLock */
    int rwp_server_socket;
    pthread_t rwp_server_thread;
    volatile bool running;
    /* RWPDHTHandler.__init__ */
    RoutingTable *router;
    int dht_port;    /* our UDP DHT port, included in node-info responses */
};

struct RRKDHT {
    int ksize;
    int alpha;
    EVP_PKEY *signing_private_key;
    EVP_PKEY *signing_public_key;
    Node *node;
    int rwp_port;
    EpochManager *epoch_manager;
    SecureMessaging *messaging;
    RWPDHTHandler *rwp_handler;

    /* network condition tracking */
    struct { double avg_ping_time; double success_rate; double congestion_factor; } network_conditions;
    double ping_history[20]; size_t ping_history_n;
    size_t max_ping_history;
    pthread_mutex_t netcond_mu;   /* guards network_conditions + ping_history against
                                      concurrent heartbeat-check threads */

    double heartbeat_sync_time;
    IdIntMap failed_nodes;
    pthread_mutex_t failed_mu;
    int HEARTBEAT_SYNC_INTERVAL;
    int MAX_FAILURES_BEFORE_REMOVAL;

    /* responsible-node tracking */
    RespMap possible_responsibles;
    pthread_mutex_t resp_mu;
    IdSet verified_responsibles;
    double last_responsible_check;
    bool is_orphaned;
    volatile bool rejoin_in_progress;
    uint64_t responsible_check_loop;  /* timer handle */
    int _rejoin_attempts;
    int _identity_regeneration_count;
    struct { char *node_id; char *signing_public_key; } *_original_identity;
    bool _pending_verification;
    bool _ever_had_contacts;

    RRKDHTProtocol *protocol;         /* transport = protocol->sockfd */
    uint64_t refresh_loop;
    uint64_t save_state_loop;
    uint64_t heartbeat_loop;
    pthread_t key_rotation_thread;
    volatile bool running;
    /* struct RRKDHT: */
    _Atomic int64_t last_rk_republish_ms;    /* 0 = never; calloc'd structs are fine */

    StorageMap _rendezvous_storage;
    bool rendezvous_storage_initialized;
};

static int64_t now_mono_ms(void) {
    return (int64_t)(now_mono() * 1000.0);
}
/* ============================================================================
 * RPCProtocol (rpcudp) — msgpack UDP RPC with _outstanding futures
 * ============================================================================ */

static void rpc_outstanding_remove_locked(RRKDHTProtocol *p, size_t idx) {
    memmove(&p->outstanding[idx], &p->outstanding[idx + 1],
            (p->n_out - idx - 1) * sizeof(Outstanding));
    p->n_out--;
}

/* The cleanup loops from call_find_node / call_ping / call_verify_neighbor:
 * drop entries whose future is done or cancelled, cancelling their timeout. */
static void rpc_cleanup_done_outstanding(RRKDHTProtocol *p) {
    pthread_mutex_lock(&p->out_mu);
    for (size_t i = 0; i < p->n_out;) {
        Future *f = p->outstanding[i].fut;
        if (future_done(f) || future_cancelled(f)) {
            timer_cancel(p->outstanding[i].timer_id);
            rpc_outstanding_remove_locked(p, i);
        } else i++;
    }
    pthread_mutex_unlock(&p->out_mu);
}

/* rpcudp._timeout(msg_id): resolve the future with (False, None), drop entry */
typedef struct { RRKDHTProtocol *p; uint8_t mid[20]; } TimeoutCtx;

static void rpc_timeout_cb(void *arg) {
    TimeoutCtx *ctx = arg;
    RRKDHTProtocol *p = ctx->p;
    pthread_mutex_lock(&p->out_mu);
    for (size_t i = 0; i < p->n_out; i++) {
        if (!memcmp(p->outstanding[i].mid, ctx->mid, 20)) {
            char *b64 = b64_encode(ctx->mid, 20);
            log_error("Did not receive reply for msg id %s within %d seconds",
                      b64, (int)p->wait_timeout);
            free(b64);
            RpcResult *res = SAFE_CALLOC(RpcResult, 1);
            if (!res) continue;
            res->happened = false;
            res->data = NULL;
            future_set_result(p->outstanding[i].fut, res);
            rpc_outstanding_remove_locked(p, i);
            break;
        }
    }
    pthread_mutex_unlock(&p->out_mu);
    free(ctx);
}

/* rpcudp._accept_response(msg_id, data, address) */
static void rpc_accept_response(RRKDHTProtocol *p, const uint8_t mid[20], MVal *data) {
    pthread_mutex_lock(&p->out_mu);
    for (size_t i = 0; i < p->n_out; i++) {
        if (!memcmp(p->outstanding[i].mid, mid, 20)) {
            timer_cancel(p->outstanding[i].timer_id);
            RpcResult *res = SAFE_CALLOC(RpcResult, 1);
            if (!res) continue;
            res->happened = true;
            res->data = data;
            future_set_result(p->outstanding[i].fut, res);
            rpc_outstanding_remove_locked(p, i);
            pthread_mutex_unlock(&p->out_mu);
            return;
        }
    }
    pthread_mutex_unlock(&p->out_mu);
    char *b64 = b64_encode(mid, 20);
    log_warning("received unknown message %s; ignoring", b64);
    free(b64);
    m_free(data);
}

/* --- rpc_* request handlers (defined below, after RRKDHTProtocol methods) --- */
static MVal *rpc_dispatch(RRKDHTProtocol *p, const char *funcname, MVal *args,
                          const char *sender_ip, int sender_port);

typedef struct {
    RRKDHTProtocol *p;
    uint8_t mid[20];
    MVal *data;
    char ip[64];
    int port;
} RequestCtx;

/* rpcudp._accept_request: run rpc_* handler and send back the response */
static void *rpc_accept_request_thread(void *arg) {
    RequestCtx *ctx = arg;
    RRKDHTProtocol *p = ctx->p;
    MVal *data = ctx->data;
    if (!data || data->t != M_ARR || data->nitems != 2) {
        log_error("Could not read packet (MalformedMessage)");
        m_free(data);
        free(ctx);
        return NULL;
    }
    const uint8_t *fn; size_t fnlen;
    if (!m_as_bytes(data->items[0], &fn, &fnlen) || fnlen >= 128) {
        log_error("Could not read packet (MalformedMessage)");
        m_free(data);
        free(ctx);
        return NULL;
    }
    char funcname[128];
    memcpy(funcname, fn, fnlen); funcname[fnlen] = 0;
    MVal *args = data->items[1];
    MVal *response = rpc_dispatch(p, funcname, args, ctx->ip, ctx->port);
    if (!response) {
        /* no callable rpc_<name>: warning already logged; ignore request */
        m_free(data);
        free(ctx);
        return NULL;
    }
    /* txdata = b"\x01" + msg_id + umsgpack.packb(response) */
    uint8_t *packed; size_t plen;
    mp_pack(response, &packed, &plen);
    if (21 + plen > 8192) {
        log_error("MalformedMessage: response too large (%zu bytes), dropping", 21 + plen);
        free(packed);
        m_free(response);
        m_free(data);
        free(ctx);
        return NULL;
    }
    uint8_t *tx = malloc(21 + plen);
    tx[0] = 0x01;
    memcpy(tx + 1, ctx->mid, 20);
    memcpy(tx + 21, packed, plen);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)ctx->port);
    resolve_ipv4(ctx->ip, &sa.sin_addr);
    if (p->transport_open)
        sendto(p->sockfd, tx, 21 + plen, 0, (struct sockaddr *)&sa, sizeof(sa));
    free(tx);
    free(packed);
    m_free(response);
    m_free(data);
    free(ctx);
    return NULL;
}

/* asyncio.DatagramProtocol.datagram_received equivalent — receive loop */
static void *rpc_recv_thread_main(void *arg) {
    RRKDHTProtocol *p = arg;
    uint8_t buf[9000];
    while (p->transport_open) {
        struct sockaddr_in sa; socklen_t slen = sizeof(sa);
        ssize_t n = recvfrom(p->sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &slen);
        if (n <= 0) {
            if (p->transport_open) py_sleep(0.01);
            continue;
        }
        char sender_ip[16];
        snprintf(sender_ip, sizeof(sender_ip), "%s", inet_ntoa(sa.sin_addr));

        /* === HARDENING: rate limit per IP === */
        if (!rate_check(sender_ip, MAX_UDP_PER_SEC)) {
            continue;   /* silently drop — don't waste any more resources */
        }

        log_debug("received datagram from %s:%d", sender_ip, ntohs(sa.sin_port));
        if (n < 22) {
            log_warning("received datagram too small from %s:%d, ignoring",
                        sender_ip, ntohs(sa.sin_port));
            continue;
        }
        uint8_t type = buf[0];
        const uint8_t *mid = buf + 1;
        MVal *data = mp_unpack(buf + 21, (size_t)n - 21);
        if (!data) {
            log_error("Could not unpack datagram, ignoring");
            continue;
        }
        if (type == 0x00) {
            /* === HARDENING: thread cap === */
            if (atomic_load(&g_handler_threads) >= MAX_HANDLER_THREADS) {
                log_warning("Handler thread cap (%d) reached, dropping from %s",
                            MAX_HANDLER_THREADS, sender_ip);
                m_free(data);
                continue;
            }

            /* === HARDENING: calloc NULL check === */
            RequestCtx *ctx = SAFE_CALLOC(RequestCtx, 1);
            if (!ctx) { m_free(data); continue; }
            ctx->p = p;
            memcpy(ctx->mid, mid, 20);
            ctx->data = data;
            snprintf(ctx->ip, sizeof(ctx->ip), "%s", sender_ip);
            ctx->port = ntohs(sa.sin_port);

            /* === HARDENING: wrap in thread guard (auto-decrements counter) === */
            atomic_fetch_add(&g_handler_threads, 1);
            ThreadGuardCtx *guard = SAFE_MALLOC(sizeof(ThreadGuardCtx));
            if (!guard) {
                atomic_fetch_sub(&g_handler_threads, 1);
                m_free(data);
                free(ctx);
                continue;
            }
            guard->fn = rpc_accept_request_thread;
            guard->arg = ctx;
            guard->counter = &g_handler_threads;

            pthread_t t;
            if (pthread_create(&t, NULL, thread_guard, guard) == 0)
                pthread_detach(t);
            else {
                atomic_fetch_sub(&g_handler_threads, 1);
                free(guard);
                rpc_accept_request_thread(ctx);
                atomic_fetch_sub(&g_handler_threads, 1);
            }
        } else if (type == 0x01) {
            rpc_accept_response(p, mid, data);
        } else {
            log_debug("Received unknown message from %s:%d, ignoring",
                      sender_ip, ntohs(sa.sin_port));
            m_free(data);
        }
    }
    return NULL;
}

/* rpcudp.__getattr__ closure + asyncio.wait_for: send RPC, wait for reply.
 * `args` is consumed. Returns RpcResult (caller frees data + struct).
 * timeout = outer asyncio.wait_for timeout (15.0 / 10.0 / adaptive). */
static RpcResult *rpc_call(RRKDHTProtocol *p, const char *ip, int port,
                           const char *funcname, MVal *args, double timeout) {
    /* msg_id = sha1(os.urandom(32)).digest() */
    uint8_t rnd[32]; rand_bytes(rnd, 32);
    uint8_t mid[20]; digest(rnd, 32, mid);
    /* data = umsgpack.packb([name, args]) */
    MVal *envelope = m_arr();
    m_arr_add(envelope, m_str(funcname));
    m_arr_add(envelope, args);
    uint8_t *packed; size_t plen;
    mp_pack(envelope, &packed, &plen);
    m_free(envelope);
    if (21 + plen > 8192) {
        free(packed);
        log_error("MalformedMessage: Total length of function name and arguments cannot exceed 8K");
        RpcResult *res = SAFE_CALLOC(RpcResult, 1);
        if (!res) return NULL;
        res->happened = false;
        return res;
    }
    /* txdata = b"\x00" + msg_id + data */
    uint8_t *tx = malloc(21 + plen);
    tx[0] = 0x00;
    memcpy(tx + 1, mid, 20);
    memcpy(tx + 21, packed, plen);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    bool addr_ok = resolve_ipv4(ip, &sa.sin_addr) == 0;

    /* PATCHED: register the outstanding request BEFORE sending, not
     * after. This used to send first and register second -- on a very
     * fast link (loopback especially: confirmed live, replies arriving
     * in ~0.01s) the reply can arrive and be handled by the receive
     * thread before this thread finishes registering the outstanding
     * entry. With no matching entry yet, the receive thread has no way
     * to know the reply is ours, logs "received unknown message", and
     * drops it -- silently discarding a perfectly valid reply, dooming
     * the call to the full wait_timeout even though the answer had
     * already arrived. Registering first closes that window entirely:
     * the entry always exists before any reply could possibly arrive. */
    Future *fut = future_new();
    TimeoutCtx *tctx = malloc(sizeof(TimeoutCtx));
    tctx->p = p;
    memcpy(tctx->mid, mid, 20);
    uint64_t timer_id = call_later(p->wait_timeout, rpc_timeout_cb, tctx);
    /* self._outstanding[msg_id] = (future, timeout) */
    pthread_mutex_lock(&p->out_mu);
    if (p->n_out == p->cap_out) {
        p->cap_out = p->cap_out ? p->cap_out * 2 : 16;
        p->outstanding = realloc(p->outstanding, p->cap_out * sizeof(Outstanding));
    }
    Outstanding *o = &p->outstanding[p->n_out++];
    memcpy(o->mid, mid, 20);
    o->fut = fut;
    o->timer_id = timer_id;
    o->used = true;
    pthread_mutex_unlock(&p->out_mu);

    /* transport.sendto(txdata, address) -- now safe to send: whatever
     * reply comes back, even an instant one, has somewhere to land. */
    if (addr_ok && p->transport_open) {
        char *b64 = b64_encode(mid, 20);
        log_debug("calling remote function %s on %s:%d (msgid %s)", funcname, ip, port, b64);
        free(b64);
        sendto(p->sockfd, tx, 21 + plen, 0, (struct sockaddr *)&sa, sizeof(sa));
    }
    free(tx);
    free(packed);

    /* await asyncio.wait_for(future, timeout) */
    void *result = NULL;
    int rc = future_wait(fut, timeout, &result);
    RpcResult *res;
    if (rc == 0) {
        res = result;                       /* (True, data) or (False, None) */
        res->status = RPC_STATUS_COMPLETED;
    } else {
        /* asyncio.TimeoutError path (outer wait fired before the 5s RPC
         * timeout — only possible when timeout < wait_timeout) */
        future_cancel(fut);
        timer_cancel(timer_id);
        /* remove the outstanding entry (cleanup loops in the .py) */
        pthread_mutex_lock(&p->out_mu);
        for (size_t i = 0; i < p->n_out; i++)
            if (!memcmp(p->outstanding[i].mid, mid, 20)) {
                rpc_outstanding_remove_locked(p, i);
                break;
            }
        pthread_mutex_unlock(&p->out_mu);
        res = SAFE_CALLOC(RpcResult, 1);
        if (!res) return NULL;
        res->happened = false;
        res->data = NULL;
        res->status = RPC_STATUS_TIMEOUT;
    }
    future_free(fut);
    return res;
}

/* RPCProtocol.__init__(wait_timeout=5) + RRKDHTProtocol.__init__ */
static RRKDHTProtocol *RRKDHTProtocol_new(Node *source_node, int ksize,
                                          EpochManager *epoch_manager,
                                          RWPDHTHandler *rwp_handler) {
    RRKDHTProtocol *p = calloc(1, sizeof(RRKDHTProtocol));
    p->wait_timeout = 5;
    p->sockfd = -1;
    p->transport_open = false;
    pthread_mutex_init(&p->out_mu, NULL);
    p->router = RoutingTable_new(p, ksize, source_node);
    p->source_node = source_node;
    p->epoch_manager = epoch_manager;
    p->rwp_handler = rwp_handler;
    p->ksize = ksize;
    p->learning_enabled = true;
    p->server_ref = NULL;
    return p;
}

/* ============================================================================
 * RRKDHTProtocol methods (enhanced Kademlia protocol with RWP support)
 * ============================================================================ */

/* forward decls — implemented in the RWP handler section */
static NodeInfo *RWPDHTHandler_get_node_info(RWPDHTHandler *h, const char *ip, int rwp_port);
static JVal *RWPDHTHandler_send_encrypted_message(RWPDHTHandler *h, NodeInfo *node_info,
                                                  MessageType type, JVal *payload);

/* _get_epoch_key(key, epoch): digest(f"{key.hex()}:epoch:{epoch}") */
static void RRKDHTProtocol_get_epoch_key(const uint8_t key[20], int64_t epoch, uint8_t out[20]) {
    char *hex = hex_encode(key, 20);
    StrBuf sb; sb_init(&sb);
    sb_addf(&sb, "%s:epoch:%lld", hex, (long long)epoch);
    digest(sb.buf, sb.len, out);
    sb_free(&sb);
    free(hex);
}

/* get_refresh_ids(): one random id per lonely bucket */
static size_t RRKDHTProtocol_get_refresh_ids(RRKDHTProtocol *p, uint8_t (**out)[20]) {
    RoutingTable *t = p->router;
    RoutingTable_lock(t);
    KBucket **lonely = NULL;
    size_t n = RoutingTable_lonely_buckets_list(t, &lonely);
    *out = malloc((n ? n : 1) * 20);
    for (size_t i = 0; i < n; i++) {
        /* random.randint(*bucket.range).to_bytes(20, "big") — uniform within
         * this specific bucket's range, not the whole 160-bit keyspace */
        u256 id = u256_rand_in_range(lonely[i]->range_lo, lonely[i]->range_hi);
        u256_to_bytes_be20(id, (*out)[i]);
    }
    free(lonely);
    RoutingTable_unlock(t);
    return n;
}

/* ===== LAYER 2: NEW-NEIGHBOR WATCHDOG =====
 * Every newly added neighbor gets an async ping + a 10-second watchdog.
 * Real nodes answer the ping -> Node_confirm_as_neighbor fires in
 * call_ping_thread -> kept. Fake nodes never answer -> evicted in 10
 * seconds instead of riding the 3-strike heartbeat for minutes. */
typedef struct {
    RRKDHTProtocol *p;
    uint8_t id[20];
    char ip[64];
    int port;
} WatchdogCtx;

static void neighbor_eviction_cb(void *arg) {
    WatchdogCtx *w = arg;
    if (!w->p->transport_open) { free(w); return; }   /* shutting down */

    RoutingTable *t = w->p->router;
    Node *victim = NULL;
    RoutingTable_lock(t);
    for (size_t b = 0; b < t->nbuckets && !victim; b++) {
        NodeList nl = KBucket_get_nodes(t->buckets[b]);
        for (size_t j = 0; j < nl.n; j++)
            if (!memcmp(nl.v[j]->id, w->id, 20)) { victim = nl.v[j]; break; }
        nodelist_free(&nl);
    }
    bool evict = victim && victim->last_confirmed_as_neighbor == 0;
    RoutingTable_unlock(t);

    /* removal outside the lock — same pattern as heartbeat + sybil guard */
    if (evict) {
        RoutingTable_remove_contact(t, victim);
        log_warning("Watchdog: evicted unconfirmed neighbor %s:%d (never responded since add)",
                    w->ip, w->port);
    }
    free(w);
}

static void neighbor_watchdog_arm(RRKDHTProtocol *p, Node *node) {
    WatchdogCtx *w = SAFE_MALLOC(sizeof(WatchdogCtx));
    if (!w) return;
    w->p = p;
    memcpy(w->id, node->id, 20);
    snprintf(w->ip, sizeof(w->ip), "%s", node->ip ? node->ip : "?");
    w->port = node->port;
    /* 70s: must exceed one full heartbeat cycle (~30-60s + stagger), or
    * heard-of real nodes get evicted before the heartbeat confirms them. */
    call_later(70.0, neighbor_eviction_cb, w);
}
/* ===== END LAYER 2 ===== */

/* welcome_if_new(node) */
static void RRKDHTProtocol_welcome_if_new(RRKDHTProtocol *p, Node *node) {
    if (Node_eq(node, p->source_node)) return;      /* skip ourselves */
    Node_touch(node);
    Node *existing_node = RoutingTable_find_existing_node(p->router, node);
    if (existing_node) {
        if (existing_node != node) {   /* self-update is a no-op (Python semantics) */
            free(existing_node->ip); existing_node->ip = xstrdup(node->ip);
            existing_node->port = node->port;
            existing_node->rwp_port = node->rwp_port;
            free(existing_node->rendezvous_key);
            existing_node->rendezvous_key = xstrdup(node->rendezvous_key);
        }
        Node_touch(existing_node);
        log_debug("Updated existing node: %s:%d", node->ip, node->port);
        return;
    }
    /* === SYBIL GUARD + PER-IP CAP (single bucket walk) ===
     * 1) Exact ip:port already in table under a DIFFERENT id -> replace the
     *    old entry. One socket = one node, period. Also correct semantics
     *    for a restarted node (new id, same address): the stale entry dies
     *    instantly instead of zombie-lingering until heartbeat 3-strike.
     * 2) Same IP already hosts >= SYBIL_MAX_NODES_PER_IP distinct nodes ->
     *    reject. Only bites multi-socket floods from one machine; NAT'd
     *    devices present distinct ip:port pairs and are handled by rule 1. */
    Node *same_addr = NULL;
    size_t same_ip_count = 0;
    RoutingTable_lock(p->router);
    for (size_t b = 0; b < p->router->nbuckets; b++) {
        NodeList nl = KBucket_get_nodes(p->router->buckets[b]);
        for (size_t j = 0; j < nl.n; j++) {
            Node *n = nl.v[j];
            if (n->ip && node->ip && strcmp(n->ip, node->ip) == 0) {
                same_ip_count++;
                if (n->port == node->port) same_addr = n;
            }
        }
        nodelist_free(&nl);
    }
    RoutingTable_unlock(p->router);

    if (same_addr && memcmp(same_addr->id, node->id, 20) != 0) {
        log_warning("Sybil guard: %s:%d already in table with different ID — replacing entry",
                    node->ip, node->port);
        RoutingTable_remove_contact(p->router, same_addr);
        /* replacement doesn't grow the per-IP count — fall through to add */
    } else if (same_addr) {
        /* Same address AND same ID: a racing duplicate re-add of the SAME
         * node. find_existing_node can miss while another thread is mid-add
         * (its RWP node-info fetch window). NOT a Sybil — keep the existing
         * (usually richer) entry; the next ping updates it normally. */
        log_debug("Duplicate welcome of %s:%d raced a concurrent add — ignoring",
                  node->ip, node->port);
        return;
    } else if (same_ip_count >= SYBIL_MAX_NODES_PER_IP) {
        log_warning("Per-IP cap: %s already hosts %zu node IDs, rejecting new one",
                    node->ip, same_ip_count);
        return;
    }

    char *repr = Node_repr(node);
    log_info("Never seen %s before, adding to router", repr);
    free(repr);
    /* try to get node info via RWP if rwp_port is available */
    if (node->rwp_port > 0 && p->rwp_handler) {
        NodeInfo *ni = RWPDHTHandler_get_node_info(p->rwp_handler, node->ip, node->rwp_port);
        if (ni && ni->rendezvous_key) {
            free(node->rendezvous_key);
            node->rendezvous_key = xstrdup(ni->rendezvous_key);
        }
    }
    RoutingTable_add_contact(p->router, node);

    /* LAYER 2: verify the new neighbor — 10s watchdog. */
    RRKDHTProtocol_call_ping_async(node, p);
    neighbor_watchdog_arm(p, node);
}

/* PATCHED: RRKDHTProtocol_handle_call_response() (used by call_find_node,
 * call_ping, ...) re-welcomes the node using the CALLER'S PRE-EXISTING
 * routing-table reference for whoever we just called -- not anything
 * freshly learned from that call's response body. That's fine for ping
 * (which carries no neighbor list), but for find_node it means the
 * response's own self-description (which, on a small network, is often
 * literally "the closest node I know is myself" -- including that
 * peer's correct rwp_port) gets parsed correctly by
 * RPCFindResponse_get_node_list() and then discarded: it's used only as
 * a transient candidate list for the current search, never persisted
 * back into the routing table. Confirmed live: a peer's rwp_port stayed
 * "unknown" in the routing table indefinitely -- and every subsequent
 * rendezvous-key lookup against it failed as a result -- even though
 * every find_node response correctly reported it, because nothing ever
 * applied that reported value.
 *
 * This is a narrow, ownership-safe fix for exactly that gap: given a
 * freshly-parsed candidate node (which the caller still owns and will
 * free normally), if we ALREADY know this peer (by ID) and it reports a
 * usable rwp_port, refresh just that field on our existing routing-table
 * entry. No ownership transfer, no new entries added (that's
 * welcome_if_new's job elsewhere) -- just correcting a stale field on a
 * peer we already track. */
static void RRKDHTProtocol_refresh_known_node_rwp_port(RRKDHTProtocol *p, Node *node) {
    if (!node || node->rwp_port <= 0) return;
    if (Node_eq(node, p->source_node)) return;
    RoutingTable *t = p->router;
    RoutingTable_lock(t);
    Node *existing = NULL;
    for (size_t i = 0; i < t->nbuckets && !existing; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++) {
            if (Node_eq(nl.v[j], node)) { existing = nl.v[j]; break; }
        }
        nodelist_free(&nl);
    }
    if (existing && existing->rwp_port != node->rwp_port) {
        log_debug("Learned RWP port %d for %s:%d (was %d) from a find_node response",
                  node->rwp_port, existing->ip ? existing->ip : "?", existing->port, existing->rwp_port);
        existing->rwp_port = node->rwp_port;
    }
    RoutingTable_unlock(t);
}

/* RRKDHTProtocol._find_existing_node (lines 1452-1463 of RRKDHT.py).
 * NOTE: dead code in Python (welcome_if_new calls router._find_existing_node),
 * ported for completeness. */
static Node *RRKDHTProtocol__find_existing_node(RRKDHTProtocol *p, Node *target_node) {
    RoutingTable *t = p->router;
    RoutingTable_lock(t);
    Node *result = NULL;
    for (size_t i = 0; i < t->nbuckets && !result; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++)
            if (Node_eq(nl.v[j], target_node)) { result = nl.v[j]; break; }
        if (!result)
            for (size_t j = 0; j < nl.n; j++) {
                Node *n = nl.v[j];
                bool ip_eq = (n->ip == NULL && target_node->ip == NULL) ||
                             (n->ip && target_node->ip && !strcmp(n->ip, target_node->ip));
                if (ip_eq && n->port == target_node->port) { result = n; break; }
            }
        nodelist_free(&nl);
    }
    RoutingTable_unlock(t);
    return result;
}

/* handle_call_response(result, node) */
static RpcResult *RRKDHTProtocol_handle_call_response(RRKDHTProtocol *p, RpcResult *result, Node *node) {
    if (!result->happened) {
        char *s = Node_str(node);
        log_warning("No response from %s, incrementing failed pings", s);
        free(s);
        node->failed_pings += 1;
        if (node->failed_pings >= 3) {
            char *s2 = Node_str(node);
            log_warning("Node %s failed 3+ pings, removing from router", s2);
            free(s2);
            RoutingTable_remove_contact(p->router, node);
        }
        return result;
    }
    char *s = Node_str(node);
    log_info("Got successful response from %s", s);
    free(s);
    Node_touch(node);
    if (p->learning_enabled)
        RRKDHTProtocol_welcome_if_new(p, node);
    else
        Node_touch(node);
    return result;
}

/* _track_possible_responsible(node) */
static void RRKDHTProtocol_track_possible_responsible(RRKDHTProtocol *p, Node *node) {
    RRKDHT *server = p->server_ref;
    if (!server) return;
    pthread_mutex_lock(&server->resp_mu);
    ResponsibleInfo info = { .node = node, .last_contact = now_time(), .verified = false, .fail_count = 0 };
    respmap_set(&server->possible_responsibles, node->id, info);
    pthread_mutex_unlock(&server->resp_mu);
    log_debug("Tracked possible responsible: %s:%d", node->ip, node->port);
}

/* --- rpc_* handlers: each returns the MVal to pack as the response --- */

/* rpc_stun(sender) -> sender */
static MVal *RRKDHTProtocol_rpc_stun(RRKDHTProtocol *p, const char *ip, int port) {
    (void)p;
    MVal *arr = m_arr();
    m_arr_add(arr, m_str(ip));
    m_arr_add(arr, m_int(port));
    return arr;
}

/* ===== LAYER 5 helper: sign ping args — MUST be called by EVERY ping */
static void sign_ping_args(EVP_PKEY *sk, const uint8_t id[20],
                           EpochManager *em, MVal *args) {
    if (!sk || !args) return;
    uint8_t raw_pub[32]; size_t raw_len = sizeof(raw_pub);
    if (EVP_PKEY_get_raw_public_key(sk, raw_pub, &raw_len) != 1) return;
    m_arr_add(args, m_bin(raw_pub, 32));            /* arg[2]: pubkey */
    uint8_t msg[28];
    memcpy(msg, id, 20);
    int64_t ep = (int64_t)EpochManager_get_current_epoch(em);
    for (int i = 0; i < 8; i++) msg[20 + i] = (uint8_t)(ep >> (56 - 8 * i));
    uint8_t sig[64];                                /* Ed25519 = always 64 bytes */
    size_t siglen = sizeof(sig);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx &&
        EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk) == 1 &&
        EVP_DigestSign(mdctx, sig, &siglen, msg, sizeof(msg)) == 1)
        m_arr_add(args, m_bin(sig, siglen));        /* arg[3]: signature */
    if (mdctx) EVP_MD_CTX_free(mdctx);
}

/* rpc_ping(sender, nodeid, rwp_port=None) -> our node id (bin) */
static MVal *RRKDHTProtocol_rpc_ping(RRKDHTProtocol *p, const char *sender_ip, int sender_port,
                                     MVal *args) {
    if (args->nitems < 1) return NULL;
    const uint8_t *nid; size_t nidlen;
    if (!m_as_bytes(args->items[0], &nid, &nidlen)) return NULL;
    int rwp_port = PORT_NONE;
    if (args->nitems >= 2 && m_is_intlike(args->items[1]))
        rwp_port = (int)m_as_int(args->items[1]);
    /* PLAN 4c: DONT_TRACK flag (args[4], bit 0) — question-ping. Sender asks
     * for information only and must not be recorded as a contact. Absent
     * (old senders, unsigned pings) = tracked, exactly as before. Index 4 =
     * after id, rwp_port, pubkey, sig; the signature covers id||epoch only,
     * so the flag rides outside it safely. */
    bool dont_track = false;
    if (args->nitems >= 5 && m_is_intlike(args->items[4]))
        dont_track = (m_as_int(args->items[4]) & 1) != 0;
    uint8_t id[20] = {0};
    memcpy(id, nid, nidlen < 20 ? nidlen : 20);
    char *hex = hex_encode(id, 20);
    if (rwp_port == PORT_NONE)
        log_debug("Received ping from ('%s', %d) with nodeid %s and rwp_port None",
                  sender_ip, sender_port, hex);
    else
        log_debug("Received ping from ('%s', %d) with nodeid %s and rwp_port %d",
                  sender_ip, sender_port, hex, rwp_port);
    free(hex);

    /* ===== LAYER 5: signature verification (gated by --require-sigs) ===== */
    if (g_require_sigs) {
        if (args->nitems < 4) {
            log_warning("ping from %s:%d: unsigned (require-sigs on) -- rejecting",
                        sender_ip, sender_port);
            return NULL;
        }
        const uint8_t *pub, *sig; size_t publen, siglen;
        if (!m_as_bytes(args->items[2], &pub, &publen) || publen != 32 ||
            !m_as_bytes(args->items[3], &sig, &siglen) || siglen != 64) {
            log_warning("ping from %s:%d: malformed pubkey/sig -- rejecting",
                        sender_ip, sender_port);
            return NULL;
        }

        /* Self-certifying ID: node.id == SHA-1(hex(SHA-256(pubkey))) —
         * the EXACT derivation RRKDHT_new uses (generate_peer_id produces
         * the 64-char hex string; digest() SHA-1s that TEXT). Fully
         * computable forward by the receiver -> honest nodes always pass,
         * an attacker cannot claim an ID his key doesn't derive to. */
        {
            uint8_t sha[32];
            EVP_MD_CTX *hctx = EVP_MD_CTX_new();
            bool step1 = hctx &&
                EVP_DigestInit_ex(hctx, EVP_sha256(), NULL) == 1 &&
                EVP_DigestUpdate(hctx, pub, 32) == 1 &&
                EVP_DigestFinal_ex(hctx, sha, NULL) == 1;
            if (hctx) EVP_MD_CTX_free(hctx);
            if (step1) {
                char *hexstr = hex_encode(sha, 32);          /* 64-char string */
                uint8_t derived[20];
                digest(hexstr, strlen(hexstr), derived);     /* SHA-1 over the TEXT */
                free(hexstr);
                if (memcmp(derived, id, 20) != 0) {
                    char *dh = hex_encode(derived, 12);
                    log_warning("ping from %s:%d: id does not match key (key derives to %.12s...) -- Sybil attempt, rejecting",
                                sender_ip, sender_port, dh);
                    free(dh);
                    return NULL;
                }
            } else {
                return NULL;   /* hash machinery failure -- fail closed */
            }
        }

        /* Signature over id20 || epoch_be64; accept {current, current-1} */
        int64_t my_epoch = EpochManager_get_current_epoch(p->epoch_manager);
        bool sig_ok = false;
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        if (vctx) {
            EVP_PKEY *vk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
            if (vk) {
                for (int e = 0; e < 2 && !sig_ok; e++) {
                    uint8_t msg[28];
                    memcpy(msg, id, 20);
                    int64_t ep = my_epoch - e;
                    for (int i = 0; i < 8; i++) msg[20 + i] = (uint8_t)(ep >> (56 - 8 * i));
                    if (EVP_DigestVerifyInit(vctx, NULL, NULL, NULL, vk) == 1 &&
                        EVP_DigestVerify(vctx, sig, siglen, msg, sizeof(msg)) == 1)
                        sig_ok = true;
                }
                EVP_PKEY_free(vk);
            }
            EVP_MD_CTX_free(vctx);
        }
        if (!sig_ok) {
            log_warning("ping from %s:%d: bad signature/epoch -- rejecting",
                        sender_ip, sender_port);
            return NULL;
        }
    }
    /* ===== END LAYER 5 ===== */

    if (!dont_track) {
        Node *source = Node_new_full(id, sender_ip, sender_port, rwp_port, NULL);
        RRKDHTProtocol_track_possible_responsible(p, source);
        RRKDHTProtocol_welcome_if_new(p, source);
        Node_confirm_as_neighbor(source);   /* an incoming ping proves liveness:
            direct contacts survive the watchdog instantly; heard-of nodes still
            need the heartbeat (hence the 70s window) */
    } else {
        /* question-ping: answer it, record nothing. No Node is created. */
        log_debug("Ping from %s:%d carries DONT_TRACK - not recording contact",
                  sender_ip, sender_port);
    }
    char *hex2 = hex_encode(p->source_node->id, 20);
    log_debug("Sending ping response: node_id=%s", hex2);
    free(hex2);
    /* Pong extension: id20 + rwp_port_be16 (0 = unknown). Old consumers
     * read only the first 20 bytes — unaffected (append-and-tolerate). */
    {
        uint8_t pong[22];
        memcpy(pong, p->source_node->id, 20);
        uint16_t rp = (p->source_node->rwp_port == PORT_NONE)
                      ? 0 : (uint16_t)p->source_node->rwp_port;
        pong[20] = (uint8_t)(rp >> 8);
        pong[21] = (uint8_t)(rp & 0xFF);
        return m_bin(pong, 22);
    }
}

/* rpc_find_node(sender, nodeid, key, rwp_port=None) -> [[id,ip,port,rwp],...] */
static MVal *RRKDHTProtocol_rpc_find_node(RRKDHTProtocol *p, const char *sender_ip, int sender_port,
                                          MVal *args) {
    if (args->nitems < 2) return NULL;
    const uint8_t *nid, *key; size_t nidlen, keylen;
    if (!m_as_bytes(args->items[0], &nid, &nidlen)) return NULL;
    if (!m_as_bytes(args->items[1], &key, &keylen)) return NULL;
    int rwp_port = PORT_NONE;
    if (args->nitems >= 3 && m_is_intlike(args->items[2]))
        rwp_port = (int)m_as_int(args->items[2]);
    uint8_t id[20] = {0}, keyid[20] = {0};
    memcpy(id, nid, nidlen < 20 ? nidlen : 20);
    memcpy(keyid, key, keylen < 20 ? keylen : 20);
    char *h1 = hex_encode(id, 20), *h2 = hex_encode(keyid, 20);
    if (rwp_port == PORT_NONE)
        log_debug("Received find_node from ('%s', %d) with nodeid %s, searching for target key %s, rwp_port None",
                  sender_ip, sender_port, h1, h2);
    else
        log_debug("Received find_node from ('%s', %d) with nodeid %s, searching for target key %s, rwp_port %d",
                  sender_ip, sender_port, h1, h2, rwp_port);
    free(h1);

    Node *source = Node_new_full(id, sender_ip, sender_port, rwp_port, NULL);
    RRKDHTProtocol_welcome_if_new(p, source);

    Node *target_node = Node_new(keyid);
    NodeList neighbors = RoutingTable_find_neighbors(p->router, target_node, p->ksize, source);
    /* candidates = neighbors + [source_node], excluding source */
    NodeList candidates; nodelist_init(&candidates);
    for (size_t i = 0; i < neighbors.n; i++) nodelist_add(&candidates, neighbors.v[i]);
    nodelist_add(&candidates, p->source_node);
    NodeList filtered; nodelist_init(&filtered);
    for (size_t i = 0; i < candidates.n; i++)
        if (!Node_eq(candidates.v[i], source)) nodelist_add(&filtered, candidates.v[i]);
    /* sort by distance to target (stable) */
    for (size_t i = 1; i < filtered.n; i++) {
        Node *cur = filtered.v[i];
        u256 d = Node_distance_to(target_node, cur);
        size_t j = i;
        while (j > 0 && u256_gt(Node_distance_to(target_node, filtered.v[j - 1]), d)) {
            filtered.v[j] = filtered.v[j - 1];
            j--;
        }
        filtered.v[j] = cur;
    }
    char *h3 = hex_encode(keyid, 20);
    size_t nclosest = filtered.n < (size_t)p->ksize ? filtered.n : (size_t)p->ksize;
    log_debug("find_node returning %zu neighbors closest to TARGET %.16s...", nclosest, h3);
    free(h2); free(h3);
    if (nclosest) {
        char *d1 = u256_to_dec(Node_distance_to(target_node, filtered.v[0]));
        char *d2 = u256_to_dec(Node_distance_to(p->source_node, target_node));
        log_debug("Closest neighbor distance to target: %s", d1);
        log_debug("My distance to target: %s", d2);
        free(d1); free(d2);
    }
    MVal *out = m_arr();
    for (size_t i = 0; i < nclosest; i++) {
        Node *n = filtered.v[i];
        MVal *tup = m_arr();
        m_arr_add(tup, m_bin(n->id, 20));
        m_arr_add(tup, n->ip ? m_str(n->ip) : m_nil());
        m_arr_add(tup, n->port == PORT_NONE ? m_nil() : m_int(n->port));
        m_arr_add(tup, n->rwp_port == PORT_NONE ? m_nil() : m_int(n->rwp_port));
        m_arr_add(out, tup);
    }
    nodelist_free(&neighbors);
    nodelist_free(&candidates);
    nodelist_free(&filtered);
    free(target_node);
    return out;
}

/* rpc_verify_neighbor(sender, nodeid, target_id, rwp_port=None) -> bool */
static MVal *RRKDHTProtocol_rpc_verify_neighbor(RRKDHTProtocol *p, const char *sender_ip,
                                                int sender_port, MVal *args) {
    if (args->nitems < 2) return NULL;
    const uint8_t *nid, *tid; size_t nidlen, tidlen;
    if (!m_as_bytes(args->items[0], &nid, &nidlen)) return NULL;
    if (!m_as_bytes(args->items[1], &tid, &tidlen)) return NULL;
    int rwp_port = PORT_NONE;
    if (args->nitems >= 3 && m_is_intlike(args->items[2]))
        rwp_port = (int)m_as_int(args->items[2]);
    uint8_t id[20] = {0}, target[20] = {0};
    memcpy(id, nid, nidlen < 20 ? nidlen : 20);
    memcpy(target, tid, tidlen < 20 ? tidlen : 20);
    char *h = hex_encode(target, 20);
    log_debug("Received verify_neighbor from ('%s', %d) asking if we know %s", sender_ip, sender_port, h);
    Node *source = Node_new_full(id, sender_ip, sender_port, rwp_port, NULL);
    RRKDHTProtocol_welcome_if_new(p, source);
    RoutingTable *t = p->router;
    RoutingTable_lock(t);
    bool found = false;
    for (size_t i = 0; i < t->nbuckets; i++)
        if (KBucket_get(t->buckets[i], target)) { found = true; break; }
    RoutingTable_unlock(t);
    if (found) log_debug("Confirmed: We have %s in our routing table", h);
    else log_debug("Not found: %s is not in our routing table", h);
    free(h);
    return m_bool(found);
}

/* getattr(self, "rpc_" + funcname) dispatch */
static MVal *rpc_dispatch(RRKDHTProtocol *p, const char *funcname, MVal *args,
                          const char *sender_ip, int sender_port) {
    /* PATCH 4: validate sender + funcname before dispatching anything.
     * sender_ip/port come straight from recvfrom() -- trust nothing. */
    if (!sender_ip || sender_ip[0] == '\0') {
        log_warning("rpc_dispatch: null/empty sender IP, rejecting");
        return NULL;
    }
    if (sender_port <= 0 || sender_port > 65535) {
        log_warning("rpc_dispatch: sender port %d out of range, rejecting", sender_port);
        return NULL;
    }
    if (!funcname) {
        log_warning("rpc_dispatch: null funcname, rejecting");
        return NULL;
    }
    if (!args || args->t != M_ARR) args = m_arr();
    if (!strcmp(funcname, "ping"))
        return RRKDHTProtocol_rpc_ping(p, sender_ip, sender_port, args);
    if (!strcmp(funcname, "find_node"))
        return RRKDHTProtocol_rpc_find_node(p, sender_ip, sender_port, args);
    if (!strcmp(funcname, "verify_neighbor"))
        return RRKDHTProtocol_rpc_verify_neighbor(p, sender_ip, sender_port, args);
    if (!strcmp(funcname, "stun"))
        return RRKDHTProtocol_rpc_stun(p, sender_ip, sender_port);
    log_warning("RRKDHTProtocol has no callable method rpc_%s; ignoring request", funcname);
    return NULL;
}

/* --- outbound RPC call wrappers (call_find_node / call_ping / call_verify_neighbor) --- */

/* call_find_node(node_to_ask, node_to_find) -> RpcResult */
static RpcResult *RRKDHTProtocol_call_find_node(RRKDHTProtocol *p, Node *node_to_ask, Node *node_to_find) {
    char *h = hex_encode(node_to_find->id, 20);
    log_debug("Calling find_node on %s:%d (RWP: %d) for key %s",
              node_to_ask->ip, node_to_ask->port, node_to_ask->rwp_port, h);
    free(h);
    bool udp_success = false;
    RpcResult *result = NULL;

    /* --- try UDP first --- */
    MVal *args = m_arr();
    m_arr_add(args, m_bin(p->source_node->id, 20));
    m_arr_add(args, m_bin(node_to_find->id, 20));
    m_arr_add(args, p->source_node->rwp_port == PORT_NONE ? m_nil() : m_int(p->source_node->rwp_port));
    log_debug("Attempting UDP find_node to %s:%d", node_to_ask->ip, node_to_ask->port);
    result = rpc_call(p, node_to_ask->ip, node_to_ask->port, "find_node", args, 15.0);
    if (!result) {
        log_warning("call_find_node: rpc_call returned NULL to %s:%d", node_to_ask->ip, node_to_ask->port);
        return NULL;
    }
    if (result->status == RPC_STATUS_TIMEOUT) {
        /* asyncio.TimeoutError: cleanup + early return (False, None), no RWP
         * fallback — unreachable with wait_timeout(5) < 15.0, ported for exactness */
        log_warning("call_find_node timed out to %s:%d", node_to_ask->ip, node_to_ask->port);
        rpc_cleanup_done_outstanding(p);
        return result;
    }
    if (result->happened) {
        udp_success = true;
        size_t nn = (result->data && result->data->t == M_ARR) ? result->data->nitems : 0;
        log_debug("UDP find_node successful with %zu nodes", nn);
    } else {
        log_warning("UDP find_node returned failure/empty result");
    }

    /* --- RWP fallback --- */
    if (!udp_success && node_to_ask->rwp_port > 0 && p->rwp_handler) {
        log_info("UDP failed, attempting RWP fallback to %s:%d", node_to_ask->ip, node_to_ask->rwp_port);
        NodeInfo *ni = RWPDHTHandler_get_node_info(p->rwp_handler, node_to_ask->ip, node_to_ask->rwp_port);
        if (ni) {
            char *keyhex = hex_encode(node_to_find->id, 20);
            JVal *payload = j_obj();
            j_obj_set(payload, "key", j_str(keyhex));
            free(keyhex);
            JVal *response = RWPDHTHandler_send_encrypted_message(p->rwp_handler, ni, MT_FIND_NODE, payload);
            j_free(payload);
            bool ok = false;
            if (response) {
                JVal *pl = j_obj_get(response, "payload");
                ok = pl && j_get_bool(pl, "success", false);
                if (ok) {
                    /* build (True, [node tuples]) — and welcome each node */
                    MVal *tups = m_arr();
                    JVal *nodes = j_obj_get(pl, "nodes");
                    if (nodes && nodes->t == J_ARR) {
                        for (size_t i = 0; i < nodes->nitems; i++) {
                            JVal *nd = nodes->items[i];
                            const char *idhex = j_get_str(nd, "id");
                            if (!idhex || strlen(idhex) != 40) continue;
                            uint8_t nid[20];
                            if (!hex_decode(idhex, nid, 20)) continue;
                            const char *nip = j_get_str(nd, "ip");
                            int nport = (int)j_get_num(nd, "port", PORT_NONE);
                            int nrwp = j_obj_has(nd, "rwp_port") && j_obj_get(nd, "rwp_port")->t == J_NUM
                                       ? (int)j_get_num(nd, "rwp_port", PORT_NONE) : PORT_NONE;
                            const char *rk = j_get_str(nd, "rendezvous_key");
                            Node *node = Node_new_full(nid, nip, nport, nrwp, rk);
                            MVal *tup = m_arr();
                            m_arr_add(tup, m_bin(node->id, 20));
                            m_arr_add(tup, node->ip ? m_str(node->ip) : m_nil());
                            m_arr_add(tup, m_int(node->port));
                            m_arr_add(tup, nrwp == PORT_NONE ? m_nil() : m_int(nrwp));
                            m_arr_add(tups, tup);
                            RRKDHTProtocol_welcome_if_new(p, node);
                        }
                    }
                    log_debug("RWP find_node successful, got %zu nodes", tups->nitems);
                    m_free(result->data); result->data = tups;
                    result->happened = true;
                    j_free(response);
                    return result;
                }
                log_warning("RWP find_node unsuccessful response");
                j_free(response);
            }
        }
    }

    if (udp_success)
        return RRKDHTProtocol_handle_call_response(p, result, node_to_ask);
    log_warning("Both UDP and RWP failed for find_node to %s", node_to_ask->ip);
    result->happened = false;
    m_free(result->data); result->data = NULL;
    return result;
}

/* call_ping(node_to_ask) -> RpcResult */
static RpcResult *RRKDHTProtocol_call_ping(RRKDHTProtocol *p, Node *node_to_ask) {
    log_debug("Calling ping on %s:%d (RWP: %d)", node_to_ask->ip, node_to_ask->port, node_to_ask->rwp_port);
    bool udp_success = false;
    MVal *args = m_arr();
    m_arr_add(args, m_bin(p->source_node->id, 20));
    m_arr_add(args, p->source_node->rwp_port == PORT_NONE ? m_nil() : m_int(p->source_node->rwp_port));
        /* LAYER 5: sign via the shared helper */
    if (p->rwp_handler && p->rwp_handler->messaging)
        sign_ping_args(p->rwp_handler->messaging->signing_private_key,
                       p->source_node->id, p->epoch_manager, args);
    log_debug("Attempting UDP ping to %s:%d", node_to_ask->ip, node_to_ask->port);
    RpcResult *result = rpc_call(p, node_to_ask->ip, node_to_ask->port, "ping", args, 15.0);
    if (!result) {
        /* rpc_call can return NULL (SAFE_CALLOC failure inside). The old*/
        log_warning("call_ping: rpc_call returned NULL to %s:%d", node_to_ask->ip, node_to_ask->port);
        return NULL;
    }
    if (result->status == RPC_STATUS_TIMEOUT) {
        /* asyncio.TimeoutError: cleanup + early return (False, None), no RWP
         * fallback — unreachable with wait_timeout(5) < 15.0, ported for exactness */
        log_warning("call_ping timed out to %s:%d", node_to_ask->ip, node_to_ask->port);
        rpc_cleanup_done_outstanding(p);
        return result;
    }
    if (result->happened) {
        udp_success = true;
        if (result->data && result->data->t == M_BIN) {
            char *hh = hex_encode(result->data->bin, result->data->blen < 20 ? result->data->blen : 20);
            log_debug("UDP ping successful - got node_id: %s", hh);
            free(hh);
            /* Pong learner: bytes 20-21 = rwp_port (be16, 0 = unknown).
             * Trust rules: fill-only, range-checked, and a bad field is
             * NEVER a failure — the peer answered, liveness stands. */
            if (result->data->blen >= 22 && node_to_ask->rwp_port == PORT_NONE) {
                uint16_t rp = ((uint16_t)result->data->bin[20] << 8)
                              | (uint16_t)result->data->bin[21];
                if (rp >= 1024 && rp <= 65535) {
                    node_to_ask->rwp_port = rp;
                    log_debug("Learned RWP port %u for %s:%d from pong",
                              (unsigned)rp, node_to_ask->ip, node_to_ask->port);
                } else {
                    log_debug("Pong port field invalid (%u) for %s:%d - untrusted, peer still alive",
                              (unsigned)rp, node_to_ask->ip, node_to_ask->port);
                }
            }
        }
    } else {
        log_warning("UDP ping returned failure/empty result");
    }

    /* --- RWP fallback --- */
    if (!udp_success && node_to_ask->rwp_port > 0 && p->rwp_handler) {
        log_info("UDP failed, attempting RWP fallback to %s:%d", node_to_ask->ip, node_to_ask->rwp_port);
        NodeInfo *ni = RWPDHTHandler_get_node_info(p->rwp_handler, node_to_ask->ip, node_to_ask->rwp_port);
        if (ni) {
            JVal *payload = j_obj();
            j_obj_set(payload, "timestamp", j_num(now_time()));
            JVal *response = RWPDHTHandler_send_encrypted_message(p->rwp_handler, ni, MT_PING, payload);
            j_free(payload);
            if (response) {
                const char *rtype = j_get_str(response, "type");
                if (rtype && !strcmp(rtype, "pong")) {
                    log_debug("RWP ping successful to %s:%d", node_to_ask->ip, node_to_ask->rwp_port);
                    j_free(response);
                    m_free(result->data);
                    result->data = m_bin(node_to_ask->id, 20);
                    result->happened = true;
                    return result;
                }
                log_warning("RWP ping unsuccessful response");
                j_free(response);
            }
        }
    }

    if (udp_success)
        return RRKDHTProtocol_handle_call_response(p, result, node_to_ask);
    log_warning("Both UDP and RWP failed for ping to %s", node_to_ask->ip);
    if (!result) return NULL;
    result->happened = false;
    m_free(result->data); result->data = NULL;
    return result;
}

/* asyncio.ensure_future(self.protocol.call_ping(head)) helper */
typedef struct { RRKDHTProtocol *p; Node *node; } PingAsyncCtx;

static void *call_ping_thread(void *arg) {
    PingAsyncCtx *ctx = arg;
    RpcResult *r = RRKDHTProtocol_call_ping(ctx->p, ctx->node);
    if (r && r->happened) Node_confirm_as_neighbor(ctx->node);  /* Layer 2: async
        ping success now counts — real nodes confirm fast, fakes never do */
    if (r) { m_free(r->data); free(r); }
    free(ctx);
    return NULL;
}

static void RRKDHTProtocol_call_ping_async(Node *head, RRKDHTProtocol *proto) {
    PingAsyncCtx *ctx = SAFE_MALLOC(sizeof(PingAsyncCtx));
    if (!ctx) return;
    ctx->p = proto;
    ctx->node = head;
    pthread_t t;
    if (pthread_create(&t, NULL, call_ping_thread, ctx) == 0) pthread_detach(t);
    else { free(ctx); }
}

/* call_verify_neighbor(node_to_ask, target_id) -> (happened, knows) */
static void RRKDHTProtocol_call_verify_neighbor(RRKDHTProtocol *p, Node *node_to_ask,
                                                const uint8_t target_id[20],
                                                bool *happened_out, bool *knows_out) {
    char *h = hex_encode(target_id, 20);
    log_debug("Asking %s:%d if they know %s", node_to_ask->ip, node_to_ask->port, h);
    free(h);
    /* PLAN 5b: PORT_NONE-UDP nodes can't be addressed over UDP at all —
     * dialing PORT_NONE is a garbage-port sendto. Synthesize a not-happened
     * result instead (SAFE_CALLOC pattern from safe_heartbeat_ping; failure
     * falls into the !result guard below). The chain then handles it:
     * rwp_port known -> verify-by-use RWP fallback (RWP is the PRIMARY
     * transport for these nodes); rwp_port unknown -> guarded +1000 guess
     * (no-ops on port<=0) -> caller's skip-vs-fail. */
    RpcResult *result;
    if (node_to_ask->port == PORT_NONE) {
        result = SAFE_CALLOC(RpcResult, 1);
        if (result) result->happened = false;
        log_debug("Verify: %s has no UDP port - skipping UDP dial", node_to_ask->ip);
    } else {
        MVal *args = m_arr();
        m_arr_add(args, m_bin(p->source_node->id, 20));
        m_arr_add(args, m_bin(target_id, 20));
        m_arr_add(args, p->source_node->rwp_port == PORT_NONE ? m_nil() : m_int(p->source_node->rwp_port));
        result = rpc_call(p, node_to_ask->ip, node_to_ask->port, "verify_neighbor", args, 10.0);
    }
    if (!result) {
        /* rpc_call can return NULL since SAFE_CALLOC hardening */
        log_warning("Verify neighbor: rpc_call NULL to %s:%d", node_to_ask->ip, node_to_ask->port);
        *happened_out = false;
        *knows_out = false;
        return;   /* no information — caller treats as failed check, not rejection */
    }
    if (!result->happened && node_to_ask->rwp_port == PORT_NONE && p->rwp_handler) {
        /* PORT_UNKNOWN -> DISCOVER: try the documented convention (UDP+1000).
         * One guess only — learned ports always beat it, and we don't scan.
         * Guards: the UDP port must itself be known (PORT_NONE + 1000 is a
         * garbage port), and the dial is VERIFY-BY-USE — node_id in the
         * node-info response must match the node we're guessing about,
         * or the guess is not stored. Never a strike. */
        if (node_to_ask->port > 0 && node_to_ask->port + 1000 <= 65535) {
            int guess = node_to_ask->port + 1000;
            NodeInfo *gni = RWPDHTHandler_get_node_info(p->rwp_handler, node_to_ask->ip, guess);
            if (gni && gni->node_id && strlen(gni->node_id) == 40) {
                uint8_t gnid[20];
                if (hex_decode(gni->node_id, gnid, 20) && memcmp(gnid, node_to_ask->id, 20) == 0) {
                    node_to_ask->rwp_port = guess;   /* learned AND verified */
                    log_debug("Discovered RWP port %d for %s (UDP+1000, ID verified)",
                              guess, node_to_ask->ip);
                } else {
                    log_debug("+1000 guess for %s: port answers as different node - not stored",
                              node_to_ask->ip);
                }
            }
        }
    }
    if (!result->happened && node_to_ask->rwp_port > 0 && p->rwp_handler) {
        /* UDP failed but port known (or just learned): RWP fallback.
         * The MT_VERIFY branch answers with {"success", "knows"}.
         *
         * VERIFY-BY-USE: the get_node_info dial IS the "is this info right?"
         * check — the response's node_id must match the node we think we're
         * dialing. A port that answers as someone else, or not at all, is
         * wrong data: it degrades to PORT_NONE and never costs a strike
         * (eviction is liveness-only). One wasted dial, self-healing. */
        NodeInfo *ni = RWPDHTHandler_get_node_info(p->rwp_handler, node_to_ask->ip, node_to_ask->rwp_port);
        bool id_ok = false;
        if (ni && ni->node_id && strlen(ni->node_id) == 40) {
            uint8_t nid[20];
            id_ok = hex_decode(ni->node_id, nid, 20) && memcmp(nid, node_to_ask->id, 20) == 0;
            /* 5c backfill: one dial teaches both ports — fill-only, range-checked */
            if (id_ok && node_to_ask->port == PORT_NONE && ni->port > 0 && ni->port <= 65535) {
                node_to_ask->port = ni->port;
                log_debug("Backfilled UDP port %d for %s from node-info",
                          ni->port, node_to_ask->ip);
            }
        }
        if (id_ok) {
            char *th = hex_encode(target_id, 20);
            JVal *payload = j_obj();
            j_obj_set(payload, "target_id", j_str(th));
            free(th);
            JVal *resp = RWPDHTHandler_send_encrypted_message(p->rwp_handler, ni, MT_VERIFY, payload);
            j_free(payload);
            if (resp) {
                JVal *pl = j_obj_get(resp, "payload");
                bool ok = pl && j_get_bool(pl, "success", false);
                if (ok) {
                    JVal *knows_v = j_obj_get(pl, "knows");
                    *happened_out = true;
                    *knows_out = knows_v && knows_v->t == J_BOOL && knows_v->b;
                    log_debug("Verify neighbor via RWP fallback to %s:%d (ID verified)",
                              node_to_ask->ip, node_to_ask->rwp_port);
                }
                j_free(resp);
            }
        } else {
            /* wrong or dead port: degrade to unknown, no strike */
            log_debug("RWP port %d for %s is wrong/unreachable - resetting to PORT_NONE",
                      node_to_ask->rwp_port, node_to_ask->ip);
            node_to_ask->rwp_port = PORT_NONE;
        }
        /* still nothing with a known port: genuine unreachability — the
         * caller's fail_count handles it */
    }
    if (result->happened) {
        bool knows = result->data && result->data->t == M_BOOL && result->data->b;
        char *h2 = hex_encode(target_id, 20);
        log_debug("Node %s:%d has %s: %s", node_to_ask->ip, node_to_ask->port, h2,
                  knows ? "True" : "False");
        free(h2);
        *happened_out = true;
        *knows_out = knows;
    } else if (result->status == RPC_STATUS_TIMEOUT) {
        log_warning("Verify neighbor timed out to %s:%d", node_to_ask->ip, node_to_ask->port);
        rpc_cleanup_done_outstanding(p);
        *happened_out = false;
        *knows_out = false;
    } else {
        char *h2 = hex_encode(target_id, 20);
        log_debug("Node %s:%d doesn't have %s", node_to_ask->ip, node_to_ask->port, h2);
        free(h2);
        *happened_out = false;
        *knows_out = false;
    }
    m_free(result->data);
    free(result);
}

/* ============================================================================
 * RWP PROTOCOL HANDLER (RWPProtocolHandler + RWPDHTHandler)
 * The Python code only ever instantiates the subclass; the base's methods are
 * inherited, so both are merged into RWPDHTHandler here. The subclass's
 * _handle_rendezvous_request overrides the base's (identical logic).
 * ============================================================================ */

/* _generate_rendezvous_key(): sha256(f"{node_id}:{epoch}:rwp").hexdigest()[:16] */
static char *RWPDHTHandler_generate_rendezvous_key(RWPDHTHandler *h) {
    int64_t epoch = EpochManager_get_current_epoch(h->epoch_manager);
    StrBuf sb; sb_init(&sb);
    sb_addf(&sb, "%s:%lld:rwp", h->node_id, (long long)epoch);
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t *)sb.buf, sb.len, hash);
    sb_free(&sb);
    char *hex = hex_encode(hash, SHA256_DIGEST_LENGTH);
    hex[16] = '\0';                              /* [:16] */
    return hex;
}

static RWPDHTHandler *RWPDHTHandler_new(const char *node_id, SecureMessaging *messaging,
                                        EpochManager *epoch_manager, RoutingTable *router) {
    RWPDHTHandler *h = calloc(1, sizeof(RWPDHTHandler));
    h->node_id = xstrdup(node_id);
    h->messaging = messaging;
    h->epoch_manager = epoch_manager;
    h->rendezvous_key = RWPDHTHandler_generate_rendezvous_key(h);
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&h->cache_lock, &attr);
    pthread_mutexattr_destroy(&attr);
    h->rwp_server_socket = -1;
    h->running = false;
    h->router = router;
    return h;
}

/* node_info_cache helpers (cache_lock = threading.RLock) */
static NodeInfo *cache_get(RWPDHTHandler *h, const char *key) {
    NodeInfo *r = NULL;
    pthread_mutex_lock(&h->cache_lock);
    for (size_t i = 0; i < h->cache.n; i++)
        if (!strcmp(h->cache.keys[i], key)) { r = h->cache.vals[i]; break; }
    pthread_mutex_unlock(&h->cache_lock);
    return r;
}

static void cache_set(RWPDHTHandler *h, const char *key, NodeInfo *ni) {
    pthread_mutex_lock(&h->cache_lock);
    for (size_t i = 0; i < h->cache.n; i++)
        if (!strcmp(h->cache.keys[i], key)) { h->cache.vals[i] = ni; pthread_mutex_unlock(&h->cache_lock); return; }
    if (h->cache.n == h->cache.cap) {
        h->cache.cap = h->cache.cap ? h->cache.cap * 2 : 8;
        h->cache.keys = realloc(h->cache.keys, h->cache.cap * sizeof(char *));
        h->cache.vals = realloc(h->cache.vals, h->cache.cap * sizeof(NodeInfo *));
    }
    h->cache.keys[h->cache.n] = xstrdup(key);
    h->cache.vals[h->cache.n] = ni;
    h->cache.n++;
    pthread_mutex_unlock(&h->cache_lock);
}

static void cache_del(RWPDHTHandler *h, const char *key) {
    pthread_mutex_lock(&h->cache_lock);
    for (size_t i = 0; i < h->cache.n; i++)
        if (!strcmp(h->cache.keys[i], key)) {
            free(h->cache.keys[i]);
            memmove(&h->cache.keys[i], &h->cache.keys[i + 1], (h->cache.n - i - 1) * sizeof(char *));
            memmove(&h->cache.vals[i], &h->cache.vals[i + 1], (h->cache.n - i - 1) * sizeof(NodeInfo *));
            h->cache.n--;
            break;
        }
    pthread_mutex_unlock(&h->cache_lock);
}

static void NodeInfo_free(NodeInfo *ni) {
    if (!ni) return;
    free(ni->node_id); free(ni->ip); free(ni->rendezvous_key);
    free(ni->signing_public_key); free(ni->exchange_public_key);
    free(ni);
}

/* Frees a stopped, no-longer-referenced RWPDHTHandler (its socket/thread must
 * already be down via RWPDHTHandler_stop_rwp_server). Does NOT free
 * ->messaging, which is owned/reassigned separately by RRKDHT. */
static void RWPDHTHandler_free(RWPDHTHandler *h) {
    if (!h) return;
    for (size_t i = 0; i < h->cache.n; i++) {
        free(h->cache.keys[i]);
        NodeInfo_free(h->cache.vals[i]);
    }
    free(h->cache.keys); free(h->cache.vals);
    pthread_mutex_destroy(&h->cache_lock);
    free(h->node_id);
    free(h->rendezvous_key);
    free(h);
}

/* _send_rwp_response(client_socket, status_code, body, content_type='text/plain') */
static void RWPDHTHandler_send_rwp_response(int client_socket, int status_code,
                                            const char *body, const char *content_type) {
    const char *status_text;
    switch (status_code) {
        case 200: status_text = "OK"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 413: status_text = "Request Too Large"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 501: status_text = "Not Implemented"; break;
        case 505: status_text = "Version Not Supported"; break;
        default:  status_text = "Unknown"; break;
    }
    StrBuf sb; sb_init(&sb);
    sb_addf(&sb, "RWP/1.0 %d %s\r\n", status_code, status_text);
    sb_addf(&sb, "Content-Type: %s\r\n", content_type ? content_type : "text/plain");
    sb_addf(&sb, "Content-Length: %zu\r\n", strlen(body));
    sb_add(&sb, "Server: RRKDHT/1.0\r\n");
    sb_add(&sb, "\r\n");
    sb_add(&sb, body);
    tcp_set_send_timeout(client_socket, CFG_RWP_TIMEOUT);
    send(client_socket, sb.buf, sb.len, MSG_NOSIGNAL);
    sb_free(&sb);
}

/* _send_rwp_error(client_socket, status_code, message) */
static void RWPDHTHandler_send_rwp_error(int client_socket, int status_code, const char *message) {
    RWPDHTHandler_send_rwp_response(client_socket, status_code, message, "text/plain");
}

/* _handle_node_info_request(client_socket) */
static void RWPDHTHandler_handle_node_info_request(RWPDHTHandler *h, int client_socket) {
    char *signing_pem = pem_public_key(h->messaging->signing_public_key);
    char *exchange_pem = pem_public_key(h->messaging->exchange_public_key);
    JVal *info = j_obj();
    j_obj_set(info, "node_id", j_str(h->node_id));
    j_obj_set(info, "rendezvous_key", j_str(h->rendezvous_key));
    j_obj_set(info, "signing_public_key", j_str(signing_pem));
    j_obj_set(info, "exchange_public_key", j_str(exchange_pem));
    j_obj_set(info, "epoch", j_int(EpochManager_get_current_epoch(h->epoch_manager)));
    j_obj_set(info, "port", j_int(h->dht_port));       /* our UDP DHT port — NEW */
    j_obj_set(info, "timestamp", j_num(now_time()));
    char *response = j_dumps(info);
    RWPDHTHandler_send_rwp_response(client_socket, 200, response, "application/json");
    free(response);
    free(signing_pem);
    free(exchange_pem);
    j_free(info);
}

/* _handle_dht_message(message_type, message) -> response dict (JVal) */
static JVal *RWPDHTHandler_handle_dht_message(RWPDHTHandler *h, MessageType type, JVal *message) {
    JVal *payload = j_obj_get(message, "payload");
    JVal *resp = j_obj();
    uint8_t rnd[16];

    if (type == MT_PING || type == MT_HEARTBEAT) {
        rand_bytes(rnd, 16);
        char *mid = hex_encode(rnd, 16);
        j_obj_set(resp, "type", j_str(message_type_value(MT_PONG)));
        j_obj_set(resp, "sender_id", j_str(h->node_id));
        JVal *pl = j_obj();
        j_obj_set(pl, "timestamp", j_num(now_time()));
        j_obj_set(pl, "node_id", j_str(h->node_id));
        j_obj_set(resp, "payload", pl);
        j_obj_set(resp, "timestamp", j_num(now_time()));
        j_obj_set(resp, "message_id", j_str(mid));
        free(mid);
        return resp;
    }

    if (type == MT_FIND_NODE) {
        const char *keyhex = payload ? j_get_str(payload, "key") : NULL;
        uint8_t key_bytes[20] = {0};
        if (keyhex) hex_decode(keyhex, key_bytes, 20);
        Node *node = Node_new(key_bytes);
        NodeList neighbors = RoutingTable_find_neighbors(h->router, node, 0, NULL);
        rand_bytes(rnd, 16);
        char *mid = hex_encode(rnd, 16);
        j_obj_set(resp, "type", j_str("find_node_response"));
        j_obj_set(resp, "sender_id", j_str(h->node_id));
        JVal *pl = j_obj();
        j_obj_set(pl, "success", j_bool(true));
        JVal *nodes = j_arr();
        for (size_t i = 0; i < neighbors.n; i++) {
            Node *n = neighbors.v[i];
            JVal *nd = j_obj();
            char *hex = hex_encode(n->id, 20);
            j_obj_set(nd, "id", j_str(hex));
            free(hex);
            j_obj_set(nd, "ip", n->ip ? j_str(n->ip) : j_null());
            j_obj_set(nd, "port", n->port == PORT_NONE ? j_null() : j_int(n->port));
            j_obj_set(nd, "rwp_port", n->rwp_port == PORT_NONE ? j_null() : j_int(n->rwp_port));
            j_obj_set(nd, "rendezvous_key", n->rendezvous_key ? j_str(n->rendezvous_key) : j_null());
            j_arr_add(nodes, nd);
        }
        j_obj_set(pl, "nodes", nodes);
        j_obj_set(resp, "payload", pl);
        j_obj_set(resp, "timestamp", j_num(now_time()));
        j_obj_set(resp, "message_id", j_str(mid));
        free(mid);
        nodelist_free(&neighbors);
        free(node);
        return resp;
    }

    if (type == MT_DHT_GET) {
        /* respond from server_ref._rendezvous_storage */
        const char *keyhex = payload ? j_get_str(payload, "key") : NULL;
        uint8_t key_hash[20] = {0};
        if (keyhex) hex_decode(keyhex, key_hash, 20);
        JVal *value = NULL;
        RRKDHT *server = (h->router && h->router->protocol) ? h->router->protocol->server_ref : NULL;
        if (server && server->rendezvous_storage_initialized)
            value = storage_get(&server->_rendezvous_storage, key_hash);
        rand_bytes(rnd, 16);
        char *mid = hex_encode(rnd, 16);
        j_obj_set(resp, "type", j_str("dht_get_response"));
        j_obj_set(resp, "sender_id", j_str(h->node_id));
        JVal *pl = j_obj();
        j_obj_set(pl, "success", j_bool(true));
        j_obj_set(pl, "found", j_bool(value != NULL));
        if (value) {
            char *vs = j_dumps(value);
            j_obj_set(pl, "value", j_str(vs));
            free(vs);
        } else {
            j_obj_set(pl, "value", j_null());
        }
        j_obj_set(resp, "payload", pl);
        j_obj_set(resp, "timestamp", j_num(now_time()));
        j_obj_set(resp, "message_id", j_str(mid));
        free(mid);
        return resp;
    }

    if (type == MT_DHT_SET) {
        bool success = false;
        const char *rendezvous_logged = NULL;
        JVal *value = NULL;
        const char *keyhex = payload ? j_get_str(payload, "key") : NULL;
        const char *value_str = payload ? j_get_str(payload, "value") : NULL;
        uint8_t key_hash[20] = {0};
        if (keyhex) hex_decode(keyhex, key_hash, 20);
        if (value_str) value = j_loads(value_str);
        RRKDHT *server = (h->router && h->router->protocol) ? h->router->protocol->server_ref : NULL;
        if (server && value) {
            if (!server->rendezvous_storage_initialized) {
                storage_init(&server->_rendezvous_storage);
                server->rendezvous_storage_initialized = true;
            }
            storage_set(&server->_rendezvous_storage, key_hash, j_deepcopy(value));
            success = true;
            rendezvous_logged = j_get_str(value, "rendezvous_key");
            log_info("Stored rendezvous key %s locally", rendezvous_logged ? rendezvous_logged : "None");
        }
        rand_bytes(rnd, 16);
        char *mid = hex_encode(rnd, 16);
        j_obj_set(resp, "type", j_str("dht_set_response"));
        j_obj_set(resp, "sender_id", j_str(h->node_id));
        JVal *pl = j_obj();
        j_obj_set(pl, "success", j_bool(success));
        j_obj_set(resp, "payload", pl);
        j_obj_set(resp, "timestamp", j_num(now_time()));
        j_obj_set(resp, "message_id", j_str(mid));
        free(mid);
        j_free(value);
        return resp;
    }

    if (type == MT_VERIFY) {
        /* RWP fallback for verify_neighbor */
        const char *tidhex = payload ? j_get_str(payload, "target_id") : NULL;
        uint8_t target[20] = {0};
        bool valid = tidhex && strlen(tidhex) == 40 && hex_decode(tidhex, target, 20);
        bool found = false;
        if (valid) {
            RoutingTable *t = h->router;
            RoutingTable_lock(t);
            for (size_t i = 0; i < t->nbuckets; i++)
                if (KBucket_get(t->buckets[i], target)) { found = true; break; }
            RoutingTable_unlock(t);
        }
        rand_bytes(rnd, 16);
        char *mid = hex_encode(rnd, 16);
        j_obj_set(resp, "type", j_str("verify_neighbor_response"));
        j_obj_set(resp, "sender_id", j_str(h->node_id));
        JVal *pl = j_obj();
        j_obj_set(pl, "success", j_bool(valid));
        j_obj_set(pl, "knows", j_bool(found));
        j_obj_set(resp, "payload", pl);
        j_obj_set(resp, "timestamp", j_num(now_time()));
        j_obj_set(resp, "message_id", j_str(mid));
        free(mid);
        return resp;
    }

    /* unknown message type */
    rand_bytes(rnd, 16);
    char *mid = hex_encode(rnd, 16);
    j_obj_set(resp, "type", j_str("error"));
    j_obj_set(resp, "sender_id", j_str(h->node_id));
    JVal *pl = j_obj();
    j_obj_set(pl, "success", j_bool(false));
    StrBuf em; sb_init(&em);
    sb_addf(&em, "Unknown message type: %s", message_type_value(type));
    j_obj_set(pl, "message", j_str(em.buf));
    sb_free(&em);
    j_obj_set(resp, "payload", pl);
    j_obj_set(resp, "timestamp", j_num(now_time()));
    j_obj_set(resp, "message_id", j_str(mid));
    free(mid);
    return resp;
}

/* RWPDHTHandler._handle_rendezvous_request (the overriding, live version) */
static void RWPDHTHandler_handle_rendezvous_request(RWPDHTHandler *h, int client_socket,
                                                    const char *request_str, const char *method,
                                                    const char *path) {
    (void)path;
    if (!strcmp(method, "POST") && strstr(request_str, "\r\n\r\n")) {
        const char *body = strstr(request_str, "\r\n\r\n") + 4;
        JVal *request_data = j_loads(body);
        if (!request_data) {
            log_error("JSON decode error in rendezvous request");
            RWPDHTHandler_send_rwp_error(client_socket, 400, "Invalid JSON");
            return;
        }
        const char *enc_b64 = j_get_str(request_data, "encrypted_data");
        const char *sender_pem = j_get_str(request_data, "sender_exchange_key");
        size_t enc_len = 0;
        uint8_t *encrypted = enc_b64 ? b64_decode(enc_b64, &enc_len) : NULL;
        EVP_PKEY *sender_key = sender_pem ? load_pem_public_key(sender_pem) : NULL;
        JVal *decrypted = NULL;
        if (encrypted && sender_key)
            decrypted = SecureMessaging_decrypt_message(h->messaging, encrypted, enc_len, sender_key);
        if (!decrypted) {
            log_error("Error handling rendezvous request: decrypt failed");
            RWPDHTHandler_send_rwp_error(client_socket, 500, "Internal Server Error");
            free(encrypted);
            if (sender_key) EVP_PKEY_free(sender_key);
            j_free(request_data);
            return;
        }
        /* message_type = MessageType(decrypted_message['type']) */
        const char *type_str = j_get_str(decrypted, "type");
        MessageType mtype;
        if (!type_str || !message_type_from_value(type_str, &mtype)) {
            log_error("Error handling rendezvous request: unknown message type");
            RWPDHTHandler_send_rwp_error(client_socket, 500, "Internal Server Error");
            free(encrypted);
            EVP_PKEY_free(sender_key);
            j_free(request_data);
            j_free(decrypted);
            return;
        }
        JVal *response_data = RWPDHTHandler_handle_dht_message(h, mtype, decrypted);
        /* encrypt response */
        size_t er_len = 0;
        uint8_t *encrypted_response = SecureMessaging_encrypt_message(h->messaging, response_data,
                                                                      sender_key, &er_len);
        j_free(response_data);
        if (!encrypted_response) {
            RWPDHTHandler_send_rwp_error(client_socket, 500, "Internal Server Error");
            free(encrypted);
            EVP_PKEY_free(sender_key);
            j_free(request_data);
            j_free(decrypted);
            return;
        }
        char *er_b64 = b64_encode(encrypted_response, er_len);
        JVal *response_body = j_obj();
        j_obj_set(response_body, "encrypted_data", j_str(er_b64));
        const char *msgid = j_get_str(decrypted, "message_id");
        j_obj_set(response_body, "message_id", j_str(msgid ? msgid : ""));
        j_obj_set(response_body, "timestamp", j_num(now_time()));
        char *body_out = j_dumps(response_body);
        RWPDHTHandler_send_rwp_response(client_socket, 200, body_out, "application/json");
        log_debug("Successfully handled RWP request: %s", message_type_value(mtype));
        free(body_out);
        j_free(response_body);
        free(er_b64);
        free(encrypted_response);
        free(encrypted);
        EVP_PKEY_free(sender_key);
        j_free(request_data);
        j_free(decrypted);
    } else {
        RWPDHTHandler_send_rwp_error(client_socket, 400, "Bad Request");
    }
}

/* _handle_rwp_client(client_socket, address) */
typedef struct { RWPDHTHandler *h; int fd; char ip[64]; int port; } ClientCtx;

static void *rwp_client_thread(void *arg) {
    ClientCtx *ctx = arg;
    RWPDHTHandler *h = ctx->h;
    int fd = ctx->fd;
    free(ctx);

    /* receive request until "\r\n\r\n" or MAX_MESSAGE_SIZE */
    StrBuf req; sb_init(&req);
    tcp_set_recv_timeout(fd, CFG_RWP_TIMEOUT);
    bool recv_failed = false;
    for (;;) {
        char buf[4096];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n == 0) break;                       /* client closed */
        if (n < 0) {                             /* timeout / error -> exception path */
            if (req.len == 0) recv_failed = true;
            break;
        }
        sb_addn(&req, buf, (size_t)n);
        if (strstr(req.buf, "\r\n\r\n")) break;
        if (req.len > CFG_MAX_MESSAGE_SIZE) {
            RWPDHTHandler_send_rwp_error(fd, 413, "Request too large");
            close(fd);
            sb_free(&req);
            return NULL;
        }
    }
    if (recv_failed || req.len == 0) {
        if (recv_failed) {
            log_error("Error handling RWP client: recv timeout/error");
            RWPDHTHandler_send_rwp_error(fd, 500, "Internal Server Error");
        }
        close(fd);
        sb_free(&req);
        return NULL;
    }

    /* parse request line */
    char *request_str = req.buf;
    /* find end of first line */
    char *eol = strstr(request_str, "\r\n");
    if (!eol) {
        close(fd);
        sb_free(&req);
        return NULL;
    }
    size_t line_len = (size_t)(eol - request_str);
    char *request_line = strndup(request_str, line_len);
    if (!starts_with(request_line, "GET") && !starts_with(request_line, "POST")) {
        RWPDHTHandler_send_rwp_error(fd, 400, "Bad Request");
        free(request_line);
        close(fd);
        sb_free(&req);
        return NULL;
    }
    /* parts = request_line.split() */
    char *parts[3] = {0};
    int nparts = 0;
    {
        char *save = NULL;
        char *tok = strtok_r(request_line, " \t", &save);
        while (tok && nparts < 3) { parts[nparts++] = tok; tok = strtok_r(NULL, " \t", &save); }
        if (tok) nparts = 4;                     /* more than 3 tokens */
    }
    if (nparts < 3) {
        RWPDHTHandler_send_rwp_error(fd, 400, "Bad Request");
        free(request_line);
        close(fd);
        sb_free(&req);
        return NULL;
    }
    char *method = parts[0], *path = parts[1], *protocol = parts[2];
    if (strcmp(protocol, "RWP/1.0")) {
        RWPDHTHandler_send_rwp_error(fd, 505, "Version Not Supported");
        free(request_line);
        close(fd);
        sb_free(&req);
        return NULL;
    }
    if (!strcmp(path, "/node-info")) {
        RWPDHTHandler_handle_node_info_request(h, fd);
    } else {
        StrBuf prefix; sb_init(&prefix);
        sb_addf(&prefix, "/%s/", h->rendezvous_key);
        if (starts_with(path, prefix.buf))
            RWPDHTHandler_handle_rendezvous_request(h, fd, request_str, method, path);
        else
            RWPDHTHandler_send_rwp_error(fd, 404, "Not Found");
        sb_free(&prefix);
    }
    free(request_line);
    close(fd);
    sb_free(&req);
    return NULL;
}

/* _run_rwp_server(port) */
static void *rwp_server_thread_main(void *arg) {
    void **ctx = arg;
    RWPDHTHandler *h = ctx[0];
    int port = (int)(intptr_t)ctx[1];
    free(ctx);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { log_error("RWP server error: socket"); return NULL; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);      /* '0.0.0.0' */
    sa.sin_port = htons((uint16_t)port);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(srv, 10) < 0) {
        log_error("RWP server error: bind/listen on port %d failed", port);
        close(srv);
        h->rwp_server_socket = -1;
        return NULL;
    }
    h->rwp_server_socket = srv;
    int consecutive_errors = 0;
    while (h->running) {
        struct sockaddr_in ca; socklen_t clen = sizeof(ca);
        int client = accept(srv, (struct sockaddr *)&ca, &clen);
        if (client < 0) {
            if (!h->running) break;              /* OSError on shutdown */
            int err = errno;
            if (err == EINTR) continue;           /* transient, not a real error */
            if (err == EBADF || err == ENOTSOCK || err == EINVAL || err == EOPNOTSUPP) {
                /* the listening socket itself is broken/closed — mirror
                 * Python's behavior of breaking the loop and shutting the
                 * server down cleanly instead of spinning forever */
                log_error("RWP server error: accept() failed fatally (%s), stopping server",
                          strerror(err));
                break;
            }
            /* EMFILE/ENFILE/ECONNABORTED/etc: transient resource pressure —
             * retry with backoff, but give up if it's clearly not recovering */
            consecutive_errors++;
            if (consecutive_errors > 1000) {
                log_error("RWP server error: accept() failing repeatedly (%s), stopping server",
                          strerror(err));
                break;
            }
            py_sleep(0.01);
            continue;
        }
                consecutive_errors = 0;

        /* === HARDENING: rate limit per IP === */
        char rwp_client_ip[16];
        snprintf(rwp_client_ip, sizeof(rwp_client_ip), "%s", inet_ntoa(ca.sin_addr));
        if (!rate_check(rwp_client_ip, MAX_RWP_PER_SEC)) {
            close(client);
            continue;
        }

        /* === HARDENING: connection cap === */
        if (atomic_load(&g_rwp_connections) >= MAX_RWP_CONNECTIONS) {
            log_warning("RWP connection cap (%d) reached, rejecting %s",
                        MAX_RWP_CONNECTIONS, rwp_client_ip);
            close(client);
            continue;
        }

        /* === HARDENING: calloc NULL check === */
        ClientCtx *cctx = SAFE_CALLOC(ClientCtx, 1);
        if (!cctx) { close(client); continue; }
        cctx->h = h;
        cctx->fd = client;
        snprintf(cctx->ip, sizeof(cctx->ip), "%s", rwp_client_ip);
        cctx->port = ntohs(ca.sin_port);

        /* === HARDENING: wrap in thread guard with connection counter === */
        atomic_fetch_add(&g_rwp_connections, 1);
        ThreadGuardCtx *guard = SAFE_MALLOC(sizeof(ThreadGuardCtx));
        if (!guard) {
            atomic_fetch_sub(&g_rwp_connections, 1);
            free(cctx);
            close(client);
            continue;
        }
        guard->fn = rwp_client_thread;
        guard->arg = cctx;
        guard->counter = &g_rwp_connections;

        pthread_t t;
        if (pthread_create(&t, NULL, thread_guard, guard) == 0)
            pthread_detach(t);
        else {
            free(guard);
            rwp_client_thread(cctx);
            atomic_fetch_sub(&g_rwp_connections, 1);
        }
    }
    h->running = false;
    close(srv);
    h->rwp_server_socket = -1;
    return NULL;
}

/* start_rwp_server(port) */
static void RWPDHTHandler_start_rwp_server(RWPDHTHandler *h, int port) {
    if (h->running) return;
    h->running = true;
    void **ctx = malloc(2 * sizeof(void *));
    ctx[0] = h;
    ctx[1] = (void *)(intptr_t)port;
    if (pthread_create(&h->rwp_server_thread, NULL, rwp_server_thread_main, ctx) != 0) {
        free(ctx);
        h->running = false;
        return;
    }
    log_info("Started RWP server on port %d", port);
}

/* stop_rwp_server() */
static void RWPDHTHandler_stop_rwp_server(RWPDHTHandler *h) {
    h->running = false;
    if (h->rwp_server_socket >= 0) {
        shutdown(h->rwp_server_socket, SHUT_RDWR);
        close(h->rwp_server_socket);
        h->rwp_server_socket = -1;
    }
    if (h->rwp_server_thread) {
        pthread_join(h->rwp_server_thread, NULL);
        h->rwp_server_thread = 0;
    }
}

/* get_node_info(ip, rwp_port) — caching + 2 attempts with backoff */
static NodeInfo *RWPDHTHandler_get_node_info(RWPDHTHandler *h, const char *ip, int rwp_port) {
    /* === HARDENING: validate inputs === */
    if (!ip || strlen(ip) == 0 || strlen(ip) > 15) return NULL;
    if (rwp_port <= 0 || rwp_port > 65535) return NULL;

    char cache_key[128];
    snprintf(cache_key, sizeof(cache_key), "%s:%d", ip, rwp_port);

    NodeInfo *cached = cache_get(h, cache_key);
    if (cached) {
        /* shorter expiration (30 seconds) for more frequent refresh */
        if (now_time() - cached->timestamp < 30)
            return cached;
        cache_del(h, cache_key);
    }

    for (int attempt = 0; attempt < 2; attempt++) {     /* reduced from 3 to 2 */
        int sock = -1;
        bool retry = false;
        /* connect with timeout 3.0 */
        sock = tcp_connect_timeout(ip, rwp_port, 3.0);
        if (sock < 0) {
            retry = true;
        } else {
            StrBuf req; sb_init(&req);
            sb_add(&req, "GET /node-info RWP/1.0\r\n");
            sb_addf(&req, "Host: %s\r\n", ip);
            sb_add(&req, "Connection: close\r\n");
            sb_add(&req, "\r\n");
            tcp_set_send_timeout(sock, 3.0);
            if (send(sock, req.buf, req.len, MSG_NOSIGNAL) < 0) {
                retry = true;
            }
            sb_free(&req);
            if (!retry) {
                /* receive response with proper buffering, timeout 2.0 */
                StrBuf resp; sb_init(&resp);
                tcp_set_recv_timeout(sock, 2.0);
                bool too_big = false;
                for (;;) {
                    char buf[4096];
                    ssize_t n = recv(sock, buf, sizeof(buf), 0);
                    if (n == 0) break;
                    if (n < 0) {
                        if (resp.len > 0) break;         /* we got some data */
                        retry = true;
                        break;
                    }
                    sb_addn(&resp, buf, (size_t)n);
                    if (resp.len > CFG_MAX_MESSAGE_SIZE) { too_big = true; break; }
                    if (strstr(resp.buf, "\r\n\r\n")) break;
                }
                if (too_big) {
                    log_error("Response too large");
                    retry = true;
                } else if (!retry && resp.len == 0) {
                    log_debug("No response received from %s:%d", ip, rwp_port);
                    retry = true;
                } else if (!retry) {
                    /* parse response */
                    if (strstr(resp.buf, "RWP/1.0 200 OK") && strstr(resp.buf, "\r\n\r\n")) {
                        const char *body = strstr(resp.buf, "\r\n\r\n") + 4;
                        JVal *node_data = j_loads(body);
                        if (node_data) {
                            const char *nid = j_get_str(node_data, "node_id");
                            const char *rk = j_get_str(node_data, "rendezvous_key");
                            const char *spk = j_get_str(node_data, "signing_public_key");
                            const char *epk = j_get_str(node_data, "exchange_public_key");
                            if (nid && rk && spk && epk) {
                                NodeInfo *ni = SAFE_CALLOC(NodeInfo, 1);
                                if (!ni) { j_free(node_data); sb_free(&resp); close(sock); retry = true; break; }
                                ni->node_id = xstrdup(nid);
                                ni->ip = xstrdup(ip);
                                ni->port = (int)j_get_num(node_data, "port", 0);                                ni->rwp_port = rwp_port;
                                ni->rendezvous_key = xstrdup(rk);
                                ni->signing_public_key = xstrdup(spk);
                                ni->exchange_public_key = xstrdup(epk);
                                ni->epoch = (int64_t)j_get_num(node_data, "epoch", 0);
                                ni->timestamp = now_time();
                                cache_set(h, cache_key, ni);
                                log_debug("Successfully got node info from %s:%d", ip, rwp_port);
                                j_free(node_data);
                                sb_free(&resp);
                                close(sock);
                                return ni;
                            }
                            log_error("Failed to parse node info response: missing keys");
                            j_free(node_data);
                        } else {
                            log_error("Failed to parse node info response: invalid JSON");
                        }
                        retry = true;
                    } else {
                        log_warning("Invalid response from %s:%d", ip, rwp_port);
                        retry = true;
                    }
                }
                sb_free(&resp);
            }
        }
        if (sock >= 0) close(sock);
        if (attempt < 1) {                               /* don't sleep on last attempt */
            py_sleep(0.2 * (attempt + 1));               /* shorter backoff */
            continue;
        }
        log_debug("Failed to get node info from %s:%d", ip, rwp_port);
    }
    return NULL;
}

/* _send_rwp_request(host, port, rendezvous_key, request_data, message_type) */
static JVal *RWPDHTHandler_send_rwp_request(const char *host, int port, const char *rendezvous_key,
                                            JVal *request_data, MessageType type) {
    char *request_body = j_dumps(request_data);
    StrBuf req; sb_init(&req);
    sb_addf(&req, "POST /%s/message RWP/1.0\r\n", rendezvous_key);
    sb_addf(&req, "Host: %s\r\n", host);
    sb_add(&req, "Content-Type: application/json\r\n");
    sb_addf(&req, "Content-Length: %zu\r\n", strlen(request_body));
    sb_addf(&req, "RWP-Message-Type: %s\r\n", message_type_value(type));
    sb_add(&req, "Connection: close\r\n");
    sb_add(&req, "\r\n");
    sb_add(&req, request_body);
    free(request_body);

    JVal *result = NULL;
    int sock = tcp_connect_timeout(host, port, CFG_RWP_TIMEOUT);
    if (sock >= 0) {
        tcp_set_send_timeout(sock, CFG_RWP_TIMEOUT);
        tcp_set_recv_timeout(sock, CFG_RWP_TIMEOUT);
        if (send(sock, req.buf, req.len, MSG_NOSIGNAL) >= 0) {
            StrBuf resp; sb_init(&resp);
            for (;;) {
                char buf[4096];
                ssize_t n = recv(sock, buf, sizeof(buf), 0);
                if (n <= 0) break;
                sb_addn(&resp, buf, (size_t)n);
                if (resp.len > CFG_MAX_MESSAGE_SIZE * 4) break;
            }
            if (resp.len && strstr(resp.buf, "RWP/1.0 200 OK") && strstr(resp.buf, "\r\n\r\n")) {
                const char *body = strstr(resp.buf, "\r\n\r\n") + 4;
                result = j_loads(body);
            }
            sb_free(&resp);
        } else {
            log_error("Error sending RWP request: send failed");
        }
        close(sock);
    } else {
        log_error("Error sending RWP request: connect to %s:%d failed", host, port);
    }
    sb_free(&req);
    return result;
}

/* send_encrypted_message(node_info, message_type, payload) -> decrypted response dict */
static JVal *RWPDHTHandler_send_encrypted_message(RWPDHTHandler *h, NodeInfo *node_info,
                                                  MessageType type, JVal *payload) {
    for (int attempt = 0; attempt < 2; attempt++) {     /* try twice */
        EVP_PKEY *exchange_key = load_pem_public_key(node_info->exchange_public_key);
        if (!exchange_key) {
            log_error("Attempt %d failed to send encrypted message to %s:%d: bad exchange key",
                      attempt + 1, node_info->ip, node_info->rwp_port);
            if (attempt < 1) { py_sleep(0.5); continue; }
            break;
        }
        /* create message */
        uint8_t rnd[16]; rand_bytes(rnd, 16);
        char *mid = hex_encode(rnd, 16);
        JVal *message = j_obj();
        j_obj_set(message, "type", j_str(message_type_value(type)));
        j_obj_set(message, "sender_id", j_str(h->node_id));
        j_obj_set(message, "payload", j_deepcopy(payload));
        j_obj_set(message, "timestamp", j_num(now_time()));
        j_obj_set(message, "message_id", j_str(mid));

        size_t enc_len = 0;
        uint8_t *encrypted = SecureMessaging_encrypt_message(h->messaging, message, exchange_key, &enc_len);
        if (!encrypted) {
            free(mid);
            j_free(message);
            EVP_PKEY_free(exchange_key);
            if (attempt < 1) { py_sleep(0.5); continue; }
            break;
        }
        char *enc_b64 = b64_encode(encrypted, enc_len);
        char *exchange_pem = pem_public_key(h->messaging->exchange_public_key);
        JVal *request_data = j_obj();
        j_obj_set(request_data, "encrypted_data", j_str(enc_b64));
        j_obj_set(request_data, "sender_exchange_key", j_str(exchange_pem));
        j_obj_set(request_data, "message_id", j_str(mid));
        j_obj_set(request_data, "timestamp", j_num(j_get_num(message, "timestamp", now_time())));

        JVal *result = RWPDHTHandler_send_rwp_request(node_info->ip, node_info->rwp_port,
                                                      node_info->rendezvous_key, request_data, type);
        free(mid);
        j_free(message);
        j_free(request_data);
        free(enc_b64);
        free(exchange_pem);
        free(encrypted);

        if (result && j_obj_has(result, "encrypted_data")) {
            const char *rb64 = j_get_str(result, "encrypted_data");
            size_t re_len = 0;
            uint8_t *re = rb64 ? b64_decode(rb64, &re_len) : NULL;
            JVal *decrypted = NULL;
            if (re)
                decrypted = SecureMessaging_decrypt_message(h->messaging, re, re_len, exchange_key);
            free(re);
            if (decrypted) {
                log_debug("Successfully sent and decrypted message response from %s:%d",
                          node_info->ip, node_info->rwp_port);
                j_free(result);
                EVP_PKEY_free(exchange_key);
                return decrypted;
            }
            log_error("Failed to decrypt response");
            j_free(result);
            EVP_PKEY_free(exchange_key);
            if (attempt < 1) { py_sleep(0.5); continue; }
            return NULL;
        }
        log_warning("No encrypted_data in response from %s:%d", node_info->ip, node_info->rwp_port);
        j_free(result);
        EVP_PKEY_free(exchange_key);
        if (attempt < 1) { py_sleep(0.5); continue; }
    }
    log_error("All attempts failed to send encrypted message to %s:%d",
              node_info->ip, node_info->rwp_port);
    return NULL;
}

/* RWPDHTHandler._get_epoch_key (identical helper on the handler class) */
static void RWPDHTHandler_get_epoch_key(const uint8_t key[20], int64_t epoch, uint8_t out[20]) {
    RRKDHTProtocol_get_epoch_key(key, epoch, out);
}

/* ============================================================================
 * SEARCH CLASSES (SearchResult, NodeSearch)
 * ============================================================================ */

/* @dataclass SearchResult */
typedef struct SearchResult {
    bool found;
    Node *target_node;             /* NULL if not found */
    int hops;
    NodeList path_hex;             /* List[str] stored as char* list below */
    char **path; size_t path_n, path_cap;
    double search_time;
    int nodes_queried;
    bool cycle_detected;
} SearchResult;

static SearchResult *SearchResult_new(void) {
    SearchResult *r = calloc(1, sizeof(SearchResult));
    nodelist_init(&r->path_hex);     /* unused; path tracked via char** */
    return r;
}

static void searchresult_path_append(SearchResult *r, const char *hexid) {
    if (r->path_n == r->path_cap) {
        r->path_cap = r->path_cap ? r->path_cap * 2 : 8;
        r->path = realloc(r->path, r->path_cap * sizeof(char *));
    }
    r->path[r->path_n++] = xstrdup(hexid);
}

/* NodeSearch — iterative search with ring-topology cycle detection */
typedef struct {
    RRKDHTProtocol *protocol;
    uint8_t target_node_id[20];
    Node *target_node;
    double timeout;
    int alpha;
    IdSet queried_nodes;
    IdSet seen_nodes;              /* starts with protocol.source_node.id */
    SearchResult *res;             /* accumulates path / nodes_queried */
    double start_time;
    int _consecutive_no_progress;
} NodeSearch;

typedef struct {
    bool found;
    NodeList neighbors;            /* Node* list */
    Node *node;                    /* target node if found */
} QueryNodeResult;

typedef struct {
    NodeSearch *ns;
    Node *node;
    QueryNodeResult *res;
} QueryTaskCtx;

/* NodeSearch._query_node(node) */
static void *NodeSearch_query_node(void *arg) {
    QueryTaskCtx *ctx = arg;
    NodeSearch *ns = ctx->ns;
    Node *node = ctx->node;
    QueryNodeResult *out = calloc(1, sizeof(QueryNodeResult));
    nodelist_init(&out->neighbors);
    ctx->res = out;

    char *th = hex_encode(ns->target_node_id, 20);
    log_debug("Querying %s:%d for target %.16s...", node->ip, node->port, th);
    free(th);

    RpcResult *result = RRKDHTProtocol_call_find_node(ns->protocol, node, ns->target_node);
    if (!result->happened) {
        m_free(result->data);
        free(result);
        return NULL;
    }
    if (result->data && result->data->t == M_ARR) {
        for (size_t i = 0; i < result->data->nitems; i++) {
            MVal *tup = result->data->items[i];
            if (!tup || tup->t != M_ARR || tup->nitems < 3) continue;
            const uint8_t *rid; size_t ridlen;
            if (!m_as_bytes(tup->items[0], &rid, &ridlen)) continue;
            uint8_t returned_id[20] = {0};
            memcpy(returned_id, rid, ridlen < 20 ? ridlen : 20);
            const char *ip = (tup->items[1]->t == M_STR) ? tup->items[1]->str : NULL;
            int port = m_is_intlike(tup->items[2]) ? (int)m_as_int(tup->items[2]) : PORT_NONE;
            int rwp_port = PORT_NONE;
            if (tup->nitems > 3 && m_is_intlike(tup->items[3]))
                rwp_port = (int)m_as_int(tup->items[3]);
            Node *returned_node = Node_new_full(returned_id, ip, port, rwp_port, NULL);
            if (!memcmp(returned_id, ns->target_node_id, 20)) {
                out->found = true;
                out->node = returned_node;
                log_info("FOUND TARGET at %s:%d!", ip ? ip : "?", port);
            } else {
                nodelist_add(&out->neighbors, returned_node);
            }
        }
    }
    m_free(result->data);
    free(result);
    return NULL;
}

/* NodeSearch.search() — iterative search with cycle detection, NO max hops */
static SearchResult *NodeSearch_search(NodeSearch *ns) {
    RRKDHTProtocol *protocol = ns->protocol;
    char *th = hex_encode(ns->target_node_id, 20);
    log_info("Starting pure cycle-detection search for node %s", th);
    free(th);

    /* disable routing-table learning during search */
    bool old_flag = protocol->learning_enabled;
    protocol->learning_enabled = false;

    SearchResult *sr = ns->res;

    /* start with our closest known neighbors to target */
    NodeList current_closest = RoutingTable_find_neighbors(protocol->router, ns->target_node,
                                                           ns->alpha, NULL);
    if (!current_closest.n) {
        log_warning("No neighbors close to target, using all available neighbors");
        NodeList all_neighbors; nodelist_init(&all_neighbors);
        RoutingTable *t = protocol->router;
        RoutingTable_lock(t);
        for (size_t i = 0; i < t->nbuckets; i++) {
            NodeList nl = KBucket_get_nodes(t->buckets[i]);
            for (size_t j = 0; j < nl.n; j++) nodelist_add(&all_neighbors, nl.v[j]);
            nodelist_free(&nl);
        }
        RoutingTable_unlock(t);
        if (!all_neighbors.n) {
            log_warning("No neighbors available to start search");
            sr->found = false;
            sr->target_node = NULL;
            sr->hops = 0;
            sr->search_time = now_time() - ns->start_time;
            sr->nodes_queried = 0;
            sr->cycle_detected = false;
            protocol->learning_enabled = old_flag;
            nodelist_free(&all_neighbors);
            nodelist_free(&current_closest);
            return sr;
        }
        /* sort by distance, take alpha closest (even if far away) */
        for (size_t i = 1; i < all_neighbors.n; i++) {
            Node *cur = all_neighbors.v[i];
            u256 d = Node_distance_to(ns->target_node, cur);
            size_t j = i;
            while (j > 0 && u256_gt(Node_distance_to(ns->target_node, all_neighbors.v[j - 1]), d)) {
                all_neighbors.v[j] = all_neighbors.v[j - 1];
                j--;
            }
            all_neighbors.v[j] = cur;
        }
        for (size_t i = 0; i < all_neighbors.n && (int)i < ns->alpha; i++)
            nodelist_add(&current_closest, all_neighbors.v[i]);
        log_debug("Starting with %zu farthest-available neighbors", current_closest.n);
        nodelist_free(&all_neighbors);
    }

    for (size_t i = 0; i < current_closest.n; i++) idset_add(&ns->seen_nodes, current_closest.v[i]->id);

    /* check if we already know the target */
    for (size_t i = 0; i < current_closest.n; i++) {
        Node *node = current_closest.v[i];
        if (!memcmp(node->id, ns->target_node_id, 20)) {
            log_info("Target node found in local routing table!");
            char *sh = hex_encode(protocol->source_node->id, 20);
            searchresult_path_append(sr, sh);
            free(sh);
            sr->found = true;
            sr->target_node = node;
            sr->hops = 0;
            sr->search_time = now_time() - ns->start_time;
            sr->nodes_queried = 0;
            sr->cycle_detected = false;
            protocol->learning_enabled = old_flag;
            nodelist_free(&current_closest);
            return sr;
        }
    }

    /* track the closest distance we've seen */
    u256 best_distance = u256_zero();
    bool first = true;
    for (size_t i = 0; i < current_closest.n; i++) {
        u256 d = Node_distance_to(ns->target_node, current_closest.v[i]);
        if (first || u256_lt(d, best_distance)) { best_distance = d; first = false; }
    }
    {
        char *bd = u256_to_dec(best_distance);
        log_debug("Starting search with best distance: %s", bd);
        free(bd);
    }

    /* track all known candidates for querying */
    NodeList all_candidates; nodelist_init(&all_candidates);
    for (size_t i = 0; i < current_closest.n; i++) nodelist_add(&all_candidates, current_closest.v[i]);

    int hop = 0;
    for (;;) {
        hop += 1;
        if (now_time() - ns->start_time > ns->timeout) {      /* primary termination: timeout */
            log_warning("Search timed out after %d hops", hop);
            break;
        }
        /* unqueried nodes from candidate pool */
        NodeList unqueried; nodelist_init(&unqueried);
        for (size_t i = 0; i < all_candidates.n; i++)
            if (!idset_contains(&ns->queried_nodes, all_candidates.v[i]->id))
                nodelist_add(&unqueried, all_candidates.v[i]);
        if (!unqueried.n) {
            log_info("No more unqueried nodes after %d hops", hop);
            nodelist_free(&unqueried);
            break;
        }
        /* query closest unqueried nodes */
        for (size_t i = 1; i < unqueried.n; i++) {
            Node *cur = unqueried.v[i];
            u256 d = Node_distance_to(ns->target_node, cur);
            size_t j = i;
            while (j > 0 && u256_gt(Node_distance_to(ns->target_node, unqueried.v[j - 1]), d)) {
                unqueried.v[j] = unqueried.v[j - 1];
                j--;
            }
            unqueried.v[j] = cur;
        }
        NodeList nodes_to_query; nodelist_init(&nodes_to_query);
        for (size_t i = 0; i < unqueried.n && (int)i < ns->alpha; i++)
            nodelist_add(&nodes_to_query, unqueried.v[i]);
        {
            char *bd = u256_to_dec(best_distance);
            log_info("Hop %d: Querying %zu nodes (best distance so far: %s, seen %zu unique nodes)",
                     hop, nodes_to_query.n, bd, ns->seen_nodes.n);
            free(bd);
        }

        QueryTaskCtx *ctxs = calloc(nodes_to_query.n, sizeof(QueryTaskCtx));
        GatherTask *tasks = calloc(nodes_to_query.n, sizeof(GatherTask));
        for (size_t i = 0; i < nodes_to_query.n; i++) {
            Node *node = nodes_to_query.v[i];
            idset_add(&ns->queried_nodes, node->id);
            char *nh = hex_encode(node->id, 20);
            searchresult_path_append(sr, nh);
            free(nh);
            sr->nodes_queried += 1;
            ctxs[i].ns = ns;
            ctxs[i].node = node;
            ctxs[i].res = NULL;
            tasks[i].fn = NodeSearch_query_node;
            tasks[i].arg = &ctxs[i];
        }
        parallel_gather(tasks, nodes_to_query.n);   /* asyncio.gather(return_exceptions=True) */

        /* process results with enhanced cycle detection */
        NodeList truly_new_nodes; nodelist_init(&truly_new_nodes);
        for (size_t i = 0; i < nodes_to_query.n; i++) {
            QueryNodeResult *result = ctxs[i].res;
            if (!result) {                          /* exception path */
                log_debug("Query to %s:%d failed", nodes_to_query.v[i]->ip, nodes_to_query.v[i]->port);
                continue;
            }
            if (result->found) {
                log_info("Target node found after %d hops!", hop);
                sr->found = true;
                sr->target_node = result->node;
                sr->hops = hop;
                sr->search_time = now_time() - ns->start_time;
                sr->cycle_detected = false;
                protocol->learning_enabled = old_flag;
                for (size_t k = 0; k < nodes_to_query.n; k++)
                    if (ctxs[k].res) { nodelist_free(&ctxs[k].res->neighbors); free(ctxs[k].res); }
                free(ctxs); free(tasks);
                nodelist_free(&nodes_to_query);
                nodelist_free(&unqueried);
                nodelist_free(&truly_new_nodes);
                nodelist_free(&all_candidates);
                nodelist_free(&current_closest);
                return sr;
            }
            for (size_t k = 0; k < result->neighbors.n; k++) {
                Node *neighbor = result->neighbors.v[k];
                idset_add(&ns->seen_nodes, neighbor->id);
                bool present = false;
                for (size_t c = 0; c < all_candidates.n; c++)
                    if (!memcmp(all_candidates.v[c]->id, neighbor->id, 20)) { present = true; break; }
                if (!present) nodelist_add(&all_candidates, neighbor);
                if (!idset_contains(&ns->queried_nodes, neighbor->id))
                    nodelist_add(&truly_new_nodes, neighbor);
            }
        }

        /* primary cycle detection: no truly new nodes discovered */
        if (!truly_new_nodes.n) {
            ns->_consecutive_no_progress += 1;
            if (ns->_consecutive_no_progress >= 5) {
                sr->cycle_detected = true;
                log_info("Network cycle COMPLETED after %d hops: queried %zu nodes, "
                         "traversed %zu total unique nodes, no new nodes for %d consecutive hops",
                         hop, ns->queried_nodes.n, ns->seen_nodes.n, ns->_consecutive_no_progress);
                nodelist_free(&truly_new_nodes);
                for (size_t k = 0; k < nodes_to_query.n; k++)
                    if (ctxs[k].res) { nodelist_free(&ctxs[k].res->neighbors); free(ctxs[k].res); }
                free(ctxs); free(tasks);
                nodelist_free(&nodes_to_query);
                nodelist_free(&unqueried);
                break;
            } else {
                log_debug("No new nodes in hop %d (progress counter: %d), continuing...",
                          hop, ns->_consecutive_no_progress);
                nodelist_free(&truly_new_nodes);
                for (size_t k = 0; k < nodes_to_query.n; k++)
                    if (ctxs[k].res) { nodelist_free(&ctxs[k].res->neighbors); free(ctxs[k].res); }
                free(ctxs); free(tasks);
                nodelist_free(&nodes_to_query);
                nodelist_free(&unqueried);
                continue;
            }
        } else {
            ns->_consecutive_no_progress = 0;
        }
        size_t truly_new_count = truly_new_nodes.n;
        nodelist_free(&truly_new_nodes);

        /* update current closest candidates */
        nodelist_free(&current_closest);
        nodelist_init(&current_closest);
        for (size_t i = 0; i < all_candidates.n; i++)
            if (!idset_contains(&ns->queried_nodes, all_candidates.v[i]->id))
                nodelist_add(&current_closest, all_candidates.v[i]);
        for (size_t i = 1; i < current_closest.n; i++) {
            Node *cur = current_closest.v[i];
            u256 d = Node_distance_to(ns->target_node, cur);
            size_t j = i;
            while (j > 0 && u256_gt(Node_distance_to(ns->target_node, current_closest.v[j - 1]), d)) {
                current_closest.v[j] = current_closest.v[j - 1];
                j--;
            }
            current_closest.v[j] = cur;
        }

        /* check distance improvement for additional early termination */
        if (current_closest.n) {
            u256 new_best = Node_distance_to(ns->target_node, current_closest.v[0]);
            if (u256_lt(new_best, best_distance)) {
                char *b1 = u256_to_dec(best_distance), *b2 = u256_to_dec(new_best);
                log_debug("Progress: distance improved from %s to %s", b1, b2);
                free(b1); free(b2);
                best_distance = new_best;
            } else if (u256_eq(new_best, best_distance) && (int)truly_new_count < ns->alpha) {
                /* no distance improvement AND few new nodes = near convergence */
                char *b1 = u256_to_dec(best_distance);
                log_debug("Convergence: distance stalled at %s with limited new nodes", b1);
                free(b1);
                for (size_t k = 0; k < nodes_to_query.n; k++)
                    if (ctxs[k].res) { nodelist_free(&ctxs[k].res->neighbors); free(ctxs[k].res); }
                free(ctxs); free(tasks);
                nodelist_free(&nodes_to_query);
                nodelist_free(&unqueried);
                break;
            }
        } else {
            log_debug("No more unqueried candidates");
            for (size_t k = 0; k < nodes_to_query.n; k++)
                if (ctxs[k].res) { nodelist_free(&ctxs[k].res->neighbors); free(ctxs[k].res); }
            free(ctxs); free(tasks);
            nodelist_free(&nodes_to_query);
            nodelist_free(&unqueried);
            break;
        }

        for (size_t k = 0; k < nodes_to_query.n; k++)
            if (ctxs[k].res) { nodelist_free(&ctxs[k].res->neighbors); free(ctxs[k].res); }
        free(ctxs); free(tasks);
        nodelist_free(&nodes_to_query);
        nodelist_free(&unqueried);
    }

    /* search exhausted */
    log_info("Search completed: %s, queried %d nodes, traversed %zu unique nodes",
             sr->cycle_detected ? "cycle detected" : "exhausted", sr->nodes_queried, ns->seen_nodes.n);
    sr->found = false;
    sr->target_node = NULL;
    sr->hops = (int)sr->path_n;
    sr->search_time = now_time() - ns->start_time;
    /* nodes_queried already tracked */
    protocol->learning_enabled = old_flag;
    nodelist_free(&all_candidates);
    nodelist_free(&current_closest);
    return sr;
}

static NodeSearch *NodeSearch_new(RRKDHTProtocol *protocol, const uint8_t target_node_id[20],
                                  double timeout, int alpha) {
    NodeSearch *ns = calloc(1, sizeof(NodeSearch));
    ns->protocol = protocol;
    memcpy(ns->target_node_id, target_node_id, 20);
    ns->target_node = Node_new(target_node_id);
    ns->timeout = timeout > 0 ? timeout : CFG_SEARCH_TIMEOUT;
    ns->alpha = alpha > 0 ? alpha : CFG_SEARCH_PARALLELISM;
    idset_init(&ns->queried_nodes);
    idset_init(&ns->seen_nodes);
    idset_add(&ns->seen_nodes, protocol->source_node->id);
    ns->res = SearchResult_new();
    ns->start_time = now_time();
    ns->_consecutive_no_progress = 0;
    return ns;
}

/* ============================================================================
 * CRAWLING CLASSES (RPCFindResponse, SpiderCrawl, NodeSpiderCrawl)
 * ============================================================================ */

/* RPCFindResponse wrapper */
typedef struct { RpcResult *response; } RPCFindResponse;

static bool RPCFindResponse_happened(RPCFindResponse *r) { return r->response->happened; }

/* get_node_list(): handle both 3-tuple and 4-tuple formats */
static NodeList RPCFindResponse_get_node_list(RPCFindResponse *r) {
    NodeList out; nodelist_init(&out);
    if (!r->response->data || r->response->data->t != M_ARR) return out;
    for (size_t i = 0; i < r->response->data->nitems; i++) {
        MVal *tup = r->response->data->items[i];
        if (!tup || tup->t != M_ARR) continue;
        if (tup->nitems >= 4) {
            const uint8_t *id; size_t idlen;
            if (!m_as_bytes(tup->items[0], &id, &idlen)) continue;
            uint8_t nid[20] = {0};
            memcpy(nid, id, idlen < 20 ? idlen : 20);
            const char *ip = (tup->items[1]->t == M_STR) ? tup->items[1]->str : NULL;
            int port = m_is_intlike(tup->items[2]) ? (int)m_as_int(tup->items[2]) : PORT_NONE;
            int rwp = m_is_intlike(tup->items[3]) ? (int)m_as_int(tup->items[3]) : PORT_NONE;
            nodelist_add(&out, Node_new_full(nid, ip, port, rwp, NULL));
        } else if (tup->nitems >= 3) {
            const uint8_t *id; size_t idlen;
            if (!m_as_bytes(tup->items[0], &id, &idlen)) continue;
            uint8_t nid[20] = {0};
            memcpy(nid, id, idlen < 20 ? idlen : 20);
            const char *ip = (tup->items[1]->t == M_STR) ? tup->items[1]->str : NULL;
            int port = m_is_intlike(tup->items[2]) ? (int)m_as_int(tup->items[2]) : PORT_NONE;
            nodelist_add(&out, Node_new_full(nid, ip, port, PORT_NONE, NULL));
        } else {
            log_warning("Invalid node tuple format (len=%zu)", tup->nitems);
        }
    }
    return out;
}

/* SpiderCrawl / NodeSpiderCrawl */
typedef struct {
    RRKDHTProtocol *protocol;
    int ksize;
    int alpha;
    Node *node;
    NodeHeap *nearest;
    uint8_t (*last_ids_crawled)[20];     /* ordered list, like Python get_ids() */
    size_t last_ids_crawled_n;
} SpiderCrawl;

static SpiderCrawl *SpiderCrawl_new(RRKDHTProtocol *protocol, Node *node, NodeList *peers,
                                    int ksize, int alpha) {
    SpiderCrawl *s = calloc(1, sizeof(SpiderCrawl));
    s->protocol = protocol;
    s->ksize = ksize;
    s->alpha = alpha;
    s->node = node;
    s->nearest = NodeHeap_new(node, ksize);
    s->last_ids_crawled = NULL;
    s->last_ids_crawled_n = 0;
    {
        /* log.info("Creating spider with peers: %s", peers) — Python list repr of Node reprs */
        StrBuf sb; sb_init(&sb);
        sb_add(&sb, "[");
        if (peers) {
            for (size_t i = 0; i < peers->n; i++) {
                char *r = Node_repr(peers->v[i]);
                sb_add(&sb, r);
                free(r);
                if (i + 1 < peers->n) sb_add(&sb, ", ");
            }
        }
        sb_add(&sb, "]");
        log_info("Creating spider with peers: %s", sb.buf);
        sb_free(&sb);
    }
    if (peers) NodeHeap_push(s->nearest, peers);
    return s;
}

typedef struct { SpiderCrawl *s; Node *peer; RpcResult *res; } CrawlTaskCtx;

static void *crawl_rpc_task(void *arg) {
    CrawlTaskCtx *ctx = arg;
    ctx->res = RRKDHTProtocol_call_find_node(ctx->s->protocol, ctx->peer, ctx->s->node);
    return NULL;
}

/* SpiderCrawl._find(rpcmethod) / NodeSpiderCrawl.find() */
static NodeList NodeSpiderCrawl_find(SpiderCrawl *s);

static NodeList SpiderCrawl__find(SpiderCrawl *s) {
    /* log current nearest */
    {
        Node *tmp[64];
        size_t n = NodeHeap_iter(s->nearest, tmp, 64);
        StrBuf sb; sb_init(&sb);
        sb_add(&sb, "(");
        for (size_t i = 0; i < n; i++) {
            char *r = Node_repr(tmp[i]);
            sb_add(&sb, r);
            free(r);
            if (i + 1 < n) sb_add(&sb, ", ");
        }
        sb_add(&sb, n == 1 ? ",)" : ")");
        log_info("Crawling network with nearest: %s", sb.buf);
        sb_free(&sb);
    }
    int count = s->alpha;
    /* Python: if self.nearest.get_ids() == self.last_ids_crawled: (ordered list equality) */
    size_t cur_n = NodeHeap_len(s->nearest);
    uint8_t (*cur_ids)[20] = malloc((cur_n ? cur_n : 1) * 20);
    NodeHeap_get_ids(s->nearest, cur_ids, cur_n);
    if (s->last_ids_crawled_n == cur_n) {
        bool same = true;
        for (size_t i = 0; i < cur_n && same; i++)
            if (memcmp(cur_ids[i], s->last_ids_crawled[i], 20) != 0) same = false;
        if (same) count = (int)NodeHeap_len(s->nearest);
    }
    free(s->last_ids_crawled);
    s->last_ids_crawled = cur_ids;
    s->last_ids_crawled_n = cur_n;

    NodeList uncontacted = NodeHeap_get_uncontacted(s->nearest);
    size_t nq = uncontacted.n < (size_t)count ? uncontacted.n : (size_t)count;
    CrawlTaskCtx *ctxs = calloc(nq ? nq : 1, sizeof(CrawlTaskCtx));
    GatherTask *tasks = calloc(nq ? nq : 1, sizeof(GatherTask));
    for (size_t i = 0; i < nq; i++) {
        ctxs[i].s = s;
        ctxs[i].peer = uncontacted.v[i];
        ctxs[i].res = NULL;
        tasks[i].fn = crawl_rpc_task;
        tasks[i].arg = &ctxs[i];
        NodeHeap_mark_contacted(s->nearest, uncontacted.v[i]);
    }
    parallel_gather(tasks, nq);                  /* gather_dict(dicts) */
    nodelist_free(&uncontacted);

    /* _nodes_found(responses) — NodeSpiderCrawl override has identical body */
    IdSet toremove; idset_init(&toremove);
    for (size_t i = 0; i < nq; i++) {
        if (!ctxs[i].res) { idset_add(&toremove, ctxs[i].peer->id); continue; }
        RPCFindResponse resp = { .response = ctxs[i].res };
        if (!RPCFindResponse_happened(&resp)) {
            idset_add(&toremove, ctxs[i].peer->id);
        } else {
            NodeList found = RPCFindResponse_get_node_list(&resp);
            NodeHeap_push(s->nearest, &found);
            nodelist_free(&found);
        }
    }
    NodeHeap_remove(s->nearest, &toremove);
    idset_free(&toremove);
    for (size_t i = 0; i < nq; i++) {
        if (ctxs[i].res) { m_free(ctxs[i].res->data); free(ctxs[i].res); }
    }
    free(ctxs);
    free(tasks);

    if (NodeHeap_have_contacted_all(s->nearest)) {
        NodeList out; nodelist_init(&out);
        Node *tmp[4096];
        size_t n = NodeHeap_iter(s->nearest, tmp, 4096);
        for (size_t i = 0; i < n; i++) nodelist_add(&out, tmp[i]);
        return out;
    }
    return NodeSpiderCrawl_find(s);              /* recursive find() */
}

static NodeList NodeSpiderCrawl_find(SpiderCrawl *s) {
    return SpiderCrawl__find(s);                 /* _find(self.protocol.call_find_node) */
}

/* ============================================================================
 * UTILITY FUNCTIONS (gather_dict, shared_prefix, bytes_to_bit_string)
 * ============================================================================ */

/* gather_dict(dic): gather a dict of coroutines into a dict of results.
 * (In this port the parallel execution is inlined at call sites; provided
 *  here as the literal equivalent for API completeness.) */
typedef struct { const uint8_t (*keys)[20]; CoroFn *fns; void **args; size_t n; } GatherDictSpec;

static void gather_dict(GatherDictSpec spec, void **results_out) {
    GatherTask *tasks = calloc(spec.n ? spec.n : 1, sizeof(GatherTask));
    for (size_t i = 0; i < spec.n; i++) {
        tasks[i].fn = spec.fns[i];
        tasks[i].arg = spec.args[i];
    }
    parallel_gather(tasks, spec.n);
    for (size_t i = 0; i < spec.n; i++) results_out[i] = tasks[i].result;
    free(tasks);
}

/* ============================================================================
 * MAIN RRKDHT CLASS
 * ============================================================================ */

/* __init__(ksize=2, alpha=3, node_id=None, signing_keys=None, rwp_port=None) */
static RRKDHT *RRKDHT_new(int ksize, int alpha, const uint8_t node_id[20],
                          EVP_PKEY *signing_private_key, EVP_PKEY *signing_public_key,
                          int rwp_port) {
    RRKDHT *s = calloc(1, sizeof(RRKDHT));
    if (ksize <= 0) ksize = 2;
    if (alpha <= 0) alpha = 3;
    s->ksize = ksize;
    s->alpha = alpha;

    /* generate or use provided signing keys */
    if (signing_private_key && signing_public_key) {
        s->signing_private_key = signing_private_key;
        s->signing_public_key = signing_public_key;
    } else {
        s->signing_private_key = create_ed25519_private_key();
        s->signing_public_key = s->signing_private_key;   /* same EVP_PKEY carries both */
    }

    /* generate node ID from public key if not provided */
    uint8_t nid[20];
    if (!node_id) {
        char *peer = generate_peer_id(s->signing_public_key);
        digest(peer, strlen(peer), nid);
        free(peer);
        node_id = nid;
    }
    s->node = Node_new(node_id);
    s->rwp_port = rwp_port;

    s->epoch_manager = EpochManager_new(CFG_EPOCH_DURATION, CFG_OVERLAP_DURATION);
    s->messaging = SecureMessaging_new(s->signing_private_key, s->signing_public_key);

    char *peer_id = hex_encode(s->node->id, 20);
    s->rwp_handler = RWPDHTHandler_new(peer_id, s->messaging, s->epoch_manager, NULL);
    free(peer_id);

    s->network_conditions.avg_ping_time = 15;
    s->network_conditions.success_rate = 1.0;
    s->network_conditions.congestion_factor = 1.0;
    s->ping_history_n = 0;
    s->max_ping_history = 20;
    pthread_mutex_init(&s->netcond_mu, NULL);

    s->heartbeat_sync_time = 0;
    idint_init(&s->failed_nodes);
    pthread_mutex_init(&s->failed_mu, NULL);
    s->HEARTBEAT_SYNC_INTERVAL = 60;
    s->MAX_FAILURES_BEFORE_REMOVAL = 3;

    respmap_init(&s->possible_responsibles);
    pthread_mutex_init(&s->resp_mu, NULL);
    idset_init(&s->verified_responsibles);
    s->last_responsible_check = 0;
    s->is_orphaned = false;
    s->rejoin_in_progress = false;
    s->responsible_check_loop = 0;
    s->_rejoin_attempts = 0;
    s->_identity_regeneration_count = 0;
    s->_original_identity = NULL;
    s->_pending_verification = false;
    s->_ever_had_contacts = false;

    s->protocol = NULL;
    s->refresh_loop = 0;
    s->save_state_loop = 0;
    s->heartbeat_loop = 0;
    s->running = false;
    s->rendezvous_storage_initialized = false;
    return s;
}

/* stop() */
static void RRKDHT_stop(RRKDHT *s) {
    s->running = false;
    if (s->protocol && s->protocol->transport_open) {       /* transport.close() */
        s->protocol->transport_open = false;
        if (s->protocol->sockfd >= 0) {
            shutdown(s->protocol->sockfd, SHUT_RDWR);
            close(s->protocol->sockfd);
            s->protocol->sockfd = -1;
        }
        pthread_join(s->protocol->recv_thread, NULL);
    }
    if (s->refresh_loop) { timer_cancel(s->refresh_loop); s->refresh_loop = 0; }
    if (s->save_state_loop) { timer_cancel(s->save_state_loop); s->save_state_loop = 0; }
    if (s->heartbeat_loop) { timer_cancel(s->heartbeat_loop); s->heartbeat_loop = 0; }
    if (s->responsible_check_loop) { timer_cancel(s->responsible_check_loop); s->responsible_check_loop = 0; }
    if (s->rwp_handler) RWPDHTHandler_stop_rwp_server(s->rwp_handler);
    if (s->key_rotation_thread) { pthread_join(s->key_rotation_thread, NULL); s->key_rotation_thread = 0; }
    s->_rejoin_attempts = 0;
    s->_identity_regeneration_count = 0;
    s->_pending_verification = false;
}

/* _create_protocol() */
static RRKDHTProtocol *RRKDHT_create_protocol(RRKDHT *s) {
    RRKDHTProtocol *protocol = RRKDHTProtocol_new(s->node, s->ksize,
                                                  s->epoch_manager, s->rwp_handler);
    s->rwp_handler->router = protocol->router;
    protocol->server_ref = s;
    return protocol;
}

/* forward decls for scheduled callbacks */
static void RRKDHT_schedule_rendezvous_republish(RRKDHT *s);
static void RRKDHT_start_key_rotation_monitor(RRKDHT *s);
static const char *RRKDHT_get_rendezvous_key(RRKDHT *s);
static void RRKDHT_refresh_table(RRKDHT *s, int interval);
static void RRKDHT_start_heartbeat(RRKDHT *s);
static void RRKDHT_schedule_responsible_check(RRKDHT *s);

/* listen(port, interface="0.0.0.0", rwp_port=None) */
static bool RRKDHT_listen(RRKDHT *s, int port, const char *interface, int rwp_port_arg) {
    s->running = true;
    if (!interface) interface = "0.0.0.0";

    if (rwp_port_arg != PORT_NONE)
        s->rwp_port = rwp_port_arg;
    else if (s->rwp_port == PORT_NONE)
        s->rwp_port = port + 1000;

    s->node->port = port;
    s->node->rwp_port = s->rwp_port;
    s->rwp_handler->dht_port = port;    /* so the RWP server can report it */
    free(s->node->ip);
    s->node->ip = xstrdup(strcmp(interface, "0.0.0.0") ? interface : "127.0.0.1");

    /* start RWP server */
    RWPDHTHandler_start_rwp_server(s->rwp_handler, s->rwp_port);

    /* start Kademlia UDP server */
    RRKDHTProtocol *protocol = RRKDHT_create_protocol(s);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { log_error("listen: socket failed"); s->running = false; return false; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (resolve_ipv4(interface, &sa.sin_addr) != 0) sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_error("listen: bind %s:%d failed: %s", interface, port, strerror(errno));
        close(fd);
        s->running = false;
        return false;
    }
    {
        char *dec = u256_to_dec(s->node->long_id);
        log_info("Node %s listening on %s:%d (RWP: %d)", dec, interface, port, s->rwp_port);
        free(dec);
    }
    protocol->sockfd = fd;
    protocol->transport_open = true;
    pthread_create(&protocol->recv_thread, NULL, rpc_recv_thread_main, protocol);
    s->protocol = protocol;

    storage_init(&s->_rendezvous_storage);
    s->rendezvous_storage_initialized = true;
    if (!g_no_self_publish) {
        RRKDHT_schedule_rendezvous_republish(s);
    } else {
        log_info("--no-publish set: this node will not publish its own rendezvous key");
    }

    RRKDHT_start_key_rotation_monitor(s);
    RRKDHT_refresh_table(s, 3600);
    RRKDHT_start_heartbeat(s);
    RRKDHT_schedule_responsible_check(s);
    return true;
}

/* _update_network_conditions(ping_time, success) */
static void RRKDHT_update_network_conditions(RRKDHT *s, double ping_time, bool success) {
    pthread_mutex_lock(&s->netcond_mu);
    if (success) {
        if (s->ping_history_n == s->max_ping_history) {
            memmove(s->ping_history, s->ping_history + 1,
                    (s->max_ping_history - 1) * sizeof(double));
            s->ping_history_n--;
        }
        s->ping_history[s->ping_history_n++] = ping_time;
    }
    if (s->ping_history_n) {
        double sum = 0;
        for (size_t i = 0; i < s->ping_history_n; i++) sum += s->ping_history[i];
        s->network_conditions.avg_ping_time = sum / (double)s->ping_history_n;
    }
    /* success rate over last 10 entries (ping < 2.0s counts as success) */
    if (s->ping_history_n) {
        size_t start = s->ping_history_n > 10 ? s->ping_history_n - 10 : 0;
        int recent_successes = 0;
        for (size_t i = start; i < s->ping_history_n; i++)
            if (s->ping_history[i] < 2.0) recent_successes++;
        size_t denom = s->ping_history_n < 10 ? s->ping_history_n : 10;
        s->network_conditions.success_rate = denom ? (double)recent_successes / (double)denom : 0;
    }
    /* (Python would ZeroDivisionError when history is empty on a failure path;
     * the exception is swallowed by callers and counted as a failed ping —
     * guarding here yields identical observable behavior.) */
    if (s->network_conditions.avg_ping_time > 1.0) {
        s->network_conditions.congestion_factor =
            fmin(2.0, s->network_conditions.congestion_factor * 1.1);
    } else {
        s->network_conditions.congestion_factor =
            fmax(0.5, s->network_conditions.congestion_factor * 0.95);
    }
    log_debug("Network conditions: avg_ping=%.2fs, success_rate=%.2f, congestion_factor=%.2f",
              s->network_conditions.avg_ping_time, s->network_conditions.success_rate,
              s->network_conditions.congestion_factor);
    pthread_mutex_unlock(&s->netcond_mu);
}

/* _get_adaptive_delay(base_delay=0.2) */
static double RRKDHT_get_adaptive_delay(RRKDHT *s, double base_delay) {
    pthread_mutex_lock(&s->netcond_mu);
    double congestion_factor = s->network_conditions.congestion_factor;
    pthread_mutex_unlock(&s->netcond_mu);
    double adaptive_delay = base_delay * congestion_factor;
    double jitter = py_uniform(0.8, 1.2);       /* ±20% jitter */
    return adaptive_delay * jitter;
}

/* _cleanup_outstanding_futures() */
static void RRKDHT_cleanup_outstanding_futures(RRKDHT *s) {
    if (!s->protocol) return;
    RRKDHTProtocol *p = s->protocol;
    pthread_mutex_lock(&p->out_mu);
    for (size_t i = 0; i < p->n_out;) {
        Future *f = p->outstanding[i].fut;
        if (future_done(f) || future_cancelled(f)) {
            timer_cancel(p->outstanding[i].timer_id);
            rpc_outstanding_remove_locked(p, i);
        } else {
            /* cancel pending futures during cleanup */
            timer_cancel(p->outstanding[i].timer_id);
            RpcResult *res = calloc(1, sizeof(RpcResult));
            res->happened = false;
            res->data = NULL;
            future_set_result(f, res);
            rpc_outstanding_remove_locked(p, i);
        }
    }
    pthread_mutex_unlock(&p->out_mu);
}

/* _safe_heartbeat_ping(node) -> RpcResult (never NULL; (False,None) on error) */
static RpcResult *RRKDHT_safe_heartbeat_ping(RRKDHT *s, Node *node) {
    double ping_start_time = now_time();
    pthread_mutex_lock(&s->netcond_mu);
    double avg_ping_time = s->network_conditions.avg_ping_time;
    pthread_mutex_unlock(&s->netcond_mu);
    double adaptive_timeout = fmax(3.0, avg_ping_time * 3);

    MVal *args = m_arr();
    m_arr_add(args, m_bin(s->node->id, 20));
    m_arr_add(args, s->node->rwp_port == PORT_NONE ? m_nil() : m_int(s->node->rwp_port));
    sign_ping_args(s->messaging->signing_private_key, s->node->id, s->epoch_manager, args);
    RpcResult *result = rpc_call(s->protocol, node->ip, node->port, "ping", args, adaptive_timeout);
    if (!result) {
        /* rpc_call CAN return NULL since the SAFE_CALLOC hardening; the
         * docstring's "never NULL" no longer holds. Fail soft like a timeout. */
        RRKDHT_update_network_conditions(s, now_time() - ping_start_time, false);
        result = SAFE_CALLOC(RpcResult, 1);   /* restore the never-NULL contract */
        if (!result) return NULL;             /* truly OOM: give up */
        result->happened = false;
        return result;
    }
    double ping_duration = now_time() - ping_start_time;
    if (result->status != RPC_STATUS_TIMEOUT) {
        /* future resolved within the adaptive timeout — Python counts this as
         * success even when the RPC result is (False, None) */
        RRKDHT_update_network_conditions(s, ping_duration, true);
    } else {
        /* asyncio.TimeoutError */
        RRKDHT_update_network_conditions(s, ping_duration, false);
        log_debug("Adaptive heartbeat ping timed out to %s:%d after %.2fs",
                  node->ip, node->port, ping_duration);
        result->happened = false;
        m_free(result->data); result->data = NULL;
    }
    /* Pong learner — same trust rules as call_ping. This is what makes
     * PORT_NONE a self-healing transient: every heartbeat teaches ports. */
    if (result->happened && result->data && result->data->t == M_BIN
        && result->data->blen >= 22 && node->rwp_port == PORT_NONE) {
        uint16_t rp = ((uint16_t)result->data->bin[20] << 8)
                      | (uint16_t)result->data->bin[21];
        if (rp >= 1024 && rp <= 65535) {
            node->rwp_port = rp;
            log_debug("Learned RWP port %u for %s:%d from pong (heartbeat)",
                      (unsigned)rp, node->ip, node->port);
        } else {
            log_debug("Pong port field invalid (%u) for %s:%d - untrusted, peer still alive",
                      (unsigned)rp, node->ip, node->port);
        }
    }
    RRKDHT_cleanup_outstanding_futures(s);      /* finally: block */
    return result;
}

/* _handle_ping_failure(node) */
static void RRKDHT_handle_ping_failure(RRKDHT *s, Node *node) {
    pthread_mutex_lock(&s->failed_mu);
    int current_failures = idint_get(&s->failed_nodes, node->id, 0) + 1;
    idint_set(&s->failed_nodes, node->id, current_failures);
    pthread_mutex_unlock(&s->failed_mu);
    log_debug("Node %s:%d failed heartbeat (%d/%d)",
              node->ip, node->port, current_failures, s->MAX_FAILURES_BEFORE_REMOVAL);
    node->failed_pings = current_failures;
    if (current_failures == 1)
        log_warning("First heartbeat failure for %s:%d", node->ip, node->port);
    else if (current_failures >= s->MAX_FAILURES_BEFORE_REMOVAL)
        log_error("Node %s:%d has failed %d heartbeats - will be removed",
                  node->ip, node->port, current_failures);
}

/* _remove_failed_nodes() */
static int RRKDHT_remove_failed_nodes(RRKDHT *s) {
    NodeList to_remove; nodelist_init(&to_remove);
    int *counts = NULL; size_t ncounts = 0;

    /* Snapshot the ids/counts that have crossed the failure threshold while
     * holding only failed_mu, then release it *before* touching the routing
     * table lock. This avoids ever holding failed_mu and the routing-table
     * lock at the same time, so no lock-ordering deadlock is possible
     * regardless of what order other code paths take those two locks in. */
    uint8_t (*candidate_ids)[20] = NULL;
    int *candidate_counts = NULL;
    size_t ncand = 0;
    pthread_mutex_lock(&s->failed_mu);
    for (size_t i = 0; i < s->failed_nodes.n; i++) {
        if (s->failed_nodes.vals[i] >= s->MAX_FAILURES_BEFORE_REMOVAL) {
            candidate_ids = realloc(candidate_ids, (ncand + 1) * sizeof(*candidate_ids));
            candidate_counts = realloc(candidate_counts, (ncand + 1) * sizeof(int));
            memcpy(candidate_ids[ncand], s->failed_nodes.keys[i], 20);
            candidate_counts[ncand] = s->failed_nodes.vals[i];
            ncand++;
        }
    }
    pthread_mutex_unlock(&s->failed_mu);

    RoutingTable *t = s->protocol->router;
    RoutingTable_lock(t);
    for (size_t i = 0; i < ncand; i++) {
        for (size_t b = 0; b < t->nbuckets; b++) {
            Node *node = KBucket_get(t->buckets[b], candidate_ids[i]);
            if (node) {
                nodelist_add(&to_remove, node);
                counts = realloc(counts, (ncounts + 1) * sizeof(int));
                counts[ncounts++] = candidate_counts[i];
                break;
            }
        }
    }
    RoutingTable_unlock(t);
    free(candidate_ids);
    free(candidate_counts);

    int removed_count = 0;
    for (size_t i = 0; i < to_remove.n; i++) {
        Node *node = to_remove.v[i];
        log_warning("Removing failed node after %d heartbeat failures: %s:%d",
                    counts[i], node->ip, node->port);
        RoutingTable_remove_contact(s->protocol->router, node);
        pthread_mutex_lock(&s->failed_mu);
        idint_pop(&s->failed_nodes, node->id);
        pthread_mutex_unlock(&s->failed_mu);
        removed_count++;
    }
    free(counts);
    nodelist_free(&to_remove);
    if (removed_count > 0) {
        log_info("Removed %d failed nodes from routing table", removed_count);
        RoutingTable *t = s->protocol->router;
        RoutingTable_lock(t);
        int total = 0;
        for (size_t b = 0; b < t->nbuckets; b++) total += (int)KBucket_len(t->buckets[b]);
        RoutingTable_unlock(t);
        log_info("Routing table now has %d nodes", total);
    }
    return removed_count;
}

/* _synchronized_heartbeat_check() — SECOND definition (lines 3425-3480).
 * In Python this re-definition shadows the first one (lines 2403-2461);
 * this is the live version. */
static void *RRKDHT_synchronized_heartbeat_check(void *arg) {
    RRKDHT *s = arg;
    if (!s->running || !s->protocol) return NULL;

    NodeList all_nodes; nodelist_init(&all_nodes);
    RoutingTable *t = s->protocol->router;
    RoutingTable_lock(t);
    for (size_t i = 0; i < t->nbuckets; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++) nodelist_add(&all_nodes, nl.v[j]);
        nodelist_free(&nl);
    }
    RoutingTable_unlock(t);

    if (!all_nodes.n) {
        log_debug("No nodes in routing table for heartbeat check");
        nodelist_free(&all_nodes);
        return NULL;
    }
    log_debug("Adaptive sequential heartbeat check for %zu nodes", all_nodes.n);

    /* adaptive stagger based on network conditions */
    char *hex = hex_encode(s->node->id, 20);
    unsigned node_hash = 0;
    sscanf(hex, "%8x", &node_hash);                     /* int(id.hex()[:8], 16) */
    free(hex);
    double base_stagger = (double)(node_hash % 2000) / 1000.0;
    pthread_mutex_lock(&s->netcond_mu);
    double adaptive_stagger = base_stagger * s->network_conditions.congestion_factor;
    pthread_mutex_unlock(&s->netcond_mu);
    if (adaptive_stagger > 0) {
        log_debug("Adaptive staggering heartbeat by %.3fs", adaptive_stagger);
        py_sleep(adaptive_stagger);
    }

    int successful_pings = 0;
    for (size_t i = 0; i < all_nodes.n; i++) {
        Node *node = all_nodes.v[i];
        RpcResult *result = RRKDHT_safe_heartbeat_ping(s, node);
        bool ok = result && result->happened;
        if (ok) {
            successful_pings += 1;
            Node_touch(node);
            pthread_mutex_lock(&s->failed_mu);
            idint_pop(&s->failed_nodes, node->id);
            pthread_mutex_unlock(&s->failed_mu);
            log_debug("Heartbeat ping successful to %s:%d", node->ip, node->port);
        } else {
            RRKDHT_handle_ping_failure(s, node);
            log_debug("Heartbeat ping failed to %s:%d", node->ip, node->port);
        }
        if (result) { m_free(result->data); free(result); }
        double delay = RRKDHT_get_adaptive_delay(s, ok ? 0.2 : 0.5);
        py_sleep(delay);
    }
    pthread_mutex_lock(&s->netcond_mu);
    double final_avg_ping = s->network_conditions.avg_ping_time;
    pthread_mutex_unlock(&s->netcond_mu);
    log_info("Adaptive heartbeat completed: %d/%zu nodes responded (avg_ping: %.2fs)",
             successful_pings, all_nodes.n, final_avg_ping);
    RRKDHT_remove_failed_nodes(s);
    nodelist_free(&all_nodes);
    return NULL;
}

/* _synchronized_heartbeat_check() — FIRST definition (lines 2403-2461).
 * Shadowed by the second definition in Python (dead code), kept for fidelity. */
static void *RRKDHT_synchronized_heartbeat_check_v1_shadowed(void *arg) {
    RRKDHT *s = arg;
    if (!s->running || !s->protocol) return NULL;
    NodeList all_nodes; nodelist_init(&all_nodes);
    RoutingTable *t = s->protocol->router;
    RoutingTable_lock(t);
    for (size_t i = 0; i < t->nbuckets; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++) nodelist_add(&all_nodes, nl.v[j]);
        nodelist_free(&nl);
    }
    RoutingTable_unlock(t);
    if (!all_nodes.n) {
        log_debug("No nodes in routing table for heartbeat check");
        nodelist_free(&all_nodes);
        return NULL;
    }
    log_debug("Sequential heartbeat check for %zu nodes", all_nodes.n);
    char *hex = hex_encode(s->node->id, 20);
    unsigned node_hash = 0;
    sscanf(hex, "%8x", &node_hash);
    free(hex);
    double stagger_delay = (double)(node_hash % 2000) / 1000.0;
    if (stagger_delay > 0) {
        log_debug("Staggering heartbeat by %.3fs", stagger_delay);
        py_sleep(stagger_delay);
    }
    int successful_pings = 0;
    for (size_t i = 0; i < all_nodes.n; i++) {
        Node *node = all_nodes.v[i];
        double ping_start = now_time();
        RpcResult *result = RRKDHT_safe_heartbeat_ping(s, node);
        double ping_duration = now_time() - ping_start;
        bool ok = result && result->happened;
        if (ok) {
            successful_pings += 1;
            Node_touch(node);
            pthread_mutex_lock(&s->failed_mu);
            idint_pop(&s->failed_nodes, node->id);
            pthread_mutex_unlock(&s->failed_mu);
            log_debug("Heartbeat ping successful to %s:%d in %.2fs", node->ip, node->port, ping_duration);
        } else {
            RRKDHT_handle_ping_failure(s, node);
            log_debug("Heartbeat ping failed to %s:%d after %.2fs", node->ip, node->port, ping_duration);
        }
        if (result) { m_free(result->data); free(result); }
        py_sleep(ok ? 0.2 : 0.5);
    }
    log_info("Heartbeat completed: %d/%zu nodes responded", successful_pings, all_nodes.n);
    RRKDHT_remove_failed_nodes(s);
    nodelist_free(&all_nodes);
    return NULL;
}

/* _schedule_sync_heartbeat() (timer callback) */
static void schedule_sync_heartbeat_cb(void *arg) {
    RRKDHT *s = arg;
    if (!s->running) return;
    log_debug("Synchronized heartbeat check starting");
    ensure_future(RRKDHT_synchronized_heartbeat_check, s);
    s->heartbeat_loop = call_later(s->HEARTBEAT_SYNC_INTERVAL, schedule_sync_heartbeat_cb, s);
}

/* start_heartbeat() */
static void RRKDHT_start_heartbeat(RRKDHT *s) {
    if (!s->running) return;
    double current_time = now_time();
    s->heartbeat_sync_time = ceil(current_time / s->HEARTBEAT_SYNC_INTERVAL) * s->HEARTBEAT_SYNC_INTERVAL;
    double delay_to_sync = s->heartbeat_sync_time - current_time;
    log_info("Starting sequential heartbeat system, next sync in %.1fs", delay_to_sync);
    s->heartbeat_loop = call_later(delay_to_sync, schedule_sync_heartbeat_cb, s);
}

/* _attempt_rejoin() — forward; defined later */
static void *RRKDHT_attempt_rejoin(void *arg);

/* _check_responsible_nodes() */
static void *RRKDHT_check_responsible_nodes(void *arg) {
    RRKDHT *s = arg;
    if (!s->running || !s->protocol) return NULL;
    log_debug("Starting responsible node verification");

    /* clean up old entries (stale_threshold = 600s) */
    double current_time = now_time();
    double stale_threshold = 600;
    pthread_mutex_lock(&s->resp_mu);
    for (size_t i = 0; i < s->possible_responsibles.n;) {
        if (current_time - s->possible_responsibles.vals[i].last_contact > stale_threshold) {
            log_debug("Removing stale possible responsible: %s",
                      s->possible_responsibles.vals[i].node->ip);
            uint8_t key[20];
            memcpy(key, s->possible_responsibles.keys[i], 20);
            pthread_mutex_unlock(&s->resp_mu);
            pthread_mutex_lock(&s->resp_mu);
            respmap_del(&s->possible_responsibles, key);
        } else i++;
    }
    bool any_possible = s->possible_responsibles.n > 0;
    pthread_mutex_unlock(&s->resp_mu);

    if (!any_possible) {
        log_info("No nodes have contacted us recently");
        if (!s->_ever_had_contacts) {
            /* check if routing table is empty */
            bool routing_table_empty = true;
            if (s->protocol && s->protocol->router) {
                RoutingTable *t = s->protocol->router;
                RoutingTable_lock(t);
                for (size_t i = 0; i < t->nbuckets; i++)
                    if (KBucket_len(t->buckets[i])) { routing_table_empty = false; break; }
                RoutingTable_unlock(t);
            }
            if (routing_table_empty) {
                log_info("First node in network - no orphan status");
                s->is_orphaned = false;
                idset_clear(&s->verified_responsibles);
                return NULL;
            }
            log_warning("Never received contacts but have neighbors - checking network");
            if (!s->rejoin_in_progress) {
                s->is_orphaned = true;
                ensure_future(RRKDHT_attempt_rejoin, s);
            }
            return NULL;
        }
        log_warning("Lost all contacts - potentially orphaned");
        if (!s->rejoin_in_progress) {
            s->is_orphaned = true;
            ensure_future(RRKDHT_attempt_rejoin, s);
        }
        return NULL;
    }

    /* mark that we've had contacts */
    pthread_mutex_lock(&s->resp_mu);
    if (s->possible_responsibles.n) s->_ever_had_contacts = true;
    size_t npossible = s->possible_responsibles.n;
    uint8_t (*keys)[20] = malloc((npossible ? npossible : 1) * 20);
    memcpy(keys, s->possible_responsibles.keys, npossible * 20);
    pthread_mutex_unlock(&s->resp_mu);
    log_debug("Verifying %zu possible responsible nodes", npossible);

    IdSet new_verified; idset_init(&new_verified);
    int successful_checks = 0, failed_checks = 0;
    for (size_t i = 0; i < npossible; i++) {
        pthread_mutex_lock(&s->resp_mu);
        ResponsibleInfo *info = respmap_get(&s->possible_responsibles, keys[i]);
        Node *node = info ? info->node : NULL;
        pthread_mutex_unlock(&s->resp_mu);
        if (!node) continue;

        bool happened = false, knows = false;
        RRKDHTProtocol_call_verify_neighbor(s->protocol, node, s->node->id, &happened, &knows);
        if (happened && knows) {
            idset_add(&new_verified, keys[i]);
            pthread_mutex_lock(&s->resp_mu);
            ResponsibleInfo *inf2 = respmap_get(&s->possible_responsibles, keys[i]);
            if (inf2) { inf2->verified = true; inf2->fail_count = 0; }
            pthread_mutex_unlock(&s->resp_mu);
            Node_confirm_as_neighbor(node);
            log_debug("[VERIFIED] %s:%d is responsible for us", node->ip, node->port);
            successful_checks += 1;
        } else if (happened && !knows) {
            log_debug("[REJECTED] %s:%d doesn't have us in routing table", node->ip, node->port);
            pthread_mutex_lock(&s->resp_mu);
            respmap_del(&s->possible_responsibles, keys[i]);
            pthread_mutex_unlock(&s->resp_mu);
            successful_checks += 1;
        } else {
            if (node->rwp_port == PORT_NONE) {
                log_debug("Skip (no info, port unknown): %s:%d", node->ip, node->port);
                /* not counted, not evicted */
            } else {
            log_debug("No response from %s:%d", node->ip, node->port);
            failed_checks += 1;
            /* 3-strike removal — same philosophy as the heartbeat's
             * MAX_FAILURES_BEFORE_REMOVAL. Gives temporarily-down nodes
             * a couple of retries. Dead nodes are re-added automatically
             * when they contact us again (track_possible_responsible). */
            pthread_mutex_lock(&s->resp_mu);
            ResponsibleInfo *inf = respmap_get(&s->possible_responsibles, keys[i]);
            if (inf) {
                inf->fail_count++;
                if (inf->fail_count >= 3) {
                    uint8_t delkey[20];
                    memcpy(delkey, keys[i], 20);
                    respmap_del(&s->possible_responsibles, delkey);
                    log_debug("Removed dead candidate %s:%d after 3 consecutive failures",
                              node->ip, node->port);
                }
            }
            pthread_mutex_unlock(&s->resp_mu);
            }
        }
        py_sleep(0.15);
    }
    free(keys);

    /* update verified responsibles */
    size_t old_count = s->verified_responsibles.n;
    idset_free(&s->verified_responsibles);
    s->verified_responsibles = new_verified;
    size_t new_count = s->verified_responsibles.n;
    pthread_mutex_lock(&s->resp_mu);
    size_t possible_count = s->possible_responsibles.n;
    pthread_mutex_unlock(&s->resp_mu);
    log_info("Verification: %zu verified from %zu candidates (was %zu, %d responses, %d failed)",
             new_count, possible_count, old_count, successful_checks, failed_checks);

    /* determine orphan status */
    if ((int)new_count < CFG_MIN_RESPONSIBLE_NODES) {
        if (successful_checks > 0) {
            log_warning("ORPHANED: Only %zu verified nodes (need %d)",
                        new_count, CFG_MIN_RESPONSIBLE_NODES);
            if (!s->rejoin_in_progress) {
                s->is_orphaned = true;
                ensure_future(RRKDHT_attempt_rejoin, s);
            }
        } else {
            log_warning("Network unreachable (%d failures) - not marking orphaned yet", failed_checks);
        }
    } else {
        if (s->is_orphaned)
            log_info("[OK] Connectivity restored: %zu verified nodes", new_count);
        s->is_orphaned = false;
        s->rejoin_in_progress = false;
        s->_rejoin_attempts = 0;
    }
    s->last_responsible_check = now_time();
    return NULL;
}

/* _schedule_responsible_check() (self-rescheduling timer callback) */
static void responsible_check_cb(void *arg) {
    RRKDHT *s = arg;
    if (!s->running) return;
    log_debug("Scheduling responsible node check");
    ensure_future(RRKDHT_check_responsible_nodes, s);
    s->responsible_check_loop = call_later(CFG_RESPONSIBLE_CHECK_INTERVAL, responsible_check_cb, s);
}

static void RRKDHT_schedule_responsible_check(RRKDHT *s) {
    if (!s->running) return;
    responsible_check_cb(s);
}

/* --- rendezvous-key storage / lookup --- */

/* _store_local_rendezvous(key_hash, value) */
static bool RRKDHT_store_local_rendezvous(RRKDHT *s, const uint8_t key_hash[20], JVal *value) {
    if (!s->rendezvous_storage_initialized) {
        storage_init(&s->_rendezvous_storage);
        s->rendezvous_storage_initialized = true;
    }
    storage_set(&s->_rendezvous_storage, key_hash, j_deepcopy(value));
    char *kh = hex_encode(key_hash, 20);
    log_info("[OK] Stored rendezvous key '%s' locally (key_hash: %.16s...)",
             j_get_str(value, "rendezvous_key"), kh);
    free(kh);
    const char *nid = j_get_str(value, "node_id");
    log_debug("  Node ID: %.16s...", nid ? nid : "?");
    int64_t stamp = (int64_t)j_get_num(value, "epoch", 0);
    log_debug("  Epoch stamp: %lld (accepted in %lld-%lld, dead at %lld)",
            (long long)stamp, (long long)stamp,
            (long long)(stamp + 1), (long long)(stamp + 2));
    log_debug("  Total local storage entries: %zu", s->_rendezvous_storage.n);
    return true;
}

/* _store_rendezvous_on_node(node, key_hash, value) — max_retries=2, retry_delay=0.5 */
static bool RRKDHT_store_rendezvous_on_node(RRKDHT *s, Node *node,
                                            const uint8_t key_hash[20], JVal *value) {
    const int max_retries = 2;
    const double retry_delay = 0.5;
    /* check if this is us - compare by Node ID */
    if (!memcmp(node->id, s->protocol->source_node->id, 20)) {
        log_debug("Storing locally (we are the target node)");
        return RRKDHT_store_local_rendezvous(s, key_hash, value);
    }
    /* try RWP for remote nodes with retries */
    if (node->rwp_port <= 0) {
        log_debug("Node %s:%d has no RWP port", node->ip, node->port);
        return false;
    }
    for (int attempt = 0; attempt < max_retries; attempt++) {
        NodeInfo *ni = RWPDHTHandler_get_node_info(s->rwp_handler, node->ip, node->rwp_port);
        if (!ni) {
            if (attempt < max_retries - 1) {
                log_debug("Could not get node info for %s:%d, retrying...", node->ip, node->rwp_port);
                py_sleep(retry_delay);
                continue;
            }
            log_warning("Could not get node info for %s:%d after %d attempts",
                        node->ip, node->rwp_port, max_retries);
            return false;
        }
        char *keyhex = hex_encode(key_hash, 20);
        char *value_str = j_dumps(value);
        JVal *payload = j_obj();
        j_obj_set(payload, "key", j_str(keyhex));
        j_obj_set(payload, "value", j_str(value_str));
        double stored_at = j_get_num(value, "stored_at", now_time());
        double expires_at = j_get_num(value, "expires_at", stored_at + CFG_DEFAULT_TTL);
        j_obj_set(payload, "ttl", j_int((int64_t)(expires_at - stored_at)));
        JVal *response = RWPDHTHandler_send_encrypted_message(s->rwp_handler, ni, MT_DHT_SET, payload);
        j_free(payload);
        free(keyhex);
        free(value_str);
        if (response) {
            /* check response format */
            bool success = false;
            JVal *pl = j_obj_get(response, "payload");
            if (pl) success = j_get_bool(pl, "success", false);
            j_free(response);
            if (success) {
                log_info("[OK] Successfully stored on remote node %s:%d", node->ip, node->port);
                return true;
            }
            if (attempt < max_retries - 1) {
                log_debug("Store failed on %s:%d, retrying...", node->ip, node->port);
                py_sleep(retry_delay);
                continue;
            }
            log_warning("Failed to store on remote node %s:%d after %d attempts",
                        node->ip, node->port, max_retries);
            return false;
        }
        if (attempt < max_retries - 1) {
            log_debug("No response from %s:%d, retrying...", node->ip, node->port);
            py_sleep(retry_delay);
            continue;
        }
        log_warning("No response from %s:%d after %d attempts", node->ip, node->port, max_retries);
        return false;
    }
    return false;
}

/* _query_node_for_closest(node, key_hash) -> NodeList */
typedef struct { RRKDHT *s; Node *node; uint8_t key_hash[20]; NodeList result; } ClosestTaskCtx;

static void *RRKDHT_query_node_for_closest(void *arg) {
    ClosestTaskCtx *ctx = arg;
    nodelist_init(&ctx->result);
    Node *key_node = Node_new(ctx->key_hash);
    RpcResult *result = RRKDHTProtocol_call_find_node(ctx->s->protocol, ctx->node, key_node);
    free(key_node);
    if (result->happened && result->data && result->data->t == M_ARR) {
        RPCFindResponse resp = { .response = result };
        ctx->result = RPCFindResponse_get_node_list(&resp);
        /* PATCHED: apply any fresher rwp_port each reported node just gave
         * us (see RRKDHTProtocol_refresh_known_node_rwp_port for why this
         * matters -- on a small network the response often self-describes
         * the very peer we're trying to reach). ctx->result keeps normal
         * ownership of these nodes; this only reads them and, if we
         * already know the peer, patches a stale field on our own
         * separate routing-table copy. */
        for (size_t ci = 0; ci < ctx->result.n; ci++) {
            RRKDHTProtocol_refresh_known_node_rwp_port(ctx->s->protocol, ctx->result.v[ci]);
        }
    }
    m_free(result->data);
    free(result);
    return NULL;
}

/* _find_closest_nodes_to_key(key_hash, k) -> NodeList
 * Exact port: candidates include ourselves; empty/error -> [source_node]. */
static NodeList RRKDHT_find_closest_nodes_to_key(RRKDHT *s, const uint8_t key_hash[20], int k) {
    NodeList result; nodelist_init(&result);
    Node *target = Node_new(key_hash);
    char *kh = hex_encode(key_hash, 20);
    log_debug("Starting iterative search for %d nodes closest to key %.16s...", k, kh);
    free(kh);

    NodeList current_closest = RoutingTable_find_neighbors(s->protocol->router, target, s->alpha, NULL);
    if (!current_closest.n) {
        log_info("No neighbors found, we are the only node for this key");
        nodelist_add(&result, s->protocol->source_node);
        nodelist_free(&current_closest);
        free(target);
        return result;
    }
    /* track all candidates, including ourselves */
    NodeList all_candidates; nodelist_init(&all_candidates);
    for (size_t i = 0; i < current_closest.n; i++) nodelist_add(&all_candidates, current_closest.v[i]);
    nodelist_add(&all_candidates, s->protocol->source_node);

    /* best distance so far (min over the initial closest list) */
    u256 best_distance = Node_distance_to(target, current_closest.v[0]);
    for (size_t i = 1; i < current_closest.n; i++) {
        u256 d = Node_distance_to(target, current_closest.v[i]);
        if (u256_lt(d, best_distance)) best_distance = d;
    }

    IdSet queried_nodes; idset_init(&queried_nodes);
    int no_improvement_count = 0;
    bool improved = true;

    while (improved) {
        improved = false;
        /* get unqueried nodes from current closest */
        NodeList unqueried; nodelist_init(&unqueried);
        for (size_t i = 0; i < current_closest.n; i++)
            if (!idset_contains(&queried_nodes, current_closest.v[i]->id))
                nodelist_add(&unqueried, current_closest.v[i]);
        if (!unqueried.n) {
            log_debug("No more unqueried nodes, search complete");
            nodelist_free(&unqueried);
            break;
        }
        NodeList nodes_to_query; nodelist_init(&nodes_to_query);
        for (size_t i = 0; i < unqueried.n && (int)i < s->alpha; i++)
            nodelist_add(&nodes_to_query, unqueried.v[i]);
        nodelist_free(&unqueried);

        /* query nodes in parallel (asyncio.gather, return_exceptions=True) */
        ClosestTaskCtx *ctxs = calloc(nodes_to_query.n, sizeof(ClosestTaskCtx));
        GatherTask *tasks = calloc(nodes_to_query.n, sizeof(GatherTask));
        for (size_t i = 0; i < nodes_to_query.n; i++) {
            ctxs[i].s = s;
            ctxs[i].node = nodes_to_query.v[i];
            memcpy(ctxs[i].key_hash, key_hash, 20);
            tasks[i].fn = RRKDHT_query_node_for_closest;
            tasks[i].arg = &ctxs[i];
        }
        parallel_gather(tasks, nodes_to_query.n);
        for (size_t i = 0; i < nodes_to_query.n; i++)
            idset_add(&queried_nodes, nodes_to_query.v[i]->id);

        /* flatten results into new_neighbors */
        NodeList new_neighbors; nodelist_init(&new_neighbors);
        for (size_t i = 0; i < nodes_to_query.n; i++) {
            for (size_t j = 0; j < ctxs[i].result.n; j++)
                nodelist_add(&new_neighbors, ctxs[i].result.v[j]);
            nodelist_free(&ctxs[i].result);
        }
        free(ctxs); free(tasks);

        if (new_neighbors.n) {
            for (size_t i = 0; i < new_neighbors.n; i++) nodelist_add(&all_candidates, new_neighbors.v[i]);
            /* merge and deduplicate (excluding queried), keep alpha*2 closest */
            typedef struct { uint8_t id[20]; Node *node; } KN;
            KN *uniq = NULL; size_t nu = 0, capu = 0;
            for (int pass = 0; pass < 2; pass++) {
                NodeList *src = pass == 0 ? &current_closest : &new_neighbors;
                for (size_t i = 0; i < src->n; i++) {
                    Node *n = src->v[i];
                    if (idset_contains(&queried_nodes, n->id)) continue;
                    bool dup = false;
                    for (size_t m = 0; m < nu; m++)
                        if (!memcmp(uniq[m].id, n->id, 20)) { dup = true; break; }
                    if (dup) continue;
                    if (nu == capu) { capu = capu ? capu * 2 : 16; uniq = realloc(uniq, capu * sizeof(KN)); }
                    memcpy(uniq[nu].id, n->id, 20);
                    uniq[nu].node = n;
                    nu++;
                }
            }
            /* sort by distance (stable) */
            for (size_t i = 1; i < nu; i++) {
                KN cur = uniq[i];
                u256 d = Node_distance_to(target, cur.node);
                size_t j = i;
                while (j > 0 && u256_gt(Node_distance_to(target, uniq[j - 1].node), d)) {
                    uniq[j] = uniq[j - 1];
                    j--;
                }
                uniq[j] = cur;
            }
            nodelist_free(&current_closest);
            nodelist_init(&current_closest);
            size_t keep = nu < (size_t)(s->alpha * 2) ? nu : (size_t)(s->alpha * 2);
            for (size_t i = 0; i < keep; i++) nodelist_add(&current_closest, uniq[i].node);

            u256 new_best;
            bool have_new_best = current_closest.n > 0;
            if (have_new_best) new_best = Node_distance_to(target, current_closest.v[0]);
            else new_best = u256_pow2(256);        /* inf approximation */
            if (have_new_best && u256_lt(new_best, best_distance)) {
                best_distance = new_best;
                improved = true;
                no_improvement_count = 0;
            } else if (have_new_best && u256_eq(new_best, best_distance)) {
                no_improvement_count += 1;
                if (no_improvement_count >= 3) {
                    log_debug("Convergence: no distance improvement for 3 iterations");
                    free(uniq);
                    nodelist_free(&new_neighbors);
                    nodelist_free(&nodes_to_query);
                    break;
                }
            } else {
                no_improvement_count = 0;
            }
            free(uniq);
        }
        nodelist_free(&new_neighbors);
        nodelist_free(&nodes_to_query);
    }

    /* final selection: unique candidates sorted by distance, take k */
    {
        typedef struct { uint8_t id[20]; Node *node; } KN;
        KN *uniq = NULL; size_t nu = 0, capu = 0;
        for (size_t i = 0; i < all_candidates.n; i++) {
            Node *n = all_candidates.v[i];
            bool dup = false;
            for (size_t m = 0; m < nu; m++)
                if (!memcmp(uniq[m].id, n->id, 20)) { dup = true; break; }
            if (dup) continue;
            if (nu == capu) { capu = capu ? capu * 2 : 16; uniq = realloc(uniq, capu * sizeof(KN)); }
            memcpy(uniq[nu].id, n->id, 20);
            uniq[nu].node = n;
            nu++;
        }
        for (size_t i = 1; i < nu; i++) {
            KN cur = uniq[i];
            u256 d = Node_distance_to(target, cur.node);
            size_t j = i;
            while (j > 0 && u256_gt(Node_distance_to(target, uniq[j - 1].node), d)) {
                uniq[j] = uniq[j - 1];
                j--;
            }
            uniq[j] = cur;
        }
        for (size_t i = 0; i < nu && (int)i < k; i++) nodelist_add(&result, uniq[i].node);
        free(uniq);
    }
    {
        char *kh2 = hex_encode(key_hash, 20);
        log_debug("Found %zu closest nodes to key %.16s...", result.n, kh2);
        free(kh2);
    }
    idset_free(&queried_nodes);
    nodelist_free(&all_candidates);
    nodelist_free(&current_closest);
    free(target);
    return result;
}

/* store_rendezvous_key(rendezvous_key, node_id(20), ttl=None) */
static bool RRKDHT_store_rendezvous_key(RRKDHT *s, const char *rendezvous_key,
                                        const uint8_t node_id[20], int ttl) {
    uint8_t key_hash[20];
    digest(rendezvous_key, strlen(rendezvous_key), key_hash);
    if (ttl <= 0) ttl = s->epoch_manager->epoch_duration * 2;
    char *nid_hex = hex_encode(node_id, 20);
    JVal *storage_value = j_obj();
    j_obj_set(storage_value, "node_id", j_str(nid_hex));
    j_obj_set(storage_value, "rendezvous_key", j_str(rendezvous_key));
    j_obj_set(storage_value, "stored_at", j_num(now_time()));
    j_obj_set(storage_value, "epoch", j_int(EpochManager_get_current_epoch(s->epoch_manager)));
    j_obj_set(storage_value, "expires_at", j_num(now_time() + ttl));
    log_debug("Storing rendezvous key '%s' for node %.16s...", rendezvous_key, nid_hex);
    {
        char *kh = hex_encode(key_hash, 20);
        log_debug("Key hash: %.16s...", kh);
        free(kh);
    }
    free(nid_hex);

    NodeList closest = RRKDHT_find_closest_nodes_to_key(s, key_hash, CFG_REPLICATION_FACTOR);
    if (!closest.n) {
        log_error("Could not find any nodes to store rendezvous key %s", rendezvous_key);
        j_free(storage_value);
        nodelist_free(&closest);
        return false;
    }
    /* log closest nodes with distances */
    Node *target = Node_new(key_hash);
    log_debug("Found %d closest nodes for storage:", (int)closest.n);
    for (size_t i = 0; i < closest.n; i++) {
        char *dd = u256_to_dec(Node_distance_to(target, closest.v[i]));
        bool is_us = !memcmp(closest.v[i]->id, s->node->id, 20);
        log_debug("  %d. %s:%d (distance: %s)%s", (int)i + 1,
                  closest.v[i]->ip, closest.v[i]->port, dd, is_us ? " US" : "");
        free(dd);
    }
    free(target);

    /* store in parallel (asyncio.gather, return_exceptions=True) */
    typedef struct { RRKDHT *s; Node *node; uint8_t kh[20]; JVal *v; bool ok; } StoreTaskCtx;
    StoreTaskCtx *ctxs = calloc(closest.n, sizeof(StoreTaskCtx));
    GatherTask *tasks = calloc(closest.n, sizeof(GatherTask));
    for (size_t i = 0; i < closest.n; i++) {
        ctxs[i].s = s; ctxs[i].node = closest.v[i];
        memcpy(ctxs[i].kh, key_hash, 20);
        ctxs[i].v = storage_value;
        ctxs[i].ok = false;
        tasks[i].arg = &ctxs[i];
    }
    /* task bodies need a fn pointer — wrap store call */
    extern void *store_rendezvous_task(void *);
    for (size_t i = 0; i < closest.n; i++) tasks[i].fn = store_rendezvous_task;
    parallel_gather(tasks, closest.n);
    int success_count = 0;
    for (size_t i = 0; i < closest.n; i++) if (ctxs[i].ok) success_count++;
    free(ctxs); free(tasks);

    int min_required = (int)closest.n == 1 ? 1 : ((int)closest.n + 1) / 2;
    int failed_count = (int)closest.n - success_count;
    if (failed_count > 0)
        log_warning("Failed to store on %d nodes", failed_count);
    if (success_count >= min_required) {
        log_info("[OK] Successfully stored rendezvous key on %d/%zu nodes",
                 success_count, closest.n);
        j_free(storage_value);
        nodelist_free(&closest);
        return true;
    }
    log_warning("[NEGATIVE] Failed to store on enough nodes: %d/%zu (needed %d)",
                success_count, closest.n, min_required);
    j_free(storage_value);
    nodelist_free(&closest);
    return false;
}

/* task wrapper (file scope required by C) */
void *store_rendezvous_task(void *arg) {
    struct StoreCtxShim { RRKDHT *s; Node *node; uint8_t kh[20]; JVal *v; bool ok; } *ctx = arg;
    ctx->ok = RRKDHT_store_rendezvous_on_node(ctx->s, ctx->node, ctx->kh, ctx->v);
    return NULL;
}

/* _lookup_local_rendezvous(key_hash) -> JVal (non-owning) or NULL */
static JVal *RRKDHT_lookup_local_rendezvous(RRKDHT *s, const uint8_t key_hash[20]) {
    if (!s->rendezvous_storage_initialized) return NULL;
    JVal *value = storage_get(&s->_rendezvous_storage, key_hash);
    if (value) {
        log_info("[OK] Found rendezvous key '%s' in local storage", j_get_str(value, "rendezvous_key"));
        const char *nid = j_get_str(value, "node_id");
        log_debug("  Node ID: %.16s...", nid ? nid : "?");
        log_debug("  Epoch: %d", (int)j_get_num(value, "epoch", 0));
        return value;
    }
    char *kh = hex_encode(key_hash, 20);
    log_debug("Key hash %.16s... not found in local storage", kh);
    free(kh);
    return NULL;
}

/* _lookup_rendezvous_on_node(node, key_hash) -> JVal or NULL (max_retries=2, retry_delay=0.3) */
static JVal *RRKDHT_lookup_rendezvous_on_node(RRKDHT *s, Node *node, const uint8_t key_hash[20]) {
    const int max_retries = 2;
    const double retry_delay = 0.3;
    /* check if this is us - compare by Node ID */
    if (!memcmp(node->id, s->protocol->source_node->id, 20)) {
        log_debug("Looking up locally (we are the target node)");
        return j_deepcopy(RRKDHT_lookup_local_rendezvous(s, key_hash));
    }
    /* use RWP for remote nodes with retries */
    if (node->rwp_port <= 0) {
        log_debug("Node %s:%d has no RWP port", node->ip, node->port);
        return NULL;
    }
    for (int attempt = 0; attempt < max_retries; attempt++) {
        NodeInfo *ni = RWPDHTHandler_get_node_info(s->rwp_handler, node->ip, node->rwp_port);
        if (!ni) {
            if (attempt < max_retries - 1) { py_sleep(retry_delay); continue; }
            log_debug("Could not get node info for %s:%d", node->ip, node->rwp_port);
            return NULL;
        }
        char *keyhex = hex_encode(key_hash, 20);
        JVal *payload = j_obj();
        j_obj_set(payload, "key", j_str(keyhex));
        JVal *response = RWPDHTHandler_send_encrypted_message(s->rwp_handler, ni, MT_DHT_GET, payload);
        j_free(payload);
        free(keyhex);
        if (response) {
            JVal *pl = j_obj_get(response, "payload");
            if (pl && j_get_bool(pl, "found", false)) {
                const char *value_str = j_get_str(pl, "value");
                JVal *result = value_str ? j_loads(value_str) : NULL;
                if (result) {
                    log_debug("[OK] Found value on remote node %s:%d", node->ip, node->port);
                    j_free(response);
                    return result;
                }
            }
            /* if not found, don't retry */
            log_debug("Value not found on remote node %s:%d", node->ip, node->port);
            j_free(response);
            return NULL;
        }
        if (attempt < max_retries - 1) {
            log_debug("No valid response from %s:%d, retrying...", node->ip, node->port);
            py_sleep(retry_delay);
            continue;
        }
        log_debug("No valid response from %s:%d after %d attempts", node->ip, node->port, max_retries);
        return NULL;
    }
    return NULL;
}

/* lookup_rendezvous_key(rendezvous_key) -> JVal or NULL */
static JVal *RRKDHT_lookup_rendezvous_key(RRKDHT *s, const char *rendezvous_key) {
    uint8_t key_hash[20];
    digest(rendezvous_key, strlen(rendezvous_key), key_hash);
    {
        char *kh = hex_encode(key_hash, 20);
        log_info("Looking up rendezvous key %s (hash: %.16s...)", rendezvous_key, kh);
        free(kh);
    }
    NodeList closest = RRKDHT_find_closest_nodes_to_key(s, key_hash, CFG_REPLICATION_FACTOR);
    if (!closest.n) {
        log_warning("No nodes found close to rendezvous key hash");
        nodelist_free(&closest);
        return NULL;
    }
    log_debug("Looking up on %zu closest nodes", closest.n);
    /* parallel lookups */
    typedef struct { RRKDHT *s; Node *node; uint8_t kh[20]; JVal *res; } LookupTaskCtx;
    LookupTaskCtx *ctxs = calloc(closest.n ? closest.n : 1, sizeof(LookupTaskCtx));
    GatherTask *tasks = calloc(closest.n ? closest.n : 1, sizeof(GatherTask));
    extern void *lookup_rendezvous_task(void *);
    for (size_t i = 0; i < closest.n; i++) {
        ctxs[i].s = s; ctxs[i].node = closest.v[i];
        memcpy(ctxs[i].kh, key_hash, 20);
        tasks[i].fn = lookup_rendezvous_task;
        tasks[i].arg = &ctxs[i];
    }
    parallel_gather(tasks, closest.n);
    /* return first valid result */
    int64_t current_epoch = EpochManager_get_current_epoch(s->epoch_manager);
    JVal *found = NULL;
    for (size_t i = 0; i < closest.n; i++) {
        JVal *r = ctxs[i].res;
        if (!r) continue;
        /* check if expired */
        if (j_get_num(r, "expires_at", 0) < now_time()) {
            log_debug("Found expired rendezvous key entry");
            continue;
        }
        /* check if from wrong epoch */
        int64_t rec_epoch = (int64_t)j_get_num(r, "epoch", -1);
        if (rec_epoch != current_epoch && rec_epoch != current_epoch - 1) {
            log_debug("Found rendezvous key from stale epoch %lld (current %lld)",
                    (long long)rec_epoch, (long long)current_epoch);
            continue;
        }
        const char *nid = j_get_str(r, "node_id");
        log_info("Found rendezvous key mapping: %s -> %.16s...", rendezvous_key, nid ? nid : "?");
        found = r;
        break;
    }
    for (size_t i = 0; i < closest.n; i++)
        if (ctxs[i].res && ctxs[i].res != found) j_free(ctxs[i].res);
    free(ctxs); free(tasks);
    nodelist_free(&closest);
    if (!found) log_info("Rendezvous key %s not found on any closest nodes", rendezvous_key);
    return found;
}

void *lookup_rendezvous_task(void *arg) {
    struct LookupCtxShim { RRKDHT *s; Node *node; uint8_t kh[20]; JVal *res; } *ctx = arg;
    ctx->res = RRKDHT_lookup_rendezvous_on_node(ctx->s, ctx->node, ctx->kh);
    return NULL;
}

static void *RRKDHT_republish_rendezvous_key(void *arg) {
    RRKDHT *s = arg;
    if (!s->running || !s->protocol) return NULL;
    const char *rk = RRKDHT_get_rendezvous_key(s);
    if (!rk) { log_warning("No rendezvous key to republish"); return NULL; }
    bool ok = RRKDHT_store_rendezvous_key(s, rk, s->node->id, 0);
    if (ok) {
        atomic_store(&s->last_rk_republish_ms, now_mono_ms());   /* ← NEW */
        log_info("Successfully republished rendezvous key");
    } else {
        log_warning("Failed to republish rendezvous key");
    }
    return NULL;
}

/* _cleanup_expired_rendezvous() */
static int RRKDHT_cleanup_expired_rendezvous(RRKDHT *s) {
    if (!s->rendezvous_storage_initialized) return 0;
    double current_time = now_time();
    int64_t current_epoch = EpochManager_get_current_epoch(s->epoch_manager);
    /* snapshot keys to remove */
    uint8_t (*expired)[20] = NULL; size_t nexp = 0;
    StorageMap *m = &s->_rendezvous_storage;
    pthread_mutex_lock(&m->mu);
    for (size_t i = 0; i < m->n; i++) {
        JVal *value = m->vals[i];
        double expires_at = j_get_num(value, "expires_at", 0);
        int64_t epoch = (int64_t)j_get_num(value, "epoch", -1);
        if (current_time > expires_at || epoch < current_epoch - 1) {
            expired = realloc(expired, (nexp + 1) * 20);
            memcpy(expired[nexp++], m->keys[i], 20);
        }
    }
    pthread_mutex_unlock(&m->mu);
    for (size_t i = 0; i < nexp; i++) storage_del(m, expired[i]);
    free(expired);
    if (nexp) log_info("Cleaned up %zu expired rendezvous keys", nexp);
    return (int)nexp;
}

/* _cleanup_expired_rendezvous_task() */
static void *RRKDHT_cleanup_expired_rendezvous_task(void *arg) {
    RRKDHT_cleanup_expired_rendezvous((RRKDHT *)arg);
    return NULL;
}

/* _schedule_rendezvous_republish() (self-rescheduling, handle not stored) */
static void rendezvous_republish_cb(void *arg) {
    RRKDHT *s = arg;
    if (!s->running) return;

    int64_t last = atomic_load(&s->last_rk_republish_ms);
    int64_t age  = (last == 0) ? INT64_MAX : now_mono_ms() - last;

    if (age < 120000) {                       /* one full timer period, NOT 10s */
        log_debug("Skipping rendezvous republish (done %.1fs ago)", age / 1000.0);
    } else {
        log_debug("Scheduling rendezvous key republish");
        ensure_future(RRKDHT_republish_rendezvous_key, s);
    }
    ensure_future(RRKDHT_cleanup_expired_rendezvous_task, s);  /* ALWAYS */
    call_later(120, rendezvous_republish_cb, s);               /* ALWAYS */
}

static void RRKDHT_schedule_rendezvous_republish(RRKDHT *s) {
    if (!s->running) return;
    rendezvous_republish_cb(s);
}

/* --- rejoin / identity regeneration --- */

/* _attempt_rejoin() */
static void RRKDHT_regenerate_identity(RRKDHT *s);

static void *RRKDHT_attempt_rejoin(void *arg) {
    RRKDHT *s = arg;
    if (s->rejoin_in_progress) {
        log_debug("Rejoin already in progress, skipping");
        return NULL;
    }
    s->rejoin_in_progress = true;
    s->_rejoin_attempts += 1;
    log_warning("Attempting to rejoin network (attempt #%d/%d, identity regeneration #%d)",
                s->_rejoin_attempts, CFG_MAX_REJOIN_ATTEMPTS, s->_identity_regeneration_count);

    /* get all known neighbors */
    NodeList all_neighbors; nodelist_init(&all_neighbors);
    RoutingTable *t = s->protocol->router;
    RoutingTable_lock(t);
    for (size_t i = 0; i < t->nbuckets; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++) nodelist_add(&all_neighbors, nl.v[j]);
        nodelist_free(&nl);
    }
    RoutingTable_unlock(t);

    if (!all_neighbors.n) {
        log_error("No known neighbors to rejoin through");
        /* check if we should regenerate identity */
        if (s->_rejoin_attempts >= CFG_MAX_REJOIN_ATTEMPTS)
            RRKDHT_regenerate_identity(s);
        nodelist_free(&all_neighbors);
        return NULL;
    }

    /* find nodes closest to us */
    for (size_t i = 1; i < all_neighbors.n; i++) {
        Node *cur = all_neighbors.v[i];
        u256 d = Node_distance_to(s->node, cur);
        size_t j = i;
        while (j > 0 && u256_gt(Node_distance_to(s->node, all_neighbors.v[j - 1]), d)) {
            all_neighbors.v[j] = all_neighbors.v[j - 1];
            j--;
        }
        all_neighbors.v[j] = cur;
    }
    size_t nclosest = all_neighbors.n < (size_t)(s->ksize * 3) ? all_neighbors.n : (size_t)(s->ksize * 3);
    log_info("Re-announcing ourselves to %zu nearby nodes", nclosest);

    /* ping each node and verify acceptance */
    NodeList verified_acceptances; nodelist_init(&verified_acceptances);
    int successful_pings = 0;
    for (size_t i = 0; i < nclosest; i++) {
        Node *node = all_neighbors.v[i];
        RpcResult *result = RRKDHTProtocol_call_ping(s->protocol, node);
        bool ping_success = result->happened;
        m_free(result->data);
        free(result);
        if (ping_success) {
            successful_pings += 1;
            log_debug("Successfully pinged %s:%d", node->ip, node->port);
            /* CRITICAL: wait a moment for their routing table to update */
            py_sleep(0.5);
            /* verify they actually added us */
            bool happened = false, knows = false;
            RRKDHTProtocol_call_verify_neighbor(s->protocol, node, s->node->id, &happened, &knows);
            if (happened && knows) {
                nodelist_add(&verified_acceptances, node);
                pthread_mutex_lock(&s->resp_mu);
                ResponsibleInfo info = { .node = node, .last_contact = now_time(), .verified = true };
                respmap_set(&s->possible_responsibles, node->id, info);
                pthread_mutex_unlock(&s->resp_mu);
                idset_add(&s->verified_responsibles, node->id);
                log_info("[VERIFIED] Node %s:%d confirmed acceptance", node->ip, node->port);
            } else {
                log_warning("[REJECTED] Node %s:%d did not add us to routing table",
                            node->ip, node->port);
            }
        } else {
            log_debug("Failed to ping %s:%d", node->ip, node->port);
        }
        py_sleep(0.3);
    }

    log_info("Rejoin attempt %d: %d pings, %zu verified acceptances",
             s->_rejoin_attempts, successful_pings, verified_acceptances.n);

    if ((int)verified_acceptances.n >= CFG_MIN_RESPONSIBLE_NODES) {
        /* success - we have verified acceptances */
        log_info("[SUCCESS] Rejoined network with %zu verified nodes", verified_acceptances.n);
        s->_rejoin_attempts = 0;
        s->is_orphaned = false;
        s->rejoin_in_progress = false;
        nodelist_free(&verified_acceptances);
        nodelist_free(&all_neighbors);
        return NULL;
    }

    /* check if we should regenerate identity */
    if (s->_rejoin_attempts >= CFG_MAX_REJOIN_ATTEMPTS) {
        log_warning("Failed to rejoin after %d attempts - attempting identity regeneration",
                    CFG_MAX_REJOIN_ATTEMPTS);
        RRKDHT_regenerate_identity(s);
    } else {
        /* still have attempts left with current identity */
        log_warning("Rejoin attempt %d failed - %d attempts remaining",
                    s->_rejoin_attempts, CFG_MAX_REJOIN_ATTEMPTS - s->_rejoin_attempts);
        s->rejoin_in_progress = false;
    }
    nodelist_free(&verified_acceptances);
    nodelist_free(&all_neighbors);
    return NULL;
}

/* _regenerate_identity() */
static void RRKDHT_regenerate_identity(RRKDHT *s) {
    if (s->_identity_regeneration_count >= CFG_MAX_IDENTITY_REGENERATIONS) {
        log_error("Reached maximum identity regenerations (%d). "
                  "Network may be incompatible or node is truly isolated.",
                  CFG_MAX_IDENTITY_REGENERATIONS);
        s->rejoin_in_progress = false;
        s->_rejoin_attempts = 0;
        return;
    }
    s->_identity_regeneration_count += 1;
    log_warning("=== REGENERATING IDENTITY #%d/%d ===",
                s->_identity_regeneration_count, CFG_MAX_IDENTITY_REGENERATIONS);

    /* store original identity info on first regeneration */
    if (!s->_original_identity) {
        s->_original_identity = calloc(1, sizeof(*s->_original_identity));
        s->_original_identity->node_id = hex_encode(s->node->id, 20);
        s->_original_identity->signing_public_key = pem_public_key(s->signing_public_key);
        log_info("Original identity: %.16s...", s->_original_identity->node_id);
    }

    /* generate new signing keys */
    char *old_node_id = hex_encode(s->node->id, 20);
    EVP_PKEY *old_signing_key = s->signing_private_key;  /* signing_private_key == signing_public_key (same EVP_PKEY) */
    SecureMessaging *old_messaging = s->messaging;
    RWPDHTHandler *old_rwp_handler = s->rwp_handler;
    EVP_PKEY *new_signing_private = create_ed25519_private_key();
    EVP_PKEY *new_signing_public = new_signing_private;

    /* generate new node ID from new public key */
    char *new_peer_id = generate_peer_id(new_signing_public);
    uint8_t new_node_id[20];
    digest(new_peer_id, strlen(new_peer_id), new_node_id);
    u256 old_long_id = s->node->long_id;

    /* update node identity */
    memcpy(s->node->id, new_node_id, 20);
    s->node->long_id = u256_from_bytes_be20(new_node_id);
    s->signing_private_key = new_signing_private;
    s->signing_public_key = new_signing_public;

    /* regenerate messaging with new keys */
    s->messaging = SecureMessaging_new(new_signing_private, new_signing_public);

    /* update RWP handler with new identity
     * NOTE: replicates the Python code exactly — peer_id here is
     * generate_peer_id(public_key) (64-char), not node.id.hex() (40-char) */
    char *peer_id = generate_peer_id(new_signing_public);
    char *old_rendezvous_key = xstrdup(s->rwp_handler->rendezvous_key);

    /* recreate RWP handler with new identity */
    RWPDHTHandler_stop_rwp_server(s->rwp_handler);
    RWPDHTHandler *new_rwp_handler = RWPDHTHandler_new(peer_id, s->messaging,
                                                       s->epoch_manager,
                                                       s->protocol ? s->protocol->router : NULL);
    s->rwp_handler = new_rwp_handler;
    RWPDHTHandler_start_rwp_server(new_rwp_handler, s->rwp_port);

    /* update protocol's source node */
    if (s->protocol) {
        s->protocol->source_node = s->node;
        s->protocol->rwp_handler = new_rwp_handler;
    }

    /* update node in existing connections */
    free(s->node->rendezvous_key);
    s->node->rendezvous_key = xstrdup(new_rwp_handler->rendezvous_key);

    /* free the superseded identity/messaging/handler now that nothing
     * references them (old_rwp_handler's socket+thread were already torn
     * down by RWPDHTHandler_stop_rwp_server above) */
    RWPDHTHandler_free(old_rwp_handler);
    SecureMessaging_free(old_messaging);
    if (old_signing_key) EVP_PKEY_free(old_signing_key);

    /* clear orphan tracking */
    s->_rejoin_attempts = 0;
    pthread_mutex_lock(&s->resp_mu);
    respmap_clear(&s->possible_responsibles);
    pthread_mutex_unlock(&s->resp_mu);
    idset_clear(&s->verified_responsibles);

    char *new_id_hex = hex_encode(new_node_id, 20);
    char *old_dec = u256_to_dec(old_long_id);
    char *new_dec = u256_to_dec(s->node->long_id);
    log_warning("Identity regenerated:");
    log_warning("  Old ID: %.16s... (long_id: %s)", old_node_id, old_dec);
    log_warning("  New ID: %.16s... (long_id: %s)", new_id_hex, new_dec);
    log_warning("  Old rendezvous: %s", old_rendezvous_key);
    log_warning("  New rendezvous: %s", new_rwp_handler->rendezvous_key);
    free(old_node_id); free(new_id_hex); free(old_dec); free(new_dec);
    free(old_rendezvous_key);

    /* wait a moment for RWP server to stabilize */
    py_sleep(1);

    /* attempt to rejoin with new identity */
    log_info("Attempting rejoin with new identity...");
    s->rejoin_in_progress = false;             /* reset flag so rejoin can proceed */
    RRKDHT_attempt_rejoin(s);
    free(peer_id);
    free(new_peer_id);
}

/* --- search --- */

/* search_node(node_id hex string) -> SearchResult */
static SearchResult *RRKDHT_search_node(RRKDHT *s, const char *node_id_hex) {
    char *th = xstrdup(node_id_hex);
    log_info("Starting iterative search for node %s", th);
    free(th);
    if (!s->protocol) {
        log_error("Cannot search: protocol not initialized");
        SearchResult *r = SearchResult_new();
        r->found = false; r->hops = 0; r->search_time = 0; r->nodes_queried = 0; r->cycle_detected = false;
        return r;
    }
    uint8_t target[20];
    if (strlen(node_id_hex) != 40 || !hex_decode(node_id_hex, target, 20)) {
        log_error("Invalid node ID format: %s", node_id_hex);
        SearchResult *r = SearchResult_new();
        r->found = false; r->hops = 0; r->search_time = 0; r->nodes_queried = 0; r->cycle_detected = false;
        return r;
    }
    NodeSearch *ns = NodeSearch_new(s->protocol, target, CFG_SEARCH_TIMEOUT, CFG_SEARCH_PARALLELISM);
    SearchResult *result = NodeSearch_search(ns);
    free(ns->target_node);
    idset_free(&ns->queried_nodes);
    idset_free(&ns->seen_nodes);
    free(ns);
    return result;
}

/* search_by_rendezvous_key(rendezvous_key) -> SearchResult */
static SearchResult *RRKDHT_search_by_rendezvous_key(RRKDHT *s, const char *rendezvous_key) {
    double start_time = now_time();
    log_info("Starting search by rendezvous key %s", rendezvous_key);
    JVal *mapping = RRKDHT_lookup_rendezvous_key(s, rendezvous_key);
    if (!mapping) {
        log_warning("No mapping found for rendezvous key %s", rendezvous_key);
        SearchResult *r = SearchResult_new();
        r->found = false; r->hops = 0; r->search_time = now_time() - start_time;
        r->nodes_queried = 0; r->cycle_detected = false;
        return r;
    }
    const char *node_id_hex = j_get_str(mapping, "node_id");
    SearchResult *result = NULL;
    if (node_id_hex) {
        log_info("Found mapping: rendezvous key %s -> node %.16s...", rendezvous_key, node_id_hex);
        result = RRKDHT_search_node(s, node_id_hex);
        result->search_time = now_time() - start_time;
    } else {
        result = SearchResult_new();
        result->found = false; result->hops = 0;
        result->search_time = now_time() - start_time;
        result->nodes_queried = 0; result->cycle_detected = false;
    }
    j_free(mapping);
    return result;
}

/* get_rendezvous_key() */
static const char *RRKDHT_get_rendezvous_key(RRKDHT *s) { return s->rwp_handler->rendezvous_key; }

/* get_rwp_url(content="") */
static char *RRKDHT_get_rwp_url(RRKDHT *s, const char *content) {
    return Node_get_rwp_url(s->node, content ? content : "");
}

/* find_node_by_rendezvous_key(rendezvous_key) -> NodeList */
static NodeList RRKDHT_find_node_by_rendezvous_key(RRKDHT *s, const char *rendezvous_key) {
    NodeList out; nodelist_init(&out);
    if (!s->protocol) return out;
    RoutingTable *t = s->protocol->router;
    RoutingTable_lock(t);
    for (size_t i = 0; i < t->nbuckets; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++)
            if (nl.v[j]->rendezvous_key && !strcmp(nl.v[j]->rendezvous_key, rendezvous_key))
                nodelist_add(&out, nl.v[j]);
        nodelist_free(&nl);
    }
    RoutingTable_unlock(t);
    return out;
}

/* --- key rotation monitor thread --- */

static void *key_rotation_monitor_main(void *arg) {
    RRKDHT *s = arg;
    if (!s->epoch_manager) {
        log_error("Key rotation monitor: no epoch manager, exiting");
        return NULL;
    }
    int64_t last_epoch = EpochManager_get_current_epoch(s->epoch_manager);
    while (s->running) {
        /* guard against known recoverable failure states instead of
         * dereferencing NULL/stale pointers — mirrors Python's
         * try/except Exception: log + sleep(60) + retry, since a raw
         * NULL dereference here would crash the whole process, not
         * just this thread */
        if (!s->rwp_handler) {
            log_error("Key rotation monitor: no RWP handler available, retrying in 60s");
            py_sleep(60);
            continue;
        }
        int64_t current_epoch = EpochManager_get_current_epoch(s->epoch_manager);
        if (current_epoch > last_epoch) {
            log_info("Epoch changed from %lld to %lld", (long long)last_epoch, (long long)current_epoch);
            last_epoch = current_epoch;        /* moved UP: one fire per epoch even if
                                                generate fails (old code retried the
                                                whole branch every 60s — re-logging and
                                                re-storing; if you want that back, move
                                                it down, but know what refires) */

            if (!g_no_self_publish) {          /* CRITICAL — see below */
                /* Re-stamp the CURRENT (old) key, inline and BEFORE the swap, so it's
                * guaranteed to store the old string (a spawned task here would race
                * the swap). Gives the old key one full epoch of life → covers your
                * JS retarget's ≤30s lag. Blocking call is fine — the monitor has
                * nothing else to do. */
                if (RRKDHT_store_rendezvous_key(s, s->rwp_handler->rendezvous_key,
                                                s->node->id, 0)) {
                    atomic_store(&s->last_rk_republish_ms, now_mono_ms());
                }
            }

            RWPDHTHandler *h = s->rwp_handler;
            char *new_key = RWPDHTHandler_generate_rendezvous_key(h);
            if (!new_key) {
                log_error("Key rotation monitor: failed to generate key (staying stable this epoch)");
                continue;    /* old key already re-stamped above — no 502 window */
            }
            char *old_key = h->rendezvous_key;
            h->rendezvous_key = new_key;
            log_info("Rendezvous key rotated: %s -> %s", old_key, h->rendezvous_key);
            /* free(old_key); */

            if (!g_no_self_publish) {
                ensure_future(RRKDHT_republish_rendezvous_key, s);   /* publish NEW key NOW */
            }
        }
        py_sleep(30);                            /* check every 30 seconds */
    }
    return NULL;
}

/* _start_key_rotation_monitor() */
static void RRKDHT_start_key_rotation_monitor(RRKDHT *s) {
    pthread_create(&s->key_rotation_thread, NULL, key_rotation_monitor_main, s);
}

/* --- routing table refresh --- */

typedef struct { RRKDHT *s; uint8_t node_id[20]; } RefreshTaskCtx;

static void *refresh_spider_task(void *arg) {
    RefreshTaskCtx *ctx = arg;
    RRKDHT *s = ctx->s;
    Node *node = Node_new(ctx->node_id);
    NodeList neighbors = RoutingTable_find_neighbors(s->protocol->router, node, s->alpha, NULL);
    SpiderCrawl *spider = SpiderCrawl_new(s->protocol, node, &neighbors, s->ksize, s->alpha);
    NodeList found = NodeSpiderCrawl_find(spider);
    nodelist_free(&found);
    nodelist_free(&neighbors);
    free(spider->last_ids_crawled);
    free(spider->nearest->heap);
    idset_free(&spider->nearest->contacted);
    free(spider->nearest);
    free(spider);
    free(node);
    return NULL;
}

/* _refresh_table() */
static void *RRKDHT_refresh_table_task(void *arg) {
    RRKDHT *s = arg;
    if (!s->running) return NULL;
    uint8_t (*ids)[20] = NULL;
    size_t n = RRKDHTProtocol_get_refresh_ids(s->protocol, &ids);
    RefreshTaskCtx *ctxs = calloc(n ? n : 1, sizeof(RefreshTaskCtx));
    GatherTask *tasks = calloc(n ? n : 1, sizeof(GatherTask));
    for (size_t i = 0; i < n; i++) {
        ctxs[i].s = s;
        memcpy(ctxs[i].node_id, ids[i], 20);
        tasks[i].fn = refresh_spider_task;
        tasks[i].arg = &ctxs[i];
    }
    parallel_gather(tasks, n);                   /* asyncio.gather(*results) */
    free(ctxs);
    free(tasks);
    free(ids);
    return NULL;
}

static void refresh_table_cb(void *arg) {
    RRKDHT *s = arg;
    if (!s->running) return;
    RRKDHT_refresh_table(s, 3600);               /* call_later drops interval arg */
}

/* refresh_table(interval=3600) */
static void RRKDHT_refresh_table(RRKDHT *s, int interval) {
    if (!s->running) return;
    log_debug("Refreshing routing table");
    ensure_future(RRKDHT_refresh_table_task, s);
    s->refresh_loop = call_later(interval > 0 ? interval : 3600, refresh_table_cb, s);
}

/* --- bootstrap --- */

/* bootstrap_node(addr dict {ip, port, rwp_port?}) -> Node or NULL */
static Node *RRKDHT_bootstrap_node(RRKDHT *s, const char *ip, int port, int rwp_port) {
    /* PATCHED: this used to guess "port + 363" as a fake default RWP port
     * whenever the caller didn't supply one (i.e. every plain "ip:port"
     * bootstrap string, which is the common case). That guess has no
     * real relationship to the target's actual RWP port -- DHT port and
     * RWP port are chosen independently -- so it poisoned the resulting
     * Node's rwp_port with a confidently WRONG value. Every subsequent
     * rendezvous-key lookup against that node then called
     * RWPDHTHandler_get_node_info on the WRONG port and failed, for as
     * many resolve attempts as it took until the peer happened to ping
     * us (or send a find_node response) carrying its real rwp_port and
     * overwrote the bad value as a side effect. Confirmed via live
     * testing: bootstrapping "127.0.0.1:19700" produced rwp_port=20063
     * (=19700+363) while the peer's REAL rwp_port was 20701 -- every
     * lookup failed against 20063 until corrected.
     *
     * Fix: track "don't know their RWP port yet" HONESTLY as PORT_NONE
     * instead of fabricating a wrong number. RRKDHT_lookup_rendezvous_on_node
     * already checks `rwp_port <= 0` and bails out immediately in that
     * case rather than wasting a doomed connection attempt, so this is a
     * strict improvement with no new failure mode. The routing table
     * entry still self-corrects the moment we learn their real rwp_port
     * from a ping or find_node exchange, same as before -- we just never
     * start from a wrong answer that has to be overwritten first. */
    bool rwp_port_known = (rwp_port != PORT_NONE);

    /* check if we already know this node by IP+port */
    RoutingTable *t = s->protocol->router;
    RoutingTable_lock(t);
    Node *existing = NULL;
    for (size_t i = 0; i < t->nbuckets && !existing; i++) {
        NodeList nl = KBucket_get_nodes(t->buckets[i]);
        for (size_t j = 0; j < nl.n; j++) {
            Node *n = nl.v[j];
            if (n->ip && !strcmp(n->ip, ip) && n->port == port) { existing = n; break; }
        }
        nodelist_free(&nl);
    }
    RoutingTable_unlock(t);
    if (existing) {
        log_debug("Already know bootstrap node %s:%d, returning existing", ip, port);
        return existing;
    }

    if (rwp_port_known) {
        log_debug("Bootstrapping node %s:%d (RWP: %d)", ip, port, rwp_port);
    } else {
        log_debug("Bootstrapping node %s:%d (RWP port unknown -- will discover it via "
                  "ping/find_node rather than guess)", ip, port);
    }

    /* Try RWP first -- only meaningful if we actually know a real RWP
     * port for them. Guessing one here is exactly the bug this patches. */
    if (rwp_port_known) {
        NodeInfo *ni = RWPDHTHandler_get_node_info(s->rwp_handler, ip, rwp_port);
        if (ni && ni->node_id && strlen(ni->node_id) == 40) {
            uint8_t nid[20];
            if (hex_decode(ni->node_id, nid, 20)) {
                int udp_port = (ni->port > 0) ? ni->port : port;
                Node *node = Node_new_full(nid, ip, udp_port, rwp_port, ni->rendezvous_key);
                char *r = Node_repr(node);
                log_debug("Bootstrap via RWP successful: %s", r);
                free(r);
                return node;
            }
        }
    }

    /* Fallback to traditional ping */
    log_debug("Trying UDP ping for bootstrap");
    MVal *args = m_arr();
    m_arr_add(args, m_bin(s->node->id, 20));
    /* LAYER 5 + discovery bonus: now includes rwp_port (arg[1]) AND the
     * signature (args 2+3).*/
    m_arr_add(args, s->rwp_port == PORT_NONE ? m_nil() : m_int(s->rwp_port));
    sign_ping_args(s->messaging->signing_private_key, s->node->id,
                   s->epoch_manager, args);
    RpcResult *result = rpc_call(s->protocol, ip, port, "ping", args, 15.0);
    {
        /* log.debug(f"Bootstrap ping result: {result}") — (bool, bytes) tuple repr */
        StrBuf sb; sb_init(&sb);
        sb_add(&sb, result->happened ? "(True, " : "(False, ");
        if (result->data) {
            const uint8_t *b; size_t bl;
            if (m_as_bytes(result->data, &b, &bl)) {
                char *br = py_bytes_repr(b, bl);
                sb_add(&sb, br);
                free(br);
            } else {
                sb_add(&sb, "None");
            }
        } else {
            sb_add(&sb, "None");
        }
        sb_add(&sb, ")");
        log_debug("Bootstrap ping result: %s", sb.buf);
        sb_free(&sb);
    }
    if (result->happened && result->data) {
        const uint8_t *id; size_t idlen;
        if (m_as_bytes(result->data, &id, &idlen) && idlen >= 20) {
            uint8_t nid[20];
            memcpy(nid, id, 20);
            m_free(result->data);
            free(result);
            /* rwp_port stays PORT_NONE here if it was unknown coming in --
             * honest "don't know yet" instead of a fabricated guess. It
             * self-corrects the moment a ping/find_node from this peer
             * carries their real rwp_port. */
            return Node_new_full(nid, ip, port, rwp_port, NULL);
        }
    }
    m_free(result->data);
    free(result);

    /* FIX: UDP ping failed — last resort: try RWP on the same port number.
     * The port might actually be the node's RWP port (user passed it in
     * the 2-field format). RWP is TCP, DHT is UDP — same number, no
     * conflict. If an RWP server answers, its response tells us the
     * node's real UDP port, so the crawl still works. */
    {
        NodeInfo *ni = RWPDHTHandler_get_node_info(s->rwp_handler, ip, port);
        if (ni && ni->node_id && strlen(ni->node_id) == 40) {
            uint8_t nid[20];
            if (hex_decode(ni->node_id, nid, 20)) {
                int udp_port = (ni->port > 0) ? ni->port : port;
                Node *node = Node_new_full(nid, ip, udp_port, port, ni->rendezvous_key);
                char *r = Node_repr(node);
                log_debug("Bootstrap via RWP fallback successful: %s", r);
                free(r);
                return node;
            }
        }
    }
    return NULL;
}

typedef struct { RRKDHT *s; char *ip; int port; int rwp; Node *res; } BootTaskCtx;

static void *bootstrap_task(void *arg) {
    BootTaskCtx *ctx = arg;
    ctx->res = RRKDHT_bootstrap_node(ctx->s, ctx->ip, ctx->port, ctx->rwp);
    return NULL;
}

/* bootstrap(addrs) -> NodeList of spider-crawl results (empty on failure) */
static NodeList RRKDHT_bootstrap(RRKDHT *s, size_t naddrs, char **ips, int *ports, int *rwps) {
    log_debug("Attempting to bootstrap node with %zu initial contacts", naddrs);
    BootTaskCtx *ctxs = calloc(naddrs ? naddrs : 1, sizeof(BootTaskCtx));
    GatherTask *tasks = calloc(naddrs ? naddrs : 1, sizeof(GatherTask));
    for (size_t i = 0; i < naddrs; i++) {
        ctxs[i].s = s;
        ctxs[i].ip = ips[i];
        ctxs[i].port = ports[i];
        ctxs[i].rwp = rwps[i];
        ctxs[i].res = NULL;
        tasks[i].fn = bootstrap_task;
        tasks[i].arg = &ctxs[i];
    }
    parallel_gather(tasks, naddrs);              /* asyncio.gather */
    NodeList nodes; nodelist_init(&nodes);
    for (size_t i = 0; i < naddrs; i++)
        if (ctxs[i].res) nodelist_add(&nodes, ctxs[i].res);
    free(ctxs);
    free(tasks);
    SpiderCrawl *spider = SpiderCrawl_new(s->protocol, s->node, &nodes, s->ksize, s->alpha);
    NodeList found = NodeSpiderCrawl_find(spider);
    nodelist_free(&nodes);
    free(spider->last_ids_crawled);
    free(spider->nearest->heap);
    idset_free(&spider->nearest->contacted);
    free(spider->nearest);
    free(spider);
    return found;
}

/* bootstrappable_neighbors() -> array of (ip, port, rwp_port) triples */
typedef struct { char *ip; int port; int rwp_port; } BootNeighbor;

static size_t RRKDHT_bootstrappable_neighbors(RRKDHT *s, BootNeighbor **out) {
    NodeList neighbors = RoutingTable_find_neighbors(s->protocol->router, s->node, 0, NULL);
    BootNeighbor *res = NULL;
    size_t n = 0, cap = 0;
    for (size_t i = 0; i < neighbors.n; i++) {
        Node *node = neighbors.v[i];
        if (!node->ip || node->port == PORT_NONE) continue;
        bool dup = false;
        for (size_t j = 0; j < n; j++)
            if (!strcmp(res[j].ip, node->ip) && res[j].port == node->port) { dup = true; break; }
        if (dup) continue;
        if (n == cap) { cap = cap ? cap * 2 : 8; res = realloc(res, cap * sizeof(BootNeighbor)); }
        res[n].ip = xstrdup(node->ip);
        res[n].port = node->port;
        res[n].rwp_port = node->rwp_port;
        n++;
    }
    nodelist_free(&neighbors);
    *out = res;
    return n;
}

/* --- persistence (pickle state files) --- */

/* save_state(filename) */
static bool RRKDHT_save_state(RRKDHT *s, const char *filename) {
    log_info("Saving state to %s", filename);
    char *priv_pem = pem_private_key(s->signing_private_key);
    char *pub_pem = pem_public_key(s->signing_public_key);
    char *id_hex = hex_encode(s->node->id, 20);

    PVal *data = p_dict();
    p_dict_set(data, "ksize", p_int(s->ksize));
    p_dict_set(data, "alpha", p_int(s->alpha));
    p_dict_set(data, "id", p_str(id_hex));
    p_dict_set(data, "signing_private_key", p_str(priv_pem));
    p_dict_set(data, "signing_public_key", p_str(pub_pem));

    BootNeighbor *neighbors = NULL;
    size_t nnb = RRKDHT_bootstrappable_neighbors(s, &neighbors);
    PVal *nlist = p_list();
    for (size_t i = 0; i < nnb; i++) {
        PVal *tup = p_new(P_TUPLE);
        p_list_add(tup, p_str(neighbors[i].ip));
        p_list_add(tup, p_int(neighbors[i].port));
        if (neighbors[i].rwp_port == PORT_NONE) p_list_add(tup, p_none());
        else p_list_add(tup, p_int(neighbors[i].rwp_port));
        p_list_add(nlist, tup);
        free(neighbors[i].ip);
    }
    free(neighbors);
    p_dict_set(data, "neighbors", nlist);
    if (s->rwp_port == PORT_NONE) p_dict_set(data, "rwp_port", p_none());
    else p_dict_set(data, "rwp_port", p_int(s->rwp_port));
    p_dict_set(data, "epoch", p_int(EpochManager_get_current_epoch(s->epoch_manager)));
    p_dict_set(data, "rendezvous_key", p_str(s->rwp_handler->rendezvous_key));

    free(priv_pem); free(pub_pem); free(id_hex);

    if (!nnb) {
        log_warning("No known neighbors, so not writing to cache.");
        p_free(data);
        return false;
    }
    size_t plen;
    uint8_t *pdata = pkl_dump(data, &plen);
    p_free(data);
    FILE *f = fopen(filename, "wb");
    if (!f) {
        log_error("Failed to save state to %s: %s", filename, strerror(errno));
        free(pdata);
        return false;
    }
    fwrite(pdata, 1, plen, f);
    fclose(f);
    free(pdata);
    return true;
}

/* load_state(filename, port, interface='0.0.0.0', rwp_port=None) -> RRKDHT* */
static RRKDHT *RRKDHT_load_state(const char *filename, int port, const char *interface, int rwp_port) {
    log_info("Loading state from %s", filename);
    FILE *f = fopen(filename, "rb");
    if (!f) {
        log_error("Failed to load state from %s: %s", filename, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(flen);
    if (fread(buf, 1, flen, f) != (size_t)flen) { fclose(f); free(buf); return NULL; }
    fclose(f);
    PVal *data = pkl_load(buf, (size_t)flen);
    free(buf);
    if (!data || data->t != P_DICT) {
        log_error("Failed to load state from %s: invalid pickle", filename);
        p_free(data);
        return NULL;
    }

    int ksize = 2, alpha = 3;
    PVal *v;
    if ((v = p_dict_get(data, "ksize")) && v->t == P_INT) ksize = (int)v->i;
    if ((v = p_dict_get(data, "alpha")) && v->t == P_INT) alpha = (int)v->i;

    uint8_t node_id[20];
    bool have_id = false;
    if ((v = p_dict_get(data, "id")) && v->t == P_STR && strlen(v->s) == 40)
        have_id = hex_decode(v->s, node_id, 20);

    EVP_PKEY *priv = NULL, *pub = NULL;
    if ((v = p_dict_get(data, "signing_private_key")) && v->t == P_STR)
        priv = load_pem_private_key(v->s);
    if ((v = p_dict_get(data, "signing_public_key")) && v->t == P_STR)
        pub = load_pem_public_key(v->s);
    if (!priv || !pub) {
        log_error("Failed to load state from %s: invalid keys", filename);
        p_free(data);
        return NULL;
    }
    /* Ed25519 EVP_PKEY from private key already contains the public part */
    pub = priv;

    int saved_rwp = PORT_NONE;
    if ((v = p_dict_get(data, "rwp_port")) && v->t == P_INT) saved_rwp = (int)v->i;
    int use_rwp = rwp_port != PORT_NONE ? rwp_port : saved_rwp;

    RRKDHT *server = RRKDHT_new(ksize, alpha, have_id ? node_id : NULL, priv, pub, use_rwp);
    log_info("Loaded state from %s", filename);
    if (!RRKDHT_listen(server, port, interface ? interface : "0.0.0.0", use_rwp)) {
        p_free(data);
        return NULL;
    }

    /* bootstrap with saved neighbors */
    if ((v = p_dict_get(data, "neighbors")) && v->t == P_LIST && v->n) {
        size_t naddrs = v->n;
        char **ips = calloc(naddrs, sizeof(char *));
        int *ports = calloc(naddrs, sizeof(int));
        int *rwps = calloc(naddrs, sizeof(int));
        size_t real = 0;
        for (size_t i = 0; i < naddrs; i++) {
            PVal *tup = v->items[i];
            if (!tup || (tup->t != P_TUPLE && tup->t != P_LIST) || tup->n < 2) continue;
            if (tup->items[0]->t != P_STR || tup->items[1]->t != P_INT) continue;
            ips[real] = tup->items[0]->s;
            ports[real] = (int)tup->items[1]->i;
            rwps[real] = (tup->n >= 3 && tup->items[2]->t == P_INT) ? (int)tup->items[2]->i : PORT_NONE;
            real++;
        }
        log_info("Bootstrapping with %zu saved neighbors", real);
        NodeList found = RRKDHT_bootstrap(server, real, ips, ports, rwps);
        log_info("Bootstrapped with %zu nodes", found.n);
        nodelist_free(&found);
        free(ips); free(ports); free(rwps);
        if (!g_no_self_publish)
            RRKDHT_republish_rendezvous_key(server);
    }
    p_free(data);
    return server;
}

/* save_state_regularly(filename, frequency=600) */
typedef struct { RRKDHT *s; char *fname; int frequency; } SaveLoopCtx;

static void save_state_cb(void *arg) {
    SaveLoopCtx *ctx = arg;
    RRKDHT *s = ctx->s;
    if (!s->running) { free(ctx->fname); free(ctx); return; }
    RRKDHT_save_state(s, ctx->fname);
    s->save_state_loop = call_later(ctx->frequency, save_state_cb, ctx);
}

static void RRKDHT_save_state_regularly(RRKDHT *s, const char *filename, int frequency) {
    if (!s->running) return;
    if (frequency <= 0) frequency = 600;
    SaveLoopCtx *ctx = malloc(sizeof(SaveLoopCtx));
    ctx->s = s;
    ctx->fname = xstrdup(filename);
    ctx->frequency = frequency;
    RRKDHT_save_state(s, filename);
    s->save_state_loop = call_later(frequency, save_state_cb, ctx);
}

/* --- diagnostics --- */

/* get_debug_info() -> JVal dict (same shape as the Python dict) */
static JVal *RRKDHT_get_debug_info(RRKDHT *s) {
    JVal *info = j_obj();

    /* node_info */
    JVal *node_info = j_obj();
    char *self_hex = hex_encode(s->node->id, 20);
    j_obj_set(node_info, "node_id", j_str(self_hex));
    j_obj_set(node_info, "long_id", j_u256(s->node->long_id));
    j_obj_set(node_info, "ip", s->node->ip ? j_str(s->node->ip) : j_null());
    j_obj_set(node_info, "port", s->node->port == PORT_NONE ? j_null() : j_int(s->node->port));
    j_obj_set(node_info, "rwp_port", s->rwp_port == PORT_NONE ? j_null() : j_int(s->rwp_port));
    j_obj_set(node_info, "rendezvous_key",
              s->rwp_handler ? j_str(s->rwp_handler->rendezvous_key) : j_null());
    j_obj_set(info, "node_info", node_info);

    /* epoch_info */
    JVal *epoch_info = j_obj();
    j_obj_set(epoch_info, "current_epoch", j_int(EpochManager_get_current_epoch(s->epoch_manager)));
    int64_t *epochs = NULL;
    size_t ne = EpochManager_get_storage_epochs(s->epoch_manager, &epochs);
    JVal *se = j_arr();
    for (size_t i = 0; i < ne; i++) j_arr_add(se, j_int(epochs[i]));
    free(epochs);
    j_obj_set(epoch_info, "storage_epochs", se);
    ne = EpochManager_get_retrieval_epochs(s->epoch_manager, &epochs);
    JVal *re = j_arr();
    for (size_t i = 0; i < ne; i++) j_arr_add(re, j_int(epochs[i]));
    free(epochs);
    j_obj_set(epoch_info, "retrieval_epochs", re);
    j_obj_set(info, "epoch_info", epoch_info);

    /* responsible_node_info */
    JVal *rni = j_obj();
    pthread_mutex_lock(&s->resp_mu);
    j_obj_set(rni, "possible_responsibles_count", j_int((int64_t)s->possible_responsibles.n));
    pthread_mutex_unlock(&s->resp_mu);
    j_obj_set(rni, "verified_responsibles_count", j_int((int64_t)s->verified_responsibles.n));
    JVal *vids = j_arr();
    for (size_t i = 0; i < s->verified_responsibles.n; i++) {
        char *h = hex_encode(s->verified_responsibles.ids[i], 20);
        j_arr_add(vids, j_str(h));
        free(h);
    }
    j_obj_set(rni, "verified_node_ids", vids);
    JVal *parr = j_arr();
    pthread_mutex_lock(&s->resp_mu);
    for (size_t i = 0; i < s->possible_responsibles.n; i++) {
        ResponsibleInfo *inf = &s->possible_responsibles.vals[i];
        JVal *pd = j_obj();
        char *h = hex_encode(s->possible_responsibles.keys[i], 20);
        j_obj_set(pd, "node_id", j_str(h));
        free(h);
        j_obj_set(pd, "ip", inf->node->ip ? j_str(inf->node->ip) : j_null());
        j_obj_set(pd, "port", inf->node->port == PORT_NONE ? j_null() : j_int(inf->node->port));
        j_obj_set(pd, "last_contact", j_num(inf->last_contact));
        j_obj_set(pd, "seconds_since_contact", j_int((int64_t)(now_time() - inf->last_contact)));
        j_obj_set(pd, "verified", j_bool(inf->verified));
        j_arr_add(parr, pd);
    }
    pthread_mutex_unlock(&s->resp_mu);
    j_obj_set(rni, "possible_responsibles", parr);
    j_obj_set(rni, "is_orphaned", j_bool(s->is_orphaned));
    j_obj_set(rni, "rejoin_in_progress", j_bool(s->rejoin_in_progress));
    j_obj_set(rni, "last_check", j_num(s->last_responsible_check));
    if (s->last_responsible_check)
        j_obj_set(rni, "seconds_since_check", j_int((int64_t)(now_time() - s->last_responsible_check)));
    else
        j_obj_set(rni, "seconds_since_check", j_null());
    j_obj_set(info, "responsible_node_info", rni);

    /* rwp_info */
    JVal *rwp_info = j_obj();
    if (s->rwp_handler) {
        pthread_mutex_lock(&s->rwp_handler->cache_lock);
        j_obj_set(rwp_info, "node_info_cache_size", j_int((int64_t)s->rwp_handler->cache.n));
        JVal *cached = j_arr();
        for (size_t i = 0; i < s->rwp_handler->cache.n; i++)
            j_arr_add(cached, j_str(s->rwp_handler->cache.keys[i]));
        pthread_mutex_unlock(&s->rwp_handler->cache_lock);
        j_obj_set(rwp_info, "cached_nodes", cached);
    } else {
        j_obj_set(rwp_info, "node_info_cache_size", j_int(0));
        j_obj_set(rwp_info, "cached_nodes", j_arr());
    }
    j_obj_set(info, "rwp_info", rwp_info);

    /* identity_info */
    JVal *idi = j_obj();
    j_obj_set(idi, "current_node_id", j_str(self_hex));
    j_obj_set(idi, "identity_regeneration_count", j_int(s->_identity_regeneration_count));
    j_obj_set(idi, "rejoin_attempts", j_int(s->_rejoin_attempts));
    if (s->_original_identity) {
        StrBuf ob; sb_init(&ob);
        sb_addf(&ob, "%.16s...", s->_original_identity->node_id);
        j_obj_set(idi, "original_identity", j_str(ob.buf));
        sb_free(&ob);
    } else {
        j_obj_set(idi, "original_identity", j_str("current"));
    }
    j_obj_set(idi, "max_regenerations", j_int(CFG_MAX_IDENTITY_REGENERATIONS));
    j_obj_set(idi, "max_rejoin_attempts", j_int(CFG_MAX_REJOIN_ATTEMPTS));
    j_obj_set(info, "identity_info", idi);
    free(self_hex);

    /* enhanced routing info */
    if (s->protocol) {
        RoutingTable *t = s->protocol->router;
        JVal *routing_info = RoutingTable_get_detailed_routing_info(t);
        JVal *health_report = RoutingTable_analyze_routing_health(t);
        JVal *ri = j_obj();
        j_obj_set(ri, "total_buckets", j_int((int64_t)j_get_num(routing_info, "total_buckets", 0)));
        j_obj_set(ri, "total_nodes", j_int((int64_t)j_get_num(routing_info, "total_nodes", 0)));
        j_obj_set(ri, "total_replacement_nodes", j_int((int64_t)j_get_num(routing_info, "total_replacement_nodes", 0)));
        j_obj_set(ri, "lonely_buckets", j_int((int64_t)j_get_num(routing_info, "lonely_buckets", 0)));
        j_obj_set(ri, "stale_nodes", j_int((int64_t)j_get_num(routing_info, "stale_nodes", 0)));
        j_obj_set(ri, "failed_nodes", j_int((int64_t)j_get_num(routing_info, "failed_nodes", 0)));
        j_obj_set(ri, "node_distribution", j_deepcopy(j_obj_get(routing_info, "node_distribution")));
        j_obj_set(ri, "health", health_report);
        j_obj_set(info, "routing_info", ri);

        /* detailed bucket info */
        j_obj_set(info, "detailed_buckets", j_deepcopy(j_obj_get(routing_info, "buckets")));

        /* neighbor summary, sorted by distance */
        JVal *all_neighbors = j_arr();
        JVal *buckets = j_obj_get(routing_info, "buckets");
        if (buckets) {
            for (size_t i = 0; i < buckets->nitems; i++) {
                JVal *bi = buckets->items[i];
                JVal *nodes = j_obj_get(bi, "nodes");
                if (!nodes) continue;
                for (size_t j = 0; j < nodes->nitems; j++) {
                    JVal *node = nodes->items[j];
                    JVal *nsm = j_obj();
                    j_obj_set(nsm, "id", j_deepcopy(j_obj_get(node, "id")));
                    j_obj_set(nsm, "ip", j_deepcopy(j_obj_get(node, "ip")));
                    j_obj_set(nsm, "port", j_deepcopy(j_obj_get(node, "port")));
                    j_obj_set(nsm, "rwp_port", j_deepcopy(j_obj_get(node, "rwp_port")));
                    j_obj_set(nsm, "rendezvous_key", j_deepcopy(j_obj_get(node, "rendezvous_key")));
                    j_obj_set(nsm, "distance", j_deepcopy(j_obj_get(node, "distance_to_self")));
                    j_obj_set(nsm, "last_seen", j_deepcopy(j_obj_get(node, "last_seen")));
                    j_obj_set(nsm, "is_stale", j_deepcopy(j_obj_get(node, "is_stale")));
                    j_obj_set(nsm, "failed_pings", j_deepcopy(j_obj_get(node, "failed_pings")));
                    j_obj_set(nsm, "bucket_index", j_deepcopy(j_obj_get(bi, "index")));
                    j_arr_add(all_neighbors, nsm);
                }
            }
        }
        /* sort by distance (numeric compare on rawnum/num) */
        for (size_t i = 1; i < all_neighbors->nitems; i++) {
            JVal *cur = all_neighbors->items[i];
            JVal *cd = j_obj_get(cur, "distance");
            size_t j = i;
            while (j > 0) {
                JVal *pd = j_obj_get(all_neighbors->items[j - 1], "distance");
                int cmp;
                if (pd->rawnum && cd->rawnum) {
                    /* big ints: compare by length then lexically */
                    size_t la = strlen(pd->rawnum), lb = strlen(cd->rawnum);
                    cmp = la != lb ? (la > lb ? 1 : -1) : strcmp(pd->rawnum, cd->rawnum);
                } else cmp = pd->num > cd->num ? 1 : (pd->num < cd->num ? -1 : 0);
                if (cmp <= 0) break;
                all_neighbors->items[j] = all_neighbors->items[j - 1];
                j--;
            }
            all_neighbors->items[j] = cur;
        }
        j_obj_set(info, "all_neighbors", all_neighbors);
        j_obj_set(info, "total_neighbors", j_int((int64_t)all_neighbors->nitems));
        JVal *closest = j_arr();
        for (size_t i = 0; i < all_neighbors->nitems && i < 10; i++)
            j_arr_add(closest, j_deepcopy(all_neighbors->items[i]));
        j_obj_set(info, "closest_neighbors", closest);
        j_free(routing_info);
    } else {
        JVal *ri = j_obj();
        j_obj_set(ri, "total_buckets", j_int(0));
        j_obj_set(ri, "total_nodes", j_int(0));
        j_obj_set(ri, "lonely_buckets", j_int(0));
        j_obj_set(info, "routing_info", ri);
        j_obj_set(info, "all_neighbors", j_arr());
        j_obj_set(info, "total_neighbors", j_int(0));
    }
    return info;
}

/* ping_node(ip, port, rwp_port=-1) -> JVal result dict */
static JVal *RRKDHT_ping_node(RRKDHT *s, const char *ip, int port, int rwp_port) {
    /* try RWP first if rwp_port provided */
    if (rwp_port != PORT_NONE) {
        NodeInfo *ni = RWPDHTHandler_get_node_info(s->rwp_handler, ip, rwp_port);
        if (ni) {
            log_debug("RWP ping successful to %s:%d (rwp %d)", ip, port, rwp_port);
            JVal *r = j_obj();
            j_obj_set(r, "success", j_bool(true));
            j_obj_set(r, "method", j_str("rwp"));
            j_obj_set(r, "node_id", j_str(ni->node_id));
            j_obj_set(r, "rendezvous_key", j_str(ni->rendezvous_key));
            j_obj_set(r, "epoch", j_int(ni->epoch));
            return r;
        }
        log_debug("RWP ping failed, trying UDP: %s:%d", ip, port);
    }

    /* fallback to UDP (LAYER 5: signed; NULL-safe; single free path) */
    MVal *args = m_arr();
    m_arr_add(args, m_bin(s->node->id, 20));
    m_arr_add(args, s->rwp_port == PORT_NONE ? m_nil() : m_int(s->rwp_port));
    sign_ping_args(s->messaging->signing_private_key, s->node->id, s->epoch_manager, args);
    RpcResult *result = rpc_call(s->protocol, ip, port, "ping", args, 15.0);

    JVal *r = NULL;
    if (result && result->happened && result->data) {
        const uint8_t *id; size_t idlen;
        if (m_as_bytes(result->data, &id, &idlen)) {
            char *hex = hex_encode(id, idlen < 20 ? idlen : 20);
            log_debug("UDP ping successful to %s:%d", ip, port);
            r = j_obj();
            j_obj_set(r, "success", j_bool(true));
            j_obj_set(r, "method", j_str("udp"));
            j_obj_set(r, "node_id", j_str(hex));
            free(hex);
        }
    }
    if (!r) log_error("Ping failed to %s:%d", ip, port);

    /* single cleanup point: result may be NULL (SAFE_CALLOC) or hold data */
    if (result) {
        m_free(result->data);
        free(result);
    }
    if (!r) {
        r = j_obj();
        j_obj_set(r, "success", j_bool(false));
    }
    return r;
}

/* ============================================================================
 * CLI main() — the Python module is a library with no __main__ block; this
 * driver mirrors typical usage of the API so the port runs standalone.
 * ============================================================================ */
#ifndef RRKDHT_NO_MAIN

/* ---- CLI display helpers (mirror multi.py GUI formatters) ---- */

static void print_routing_info(RoutingTable *t) {
    JVal *ri = RoutingTable_get_detailed_routing_info(t);
    JVal *hr = RoutingTable_analyze_routing_health(t);

    printf("\n========================================\n");
    printf("Routing Info\n");
    printf("========================================\n");
    printf("%-22s %-15s %-15s\n", "Configuration", "Value", "Status");
    printf("----------------------------------------\n");
    printf("%-22s %-15d (LIMIT)\n",       "Max Neighbors",      (int)j_get_num(ri, "max_neighbors", 0));
    printf("%-22s %-15d (BUCKET SIZE)\n",  "KSize",              (int)j_get_num(ri, "ksize", 0));
    printf("%-22s %-15d (CURRENT)\n",      "Total Nodes",        (int)j_get_num(ri, "total_nodes", 0));
    printf("%-22s %-15d\n",                "Total Buckets",      (int)j_get_num(ri, "total_buckets", 0));
    printf("%-22s %-15d\n",                "Lonely Buckets",     (int)j_get_num(ri, "lonely_buckets", 0));
    int stale  = (int)j_get_num(ri, "stale_nodes", 0);
    int failed = (int)j_get_num(ri, "failed_nodes", 0);
    printf("%-22s %-15d %s\n",             "Stale Nodes",        stale,  stale  > 0 ? "[!]" : "[OK]");
    printf("%-22s %-15d %s\n",             "Failed Nodes",       failed, failed > 0 ? "[X]" : "[OK]");
    printf("%-22s %-15d\n",                "Replacement Nodes",  (int)j_get_num(ri, "total_replacement_nodes", 0));

    printf("\n----------------------------------------\n");
    const char *hs = j_get_str(hr, "overall_health");
    printf("Health: %s\n", hs ? hs : "?");
    printf("----------------------------------------\n");
    JVal *m = j_obj_get(hr, "metrics");
    if (m) {
        printf("Fill Ratio:     %.2f%%\n",  j_get_num(m, "fill_ratio", 0)   * 100);
        printf("Stale Ratio:    %.2f%%\n",  j_get_num(m, "stale_ratio", 0)  * 100);
        printf("Failed Ratio:   %.2f%%\n",  j_get_num(m, "failed_ratio", 0) * 100);
        printf("Lonely Ratio:   %.2f%%\n",  j_get_num(m, "lonely_ratio", 0) * 100);
    }
    JVal *issues = j_obj_get(hr, "issues");
    if (issues && issues->nitems) {
        printf("\nIssues Found:\n");
        for (size_t i = 0; i < issues->nitems; i++)
            if (issues->items[i]->t == J_STR)
                printf("  * %s\n", issues->items[i]->s);
    }
    printf("========================================\n\n");
    j_free(ri);
    j_free(hr);
}

static void print_neighbors(RoutingTable *t) {
    NodeList neighbors = RoutingTable_get_neighbors_by_distance(t, NULL, 0);
    if (!neighbors.n) {
        printf("No neighbors found\n");
        nodelist_free(&neighbors);
        return;
    }
    printf("\nNeighbors:\n");
    printf("============================================================\n");
    printf("%-5s %-20s %-22s %-8s\n", "Rank", "Node ID (trunc)", "IP:Port", "RWP");
    printf("------------------------------------------------------------\n");
    size_t show = neighbors.n < 20 ? neighbors.n : 20;
    for (size_t i = 0; i < show; i++) {
        Node *n = neighbors.v[i];
        char *hex = hex_encode(n->id, 20);
        printf("%-5zu %.16s...           %s:%-15d %d\n",
               i + 1, hex,
               n->ip ? n->ip : "None", n->port,
               n->rwp_port != PORT_NONE ? n->rwp_port : -1);
        free(hex);
    }
    printf("============================================================\n");
    printf("Showing %zu/%zu neighbors\n\n", show, neighbors.n);
    nodelist_free(&neighbors);
}

static void print_health(RoutingTable *t) {
    JVal *h = RoutingTable_analyze_routing_health(t);
    printf("\nHealth Report:\n");
    printf("==================================================\n");
    const char *overall = j_get_str(h, "overall_health");
    printf("Overall Health: %s\n", overall ? overall : "?");
    printf("\nMetrics:\n");
    JVal *m = j_obj_get(h, "metrics");
    if (m) {
        for (size_t i = 0; i < m->npairs; i++)
            printf("  %s: %.4f\n", m->keys[i], m->vals[i]->num);
    }
    JVal *issues = j_obj_get(h, "issues");
    if (issues && issues->nitems) {
        printf("\nIssues:\n");
        for (size_t i = 0; i < issues->nitems; i++)
            if (issues->items[i]->t == J_STR)
                printf("  [!] %s\n", issues->items[i]->s);
    }
    JVal *recs = j_obj_get(h, "recommendations");
    if (recs && recs->nitems) {
        printf("\nRecommendations:\n");
        for (size_t i = 0; i < recs->nitems; i++)
            if (recs->items[i]->t == J_STR)
                printf("  -> %s\n", recs->items[i]->s);
    }
    printf("==================================================\n\n");
    j_free(h);
}

static void print_status(RRKDHT *s) {
    printf("\nStatus:\n");
    printf("==================================================\n");
    printf("DHT Port: %d\n", s->node->port);
    printf("RWP Port: %d\n", s->rwp_port);
    char *hex = hex_encode(s->node->id, 20);
    printf("Node ID: %s\n", hex);
    free(hex);
    printf("Rendezvous Key: %s\n", RRKDHT_get_rendezvous_key(s));
    printf("Status: RUNNING\n");
    BootNeighbor *nb = NULL;
    size_t nnb = RRKDHT_bootstrappable_neighbors(s, &nb);
    printf("Neighbors: %zu\n", nnb);
    for (size_t i = 0; i < nnb; i++) free(nb[i].ip);
    free(nb);
    if (s->protocol) {
        int total = RoutingTable_get_total_neighbor_count(s->protocol->router);
        printf("Total Routing Table Nodes: %d\n", total);
        printf("Max Neighbors Limit: %d\n", s->protocol->router->max_neighbors);
    }
    printf("Is Orphaned: %s\n", s->is_orphaned ? "true" : "false");
    printf("Rejoin In Progress: %s\n", s->rejoin_in_progress ? "true" : "false");
    printf("Identity Regenerations: %d\n", s->_identity_regeneration_count);
    printf("Rejoin Attempts: %d\n", s->_rejoin_attempts);
    printf("==================================================\n\n");
}

static void print_help(void) {
    printf("\nAvailable Commands:\n");
    printf("  rt, routing                    - Show routing table\n");
    printf("  rt-full                        - Show routing table with empty buckets\n");
    printf("  rt-repl                        - Show routing table with replacement nodes\n");
    printf("  rt-info                        - Show concise routing info (incl max_neighbors)\n");
    printf("  neighbors                      - Show all neighbors\n");
    printf("  health                         - Show routing health analysis\n");
    printf("  status                         - Show node status\n");
    printf("  debug                          - Show comprehensive debug info\n");
    printf("  ping <ip> <port> [rwp_port]    - Ping a specific node\n");
    printf("  search <node_id>               - Search for a node by Node ID\n");
    printf("  search-rk <key>                - Search for a node by Rendezvous Key\n");
    printf("  rksearch <key>                 - Alias for search-rk\n");
    printf("  resolve <rendezvous_key>       - Lookup + search in one call (JSON w/ ip/port/epoch)\n");
    printf("  store <rendezvous_key>         - Store our node id under a rendezvous key\n");
    printf("  lookup <rendezvous_key>        - Look up a rendezvous key\n");
    printf("  save <file>                    - Save state to file\n");
    printf("  key                            - Print our rendezvous key\n");
    printf("  id                             - Print our node id\n");
    printf("  table                          - Print routing table (alias for rt)\n");
    printf("  quit, exit, stop               - Shut down\n");
    printf("  help                           - Show this help message\n\n");
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "RRKDHT — Rotating Rendezvous Kademlia DHT (C port)\n"
        "Usage:\n"
        "  %s <udp_port> [rwp_port] [--bootstrap ip:udp_port[:rwp_port]]... [--ksize N] [--no-publish]\n"
        "  %s --load <statefile> <udp_port> [--bootstrap ip:udp_port[:rwp_port]]... [--no-publish]\n"
        "  --no-publish   join the DHT for lookups/routing only; never store our own\n"
        "                 rendezvous key (for clients that host nothing findable)\n"
        "Commands on stdin once running:\n"
        "  rt, routing                    - Show routing table\n"
        "  rt-full                        - Show routing table with empty buckets\n"
        "  rt-repl                        - Show routing table with replacement nodes\n"
        "  rt-info                        - Show concise routing info (incl max_neighbors)\n"
        "  neighbors                      - Show all neighbors\n"
        "  health                         - Show routing health analysis\n"
        "  status                         - Show node status\n"
        "  debug                          - dump get_debug_info() JSON\n"
        "  ping <ip> <port> [rwp_port]    - ping a node\n"
        "  search <node_id_hex>           - iterative node search\n"
        "  search-rk <rendezvous_key>     - search node by rendezvous key\n"
        "  rksearch <rendezvous_key>      - alias for search-rk\n"
        "  resolve <rendezvous_key>       - lookup + search in one call; JSON with ip/port/epoch\n"
        "  store <rendezvous_key>         - store our node id under a rendezvous key\n"
        "  lookup <rendezvous_key>        - look up a rendezvous key\n"
        "  table                          - print routing table (alias for rt)\n"
        "  save <file>                    - save_state()\n"
        "  key                            - print our rendezvous key\n"
        "  id                             - print our node id\n"
        "  help                           - show available commands\n"
        "  stop, quit, exit               - shut down\n", prog, prog);
}

static void free_search_result(SearchResult *r) {
    if (!r) return;
    for (size_t i = 0; i < r->path_n; i++) free(r->path[i]);
    free(r->path);
    nodelist_free(&r->path_hex);
    free(r);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);        /* unbuffered: scriptable/interactive use */
    log_init_from_env();
    if (argc < 2) { print_usage(argv[0]); return 1; }

    const char *load_file = NULL;
    int argi = 1;
    if (!strcmp(argv[1], "--load")) {
        if (argc < 4) { print_usage(argv[0]); return 1; }
        load_file = argv[2];
        argi = 3;
    }
    int udp_port = atoi(argv[argi++]);
    if (udp_port <= 0 || udp_port > 65535) { print_usage(argv[0]); return 1; }
    int rwp_port = PORT_NONE;
    if (argi < argc && argv[argi][0] != '-') rwp_port = atoi(argv[argi++]);

    /* collect bootstrap addresses */
    int ksize = 2;
    char *boot_ips[64]; int boot_ports[64], boot_rwps[64]; size_t nboot = 0;
    while (argi < argc) {
        if (!strcmp(argv[argi], "--ksize") && argi + 1 < argc) {
            argi++;
            ksize = atoi(argv[argi++]);
        } else if (!strcmp(argv[argi], "--bootstrap") && argi + 1 < argc) {
            argi++;
            char *spec = xstrdup(argv[argi++]);
            char *c1 = strchr(spec, ':');
            if (c1 && nboot < 64) {
                *c1 = 0;
                char *c2 = strchr(c1 + 1, ':');
                boot_ips[nboot] = spec;
                if (c2) {
                    *c2 = 0;
                    boot_ports[nboot] = atoi(c1 + 1);
                    boot_rwps[nboot] = atoi(c2 + 1);
                    /* Validate both ports */
                    if (boot_ports[nboot] <= 0 || boot_ports[nboot] > 65535) {
                        fprintf(stderr, "Invalid bootstrap UDP port: %d (must be 1-65535)\n",
                                boot_ports[nboot]);
                        free(spec);
                        continue;
                    }
                    if (boot_rwps[nboot] != PORT_NONE &&
                        (boot_rwps[nboot] <= 0 || boot_rwps[nboot] > 65535)) {
                        fprintf(stderr, "Invalid bootstrap RWP port: %d (must be 1-65535)\n",
                                boot_rwps[nboot]);
                        free(spec);
                        continue;
                    }
                } else {
                    boot_ports[nboot] = atoi(c1 + 1);
                    boot_rwps[nboot] = PORT_NONE;
                    if (boot_ports[nboot] <= 0 || boot_ports[nboot] > 65535) {
                        fprintf(stderr, "Invalid bootstrap UDP port: %d (must be 1-65535)\n",
                                boot_ports[nboot]);
                        free(spec);
                        continue;
                    }
                }
                nboot++;
            } else free(spec);
        } else if (!strcmp(argv[argi], "--no-publish")) {
            g_no_self_publish = true;
            argi++;
        } else if (!strcmp(argv[argi], "--require-sigs")) {
            g_require_sigs = true;
            argi++;
        } else argi++;
    }

    RRKDHT *server;
    if (load_file) {
        server = RRKDHT_load_state(load_file, udp_port, "0.0.0.0", rwp_port);
        if (!server) { fprintf(stderr, "Failed to load state\n"); return 1; }
    } else {
        server = RRKDHT_new(ksize, 3, NULL, NULL, NULL, rwp_port);
        if (!RRKDHT_listen(server, udp_port, "0.0.0.0", rwp_port)) {
            fprintf(stderr, "Failed to listen on port %d\n", udp_port);
            return 1;
        }
        if (nboot) {
            NodeList found = RRKDHT_bootstrap(server, nboot, boot_ips, boot_ports, boot_rwps);
            printf("Bootstrapped with %zu nodes\n", found.n);
            nodelist_free(&found);
        }
        if (!g_no_self_publish)
            RRKDHT_republish_rendezvous_key(server);
    }
    for (size_t i = 0; i < nboot; i++) free(boot_ips[i]);

    char *id_hex = hex_encode(server->node->id, 20);
    printf("Node ID: %s\n", id_hex);
    printf("Rendezvous key: %s\n", RRKDHT_get_rendezvous_key(server));
    printf("UDP port: %d  RWP port: %d\n", server->node->port, server->rwp_port);
    printf("Type 'stop' to quit, 'debug' for state.\n");
    free(id_hex);

    printf("__RRKDHT_READY_d4e5f6__\n");
    fflush(stdout);

    /* simple stdin command loop */
    char line[1024];
    while (server->running && fgets(line, sizeof(line), stdin)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *cr = strchr(line, '\r');
        if (cr) *cr = 0;
        char *save = NULL;
        char *cmd = strtok_r(line, " \t", &save);
        if (!cmd) { printf("__RRKDHT_CMD_END_a1b2c3__\n"); fflush(stdout); continue; }
        if (!strcmp(cmd, "stop") || !strcmp(cmd, "quit") || !strcmp(cmd, "exit")) {
            printf("__RRKDHT_CMD_END_a1b2c3__\n"); fflush(stdout);
            break;
        } else if (!strcmp(cmd, "store")) {
            char *key = strtok_r(NULL, " \t", &save);
            if (!key) { printf("usage: store <rendezvous_key>\n"); continue; }
            bool ok = RRKDHT_store_rendezvous_key(server, key, server->node->id, 0);
            printf("store: %s\n", ok ? "OK" : "FAILED");
        } else if (!strcmp(cmd, "lookup")) {
            char *key = strtok_r(NULL, " \t", &save);
            if (!key) { printf("usage: lookup <rendezvous_key>\n"); continue; }
            JVal *r = RRKDHT_lookup_rendezvous_key(server, key);
            if (r) { char *js = j_dumps(r); printf("lookup: %s\n", js); free(js); j_free(r); }
            else printf("lookup: NOT FOUND\n");
        } else if (!strcmp(cmd, "search")) {
            char *key = strtok_r(NULL, " \t", &save);
            if (!key) { printf("usage: search <node_id_hex>\n"); continue; }
            SearchResult *r = RRKDHT_search_node(server, key);
            printf("search: found=%s hops=%d nodes_queried=%d time=%.2fs cycle=%s\n",
                   r->found ? "true" : "false", r->hops, r->nodes_queried,
                   r->search_time, r->cycle_detected ? "true" : "false");
            if (r->found && r->target_node) {
                char *ns = Node_str(r->target_node);
                printf("  target: %s\n", ns);
                free(ns);
            }
            free_search_result(r);
            } else if (!strcmp(cmd, "rksearch") || !strcmp(cmd, "search-rk")) {
            char *key = strtok_r(NULL, " \t", &save);
            if (!key) { printf("usage: search-rk <rendezvous_key>\n"); continue; }
            SearchResult *r = RRKDHT_search_by_rendezvous_key(server, key);
            printf("search-rk: found=%s hops=%d nodes_queried=%d time=%.2fs cycle=%s\n",
                   r->found ? "true" : "false", r->hops, r->nodes_queried,
                   r->search_time, r->cycle_detected ? "true" : "false");
            free_search_result(r);
        } else if (!strcmp(cmd, "resolve")) {
            /* One-shot: rendezvous key -> {node_id, epoch, ip, port, rwp_port}.
             * This is the single call a client needs to turn a rendezvous key
             * (typed in a URL bar) into a connectable address. */
            char *key = strtok_r(NULL, " \t", &save);
            if (!key) { printf("usage: resolve <rendezvous_key>\n"); continue; }
            JVal *mapping = RRKDHT_lookup_rendezvous_key(server, key);
            JVal *out = j_obj();
            if (!mapping) {
                j_obj_set(out, "found", j_bool(false));
            } else {
                const char *node_id_hex = j_get_str(mapping, "node_id");
                j_obj_set(out, "rendezvous_key", j_str(key));
                j_obj_set(out, "node_id", node_id_hex ? j_str(node_id_hex) : j_null());
                j_obj_set(out, "epoch", j_int((int64_t)j_get_num(mapping, "epoch", -1)));
                j_obj_set(out, "stored_at", j_num(j_get_num(mapping, "stored_at", 0)));
                j_obj_set(out, "expires_at", j_num(j_get_num(mapping, "expires_at", 0)));
                SearchResult *r = node_id_hex ? RRKDHT_search_node(server, node_id_hex) : NULL;
                bool have_addr = r && r->found && r->target_node;
                j_obj_set(out, "found", j_bool(have_addr));
                if (have_addr) {
                    j_obj_set(out, "ip", j_str(r->target_node->ip ? r->target_node->ip : ""));
                    j_obj_set(out, "port", r->target_node->port == PORT_NONE ? j_null() : j_int(r->target_node->port));
                    j_obj_set(out, "rwp_port", r->target_node->rwp_port == PORT_NONE ? j_null() : j_int(r->target_node->rwp_port));
                    j_obj_set(out, "hops", j_int(r->hops));
                    j_obj_set(out, "nodes_queried", j_int(r->nodes_queried));
                }
                if (r) free_search_result(r);
                j_free(mapping);
            }
            char *js = j_dumps(out);
            printf("resolve: %s\n", js);
            free(js);
            j_free(out);
        } else if (!strcmp(cmd, "ping")) {
            char *ip = strtok_r(NULL, " \t", &save);
            char *ps = strtok_r(NULL, " \t", &save);
            char *rs = strtok_r(NULL, " \t", &save);
            if (!ip || !ps) { printf("usage: ping <ip> <port> [rwp_port]\n"); continue; }
            JVal *r = RRKDHT_ping_node(server, ip, atoi(ps), rs ? atoi(rs) : PORT_NONE);
            char *js = j_dumps(r);
            printf("ping: %s\n", js);
            free(js);
            j_free(r);
        } else if (!strcmp(cmd, "debug")) {
            JVal *info = RRKDHT_get_debug_info(server);
            char *js = j_dumps(info);
            printf("%s\n", js);
            free(js);
            j_free(info);
                } else if (!strcmp(cmd, "table") || !strcmp(cmd, "rt") || !strcmp(cmd, "routing")) {
            RoutingTable_print(server->protocol->router, false, false);
        } else if (!strcmp(cmd, "rt-full")) {
            RoutingTable_print(server->protocol->router, true, false);
        } else if (!strcmp(cmd, "rt-repl")) {
            RoutingTable_print(server->protocol->router, false, true);
        } else if (!strcmp(cmd, "rt-info")) {
            print_routing_info(server->protocol->router);
        } else if (!strcmp(cmd, "neighbors")) {
            print_neighbors(server->protocol->router);
        } else if (!strcmp(cmd, "health")) {
            print_health(server->protocol->router);
        } else if (!strcmp(cmd, "status")) {
            print_status(server);
        } else if (!strcmp(cmd, "help")) {
            print_help();
        } else if (!strcmp(cmd, "save")) {
            char *fn = strtok_r(NULL, " \t", &save);
            if (!fn) { printf("usage: save <file>\n"); continue; }
            printf("save: %s\n", RRKDHT_save_state(server, fn) ? "OK" : "FAILED");
        } else if (!strcmp(cmd, "key")) {
            printf("%s\n", RRKDHT_get_rendezvous_key(server));
        } else if (!strcmp(cmd, "id")) {
            char *h = hex_encode(server->node->id, 20);
            printf("%s\n", h);
            free(h);
        } else {
            printf("unknown command '%s'\n", cmd);
        }
        printf("__RRKDHT_CMD_END_a1b2c3__\n");
        fflush(stdout);
    }

    RRKDHT_stop(server);
    return 0;
}

#endif /* RRKDHT_NO_MAIN */
