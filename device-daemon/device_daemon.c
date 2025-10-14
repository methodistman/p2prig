// device_daemon.c  (compile: gcc -O2 -pthread -o device_daemon device_daemon.c)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <endian.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>
#include <signal.h>
#include <poll.h>
#include <stdarg.h>
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#ifdef HAVE_RANDOMX
#include <randomx.h>
#endif

// Android bionic compatibility for byte order helpers (Ubuntu glibc provides these via <endian.h>)
#if defined(__ANDROID__)
#ifndef htobe64
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define htobe64(x) __builtin_bswap64((uint64_t)(x))
#  define be64toh(x) __builtin_bswap64((uint64_t)(x))
#  define htobe32(x) __builtin_bswap32((uint32_t)(x))
#  define be32toh(x) __builtin_bswap32((uint32_t)(x))
#  define htobe16(x) __builtin_bswap16((uint16_t)(x))
#  define be16toh(x) __builtin_bswap16((uint16_t)(x))
# else
#  define htobe64(x) (x)
#  define be64toh(x) (x)
#  define htobe32(x) (x)
#  define be32toh(x) (x)
#  define htobe16(x) (x)
#  define be16toh(x) (x)
# endif
#endif
#endif

#define OPC_META_REQ 0x01
#define OPC_META_RESP 0x02
#define OPC_JOB_SUBMIT 0x10
#define OPC_JOB_ABORT 0x11
#define OPC_RESULT 0x12
#define OPC_DONE 0x13
#define OPC_PING 0x20
#define OPC_PONG 0x21
// Phase 1: versioned handshake & errors
#define OPC_CLIENT_HELLO 0x30
#define OPC_SERVER_HELLO 0x31
#define OPC_ERROR        0x7F

typedef struct {
    uint64_t job_id;
    unsigned char header[80];
    unsigned char target[32];
    uint64_t nonce_start;
    uint32_t nonce_count;
    uint8_t flags; // bit0: RANDOMX
#ifdef HAVE_RANDOMX
    unsigned char rx_seed[32];
    uint32_t rx_height;
#endif
    volatile int canceled;
    // Extended format fields (when blob_len > 0)
    unsigned char *blob;
    uint32_t blob_len;
    uint32_t nonce_off;
    uint8_t nonce_size; // 4 or 8
    uint64_t target64; // optional 64-bit target threshold (XMRig-style)
} job_t;

// Phase 2: simple token-based auth (mTLS scaffolding behind HAVE_OPENSSL)
static const char *g_auth_token = NULL;        // set via -T or env P2PRIG_TOKEN
static int g_require_handshake = 0;            // set via --require-handshake
// Phase 3: quotas and throttling
static int g_max_workers = 0;                  // 0 = auto (online)
static uint32_t g_max_batch = 0;               // 0 = unlimited
static int g_throttle_temp_c = 80;             // temperature threshold
static int g_throttle_batt_pct = 15;           // battery capacity threshold
static int g_throttle_sleep_ms = 5;            // sleep per loop when throttled
static volatile int g_throttle_on = 0;         // shared flag updated by monitor
// Phase 4: sandboxing
static char *g_run_as_user = NULL;             // user to drop privileges to
static char *g_chroot_dir = NULL;              // optional chroot dir
static int g_no_new_privs = 0;                 // prctl no_new_privs
// Bind address (Android/Termux may require 127.0.0.1)
static const char *g_bind_addr = "0.0.0.0";

#ifdef HAVE_OPENSSL
// TLS server globals (enabled when cert/key provided)
static SSL_CTX *g_ssl_ctx = NULL;
static int g_tls_enabled = 0;
static int g_tls_require_client_cert = 0;
static const char *g_tls_cert = NULL;
static const char *g_tls_key  = NULL;
static const char *g_tls_ca   = NULL; // optional CA for client cert verify
#endif

// Connection context (used by IO and writers)
typedef struct {
    int fd;
    pthread_mutex_t wlock;
#ifdef HAVE_OPENSSL
    SSL *ssl;
#endif
    // Prefetch buffer used to "unread" a frame (for optional handshake probe)
    unsigned char *prefetch;
    size_t prefetch_len;
    size_t prefetch_off;
} conn_ctx_t;

// ---- Observability ----
#define LOG_ERROR 0
#define LOG_INFO  1
#define LOG_DEBUG 2
static int g_log_level = LOG_INFO;
static int g_stats_interval_sec = 30;

static volatile uint64_t g_ctr_frames_in = 0;
static volatile uint64_t g_ctr_frames_out = 0;
static volatile uint64_t g_ctr_errors = 0;
static volatile uint64_t g_ctr_jobs_enq = 0;
static volatile uint64_t g_ctr_jobs_drop = 0;
static volatile uint64_t g_ctr_results = 0;
static volatile uint64_t g_ctr_done = 0;
static volatile uint64_t g_ctr_pings = 0;
static volatile uint64_t g_ctr_pongs = 0;
static volatile uint64_t g_ctr_hellos = 0;
static volatile uint64_t g_ctr_server_hello = 0;
static volatile uint64_t g_ctr_tls_accepts = 0;
static volatile uint64_t g_ctr_tls_errors = 0;

static void log_emit(int lvl, const char *fmt, ...)
{
    if (lvl > g_log_level) return;
    const char *lv = (lvl==LOG_DEBUG?"DEBUG":(lvl==LOG_INFO?"INFO":"ERROR"));
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    char buf[64];
    struct tm tm; time_t sec = ts.tv_sec; localtime_r(&sec, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(stderr, "%s.%03ld %s: ", buf, ts.tv_nsec/1000000, lv);
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}

static void* stats_thread(void *arg)
{
    (void)arg;
    for(;;){
        sleep(g_stats_interval_sec > 0 ? g_stats_interval_sec : 30);
        uint64_t in  = __sync_add_and_fetch(&g_ctr_frames_in, 0);
        uint64_t out = __sync_add_and_fetch(&g_ctr_frames_out, 0);
        uint64_t err = __sync_add_and_fetch(&g_ctr_errors, 0);
        uint64_t enq = __sync_add_and_fetch(&g_ctr_jobs_enq, 0);
        uint64_t drp = __sync_add_and_fetch(&g_ctr_jobs_drop, 0);
        uint64_t res = __sync_add_and_fetch(&g_ctr_results, 0);
        uint64_t don = __sync_add_and_fetch(&g_ctr_done, 0);
        uint64_t png = __sync_add_and_fetch(&g_ctr_pings, 0);
        uint64_t png2= __sync_add_and_fetch(&g_ctr_pongs, 0);
        uint64_t hlo = __sync_add_and_fetch(&g_ctr_hellos, 0);
        uint64_t shl = __sync_add_and_fetch(&g_ctr_server_hello, 0);
        uint64_t tacc= __sync_add_and_fetch(&g_ctr_tls_accepts, 0);
        uint64_t terr= __sync_add_and_fetch(&g_ctr_tls_errors, 0);
        log_emit(LOG_INFO, "stats frames[in=%" PRIu64 ",out=%" PRIu64 "] errors=%" PRIu64 ", jobs[enq=%" PRIu64 ",drop=%" PRIu64 "] results=%" PRIu64 ", done=%" PRIu64 ", ping=%" PRIu64 ", pong=%" PRIu64 ", hello=%" PRIu64 ", server_hello=%" PRIu64 ", tls[ok=%" PRIu64 ",err=%" PRIu64 "]",
                 in, out, err, enq, drp, res, don, png, png2, hlo, shl, tacc, terr);
    }
    return NULL;
}

// ---- TLS I/O hardening ----
#ifdef HAVE_OPENSSL
static int wait_fd_ready(int fd, int want_write, int timeout_ms)
{
    struct pollfd p = { .fd = fd, .events = (short)(want_write ? POLLOUT : POLLIN), .revents = 0 };
    int r = poll(&p, 1, timeout_ms);
    return (r > 0) ? 0 : -1;
}

static int ssl_accept_with_timeout(SSL *ssl, int fd, int timeout_ms)
{
    struct timespec ts0; clock_gettime(CLOCK_MONOTONIC, &ts0);
    for(;;){
        int r = SSL_accept(ssl);
        if (r == 1) return 0;
        int e = SSL_get_error(ssl, r);
        struct timespec ts1; clock_gettime(CLOCK_MONOTONIC, &ts1);
        long elapsed_ms = (long)((ts1.tv_sec - ts0.tv_sec)*1000 + (ts1.tv_nsec - ts0.tv_nsec)/1000000);
        if (elapsed_ms >= timeout_ms) return -1;
        int remain = timeout_ms - (int)elapsed_ms;
        if (e == SSL_ERROR_WANT_READ) { if (wait_fd_ready(fd, 0, remain) != 0) return -1; continue; }
        if (e == SSL_ERROR_WANT_WRITE){ if (wait_fd_ready(fd, 1, remain) != 0) return -1; continue; }
        return -1;
    }
}
#endif

// 32-bit byte swap with inline assembly where available
static inline uint32_t bswap32_asm(uint32_t x)
{
#if defined(__aarch64__)
    uint32_t r;
    __asm__ __volatile__("rev %w0, %w1" : "=r"(r) : "r"(x));
    return r;
#elif defined(__x86_64__)
    uint32_t r = x;
    __asm__ __volatile__("bswap %0" : "+r"(r));
    return r;
#else
    return __builtin_bswap32(x);
#endif
}

// ---- Phase 3: thermal & battery monitor ----
static int read_int_file(const char *path, int *out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[64]; int n = (int)read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return -1; buf[n] = '\0';
    *out = atoi(buf);
    return 0;
}

static int get_max_temp_c()
{
    int maxc = -1000;
    DIR *d = opendir("/sys/class/thermal");
    if (!d) return -1000;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "thermal_zone", 12) != 0) continue;
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/thermal/%s/temp", de->d_name);
        int millic=-1000; if (read_int_file(path, &millic) == 0) {
            int c = millic / 1000;
            if (c > maxc) maxc = c;
        }
    }
    closedir(d);
    return maxc;
}

static int get_battery_capacity()
{
    int cap = -1;
    DIR *d = opendir("/sys/class/power_supply");
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "BAT", 3) != 0) continue;
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/capacity", de->d_name);
        int v; if (read_int_file(path, &v) == 0) { cap = v; break; }
    }
    closedir(d);
    return cap;
}

static int get_battery_charging()
{
    int charging = 0;
    DIR *d = opendir("/sys/class/power_supply");
    if (!d) return 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "BAT", 3) != 0) continue;
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/status", de->d_name);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char buf[32]; int n = (int)read(fd, buf, sizeof(buf)-1); close(fd);
            if (n > 0) { buf[n] = '\0'; if (strstr(buf, "Charging")) { charging = 1; break; } }
        }
    }
    closedir(d);
    return charging;
}

static void* throttle_monitor_thread(void *arg)
{
    (void)arg;
    for (;;) {
        int tempc = get_max_temp_c();
        int batt = get_battery_capacity();
        int charging = get_battery_charging();
        int on = 0;
        if (tempc >= 0 && g_throttle_temp_c > 0 && tempc >= g_throttle_temp_c) on = 1;
        if (!charging && batt >= 0 && g_throttle_batt_pct > 0 && batt <= g_throttle_batt_pct) on = 1;
        g_throttle_on = on;
        struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
    }
    return NULL;
}

// ---- Phase 1/2 helpers ----
// forward declarations for I/O helpers used below
static ssize_t io_read(conn_ctx_t *ctx, void *buf, size_t len);
static int send_frame_locked(conn_ctx_t *ctx, uint8_t opcode, const void* payload, uint64_t len);
static int read_full_ctx(conn_ctx_t *ctx, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t r = io_read(ctx, p + off, len - off);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

static int recv_frame_simple(conn_ctx_t *ctx, uint8_t *opcode, unsigned char **payload, uint64_t *plen, int timeout_ms) {
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    unsigned char hdr8[8];
    if (read_full_ctx(ctx, hdr8, 8) != 0) return -1;
    uint64_t len_be = 0; memcpy(&len_be, hdr8, 8);
    uint64_t len = be64toh(len_be);
    if (len == 0) return -1;
    unsigned char op;
    if (read_full_ctx(ctx, &op, 1) != 0) return -1;
    uint64_t p_len = len - 1;
    unsigned char *p = NULL;
    if (p_len > 0) {
        if (p_len > (1ULL<<20)) return -1; // sanity: 1MB max
        p = (unsigned char*)malloc((size_t)p_len);
        if (!p) return -1;
        if (read_full_ctx(ctx, p, (size_t)p_len) != 0) { free(p); return -1; }
    }
    *opcode = op; *payload = p; *plen = p_len;
    // clear timeout
    struct timeval tv0 = {0}; setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
    return 0;
}

static int token_allowed(const char *incoming, size_t in_len) {
    if (!g_auth_token || !*g_auth_token) return 1; // no token required
    // g_auth_token can be a comma-separated list of tokens
    const char *start = g_auth_token;
    while (start && *start) {
        const char *comma = strchr(start, ',');
        size_t seg_len = comma ? (size_t)(comma - start) : strlen(start);
        if (seg_len == in_len && memcmp(start, incoming, in_len) == 0) return 1;
        if (!comma) break;
        start = comma + 1;
    }
    return 0;
}

static void send_error(conn_ctx_t *ctx, uint16_t code, const char *msg) {
    uint16_t cbe = htobe16(code);
    uint16_t mlen = (uint16_t) (msg ? strlen(msg) : 0);
    uint16_t mlbe = htobe16(mlen);
    size_t tot = 2 + 2 + mlen;
    unsigned char *buf = (unsigned char*)malloc(tot);
    if (!buf) return;
    memcpy(buf, &cbe, 2);
    memcpy(buf+2, &mlbe, 2);
    if (mlen) memcpy(buf+4, msg, mlen);
    send_frame_locked(ctx, OPC_ERROR, buf, (uint64_t)tot);
    free(buf);
}

#define MAX_QUEUE 256
static job_t *job_queue[MAX_QUEUE];
static int jq_head=0, jq_tail=0;
static pthread_mutex_t jq_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t jq_cond = PTHREAD_COND_INITIALIZER;

/* conn_ctx_t typedef moved earlier */

// RandomX globals and helpers at file scope (when enabled)
#ifdef HAVE_RANDOMX
static pthread_mutex_t rx_lock = PTHREAD_MUTEX_INITIALIZER;
static randomx_cache *g_rx_cache = NULL;
static unsigned char g_rx_seed[32] = {0};
static uint64_t g_rx_seed_ver = 0; // incremented on seed change
static uint32_t g_rx_flags = (RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_FULL_MEM);

static void ensure_rx_seed(const unsigned char seed[32])
{
    pthread_mutex_lock(&rx_lock);
    if (memcmp(g_rx_seed, seed, 32) != 0) {
        if (!g_rx_cache) {
            // Try progressively less demanding flags for Android/Termux compatibility
            const uint32_t tries[] = {
                (RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_FULL_MEM),
                (RANDOMX_FLAG_JIT),
                (0u)
            };
            for (size_t i = 0; i < sizeof(tries)/sizeof(tries[0]) && !g_rx_cache; ++i) {
                randomx_cache *c = randomx_alloc_cache(tries[i]);
                if (c) { g_rx_cache = c; g_rx_flags = tries[i]; }
            }
        }
        randomx_init_cache(g_rx_cache, seed, 32);
        memcpy(g_rx_seed, seed, 32);
        g_rx_seed_ver++;
    }
    pthread_mutex_unlock(&rx_lock);
}

static int hash_randomx(const unsigned char *header, size_t header_len, uint64_t nonce, unsigned char out32[32])
{
    // Compose input as header || nonce_be64 (length-prefixed input OK for RandomX)
    unsigned char inbuf[88];
    size_t inlen = header_len;
    if (inlen > sizeof(inbuf) - 8) inlen = sizeof(inbuf) - 8;
    memcpy(inbuf, header, inlen);
    uint64_t nbe = htobe64(nonce);
    memcpy(inbuf + inlen, &nbe, 8);
    inlen += 8;

    static __thread randomx_vm *vm = NULL;
    static __thread uint64_t tls_seed_ver = 0;

    // Recreate VM if seed changed
    if (!vm || tls_seed_ver != g_rx_seed_ver) {
        if (vm) { randomx_destroy_vm(vm); vm = NULL; }
        pthread_mutex_lock(&rx_lock);
        randomx_cache *cache = g_rx_cache;
        if (cache) {
            uint32_t vm_flags = (g_rx_flags & RANDOMX_FLAG_JIT) ? RANDOMX_FLAG_JIT : 0u;
            vm = randomx_create_vm(vm_flags, cache, NULL);
            tls_seed_ver = g_rx_seed_ver;
        }
        pthread_mutex_unlock(&rx_lock);
        if (!vm) return -1;
    }

    randomx_calculate_hash(vm, inbuf, inlen, out32);
    return 0;
}

static int hash_randomx_data(const unsigned char *input, size_t len, unsigned char out32[32])
{
    static __thread randomx_vm *vm = NULL;
    static __thread uint64_t tls_seed_ver = 0;

    if (!vm || tls_seed_ver != g_rx_seed_ver) {
        if (vm) { randomx_destroy_vm(vm); vm = NULL; }
        pthread_mutex_lock(&rx_lock);
        randomx_cache *cache = g_rx_cache;
        if (cache) {
            uint32_t vm_flags = (g_rx_flags & RANDOMX_FLAG_JIT) ? RANDOMX_FLAG_JIT : 0u;
            vm = randomx_create_vm(vm_flags, cache, NULL);
            tls_seed_ver = g_rx_seed_ver;
        }
        pthread_mutex_unlock(&rx_lock);
        if (!vm) return -1;
    }
    randomx_calculate_hash(vm, input, len, out32);
    return 0;
}

// inline asm helpers
static inline uint64_t bswap64_asm(uint64_t x)
{
#if defined(__aarch64__)
    uint64_t r;
    __asm__ __volatile__("rev %0, %1" : "=r"(r) : "r"(x));
    return r;
#elif defined(__x86_64__)
    uint64_t r = x;
    __asm__ __volatile__("bswap %0" : "+r"(r));
    return r;
#else
    return __builtin_bswap64(x);
#endif
}

static inline int hash_meets_target(const unsigned char hash_le[32], const unsigned char target_be[32])
{
    // Fast path: interpret 32-byte values as 4x u64 and compare in big-endian order.
    const uint64_t *h64 = (const uint64_t *)hash_le;       // LE words
    uint64_t hb0 = bswap64_asm(h64[3]); // first 8 bytes in BE
    uint64_t hb1 = bswap64_asm(h64[2]);
    uint64_t hb2 = bswap64_asm(h64[1]);
    uint64_t hb3 = bswap64_asm(h64[0]);

    uint64_t t0, t1, t2, t3;
    memcpy(&t0, target_be + 0, 8);
    memcpy(&t1, target_be + 8, 8);
    memcpy(&t2, target_be + 16, 8);
    memcpy(&t3, target_be + 24, 8);

    // Convert target limbs from big-endian bytes to host-endian u64 values
    t0 = be64toh(t0);
    t1 = be64toh(t1);
    t2 = be64toh(t2);
    t3 = be64toh(t3);

#if defined(__aarch64__)
    // Inline assembly: lexicographic compare of 4x u64 limbs
    // Return 1 if (hb0,hb1,hb2,hb3) <= (t0,t1,t2,t3) in big-endian order
    uint32_t ret;
    __asm__ __volatile__(
        "cmp %x[hb0], %x[t0]\n\t"
        "b.lt 1f\n\t"
        "b.gt 2f\n\t"
        "cmp %x[hb1], %x[t1]\n\t"
        "b.lt 1f\n\t"
        "b.gt 2f\n\t"
        "cmp %x[hb2], %x[t2]\n\t"
        "b.lt 1f\n\t"
        "b.gt 2f\n\t"
        "cmp %x[hb3], %x[t3]\n\t"
        "b.ls 1f\n\t"        // hb3 <= t3
        "2:\n\t"
        "mov %w[ret], #0\n\t"
        "b 3f\n\t"
        "1:\n\t"
        "mov %w[ret], #1\n\t"
        "3:\n\t"
        : [ret] "=r" (ret)
        : [hb0] "r" (hb0), [hb1] "r" (hb1), [hb2] "r" (hb2), [hb3] "r" (hb3),
          [t0] "r" (t0),   [t1] "r" (t1),   [t2] "r" (t2),   [t3] "r" (t3)
        : "cc"
    );
    return (int)ret;
#else
    if (hb0 != t0) return hb0 < t0;
    if (hb1 != t1) return hb1 < t1;
    if (hb2 != t2) return hb2 < t2;
    return hb3 <= t3;
#endif
}
#endif

// simple job registry for abort by job_id
#define MAX_JOBS 1024
static job_t *jobs[MAX_JOBS];
static uint64_t job_ids[MAX_JOBS];
static pthread_mutex_t jobs_lock = PTHREAD_MUTEX_INITIALIZER;

static void jobs_add(uint64_t id, job_t *j){
    pthread_mutex_lock(&jobs_lock);
    for (int i=0;i<MAX_JOBS;i++){
        if (!jobs[i]){ jobs[i]=j; job_ids[i]=id; break; }
    }
    pthread_mutex_unlock(&jobs_lock);
}

static job_t* jobs_find(uint64_t id){
    pthread_mutex_lock(&jobs_lock);
    job_t* r=NULL;
    for (int i=0;i<MAX_JOBS;i++) if (jobs[i] && job_ids[i]==id){ r=jobs[i]; break; }
    pthread_mutex_unlock(&jobs_lock);
    return r;
}

static void jobs_remove(uint64_t id){
    pthread_mutex_lock(&jobs_lock);
    for (int i=0;i<MAX_JOBS;i++) if (jobs[i] && job_ids[i]==id){ jobs[i]=NULL; job_ids[i]=0; break; }
    pthread_mutex_unlock(&jobs_lock);
}

static int enqueue_job(job_t* j) {
    pthread_mutex_lock(&jq_lock);
    int next = (jq_tail+1)%MAX_QUEUE;
    if (next == jq_head) { pthread_mutex_unlock(&jq_lock); return -1; } // full
    job_queue[jq_tail]=j; jq_tail=next;
    pthread_cond_signal(&jq_cond);
    pthread_mutex_unlock(&jq_lock);
    return 0;
}
static job_t* dequeue_job() {
    pthread_mutex_lock(&jq_lock);
    while (jq_head == jq_tail) pthread_cond_wait(&jq_cond, &jq_lock);
    job_t* j = job_queue[jq_head]; jq_head=(jq_head+1)%MAX_QUEUE;
    pthread_mutex_unlock(&jq_lock);
    return j;
}

/* conn_ctx_t typedef defined earlier */

static ssize_t io_read(conn_ctx_t *ctx, void *buf, size_t len) {
    // Serve from prefetch buffer first, if any
    if (ctx->prefetch && ctx->prefetch_off < ctx->prefetch_len) {
        size_t rem = ctx->prefetch_len - ctx->prefetch_off;
        size_t n = rem < len ? rem : len;
        memcpy(buf, ctx->prefetch + ctx->prefetch_off, n);
        ctx->prefetch_off += n;
        if (ctx->prefetch_off == ctx->prefetch_len) {
            free(ctx->prefetch);
            ctx->prefetch = NULL;
            ctx->prefetch_len = ctx->prefetch_off = 0;
        }
        return (ssize_t)n;
    }
#ifdef HAVE_OPENSSL
    if (ctx->ssl) {
        for(;;){
            int r = SSL_read(ctx->ssl, buf, (int)len);
            if (r > 0) return r;
            int e = SSL_get_error(ctx->ssl, r);
            if (e == SSL_ERROR_WANT_READ) { (void)wait_fd_ready(ctx->fd, 0, -1); continue; }
            if (e == SSL_ERROR_WANT_WRITE){ (void)wait_fd_ready(ctx->fd, 1, -1); continue; }
            return -1;
        }
    }
#endif
    return read(ctx->fd, buf, len);
}

static ssize_t io_write(conn_ctx_t *ctx, const void *buf, size_t len) {
#ifdef HAVE_OPENSSL
    if (ctx->ssl) {
        size_t off = 0;
        while (off < len) {
            int w = SSL_write(ctx->ssl, (const char*)buf + off, (int)(len - off));
            if (w > 0) { off += (size_t)w; continue; }
            int e = SSL_get_error(ctx->ssl, w);
            if (e == SSL_ERROR_WANT_READ) { (void)wait_fd_ready(ctx->fd, 0, -1); continue; }
            if (e == SSL_ERROR_WANT_WRITE){ (void)wait_fd_ready(ctx->fd, 1, -1); continue; }
            return -1;
        }
        return (ssize_t)len;
    }
#endif
    return write(ctx->fd, buf, len);
}

static int send_frame_locked(conn_ctx_t *ctx, uint8_t opcode, const void* payload, uint64_t len) {
    uint64_t total = len + 1;
    unsigned char hdr[8];
    for (int i=7;i>=0;--i){ hdr[i]=total & 0xFF; total >>=8; }
    pthread_mutex_lock(&ctx->wlock);
    if (io_write(ctx, hdr, 8) != 8){ pthread_mutex_unlock(&ctx->wlock); __sync_add_and_fetch(&g_ctr_errors, 1); return -1; }
    if (io_write(ctx, &opcode, 1) != 1){ pthread_mutex_unlock(&ctx->wlock); __sync_add_and_fetch(&g_ctr_errors, 1); return -1; }
    if (len>0) if (io_write(ctx, payload, (size_t)len) != (ssize_t)len){ pthread_mutex_unlock(&ctx->wlock); __sync_add_and_fetch(&g_ctr_errors, 1); return -1; }
    pthread_mutex_unlock(&ctx->wlock);
    __sync_add_and_fetch(&g_ctr_frames_out, 1);
    return 0;
}

// trivial hash stub: replace with real mining hash
static void hash_stub(const unsigned char *header, uint64_t nonce, unsigned char out32[32]) {
    // simple deterministic pseudo-hash (not secure); for POC only
    uint64_t v = nonce;
    for (int i=0;i<32;i++){ out32[i] = (unsigned char)((v >> (i%8)) & 0xFF); }
    for (int i=0;i<32;i++) out32[i] ^= header[i%80];
}

static void* worker_thread(void* arg) {
    conn_ctx_t *ctx = (conn_ctx_t*)arg; // same connection fd used for sending results
    for (;;) {
        job_t* j = dequeue_job();
        if (!j) continue;
        uint64_t processed = 0;
        // Extended mode local buffer
        unsigned char *buf = NULL;
        if (j->blob_len > 0) {
            buf = (unsigned char*)malloc(j->blob_len);
            if (!buf) { j->canceled = 1; }
            else memcpy(buf, j->blob, j->blob_len);
        }
        for (uint64_t i=0;i<j->nonce_count && !j->canceled;i++) {
            uint64_t nonce = j->nonce_start + i;
            unsigned char hash[32];
            int got = -1;
#ifdef HAVE_RANDOMX
            if (j->flags & 0x01) {
                ensure_rx_seed(j->rx_seed);
                if (j->blob_len > 0 && buf) {
                    // write nonce into blob (little-endian)
                    if (j->nonce_size == 8) {
                        uint64_t nle = nonce; memcpy(buf + j->nonce_off, &nle, 8);
                    } else {
                        uint32_t n32 = (uint32_t)nonce; memcpy(buf + j->nonce_off, &n32, 4);
                    }
                    // hash full blob
                    got = hash_randomx_data(buf, j->blob_len, hash);
                } else {
                    got = hash_randomx(j->header, sizeof(j->header), nonce, hash);
                }
            }
#endif
            if (got != 0) {
                hash_stub(j->header, nonce, hash);
            }
            // full 256-bit target comparison for correctness
            int ok = 0;
#ifdef HAVE_RANDOMX
            if (j->flags & 0x01) {
                ok = hash_meets_target(hash, j->target);
            } else
#endif
            {
                ok = (hash[0] == 0);
            }
            if (ok) {
                // send RESULT: job_id || nonce || hash32
                unsigned char payload[8+8+32];
                uint64_t jid = htobe64(j->job_id);
                memcpy(payload, &jid, 8);
                uint64_t nbe = htobe64(nonce);
                memcpy(payload+8, &nbe, 8);
                memcpy(payload+16, hash, 32);
                if (0 == send_frame_locked(ctx, OPC_RESULT, payload, sizeof(payload))) {
                    __sync_add_and_fetch(&g_ctr_results, 1);
                }
            }
            processed++;
            // optional: throttle yield to allow cancel handling
            if ((i & 0xFFF) == 0) sched_yield();
            if (g_throttle_on && g_throttle_sleep_ms > 0) {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)g_throttle_sleep_ms * 1000000L };
                nanosleep(&ts, NULL);
            }
        }
        // send DONE: job_id || processed_count
        unsigned char donep[8+8];
        uint64_t jid = htobe64(j->job_id);
        memcpy(donep, &jid, 8);
        uint64_t pbe = htobe64(processed);
        memcpy(donep+8, &pbe, 8);
        if (0 == send_frame_locked(ctx, OPC_DONE, donep, sizeof(donep))) {
            __sync_add_and_fetch(&g_ctr_done, 1);
        }
        jobs_remove(j->job_id);
        if (buf) free(buf);
        if (j->blob) free(j->blob);
        free(j);
    }
    return NULL;
}

static void* heartbeat_thread(void *arg){
    conn_ctx_t *ctx = (conn_ctx_t*)arg;
    for(;;){
        struct timespec ts = { .tv_sec = 5, .tv_nsec = 0 };
        nanosleep(&ts, NULL);
        if (send_frame_locked(ctx, OPC_PING, NULL, 0) != 0) break;
    }
    return NULL;
}

static void handle_connection(int cfd) {
    // simple fixed meta: cpu_count=online, max_batch=1<<20
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    int workers = (online > 0 && online < 256) ? (int)online : 4;
    if (g_max_workers > 0 && workers > g_max_workers) workers = g_max_workers;

    conn_ctx_t *ctx = (conn_ctx_t*)calloc(1, sizeof(conn_ctx_t));
    ctx->fd = cfd;
    pthread_mutex_init(&ctx->wlock, NULL);

    // TLS accept (if enabled)
    #ifdef HAVE_OPENSSL
    if (g_tls_enabled && g_ssl_ctx) {
        ctx->ssl = SSL_new(g_ssl_ctx);
        if (!ctx->ssl) { __sync_add_and_fetch(&g_ctr_tls_errors, 1); log_emit(LOG_ERROR, "SSL_new failed"); goto conn_close; }
        SSL_set_fd(ctx->ssl, cfd);
        if (ssl_accept_with_timeout(ctx->ssl, cfd, 5000) != 0) {
            __sync_add_and_fetch(&g_ctr_tls_errors, 1);
            log_emit(LOG_ERROR, "TLS accept timeout/failure");
            SSL_free(ctx->ssl); ctx->ssl=NULL; goto conn_close;
        }
        __sync_add_and_fetch(&g_ctr_tls_accepts, 1);
        log_emit(LOG_INFO, "TLS accepted");
    }
    #endif

    // Phase 1/2: optional/required handshake with token auth
    int handshake_ok = 1;
    if (g_require_handshake) {
        uint8_t op=0; unsigned char *pl=NULL; uint64_t plen=0;
        if (recv_frame_simple(ctx, &op, &pl, &plen, 5000) != 0 || op != OPC_CLIENT_HELLO) {
            send_error(ctx, 0x0002 /*auth_required*/, "handshake required"); __sync_add_and_fetch(&g_ctr_errors, 1);
            handshake_ok = 0;
        } else {
            // CLIENT_HELLO payload: ver(be16) | caps(be32) | tlen(be16) | token[...]
            if (plen < 2+4+2) {
                send_error(ctx, 0x0004 /*malformed*/, "bad hello"); __sync_add_and_fetch(&g_ctr_errors, 1);
                handshake_ok = 0;
            } else {
                const unsigned char *pp = pl;
                uint16_t ver; memcpy(&ver, pp, 2); pp+=2; ver = be16toh(ver);
                uint32_t caps; memcpy(&caps, pp, 4); pp+=4; caps = be32toh(caps);
                uint16_t tlen; memcpy(&tlen, pp, 2); pp+=2; tlen = be16toh(tlen);
                const char *tok = (const char*)pp; size_t toklen = (size_t)tlen;
                if (2+4+2+toklen > plen) toklen = 0; // tolerate unknown tail
                if (ver < 1) {
                    send_error(ctx, 0x0001 /*version_unsupported*/, "version"); __sync_add_and_fetch(&g_ctr_errors, 1);
                    handshake_ok = 0;
                } else if (!token_allowed(tok, toklen)) {
                    send_error(ctx, 0x0003 /*unauthorized*/, "token"); __sync_add_and_fetch(&g_ctr_errors, 1);
                    handshake_ok = 0;
                } else {
                    // SERVER_HELLO: ver(be16) | caps(be32) | auth_required(u8)
                    uint16_t vbe = htobe16(1);
                    uint32_t scaps = 0;
                    #ifdef HAVE_RANDOMX
                        scaps |= 0x1u; // RANDOMX
                    #endif
                    uint32_t scbe = htobe32(scaps);
                    uint8_t auth_req = (g_auth_token && *g_auth_token) ? 1 : 0;
                    unsigned char sh[2+4+1];
                    memcpy(sh, &vbe, 2); memcpy(sh+2, &scbe, 4); sh[6]=auth_req;
                    if (0 == send_frame_locked(ctx, OPC_SERVER_HELLO, sh, sizeof(sh))) __sync_add_and_fetch(&g_ctr_server_hello, 1);
                }
            }
        }
        if (pl) free(pl);
        if (!handshake_ok) goto conn_close;
    } else {
        // Optional handshake: avoid blocking indefinitely under TLS
        #ifdef HAVE_OPENSSL
        if (ctx->ssl) {
            // Skip optional probe when TLS is active
        } else
        #endif
        {
            // Try to read a frame quickly; if it's not HELLO, buffer it for later processing
            uint8_t op=0; unsigned char *pl=NULL; uint64_t plen=0;
            if (recv_frame_simple(ctx, &op, &pl, &plen, 500) == 0) {
                if (op == OPC_CLIENT_HELLO) {
                __sync_add_and_fetch(&g_ctr_hellos, 1);
                    const unsigned char *pp = pl;
                    if (plen >= 2+4+2) {
                        uint16_t ver; memcpy(&ver, pp, 2); pp+=2; ver = be16toh(ver);
                        uint32_t caps; memcpy(&caps, pp, 4); pp+=4; (void)caps;
                        uint16_t tlen; memcpy(&tlen, pp, 2); pp+=2; tlen = be16toh(tlen);
                        const char *tok = (const char*)pp; size_t toklen = (size_t)tlen;
                        if (2+4+2+toklen > plen) toklen = 0;
                        if (ver >= 1 && token_allowed(tok, toklen)) {
                            uint16_t vbe = htobe16(1);
                            uint32_t scaps = 0;
                            #ifdef HAVE_RANDOMX
                                scaps |= 0x1u;
                            #endif
                            uint32_t scbe = htobe32(scaps);
                            uint8_t auth_req = (g_auth_token && *g_auth_token) ? 1 : 0;
                            unsigned char sh[2+4+1];
                            memcpy(sh, &vbe, 2); memcpy(sh+2, &scbe, 4); sh[6]=auth_req;
                            if (0 == send_frame_locked(ctx, OPC_SERVER_HELLO, sh, sizeof(sh))) __sync_add_and_fetch(&g_ctr_server_hello, 1);
                        } else if (!token_allowed(tok, toklen)) {
                            send_error(ctx, 0x0003, "token"); __sync_add_and_fetch(&g_ctr_errors, 1);
                            if (pl) free(pl);
                            goto conn_close;
                        }
                    }
                } else {
                    // Buffer the non-HELLO frame for the main loop to consume
                    uint64_t total = plen + 1;
                    size_t flen = 8 + 1 + (size_t)plen;
                    unsigned char *fb = (unsigned char*)malloc(flen);
                    if (fb) {
                        uint64_t t = total;
                        for (int i=7;i>=0;--i){ fb[i] = (unsigned char)(t & 0xFF); t >>= 8; }
                        fb[8] = op;
                        if (plen) memcpy(fb+9, pl, (size_t)plen);
                        ctx->prefetch = fb;
                        ctx->prefetch_len = flen;
                        ctx->prefetch_off = 0;
                    }
                }
                if (pl) free(pl);
            }
        }
    }

    char meta[128];
    uint32_t adv_max_batch = (g_max_batch > 0 ? g_max_batch : 1048576u);
    int meta_len = snprintf(meta, sizeof(meta), "{\"cpu_count\":%d,\"max_batch\":%u}", workers, adv_max_batch);
    send_frame_locked(ctx, OPC_META_RESP, meta, (uint64_t)meta_len);

    // spawn worker threads (sharing same ctx for result writes)
    pthread_t *tids = (pthread_t*)calloc((size_t)workers, sizeof(pthread_t));
    for (int i=0;i<workers;i++){ pthread_create(&tids[i], NULL, worker_thread, ctx); pthread_detach(tids[i]); }
    free(tids);

    // heartbeat thread
    pthread_t hb; pthread_create(&hb, NULL, heartbeat_thread, ctx); pthread_detach(hb);

    // read frames loop (simple blocking)
    for (;;) {
        unsigned char hdr8[8];
        ssize_t r = io_read(ctx, hdr8, 8);
        if (r <= 0) break;
        __sync_add_and_fetch(&g_ctr_frames_in, 1);
        uint64_t len_be = 0;
        memcpy(&len_be, hdr8, 8);
        uint64_t len = be64toh(len_be);
        // Cap frame length to 1 MiB payload to avoid OOM
        if (len == 0 || len > ((1ULL<<20) + 1)) { send_error(ctx, 0x0004, "frame too large"); break; }
        if (len == 0) break;
        unsigned char opcode;
        if (io_read(ctx, &opcode, 1) != 1) break;
        uint64_t payload_len = len - 1;
        unsigned char *p = malloc(payload_len?payload_len:1);
        if (payload_len) {
            ssize_t got = 0;
            while (got < (ssize_t)payload_len) {
                ssize_t z = io_read(ctx, p+got, payload_len - got);
                if (z <= 0) { free(p); goto conn_close; }
                got += z;
            }
        }
        if (opcode == OPC_JOB_SUBMIT) {
            // support payload with/without job_id and optional flags byte at end
            // formats:
            //  a) 80+32+8+4 = 124 bytes (no job_id, no flags)
            //  b) 80+32+8+4+8 = 132 bytes (with job_id)
            //  c) 80+32+8+4+8+1 = 133 bytes (with job_id + flags)
            job_t* j = calloc(1, sizeof(job_t));
            if (!j) { free(p); continue; }
            uint8_t *pp = p;
            // Extended format check: magic 'X''J'
            if (payload_len >= 2 && pp[0] == 'X' && pp[1] == 'J') {
                pp += 2;
                if ((size_t)(pp - p) >= payload_len) { free(j); free(p); continue; }
                uint8_t ver = *pp++; (void)ver;
                uint64_t jid; if ((size_t)(pp - p) + 8 > payload_len) { free(j); free(p); continue; }
                memcpy(&jid, pp, 8); pp += 8; j->job_id = be64toh(jid);
                if ((size_t)(pp - p) + 1 > payload_len) { free(j); free(p); continue; }
                j->flags = *pp++;
                if ((size_t)(pp - p) + 1 + 4 + 4 > payload_len) { free(j); free(p); continue; }
                j->nonce_size = *pp++;
                uint32_t offbe; memcpy(&offbe, pp, 4); pp += 4; j->nonce_off = be32toh(offbe);
                uint32_t blbe; memcpy(&blbe, pp, 4); pp += 4; j->blob_len = be32toh(blbe);
                if ((size_t)(pp - p) + j->blob_len + 8 + 4 + 32 > payload_len) { free(j); free(p); continue; }
                if (j->blob_len > 0) { j->blob = (unsigned char*)malloc(j->blob_len); if (!j->blob) { free(j); free(p); continue; } memcpy(j->blob, pp, j->blob_len); }
                pp += j->blob_len;
                uint64_t ns; memcpy(&ns, pp, 8); pp += 8; j->nonce_start = be64toh(ns);
                uint32_t nc; memcpy(&nc, pp, 4); pp += 4; j->nonce_count = be32toh(nc);
                if (g_max_batch > 0 && j->nonce_count > g_max_batch) j->nonce_count = g_max_batch;
                memcpy(j->target, pp, 32); pp += 32;
                // Optional target64 (be64) if present
                if ((size_t)(pp - p) + 8 <= payload_len) {
                    uint64_t t64; memcpy(&t64, pp, 8); pp += 8; j->target64 = be64toh(t64);
                }
#ifdef HAVE_RANDOMX
                if (j->flags & 0x01) {
                    if ((size_t)(pp - p) + 32 + 4 <= payload_len) {
                        memcpy(j->rx_seed, pp, 32); pp += 32;
                        uint32_t bhe; memcpy(&bhe, pp, 4); pp += 4; j->rx_height = be32toh(bhe);
                    } else {
                        j->flags &= ~0x01;
                    }
                }
#endif
            } else {
                // Legacy format
                if (payload_len < (80+32+8+4)) { free(j); free(p); continue; }
                memcpy(j->header, pp, 80); pp += 80;
                memcpy(j->target, pp, 32); pp += 32;
                uint64_t ns; memcpy(&ns, pp, 8); pp += 8; j->nonce_start = be64toh(ns);
                uint32_t nc; memcpy(&nc, pp, 4); pp += 4; j->nonce_count = be32toh(nc);
                if (g_max_batch > 0 && j->nonce_count > g_max_batch) j->nonce_count = g_max_batch;
                j->flags = 0;
                j->canceled = 0;
                if (payload_len >= (80+32+8+4+8)) {
                    uint64_t jid2; memcpy(&jid2, pp, 8); pp += 8; j->job_id = be64toh(jid2);
                } else {
                    j->job_id = (uint64_t)time(NULL) ^ (uint64_t)rand();
                }
                if ((size_t)(pp - p) < payload_len) {
                    // optional flags
                    j->flags = *pp; pp += 1;
                }
#ifdef HAVE_RANDOMX
                if (j->flags & 0x01) {
                    if ((size_t)(pp - p) + 32 + 4 <= payload_len) {
                        memcpy(j->rx_seed, pp, 32); pp += 32;
                        uint32_t bhe; memcpy(&bhe, pp, 4); pp += 4; j->rx_height = be32toh(bhe);
                    } else {
                        // missing RandomX params -> disable
                        j->flags &= ~0x01;
                    }
                }
#endif
            }
            jobs_add(j->job_id, j);
            if (enqueue_job(j) != 0) { jobs_remove(j->job_id); if (j->blob) free(j->blob); free(j); __sync_add_and_fetch(&g_ctr_jobs_drop, 1); }
            else { __sync_add_and_fetch(&g_ctr_jobs_enq, 1); }
        } else if (opcode == OPC_JOB_ABORT) {
            if (payload_len >= 8){
                uint64_t jid; memcpy(&jid, p, 8); uint64_t job_id = be64toh(jid);
                job_t *j = jobs_find(job_id);
                if (j){ j->canceled = 1; }
            }
        } else if (opcode == OPC_PING) {
            send_frame_locked(ctx, OPC_PONG, NULL, 0);
            __sync_add_and_fetch(&g_ctr_pings, 1);
        } else if (opcode == OPC_META_REQ) {
            // re-send META_RESP
            send_frame_locked(ctx, OPC_META_RESP, meta, (uint64_t)meta_len);
        }
        free(p);
    }
conn_close:
    #ifdef HAVE_OPENSSL
    if (ctx->ssl) { SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); ctx->ssl = NULL; }
    #endif
    close(cfd);
    pthread_mutex_destroy(&ctx->wlock);
    if (ctx->prefetch) { free(ctx->prefetch); ctx->prefetch = NULL; }
    free(ctx);
}

static int listen_socket(const char *addr, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int opt=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (addr && *addr) {
        struct in_addr ina;
        if (inet_pton(AF_INET, addr, &ina) == 1) {
            sa.sin_addr = ina;
        } else {
            sa.sin_addr.s_addr = htonl(INADDR_ANY);
        }
    } else {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(s, (struct sockaddr*)&sa, sizeof(sa))<0){close(s);return -1;}
    if (listen(s, 8)<0){close(s);return -1;}
    return s;
}

// ---- Phase 4: sandbox ----
static int drop_privileges_and_sandbox()
{
    // no_new_privs
    if (g_no_new_privs) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            perror("prctl no_new_privs");
            return -1;
        }
    }
    // chroot if requested
    if (g_chroot_dir) {
        if (chdir(g_chroot_dir) != 0) { perror("chdir chroot"); return -1; }
        if (chroot(g_chroot_dir) != 0) { perror("chroot"); return -1; }
        if (chdir("/") != 0) { perror("chdir /"); return -1; }
    }
    // drop to user
    if (g_run_as_user) {
        struct passwd *pw = getpwnam(g_run_as_user);
        if (!pw) { fprintf(stderr, "unknown user: %s\n", g_run_as_user); return -1; }
        if (setgid(pw->pw_gid) != 0) { perror("setgid"); return -1; }
        if (setgroups(0, NULL) != 0) { perror("setgroups"); return -1; }
        if (setuid(pw->pw_uid) != 0) { perror("setuid"); return -1; }
    }
    return 0;
}

int main(int argc, char **argv) {
    int port = 9000;
    const char *env_tok = getenv("P2PRIG_TOKEN");
    if (env_tok && *env_tok) g_auth_token = env_tok;
    // simple args: -p <port>  -T <token>  --require-handshake
    // TLS (if built with HAVE_OPENSSL): --tls-cert <pem> --tls-key <pem> [--tls-ca <pem>] [--tls-require-client-cert]
    for (int i=1;i<argc;i++){
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc){ port = atoi(argv[++i]); }
        else if (strcmp(argv[i], "-T") == 0 && i+1 < argc){ g_auth_token = argv[++i]; }
        else if (strcmp(argv[i], "--require-handshake") == 0){ g_require_handshake = 1; }
        else if (strcmp(argv[i], "--log-level") == 0 && i+1 < argc){ const char *lv = argv[++i]; g_log_level = (!strcmp(lv,"debug")?LOG_DEBUG:!strcmp(lv,"info")?LOG_INFO:LOG_ERROR); }
        else if (strcmp(argv[i], "--stats-interval") == 0 && i+1 < argc){ g_stats_interval_sec = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--max-workers") == 0 && i+1 < argc){ g_max_workers = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--max-batch") == 0 && i+1 < argc){ g_max_batch = (uint32_t)strtoul(argv[++i], NULL, 10); }
        else if (strcmp(argv[i], "--throttle-temp") == 0 && i+1 < argc){ g_throttle_temp_c = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--throttle-batt") == 0 && i+1 < argc){ g_throttle_batt_pct = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--throttle-sleep") == 0 && i+1 < argc){ g_throttle_sleep_ms = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--run-as") == 0 && i+1 < argc){ g_run_as_user = argv[++i]; }
        else if (strcmp(argv[i], "--chroot") == 0 && i+1 < argc){ g_chroot_dir = argv[++i]; }
        else if (strcmp(argv[i], "--no-new-privs") == 0){ g_no_new_privs = 1; }
        else if (strcmp(argv[i], "--bind") == 0 && i+1 < argc){ g_bind_addr = argv[++i]; }
        #ifdef HAVE_OPENSSL
        else if (strcmp(argv[i], "--tls-cert") == 0 && i+1 < argc){ g_tls_cert = argv[++i]; }
        else if (strcmp(argv[i], "--tls-key") == 0 && i+1 < argc){ g_tls_key = argv[++i]; }
        else if (strcmp(argv[i], "--tls-ca") == 0 && i+1 < argc){ g_tls_ca = argv[++i]; }
        else if (strcmp(argv[i], "--tls-require-client-cert") == 0){ g_tls_require_client_cert = 1; }
        #endif
        else if (argv[i][0] != '\0' && argv[i][0] != '-') { port = atoi(argv[i]); }
    }
    #ifdef HAVE_OPENSSL
    if (g_tls_cert && g_tls_key) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        const SSL_METHOD *method = TLS_server_method();
        g_ssl_ctx = SSL_CTX_new(method);
        if (!g_ssl_ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); return 1; }
        if (SSL_CTX_use_certificate_file(g_ssl_ctx, g_tls_cert, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "use_certificate failed\n"); return 1; }
        if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_tls_key, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "use_key failed\n"); return 1; }
        if (g_tls_ca) {
            if (SSL_CTX_load_verify_locations(g_ssl_ctx, g_tls_ca, NULL) != 1) {
                fprintf(stderr, "load CA failed\n"); return 1; }
            SSL_CTX_set_verify(g_ssl_ctx, g_tls_require_client_cert ? (SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_PEER, NULL);
        } else if (g_tls_require_client_cert) {
            fprintf(stderr, "--tls-require-client-cert needs --tls-ca\n"); return 1;
        }
        g_tls_enabled = 1;
    }
    #endif
    int ls = listen_socket(g_bind_addr, port);
    if (ls<0){ perror("listen"); return 1; }
    // Apply sandbox after listening (to allow low ports) but before accept loop
    if (drop_privileges_and_sandbox() != 0) {
        fprintf(stderr, "sandbox init failed\n");
        return 1;
    }
    // Launch throttle monitor + stats thread
    pthread_t tm; pthread_create(&tm, NULL, throttle_monitor_thread, NULL); pthread_detach(tm);
    pthread_t st; pthread_create(&st, NULL, stats_thread, NULL); pthread_detach(st);

    // Reap children to avoid zombies
    signal(SIGCHLD, SIG_IGN);

    printf("device daemon listening on %s:%d (handshake:%s, token:%s, workers:%s, max_batch:%s"
#ifdef HAVE_OPENSSL
           ", tls:%s"
#endif
           ")\n",
           g_bind_addr ? g_bind_addr : "*", port, g_require_handshake?"on":"off", (g_auth_token&&*g_auth_token)?"set":"none",
           (g_max_workers>0?"capped":"auto"), (g_max_batch>0?"capped":"unlimited")
#ifdef HAVE_OPENSSL
           , g_tls_enabled?"on":"off"
#endif
    );
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) continue;
        if (!fork()) {
            close(ls);
            handle_connection(c);
            exit(0);
        }
        close(c);
    }
    return 0;
}
