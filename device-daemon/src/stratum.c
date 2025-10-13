#include "stratum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
// Simple JSON helpers (minimal implementation)
static int json_send(stratum_t *s, const char *method, const char *params) {
    char msg[STRATUM_BUFFER_SIZE];
    int len = snprintf(msg, sizeof(msg),
        "{\"id\":%lu,\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s}\n",
        s->msg_id++, method, params);
    if (len >= (int)sizeof(msg)) {
        fprintf(stderr, "Stratum: Message too large\n");
        return -1;
    }
    ssize_t sent = send(s->socket_fd, msg, len, 0);
    if (sent != len) {
        fprintf(stderr, "Stratum: Failed to send message\n");
        return -1;
    }
    printf("Stratum TX: %.*s", len - 1, msg);
    return 0;
}

// Get the first top-level numeric id value ("id":123) and ignore string ids ("id":"...")
static int json_get_numeric_id(const char *json, uint64_t *out) {
    if (!json || !out) return -1;
    const char *p = json;
    while ((p = strstr(p, "\"id\":")) != NULL) {
        p += 5; // move past "id":
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '"') {
            // string id (e.g., session id), skip this occurrence
            p++;
            const char *q = strchr(p, '"');
            if (!q) return -1;
            p = q + 1;
            continue;
        }
        // parse number
        uint64_t val = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            val = val * 10 + (uint64_t)(*p - '0');
            p++; digits++;
        }
        if (digits > 0) { *out = val; return 0; }
    }
    return -1;
}

static char *json_get_string(const char *json, const char *key) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *start = strstr(json, search);
    if (!start) return NULL;
    start += strlen(search);
    const char *end = strchr(start, '"');
    if (!end) return NULL;
    size_t len = end - start;
    char *result = malloc(len + 1);
    if (!result) return NULL;
    memcpy(result, start, len);
    result[len] = '\0';
    return result;
}

// Minimal hex decoder (expects even-length ASCII hex)
static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_out, size_t *out_len) {
    size_t n = strlen(hex);
    if (n % 2 != 0) return -1;
    size_t bytes = n / 2;
    if (bytes > max_out) return -1;
    for (size_t i = 0; i < bytes; i++) {
        char c1 = hex[2*i];
        char c2 = hex[2*i+1];
        int v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' : (c1 >= 'a' && c1 <= 'f') ? 10 + c1 - 'a' : (c1 >= 'A' && c1 <= 'F') ? 10 + c1 - 'A' : -1;
        int v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' : (c2 >= 'a' && c2 <= 'f') ? 10 + c2 - 'a' : (c2 >= 'A' && c2 <= 'F') ? 10 + c2 - 'A' : -1;
        if (v1 < 0 || v2 < 0) return -1;
        out[i] = (uint8_t)((v1 << 4) | v2);
    }
    if (out_len) *out_len = bytes;
    return 0;
}

// Parse hex string representing little-endian target to uint64
static int hex_to_u64_le(const char *hex, uint64_t *out) {
    if (!hex || !out) return -1;
    size_t n = strlen(hex);
    if (n == 0) return -1;
    size_t take = n > 16 ? 16 : n;
    char buf[17] = {0};
    if (take % 2 == 1) {
        buf[0] = '0';
        strncpy(buf + 1, hex, take - 1);
    } else {
        strncpy(buf, hex, take);
    }
    uint8_t bytes[8] = {0};
    size_t bytes_count = take / 2;
    for (size_t i = 0; i < bytes_count && i < 8; i++) {
        char c1 = buf[2 * i];
        char c2 = buf[2 * i + 1];
        int v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' : (c1 >= 'a' && c1 <= 'f') ? 10 + c1 - 'a' : (c1 >= 'A' && c1 <= 'F') ? 10 + c1 - 'A' : -1;
        int v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' : (c2 >= 'a' && c2 <= 'f') ? 10 + c2 - 'a' : (c2 >= 'A' && c2 <= 'F') ? 10 + c2 - 'A' : -1;
        if (v1 < 0 || v2 < 0) return -1;
        bytes[i] = (uint8_t)((v1 << 4) | v2);
    }
    uint64_t val = 0;
    for (int i = (int)bytes_count - 1; i >= 0; i--) {
        val = (val << 8) | bytes[i];
    }
    *out = val;
    return 0;
}

// Compute full 256-bit target from 32-bit pool target (exact)
// Identity: (2^256 - 1) / (2^32 - 1) = 1 + 2^32 + 2^64 + ... + 2^224
// Therefore: target256 = floor(((2^256 - 1) * t32) / 0xFFFFFFFF) = t32 * sum_{k=0..7} 2^{32k}
// Which is simply eight 32-bit little-endian limbs, each equal to t32.
static void compute_target256(uint32_t t32, uint8_t output[32]) {
    for (int k = 0; k < 8; k++) {
        output[4 * k + 0] = (uint8_t)(t32 & 0xFF);
        output[4 * k + 1] = (uint8_t)((t32 >> 8) & 0xFF);
        output[4 * k + 2] = (uint8_t)((t32 >> 16) & 0xFF);
        output[4 * k + 3] = (uint8_t)((t32 >> 24) & 0xFF);
    }
}

stratum_t *stratum_create(const char *host, int port, const char *user, const char *password) {
    stratum_t *s = calloc(1, sizeof(stratum_t));
    if (!s) return NULL;
    
    strncpy(s->host, host, sizeof(s->host) - 1);
    s->port = port;
    strncpy(s->user, user, sizeof(s->user) - 1);
    strncpy(s->password, password, sizeof(s->password) - 1);
    
    s->socket_fd = -1;
    s->state = STRATUM_STATE_DISCONNECTED;
    s->msg_id = 1;
    
    return s;
}

void stratum_destroy(stratum_t *s) {
    if (!s) return;
    
    if (s->socket_fd >= 0) {
        close(s->socket_fd);
    }
    
    free(s);
}

int stratum_connect(stratum_t *s) {
    if (!s || s->socket_fd >= 0) return -1;
    
    printf("Stratum: Connecting to %s:%d...\n", s->host, s->port);
    
    // Resolve hostname
    struct hostent *host = gethostbyname(s->host);
    if (!host) {
        fprintf(stderr, "Stratum: Failed to resolve %s\n", s->host);
        return -1;
    }
    
    // Create socket
    s->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->socket_fd < 0) {
        perror("socket");
        return -1;
    }
    
    // Set non-blocking
    int flags = fcntl(s->socket_fd, F_GETFL, 0);
    fcntl(s->socket_fd, F_SETFL, flags | O_NONBLOCK);
    
    // Connect
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(s->port);
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
    
    int ret = connect(s->socket_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        perror("connect");
        close(s->socket_fd);
        s->socket_fd = -1;
        return -1;
    }
    
    s->state = STRATUM_STATE_CONNECTED;
    s->connected_at = time(NULL);
    s->last_activity = time(NULL);
    
    printf("Stratum: Connected\n");
    return 0;
}

int stratum_disconnect(stratum_t *s) {
    if (!s || s->socket_fd < 0) return -1;
    
    close(s->socket_fd);
    s->socket_fd = -1;
    s->state = STRATUM_STATE_DISCONNECTED;
    
    printf("Stratum: Disconnected\n");
    return 0;
}

int stratum_is_connected(stratum_t *s) {
    return s && s->socket_fd >= 0 && s->state >= STRATUM_STATE_CONNECTED;
}

int stratum_subscribe(stratum_t *s) {
    if (!stratum_is_connected(s)) return -1;
    
    // For Monero/RandomX pools (e.g., Unmineable RX), perform login instead of Bitcoin-style subscribe
    printf("Stratum: Logging in (Monero style)...\n");
    char params[512];
    snprintf(params, sizeof(params), "{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"p2p-miner/1.1.0\"}", s->user, s->password);
    if (json_send(s, "login", params) != 0) {
        return -1;
    }
    s->state = STRATUM_STATE_AUTHORIZED;
    return 0;
}

int stratum_authorize(stratum_t *s) {
    // No-op for Monero-style protocol; login already authorizes
    if (!stratum_is_connected(s)) return -1;
    printf("Stratum: authorize skipped (already logged in)\n");
    return 0;
}

int stratum_submit_share(stratum_t *s, const char *job_id, uint64_t nonce, const char *result) {
    if (!stratum_is_connected(s) || !job_id || !result) return -1;
    
    printf("Stratum: Submitting share (job=%s, nonce=%lu)...\n", job_id, (unsigned long)nonce);
    
    // Format nonce as little-endian 4-byte hex (as in blob)
    char nonce_hex[9];
    uint32_t n32 = (uint32_t)nonce;
    unsigned char nb0 = (unsigned char)(n32 & 0xFF);
    unsigned char nb1 = (unsigned char)((n32 >> 8) & 0xFF);
    unsigned char nb2 = (unsigned char)((n32 >> 16) & 0xFF);
    unsigned char nb3 = (unsigned char)((n32 >> 24) & 0xFF);
    snprintf(nonce_hex, sizeof(nonce_hex), "%02x%02x%02x%02x", nb0, nb1, nb2, nb3);
    
    // Send Monero-style submit: {"id":"SESSION","job_id":"...","nonce":"...","result":"..."}
    char params[1024];
    snprintf(params, sizeof(params), "{\"id\":\"%s\",\"job_id\":\"%s\",\"nonce\":\"%s\",\"result\":\"%s\"}",
             s->session_id, job_id, nonce_hex, result);
    // capture rpc id before send
    uint64_t rpc_id = s->msg_id;
    if (json_send(s, "submit", params) != 0) {
        return -1;
    }
    s->pending_submit_id = rpc_id;
    
    s->shares_submitted++;
    return 0;
}

static int stratum_handle_message(stratum_t *s, const char *msg) {
    printf("Stratum RX: %s\n", msg);
    s->last_activity = time(NULL);
    
    // Capture session id from login result
    if (strstr(msg, "\"result\"")) {
        char *sid = json_get_string(msg, "id");
        if (sid) {
            strncpy(s->session_id, sid, sizeof(s->session_id) - 1);
            s->session_id[sizeof(s->session_id) - 1] = '\0';
            free(sid);
        }
    }
    
    // Check for Monero-style job notifications: "method":"job" or job fields in result
    if (strstr(msg, "\"method\":\"job\"") || strstr(msg, "\"job_id\"")) {
        char *job_id = json_get_string(msg, "job_id");
        char *blob_hex = json_get_string(msg, "blob");
        char *target_hex = json_get_string(msg, "target");
        char *seed_hex = json_get_string(msg, "seed_hash");
        char *algo = json_get_string(msg, "algo");
        if (job_id) {
            memset(&s->current_job, 0, sizeof(s->current_job));
            strncpy(s->current_job.job_id, job_id, sizeof(s->current_job.job_id) - 1);
            free(job_id);
            if (blob_hex) {
                size_t out_len = 0;
                if (hex_to_bytes(blob_hex, s->current_job.blob, sizeof(s->current_job.blob), &out_len) == 0) {
                    s->current_job.blob_size = out_len;
                }
                free(blob_hex);
            }
            if (target_hex) {
                strncpy(s->current_job.target, target_hex, sizeof(s->current_job.target) - 1);
                s->current_job.target[sizeof(s->current_job.target) - 1] = '\0';
                uint64_t t64 = 0;
                if (hex_to_u64_le(target_hex, &t64) == 0) {
                    uint32_t t32 = (uint32_t)(t64 & 0xFFFFFFFFu);
                    s->current_job.target_u32 = t32;
                    s->current_job.difficulty = (t32 > 0) ? (0xFFFFFFFFull / (uint64_t)t32) : 0;
                    // threshold64 ~= (UINT64_MAX * t32) / UINT32_MAX; use precise math via 128-bit if available
                    uint64_t thr;
                    #if defined(__GNUC__)
                    {
                        unsigned __int128 num = (unsigned __int128)UINT64_MAX * (unsigned __int128)t32;
                        unsigned __int128 den = (unsigned __int128)0xFFFFFFFFu;
                        thr = (uint64_t)(num / den);
                    }
                    #else
                        thr = ((uint64_t)t32) << 32; // fallback approximation
                    #endif
                    s->current_job.threshold64 = thr;
                    // Compute full 256-bit target for exact validation
                    compute_target256(t32, s->current_job.target256);
                } else {
                    s->current_job.target_u32 = 0;
                    s->current_job.difficulty = 0;
                    s->current_job.threshold64 = 0;
                    memset(s->current_job.target256, 0, 32);
                }
                free(target_hex);
            }
            if (seed_hex) {
                strncpy(s->current_job.seed_hash, seed_hex, sizeof(s->current_job.seed_hash) - 1);
                s->current_job.seed_hash[sizeof(s->current_job.seed_hash) - 1] = '\0';
                free(seed_hex);
            }
            if (algo) {
                strncpy(s->current_job.algo, algo, sizeof(s->current_job.algo) - 1);
                s->current_job.algo[sizeof(s->current_job.algo) - 1] = '\0';
                free(algo);
            }
            s->current_job.received_at = time(NULL);
            s->has_job = 1;
            s->jobs_received++;
            printf("Stratum: New job received: %s (blob=%zu bytes)\n", s->current_job.job_id, s->current_job.blob_size);
        }
    }
    
    // Check for share result responses by matching the top-level numeric id
    uint64_t rxid = 0;
    if (s->pending_submit_id != 0 && json_get_numeric_id(msg, &rxid) == 0 && rxid == s->pending_submit_id) {
        if (strstr(msg, "true") || strstr(msg, "\"status\":\"OK\"")) {
            s->shares_accepted++;
            printf("Stratum: Share accepted!\n");
        } else {
            s->shares_rejected++;
            printf("Stratum: Share rejected\n");
        }
        s->pending_submit_id = 0;
    }
    
    // Check for errors
    if (strstr(msg, "\"error\"")) {
        fprintf(stderr, "Stratum: Error from pool: %s\n", msg);
    }
    
    return 0;
}

int stratum_process(stratum_t *s, int timeout_ms) {
    if (!s || s->socket_fd < 0) return -1;
    
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(s->socket_fd, &readfds);
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int activity = select(s->socket_fd + 1, &readfds, NULL, NULL, &tv);
    if (activity < 0 && errno != EINTR) {
        perror("select");
        return -1;
    }
    
    if (activity > 0 && FD_ISSET(s->socket_fd, &readfds)) {
        ssize_t n = recv(s->socket_fd, s->recv_buffer + s->recv_len,
                        sizeof(s->recv_buffer) - s->recv_len - 1, 0);
        
        if (n <= 0) {
            if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                fprintf(stderr, "Stratum: Connection closed\n");
                stratum_disconnect(s);
                return -1;
            }
        } else {
            s->recv_len += n;
            s->recv_buffer[s->recv_len] = '\0';
            
            // Process complete lines
            char *line_start = s->recv_buffer;
            char *line_end;
            
            while ((line_end = strchr(line_start, '\n')) != NULL) {
                *line_end = '\0';
                
                if (strlen(line_start) > 0) {
                    stratum_handle_message(s, line_start);
                }
                
                line_start = line_end + 1;
            }
            
            // Move remaining data to start of buffer
            size_t remaining = s->recv_len - (line_start - s->recv_buffer);
            if (remaining > 0 && line_start != s->recv_buffer) {
                memmove(s->recv_buffer, line_start, remaining);
            }
            s->recv_len = remaining;
        }
    }
    
    return 0;
}

int stratum_get_job(stratum_t *s, stratum_job_t *job) {
    if (!s || !job || !s->has_job) return -1;
    
    memcpy(job, &s->current_job, sizeof(stratum_job_t));
    return 0;
}

int stratum_has_new_job(stratum_t *s) {
    return s && s->has_job;
}

void stratum_print_stats(stratum_t *s) {
    if (!s) return;
    
    printf("\n=== Stratum Statistics ===\n");
    printf("Pool: %s:%d\n", s->host, s->port);
    printf("State: %s\n", stratum_state_string(s->state));
    printf("Jobs Received: %lu\n", s->jobs_received);
    printf("Shares Submitted: %lu\n", s->shares_submitted);
    printf("Shares Accepted: %lu\n", s->shares_accepted);
    printf("Shares Rejected: %lu\n", s->shares_rejected);
    
    if (s->shares_submitted > 0) {
        double acceptance_rate = (double)s->shares_accepted / (double)s->shares_submitted * 100.0;
        printf("Acceptance Rate: %.1f%%\n", acceptance_rate);
    }
    
    if (s->state >= STRATUM_STATE_CONNECTED) {
        time_t now = time(NULL);
        time_t uptime = now - s->connected_at;
        printf("Connected For: %ld seconds\n", uptime);
    }
    
    printf("\n");
}

const char *stratum_state_string(stratum_state_t state) {
    switch (state) {
        case STRATUM_STATE_DISCONNECTED: return "Disconnected";
        case STRATUM_STATE_CONNECTING: return "Connecting";
        case STRATUM_STATE_CONNECTED: return "Connected";
        case STRATUM_STATE_SUBSCRIBED: return "Subscribed";
        case STRATUM_STATE_AUTHORIZED: return "Authorized";
        case STRATUM_STATE_READY: return "Ready";
        default: return "Unknown";
    }
}
