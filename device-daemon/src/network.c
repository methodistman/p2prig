#include "network.h"
#include "mining.h"
#include "crypto.h"
#include "storage.h"
#include "workload.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

// Cache of the last RandomX seed used for remote hashing on this node
static uint8_t g_remotehash_last_seed[32];
static int g_remotehash_seed_valid = 0;

// 64-bit host/network order helpers
static uint64_t htonll_u64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL))) << 32) | htonl((uint32_t)(v >> 32));
#else
    return v;
#endif
}

// --- WAL replay for work events ---
struct wal_replay_stats { int assigns; int results; };
static int wal_replay_cb(const uint8_t *rec, size_t len, void *udata) {
    struct wal_replay_stats *st = (struct wal_replay_stats*)udata;
    if (!rec || len == 0 || !st) return -1;
    uint8_t type = rec[0];
    if (type == 'A') {
        // 'A' | work_id(8) | nonce_start(8) | nonce_end(8) | node_id[32]
        if (len != (size_t)(1 + 8 + 8 + 8 + NODE_ID_SIZE)) return -1;
        st->assigns++;
        return 0;
    } else if (type == 'R') {
        // 'R' | work_id(8) | nonce(8) | hash[32] | status(1)
        if (len != (size_t)(1 + 8 + 8 + HASH_SIZE + 1)) return -1;
        st->results++;
        return 0;
    }
    // Unknown record; treat as error to force manual inspection
    return -1;
}

int network_send_workunit_assign(network_t *network, peer_t *peer,
                                 uint64_t work_id, uint64_t nonce_start, uint64_t nonce_end,
                                 const uint8_t data[], uint8_t flags) {
    if (!network || !peer || peer->socket_fd < 0 || !data) return -1;
    // WAL: record assignment intent first (type 'A')
    if (network->work_wal) {
        uint8_t rec[1 + 8 + 8 + 8 + NODE_ID_SIZE];
        uint8_t *w = rec; *w++ = 'A';
        uint64_t wid_be2 = htonll_u64(work_id); memcpy(w, &wid_be2, 8); w += 8;
        uint64_t ns_be2 = htonll_u64(nonce_start); memcpy(w, &ns_be2, 8); w += 8;
        uint64_t ne_be2 = htonll_u64(nonce_end); memcpy(w, &ne_be2, 8); w += 8;
        memcpy(w, peer->node_id, NODE_ID_SIZE); w += NODE_ID_SIZE;
        (void)wal_append(network->work_wal, rec, sizeof(rec));
    }
    uint8_t buf[1 + 1 + 2 + 8 + 8 + 8 + WORK_UNIT_SIZE + SIG_LEN];
    uint8_t *p = buf;
    *p++ = 1; // ver
    *p++ = flags;
    *p++ = 0; *p++ = 0; // rsv
    uint64_t wid_be = htonll_u64(work_id); memcpy(p, &wid_be, 8); p += 8;
    uint64_t ns_be = htonll_u64(nonce_start); memcpy(p, &ns_be, 8); p += 8;
    uint64_t ne_be = htonll_u64(nonce_end); memcpy(p, &ne_be, 8); p += 8;
    memcpy(p, data, WORK_UNIT_SIZE); p += WORK_UNIT_SIZE;
    uint32_t len = (uint32_t)(p - buf);
    int must_sign = (peer->requires_signing != 0);
    int want_sign = (network->config && network->config->sign_messages);
    int have_token = (network->config && network->config->auth_token[0] != '\0');
    if (must_sign && !have_token) {
        return -1; // cannot satisfy peer's requirement
    }
    if ((must_sign || want_sign) && have_token) {
        uint8_t tag[SIG_LEN];
        hmac_sha256((const uint8_t*)network->config->auth_token, strlen(network->config->auth_token), buf, len, tag);
        memcpy(p, tag, SIG_LEN); p += SIG_LEN; len += SIG_LEN;
    }
    return network_send_message(peer, MSG_WORKUNIT_ASSIGN, buf, len);
}

int network_send_workunit_result(network_t *network, peer_t *peer,
                                 uint64_t work_id, uint64_t nonce,
                                 const uint8_t hash[32], uint8_t status) {
    if (!network || !peer || peer->socket_fd < 0 || !hash) return -1;
    uint8_t buf[1 + 1 + 2 + 8 + 8 + HASH_SIZE + 1 + SIG_LEN];
    uint8_t *p = buf;
    *p++ = 1; // ver
    *p++ = 0; // flags
    *p++ = 0; *p++ = 0; // rsv
    uint64_t wid_be = htonll_u64(work_id); memcpy(p, &wid_be, 8); p += 8;
    uint64_t nonce_be = htonll_u64(nonce); memcpy(p, &nonce_be, 8); p += 8;
    memcpy(p, hash, HASH_SIZE); p += HASH_SIZE;
    *p++ = status;
    uint32_t len = (uint32_t)(p - buf);
    int must_sign = (peer->requires_signing != 0);
    int want_sign = (network->config && network->config->sign_messages);
    int have_token = (network->config && network->config->auth_token[0] != '\0');
    if (must_sign && !have_token) {
        return -1;
    }
    if ((must_sign || want_sign) && have_token) {
        uint8_t tag[SIG_LEN];
        hmac_sha256((const uint8_t*)network->config->auth_token, strlen(network->config->auth_token), buf, len, tag);
        memcpy(p, tag, SIG_LEN); p += SIG_LEN; len += SIG_LEN;
    }
    return network_send_message(peer, MSG_WORKUNIT_RESULT, buf, len);
}
static uint64_t ntohll_u64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (((uint64_t)ntohl((uint32_t)(v & 0xFFFFFFFFULL))) << 32) | ntohl((uint32_t)(v >> 32));
#else
    return v;
#endif
}

// Send all bytes on a (possibly non-blocking) socket, handling EINTR/EAGAIN
static ssize_t send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent_total = 0;
    while (sent_total < len) {
        ssize_t n = send(fd, p + sent_total, len - sent_total, 0);
        if (n > 0) {
            sent_total += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EINTR)) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // Yield briefly; caller should have called select() first.
            struct timespec ts; ts.tv_sec = 0; ts.tv_nsec = 1 * 1000 * 1000L; // 1ms
            nanosleep(&ts, NULL);
            continue;
        }
        return -1;
    }
    return (ssize_t)sent_total;
}

network_t *network_create(config_t *config, node_t *local_node) {
    network_t *network = calloc(1, sizeof(network_t));
    if (!network) return NULL;
    network->config = config;
    network->local_node = local_node;
    network->listen_fd = -1;
    network->discovery_fd = -1;
    network->peer_count = 0;
    network->is_master = (config->mode == MODE_MASTER);
    network->dataset_host_peer = NULL;
    network->last_discovery_beacon = 0;
    network->last_connect_attempt = 0;
    network->last_heartbeat_sent = 0;
    network->discovered_count = 0;
    network->pending_hash_active = 0;
    network->pending_hash_peer = NULL;
    network->pending_hash_expected = 0;
    network->pending_hash_outputs = NULL;
    network->pending_hash_status = -1;
    pthread_mutex_init(&network->peers_lock, NULL);
    pthread_mutex_init(&network->discovered_lock, NULL);
    network->accept_tokens = RL_ACCEPT_TOKENS_PER_SEC;
    network->accept_last_refill = time(NULL);
    // Open a small WAL for critical work events
    network->work_wal = wal_open("work.wal");
    // Replay existing WAL to count prior events (future: rebuild state)
    struct wal_replay_stats st = {0};
    (void)wal_iterate("work.wal", wal_replay_cb, &st);
    if (st.assigns || st.results) {
        printf("WAL: replayed %d assignments, %d results\n", st.assigns, st.results);
    }
    return network;
}

void network_broadcast_peer_list(network_t *network) {
    if (!network || network->peer_count == 0) return;
    // Snapshot discovered peers while holding lock, then release before building and sending
    const int MAX_SHARE = 32;
    discovered_peer_t share[MAX_SHARE]; int share_cnt = 0;
    time_t now = time(NULL);
    pthread_mutex_lock(&network->discovered_lock);
    for (int i = 0; i < network->discovered_count && share_cnt < MAX_SHARE; i++) {
        if ((now - network->discovered[i].last_seen) > 30) continue; // stale
        if (memcmp(network->discovered[i].node_id, network->local_node->id, NODE_ID_SIZE) == 0) continue;
        share[share_cnt++] = network->discovered[i];
    }
    pthread_mutex_unlock(&network->discovered_lock);
    // Compute total payload len: count (4) + sum of entries
    // Entry v1: u8 version(1) | u8 family | u8 addr_len | addr[addr_len] | u16 port_be | node_id[32] | u32 cp_q16_be
    size_t payload_len = 4;
    for (int k = 0; k < share_cnt; k++) {
        (void)k; // currently IPv4 only
        payload_len += (size_t)(1 + 1 + 1 + 4 + 2 + 32 + 4);
    }
    uint8_t *buf = (uint8_t*)malloc(payload_len);
    if (!buf) return;
    uint8_t *p = buf;
    uint32_t cnt = (uint32_t)share_cnt; memcpy(p, &cnt, 4); p += 4;
    for (int k = 0; k < share_cnt; k++) {
        discovered_peer_t *dp = &share[k];
        // entry_version
        *p++ = 1;
        // IPv4
        *p++ = 4; // addr_family IPv4
        *p++ = 4; // addr_len
        memcpy(p, &dp->addr.sin_addr, 4); p += 4;
        uint16_t port_be = htons(dp->tcp_port); memcpy(p, &port_be, 2); p += 2;
        memcpy(p, dp->node_id, 32); p += 32;
        uint32_t cp_q16 = (uint32_t)((dp->compute_power * 65536.0f) + 0.5f);
        uint32_t cp_be = htonl(cp_q16);
        memcpy(p, &cp_be, 4); p += 4;
    }
    // Snapshot peers for I/O
    peer_t *peers_snapshot[MAX_PEERS]; int pc = 0;
    pthread_mutex_lock(&network->peers_lock);
    pc = network->peer_count;
    if (pc > MAX_PEERS) pc = MAX_PEERS;
    for (int i = 0; i < pc; i++) peers_snapshot[i] = network->peers[i];
    pthread_mutex_unlock(&network->peers_lock);
    for (int i = 0; i < pc; i++) network_send_message(peers_snapshot[i], MSG_PEER_LIST, buf, (uint32_t)payload_len);
    free(buf);
}

void network_discovery_note(network_t *network, const uint8_t node_id[NODE_ID_SIZE],
                            const struct sockaddr_in *addr, uint16_t tcp_port, float compute_power) {
    if (!network || !node_id || !addr) return;
    time_t now = time(NULL);
    pthread_mutex_lock(&network->discovered_lock);
    // Update existing by node_id
    for (int i = 0; i < network->discovered_count; i++) {
        if (memcmp(network->discovered[i].node_id, node_id, NODE_ID_SIZE) == 0) {
            network->discovered[i].addr = *addr;
            network->discovered[i].tcp_port = tcp_port;
            network->discovered[i].compute_power = compute_power;
            network->discovered[i].last_seen = now;
            pthread_mutex_unlock(&network->discovered_lock);
            return;
        }
    }
    // Insert new if space or overwrite stalest
    if (network->discovered_count < MAX_DISCOVERED) {
        int i = network->discovered_count++;
        memcpy(network->discovered[i].node_id, node_id, NODE_ID_SIZE);
        network->discovered[i].addr = *addr;
        network->discovered[i].tcp_port = tcp_port;
        network->discovered[i].compute_power = compute_power;
        network->discovered[i].last_seen = now;
        pthread_mutex_unlock(&network->discovered_lock);
        return;
    }
    // Find oldest
    int oldest = 0;
    for (int i = 1; i < network->discovered_count; i++) {
        if (network->discovered[i].last_seen < network->discovered[oldest].last_seen) oldest = i;
    }
    memcpy(network->discovered[oldest].node_id, node_id, NODE_ID_SIZE);
    network->discovered[oldest].addr = *addr;
    network->discovered[oldest].tcp_port = tcp_port;
    network->discovered[oldest].compute_power = compute_power;
    network->discovered[oldest].last_seen = now;
    pthread_mutex_unlock(&network->discovered_lock);
}
// Client-side remote hashing request
int network_request_remote_hashes(network_t *network, peer_t *host,
                                  const uint8_t seed[32],
                                  const uint8_t **inputs, size_t *input_lens,
                                  uint8_t **outputs, int count, int timeout_ms) {
    if (!network || !host || host->socket_fd < 0 || count <= 0) return -1;
    if (network->pending_hash_active) {
        // Only one outstanding request supported in this simple implementation
        return -1;
    }
    // If peer requires signing but we have no token, abort
    int want_sign = (network->config && (network->config->sign_messages || host->requires_signing) && network->config->auth_token[0] != '\0');
    if (host->requires_signing && (!network->config || network->config->auth_token[0] == '\0')) {
        fprintf(stderr, "Remote requires signing but no auth token configured\n");
        return -1;
    }
    // Build payload
    size_t total = 32 + 4;
    for (int i = 0; i < count; i++) total += 4 + input_lens[i];
    size_t extra = want_sign ? SIG_LEN : 0;
    if (total + extra > MAX_PAYLOAD_LEN) return -1;
    uint8_t *buf = (uint8_t*)malloc(total + extra);
    if (!buf) return -1;
    uint8_t *p = buf; memcpy(p, seed, 32); p += 32; uint32_t c = (uint32_t)count; memcpy(p, &c, 4); p += 4;
    for (int i = 0; i < count; i++) {
        uint32_t l = (uint32_t)input_lens[i]; memcpy(p, &l, 4); p += 4; memcpy(p, inputs[i], l); p += l;
    }
    // Append signature if required
    if (want_sign) {
        uint8_t tag[SIG_LEN];
        if (hmac_sha256((const uint8_t*)network->config->auth_token, strlen(network->config->auth_token), buf, total, tag) != 0) {
            free(buf);
            return -1;
        }
        memcpy(p, tag, SIG_LEN);
        total += SIG_LEN;
    }
    // Arm pending state
    network->pending_hash_active = 1;
    network->pending_hash_peer = host;
    network->pending_hash_expected = count;
    network->pending_hash_outputs = outputs;
    network->pending_hash_status = -2; // pending

    int rc = network_send_message(host, MSG_HASH_REQUEST, buf, (uint32_t)total);
    free(buf);
    if (rc != 0) {
        network->pending_hash_active = 0;
        network->pending_hash_peer = NULL;
        network->pending_hash_expected = 0;
        network->pending_hash_outputs = NULL;
        network->pending_hash_status = -1;
        return -1;
    }
    // Synchronously wait by pumping the event loop
    int waited_ms = 0;
    const int slice = 25; // ms
    while (waited_ms < timeout_ms) {
        network_process_events(network, slice);
        if (!network->pending_hash_active) break;
        waited_ms += slice;
    }
    int status = network->pending_hash_status;
    // Reset pending state
    network->pending_hash_active = 0;
    network->pending_hash_peer = NULL;
    network->pending_hash_expected = 0;
    network->pending_hash_outputs = NULL;
    network->pending_hash_status = -1;
    return (status == 0) ? 0 : -1;
}

void network_destroy(network_t *network) {
    if (!network) return;
    if (network->listen_fd >= 0) close(network->listen_fd);
    if (network->discovery_fd >= 0) close(network->discovery_fd);
    for (int i = 0; i < network->peer_count; i++) { peer_destroy(network->peers[i]); }
    pthread_mutex_destroy(&network->peers_lock);
    pthread_mutex_destroy(&network->discovered_lock);
    if (network->work_wal) wal_close(network->work_wal);
    free(network);
}

int network_start_listener(network_t *network) {
    if (!network) return -1;
    
    network->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (network->listen_fd < 0) {
        perror("socket");
        return -1;
    }
    
    int opt = 1;
    setsockopt(network->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    int flags = fcntl(network->listen_fd, F_GETFL, 0);
    fcntl(network->listen_fd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(network->config->port);
    
    if (bind(network->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(network->listen_fd);
        return -1;
    }
    
    if (listen(network->listen_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("listen");
        close(network->listen_fd);
        return -1;
    }
    
    printf("Network listener started on port %d\n", network->config->port);
    return 0;
}

// --- Auto-discovery and master election (MODE_AUTO) ---

static int open_discovery_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(DISCOVERY_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

int network_auto_discover_and_elect(network_t *network) {
    if (!network) return -1;
    // Open discovery socket
    int dfd = open_discovery_socket();
    if (dfd < 0) {
        fprintf(stderr, "Discovery: failed to open UDP socket on %d\n", DISCOVERY_PORT);
        // Default to master
        network->is_master = 1;
        return 0;
    }
    network->discovery_fd = dfd;

    // Broadcast our presence (manual wire format)
    uint8_t pkt[4 + NODE_ID_SIZE + 2 + 4];
    uint8_t *pp = pkt;
    pp[0] = 'D'; pp[1] = 'I'; pp[2] = 'S'; pp[3] = 'C'; pp += 4;
    memcpy(pp, network->local_node->id, NODE_ID_SIZE); pp += NODE_ID_SIZE;
    uint16_t port_be = htons((uint16_t)network->config->port);
    memcpy(pp, &port_be, 2); pp += 2;
    uint32_t cp_q16 = (uint32_t)((network->local_node->capabilities.compute_power * 65536.0f) + 0.5f);
    uint32_t cp_be = htonl(cp_q16);
    memcpy(pp, &cp_be, 4); pp += 4;

    struct sockaddr_in baddr = {0};
    baddr.sin_family = AF_INET;
    baddr.sin_port = htons(DISCOVERY_PORT);
    baddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    // Send a few beacons
    for (int i = 0; i < 3; i++) {
        sendto(dfd, pkt, sizeof(pkt), 0, (struct sockaddr *)&baddr, sizeof(baddr));
        struct timespec ts; ts.tv_sec = 0; ts.tv_nsec = 100 * 1000 * 1000L; // 100ms
        nanosleep(&ts, NULL);
    }

    // Collect peers for ~1.5s
    struct seen_s { uint8_t id[NODE_ID_SIZE]; struct sockaddr_in addr; float power; } seen[64];
    int seen_count = 0;
    time_t start = time(NULL);
    while ((time(NULL) - start) < 2) {
        struct sockaddr_in src; socklen_t slen = sizeof(src);
        uint8_t rbuf[4 + NODE_ID_SIZE + 2 + 4]; ssize_t n = recvfrom(dfd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&src, &slen);
        if (n == (ssize_t)sizeof(rbuf) && rbuf[0]=='D' && rbuf[1]=='I' && rbuf[2]=='S' && rbuf[3]=='C') {
            const uint8_t *rp = rbuf + 4;
            if (memcmp(rp, network->local_node->id, NODE_ID_SIZE) != 0) {
                if (seen_count < (int)(sizeof(seen)/sizeof(seen[0]))) {
                    memcpy(seen[seen_count].id, rp, NODE_ID_SIZE);
                    rp += NODE_ID_SIZE;
                    uint16_t pbe = 0; memcpy(&pbe, rp, 2); rp += 2;
                    uint32_t cpbe = 0; memcpy(&cpbe, rp, 4); rp += 4;
                    seen[seen_count].addr = src;
                    seen[seen_count].addr.sin_port = pbe; // keep network order in sockaddr
                    seen[seen_count].power = (float)(ntohl(cpbe)) / 65536.0f;
                    seen_count++;
                }
            }
        } else {
            struct timespec ts; ts.tv_sec = 0; ts.tv_nsec = 50 * 1000 * 1000L; // 50ms
            nanosleep(&ts, NULL);
        }
    }

    // Determine leader = smallest lexicographic node_id among all (including self)
    int self_is_leader = 1;
    for (int i = 0; i < seen_count; i++) {
        if (memcmp(seen[i].id, network->local_node->id, NODE_ID_SIZE) < 0) {
            self_is_leader = 0;
            break;
        }
    }
    if (self_is_leader) {
        network->is_master = 1;
        // No connect; others will connect to us
    } else {
        network->is_master = 0;
        // connect to leader: find min id in seen
        int idx = 0;
        for (int i = 1; i < seen_count; i++) {
            if (memcmp(seen[i].id, seen[idx].id, NODE_ID_SIZE) < 0) idx = i;
        }
        char host[64];
        inet_ntop(AF_INET, &seen[idx].addr.sin_addr, host, sizeof(host));
        int port = ntohs(seen[idx].addr.sin_port);
        char addrbuf[96];
        snprintf(addrbuf, sizeof(addrbuf), "%s:%d", host, port);
        printf("Auto-discovery: elected master=%s (port %d); connecting...\n", host, port);
        network_connect_to_master(network, addrbuf);
    }

    // Keep discovery socket open for periodic announcements and late joiners
    network->last_discovery_beacon = time(NULL);
    return 0;
}

// --- Dataset host selection ---
void network_select_dataset_host(network_t *network) {
    if (!network) return;
    // Snapshot peers under lock
    peer_t *peers_snapshot[MAX_PEERS]; int pc = 0;
    pthread_mutex_lock(&network->peers_lock);
    pc = network->peer_count; if (pc > MAX_PEERS) pc = MAX_PEERS;
    for (int i = 0; i < pc; i++) peers_snapshot[i] = network->peers[i];
    pthread_mutex_unlock(&network->peers_lock);
    // Default: if local can host, prefer self
    network->dataset_host_peer = NULL;
    int local_can = network->local_node->capabilities.can_host_dataset;
    double best_score = local_can ? (double)network->local_node->capabilities.ram_mb : -1.0;
    peer_t *best_peer = NULL;
    for (int i = 0; i < pc; i++) {
        peer_t *p = peers_snapshot[i];
        int can = p->capabilities.can_host_dataset;
        double score = can ? (double)p->capabilities.ram_mb : -1.0;
        if (score > best_score) { best_score = score; best_peer = p; }
    }
    if (best_peer && (!local_can || best_score > (double)network->local_node->capabilities.ram_mb)) {
        network->dataset_host_peer = best_peer;
    } else {
        network->dataset_host_peer = NULL; // self
    }
}

peer_t *network_get_dataset_host(network_t *network) {
    if (!network) return NULL;
    return network->dataset_host_peer;
}

int network_connect_to_master(network_t *network, const char *address) {
    char host[256];
    int port = DEFAULT_PORT;
    
    const char *colon = strchr(address, ':');
    if (colon) {
        size_t len = colon - address;
        if (len >= sizeof(host)) len = sizeof(host) - 1;
        strncpy(host, address, len);
        host[len] = '\0';
        port = atoi(colon + 1);
    } else {
        strncpy(host, address, sizeof(host) - 1);
    }
    
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) return -1;
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(sock_fd);
        return -1;
    }
    
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock_fd);
        return -1;
    }
    
    peer_t *peer = peer_create(sock_fd, &addr);
    if (!peer) {
        close(sock_fd);
        return -1;
    }
    peer->is_master = 1;
    
    network_add_peer(network, peer);
    
    // Build HELLO payload
    // v1: u8 pver(1) | u8 flags | u16 rsv | [if flags&1: u8 tlen | token[tlen]] | node_id[32] | capabilities
    // legacy: node_id[32] | capabilities
    if (network->config && network->config->auth_token[0] != '\0') {
        const char *tok = network->config->auth_token;
        size_t tlen = strlen(tok);
        if (tlen > 255) tlen = 255;
        size_t total = 1 + 1 + 2 + 1 + tlen + NODE_ID_SIZE + sizeof(node_capabilities_t);
        uint8_t *hello = (uint8_t*)malloc(total);
        if (hello) {
            uint8_t *p = hello;
            *p++ = 1; // payload ver
            uint8_t flags = 1; // bit0 auth present
            if (network->config->sign_messages) flags |= 2; // bit1 signing required
            *p++ = flags;
            *p++ = 0; *p++ = 0; // rsv
            *p++ = (uint8_t)tlen; memcpy(p, tok, tlen); p += tlen;
            memcpy(p, network->local_node->id, NODE_ID_SIZE); p += NODE_ID_SIZE;
            memcpy(p, &network->local_node->capabilities, sizeof(node_capabilities_t)); p += sizeof(node_capabilities_t);
            network_send_message(peer, MSG_HELLO, hello, (uint32_t)total);
            free(hello);
        }
    } else {
        uint8_t hello[NODE_ID_SIZE + sizeof(node_capabilities_t)];
        memcpy(hello, network->local_node->id, NODE_ID_SIZE);
        memcpy(hello + NODE_ID_SIZE, &network->local_node->capabilities, sizeof(node_capabilities_t));
        network_send_message(peer, MSG_HELLO, hello, sizeof(hello));
    }
    
    return 0;
}

peer_t *peer_create(int socket_fd, struct sockaddr_in *addr) {
    peer_t *peer = calloc(1, sizeof(peer_t));
    if (!peer) return NULL;
    
    peer->socket_fd = socket_fd;
    memcpy(&peer->addr, addr, sizeof(struct sockaddr_in));
    inet_ntop(AF_INET, &addr->sin_addr, peer->addr_str, sizeof(peer->addr_str));
    peer->last_seen = time(NULL);
    peer->is_connected = 1;
    peer->is_authenticated = 0;
    pthread_mutex_init(&peer->lock, NULL);
    // initialize rate-limiting buckets when added to network
    
    int flags = fcntl(socket_fd, F_GETFL, 0);
    fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
    
    return peer;
}

void peer_destroy(peer_t *peer) {
    if (!peer) return;
    if (peer->socket_fd >= 0) close(peer->socket_fd);
    pthread_mutex_destroy(&peer->lock);
    free(peer);
}

int network_add_peer(network_t *network, peer_t *peer) {
    if (!network || !peer || network->peer_count >= MAX_PEERS) return -1;
    pthread_mutex_lock(&network->peers_lock);
    network->peers[network->peer_count++] = peer;
    pthread_mutex_unlock(&network->peers_lock);
    printf("Peer connected: %s (total: %d)\n", peer->addr_str, network->peer_count);
    // init per-peer rate limits
    peer->rl_msg_tokens = RL_MSG_TOKENS_PER_SEC;
    peer->rl_msg_last_refill = time(NULL);
    peer->rl_hash_tokens = RL_HASH_TOKENS_PER_SEC;
    peer->rl_hash_last_refill = time(NULL);
    // Re-evaluate dataset host when topology changes
    network_select_dataset_host(network);
    // Gossip discovered peers to accelerate convergence
    network_broadcast_peer_list(network);
    return 0;
}

void network_remove_peer(network_t *network, peer_t *peer) {
    if (!network || !peer) return;
    pthread_mutex_lock(&network->peers_lock);
    for (int i = 0; i < network->peer_count; i++) {
        if (network->peers[i] == peer) {
            printf("Peer disconnected: %s\n", peer->addr_str);
            peer_destroy(peer);
            for (int j = i; j < network->peer_count - 1; j++) {
                network->peers[j] = network->peers[j + 1];
            }
            network->peer_count--;
            break;
        }
    }
    pthread_mutex_unlock(&network->peers_lock);
    network_select_dataset_host(network);
}

peer_t *network_find_peer_by_id(network_t *network, uint8_t *node_id) {
    if (!network || !node_id) return NULL;
    peer_t *found = NULL;
    pthread_mutex_lock(&network->peers_lock);
    for (int i = 0; i < network->peer_count; i++) {
        if (memcmp(network->peers[i]->node_id, node_id, NODE_ID_SIZE) == 0) {
            found = network->peers[i];
            break;
        }
    }
    pthread_mutex_unlock(&network->peers_lock);
    return found;
}

static uint32_t calculate_checksum(const void *data, size_t len) {
    uint32_t sum = 0;
    const uint8_t *bytes = data;
    for (size_t i = 0; i < len; i++) {
        sum += bytes[i];
    }
    return sum;
}

int network_send_message(peer_t *peer, msg_type_t type, const void *payload, uint32_t payload_len) {
    if (!peer || peer->socket_fd < 0) return -1;
    
    msg_header_t header;
    header.magic = PROTOCOL_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.msg_type = type;
    header.payload_len = payload_len;
    header.checksum = calculate_checksum(payload, payload_len);
    
    if (send_all(peer->socket_fd, &header, sizeof(header)) != (ssize_t)sizeof(header)) return -1;
    if (payload_len > 0 && payload) {
        if (send_all(peer->socket_fd, payload, payload_len) != (ssize_t)payload_len) return -1;
    }
    return 0;
}

int network_handle_message(network_t *network, peer_t *peer, msg_header_t *header, uint8_t *payload) {
    if (!network || !peer || !header) return -1;
    // Generic per-peer rate limiting (token bucket)
    time_t now = time(NULL);
    if (now > peer->rl_msg_last_refill) {
        long delta = now - peer->rl_msg_last_refill;
        long add = delta * RL_MSG_TOKENS_PER_SEC;
        if (add > 0) {
            peer->rl_msg_tokens += (int)add;
            if (peer->rl_msg_tokens > RL_MSG_TOKENS_PER_SEC) peer->rl_msg_tokens = RL_MSG_TOKENS_PER_SEC;
            peer->rl_msg_last_refill = now;
        }
    }
    if (header->msg_type != MSG_HEARTBEAT) { // still count heartbeats but they are infrequent
        peer->rl_msg_tokens -= 1;
        if (peer->rl_msg_tokens < 0) {
            // Drop silently to avoid amplification
            return -1;
        }
    }
    // Enforce auth for non-handshake messages when required
    if (network->config && network->config->require_auth && !peer->is_authenticated) {
        if (header->msg_type != MSG_HELLO && header->msg_type != MSG_HELLO_REPLY) {
            fprintf(stderr, "Dropping unauthenticated message type %u from %s\n", header->msg_type, peer->addr_str);
            return -1;
        }
    }
    
    switch (header->msg_type) {
        case MSG_HELLO:
            if (!payload) break;
            if (header->payload_len >= 1 && payload[0] == 1) {
                // v1 HELLO parse
                const uint8_t *p = payload; size_t remain = header->payload_len;
                uint8_t pver = *p++; remain--; (void)pver;
                if (remain < 3) break; // flags + rsv
                uint8_t flags = *p++; remain--;
                p += 2; remain -= 2; // rsv
                // authenticate if required
                if (flags & 1) {
                    if (remain < 1) break;
                    uint8_t tlen = *p++; remain--;
                    if (remain < tlen) break;
                    int auth_ok = 1;
                    if (network->config && network->config->require_auth) {
                        size_t conf_len = strlen(network->config->auth_token);
                        auth_ok = (conf_len == tlen) && (memcmp(p, network->config->auth_token, tlen) == 0);
                    }
                    p += tlen; remain -= tlen;
                    if (!auth_ok) {
                        fprintf(stderr, "HELLO auth failed from %s\n", peer->addr_str);
                        network_remove_peer(network, peer);
                        return -1;
                    }
                } else if (network->config && network->config->require_auth) {
                    fprintf(stderr, "HELLO missing auth from %s while auth required\n", peer->addr_str);
                    network_remove_peer(network, peer);
                    return -1;
                }
                if (remain < NODE_ID_SIZE) break;
                memcpy(peer->node_id, p, NODE_ID_SIZE); p += NODE_ID_SIZE; remain -= NODE_ID_SIZE;
                for (int i = 0; i < NODE_ID_SIZE; i++) sprintf(&peer->node_id_str[i * 2], "%02x", peer->node_id[i]);
                if (remain >= sizeof(node_capabilities_t)) {
                    memcpy(&peer->capabilities, p, sizeof(node_capabilities_t));
                    p += sizeof(node_capabilities_t); remain -= sizeof(node_capabilities_t);
                }
                peer->requires_signing = ((flags & 2) != 0);
                peer->is_authenticated = 1;
                printf("HELLO v1 from %s (ID: %.16s...)\n", peer->addr_str, peer->node_id_str);
                network_send_message(peer, MSG_HELLO_REPLY, network->local_node->id, NODE_ID_SIZE);
                network_send_message(peer, MSG_CAPABILITIES, &network->local_node->capabilities, (uint32_t)sizeof(node_capabilities_t));
                network_select_dataset_host(network);
            } else if (header->payload_len >= NODE_ID_SIZE) {
                // legacy HELLO
                if (network->config && network->config->require_auth) {
                    fprintf(stderr, "Legacy HELLO rejected (auth required) from %s\n", peer->addr_str);
                    network_remove_peer(network, peer);
                    return -1;
                }
                memcpy(peer->node_id, payload, NODE_ID_SIZE);
                for (int i = 0; i < NODE_ID_SIZE; i++) sprintf(&peer->node_id_str[i * 2], "%02x", peer->node_id[i]);
                if (header->payload_len >= NODE_ID_SIZE + sizeof(node_capabilities_t)) {
                    memcpy(&peer->capabilities, payload + NODE_ID_SIZE, sizeof(node_capabilities_t));
                }
                peer->is_authenticated = 1; // no auth required
                printf("HELLO (legacy) from %s (ID: %.16s...)\n", peer->addr_str, peer->node_id_str);
                network_send_message(peer, MSG_HELLO_REPLY, network->local_node->id, NODE_ID_SIZE);
                network_send_message(peer, MSG_CAPABILITIES, &network->local_node->capabilities, (uint32_t)sizeof(node_capabilities_t));
                network_select_dataset_host(network);
            }
            break;
        case MSG_HELLO_REPLY:
            printf("HELLO_REPLY from %s\n", peer->addr_str);
            // Optionally follow-up with our capabilities if we initiated connection
            network_send_message(peer, MSG_CAPABILITIES, &network->local_node->capabilities, (uint32_t)sizeof(node_capabilities_t));
            break;
        case MSG_CAPABILITIES:
            if (payload && header->payload_len >= sizeof(node_capabilities_t)) {
                memcpy(&peer->capabilities, payload, sizeof(node_capabilities_t));
                network_select_dataset_host(network);
            }
            break;
        case MSG_HEARTBEAT:
            pthread_mutex_lock(&peer->lock);
            peer->last_seen = time(NULL);
            pthread_mutex_unlock(&peer->lock);
            break;
        case MSG_STATS_UPDATE: {
            // Expect a packed payload with remote stats
            struct __attribute__((packed)) stats_payload_s {
                char algo[32];
                double hashrate;
                uint64_t hashes;
                uint64_t shares;
                uint64_t uptime;
            };
            if (payload && header->payload_len == sizeof(struct stats_payload_s)) {
                struct stats_payload_s sp;
                memcpy(&sp, payload, sizeof(sp));
                strncpy(peer->remote_algo, sp.algo, sizeof(peer->remote_algo) - 1);
                peer->remote_algo[sizeof(peer->remote_algo) - 1] = '\0';
                pthread_mutex_lock(&peer->lock);
                peer->remote_hashrate = sp.hashrate;
                peer->remote_hashes = sp.hashes;
                peer->remote_shares = sp.shares;
                peer->stats_last_update = time(NULL);
                pthread_mutex_unlock(&peer->lock);
            }
            break;
        }
        case MSG_WORKUNIT_ASSIGN: {
            // Payload v1: ver(1)=1 | flags(1) | rsv(2) | work_id(u64 be) | nonce_start(u64 be) | nonce_end(u64 be) | data[WORK_UNIT_SIZE]
            // [ | sig[32] if signing ]
            if (network->config && network->config->require_auth && !peer->is_authenticated) {
                fprintf(stderr, "Unauthorized MSG_WORKUNIT_ASSIGN from %s\n", peer->addr_str);
                break;
            }
            if (!payload) break;
            size_t base_len = 1 + 1 + 2 + 8 + 8 + 8 + WORK_UNIT_SIZE;
            if (header->payload_len != base_len && header->payload_len != base_len + SIG_LEN) {
                fprintf(stderr, "WORKUNIT_ASSIGN invalid length from %s (%u)\n", peer->addr_str, header->payload_len);
                break;
            }
            // If signing is enabled locally, require and verify signature
            int need_sig = (network->config && network->config->sign_messages && network->config->auth_token[0] != '\0');
            if (need_sig && header->payload_len != base_len + SIG_LEN) {
                fprintf(stderr, "WORKUNIT_ASSIGN missing signature from %s\n", peer->addr_str);
                break;
            }
            if (need_sig) {
                const uint8_t *sig = payload + base_len;
                uint8_t calc[SIG_LEN];
                if (hmac_sha256((const uint8_t*)network->config->auth_token, strlen(network->config->auth_token), payload, base_len, calc) != 0 || memcmp(sig, calc, SIG_LEN) != 0) {
                    fprintf(stderr, "WORKUNIT_ASSIGN signature invalid from %s\n", peer->addr_str);
                    break;
                }
            }
            // Parse fields (we don't execute work here; mining loop would consume)
            const uint8_t *p = payload;
            uint8_t ver = *p++; (void)ver; uint8_t flags = *p++; (void)flags; p += 2;
            uint64_t work_id_be=0, ns_be=0, ne_be=0; memcpy(&work_id_be, p, 8); p += 8; memcpy(&ns_be, p, 8); p += 8; memcpy(&ne_be, p, 8); p += 8;
            uint64_t work_id = ntohll_u64(work_id_be);
            uint64_t nonce_start = ntohll_u64(ns_be);
            uint64_t nonce_end = ntohll_u64(ne_be);
            (void)work_id; (void)nonce_start; (void)nonce_end;
            // data pointer p now at work data (WORK_UNIT_SIZE)
            // In a full implementation, we'd pass this to a worker queue and persist assignment here.
            printf("Received WORKUNIT_ASSIGN id=%llu range=[%llu,%llu] from %s\n",
                   (unsigned long long)work_id, (unsigned long long)nonce_start, (unsigned long long)nonce_end, peer->addr_str);
            break;
        }
        case MSG_WORKUNIT_RESULT: {
            // Payload v1: ver(1)=1 | flags(1) | rsv(2) | work_id(u64 be) | nonce(u64 be) | hash[32] | status(u8)
            // [ | sig[32] if signing ]
            if (network->config && network->config->require_auth && !peer->is_authenticated) {
                fprintf(stderr, "Unauthorized MSG_WORKUNIT_RESULT from %s\n", peer->addr_str);
                break;
            }
            if (!payload) break;
            size_t base_len = 1 + 1 + 2 + 8 + 8 + HASH_SIZE + 1;
            if (header->payload_len != base_len && header->payload_len != base_len + SIG_LEN) {
                fprintf(stderr, "WORKUNIT_RESULT invalid length from %s (%u)\n", peer->addr_str, header->payload_len);
                break;
            }
            int need_sig = (network->config && network->config->sign_messages && network->config->auth_token[0] != '\0');
            if (need_sig && header->payload_len != base_len + SIG_LEN) {
                fprintf(stderr, "WORKUNIT_RESULT missing signature from %s\n", peer->addr_str);
                break;
            }
            if (need_sig) {
                const uint8_t *sig = payload + base_len;
                uint8_t calc[SIG_LEN];
                if (hmac_sha256((const uint8_t*)network->config->auth_token, strlen(network->config->auth_token), payload, base_len, calc) != 0 || memcmp(sig, calc, SIG_LEN) != 0) {
                    fprintf(stderr, "WORKUNIT_RESULT signature invalid from %s\n", peer->addr_str);
                    break;
                }
            }
            const uint8_t *p = payload;
            uint8_t ver = *p++; (void)ver; uint8_t flags = *p++; (void)flags; p += 2;
            uint64_t work_id_be=0, nonce_be=0; memcpy(&work_id_be, p, 8); p += 8; memcpy(&nonce_be, p, 8); p += 8;
            uint64_t work_id = ntohll_u64(work_id_be);
            uint64_t nonce = ntohll_u64(nonce_be);
            uint8_t hash[HASH_SIZE]; memcpy(hash, p, HASH_SIZE); p += HASH_SIZE;
            uint8_t status = *p++;
            printf("Received WORKUNIT_RESULT id=%llu status=%u from %s\n", (unsigned long long)work_id, (unsigned)status, peer->addr_str);
            // Append to WAL: type 'R' | work_id(u64 be) | nonce(u64 be) | hash[32] | status(u8)
            if (network->work_wal) {
                uint8_t rec[1 + 8 + 8 + HASH_SIZE + 1];
                uint8_t *w = rec; *w++ = 'R';
                uint64_t wid_be = htonll_u64(work_id); memcpy(w, &wid_be, 8); w += 8;
                uint64_t non_be = htonll_u64(nonce); memcpy(w, &non_be, 8); w += 8;
                memcpy(w, hash, HASH_SIZE); w += HASH_SIZE;
                *w++ = status;
                (void)wal_append(network->work_wal, rec, sizeof(rec));
            }
            break;
        }
        case MSG_PEER_LIST: {
            // Payload: u32 count, then entries
            // v1 entry: u8 ver(=1) | u8 family | u8 addr_len | addr[addr_len] | u16 port_be | node_id[32] | u32 cp_q16_be
            // legacy entry: node_id[32] | ipv4_be[4] | port_be[2] | float compute_power (native ordering on sender)
            if (!payload || header->payload_len < 4) break;
            const uint8_t *p = payload; uint32_t cnt = 0; memcpy(&cnt, p, 4); p += 4;
            if (cnt > MAX_PEER_LIST_ENTRIES) cnt = MAX_PEER_LIST_ENTRIES;
            size_t remain = header->payload_len - 4;
            for (uint32_t i = 0; i < cnt; i++) {
                if (remain == 0) break;
                const uint8_t *entry_start = p; size_t entry_rem = remain;
                if (entry_rem >= 3) {
                    uint8_t ver = p[0]; uint8_t family = p[1]; uint8_t alen = p[2];
                    if (ver == 1) {
                        p += 3; entry_rem -= 3;
                        if (entry_rem < (size_t)alen + 2 + 32 + 4) break;
                        const uint8_t *addr = p; p += alen; entry_rem -= alen;
                        uint16_t port_be = 0; memcpy(&port_be, p, 2); p += 2; entry_rem -= 2;
                        uint8_t nid[NODE_ID_SIZE]; memcpy(nid, p, 32); p += 32; entry_rem -= 32;
                        uint32_t cp_be = 0; memcpy(&cp_be, p, 4); p += 4; entry_rem -= 4;
                        uint16_t port = ntohs(port_be);
                        float cp = (float)(ntohl(cp_be)) / 65536.0f;
                        if (family == 4 && alen == 4) {
                            struct sockaddr_in a = {0}; a.sin_family = AF_INET; memcpy(&a.sin_addr, addr, 4); a.sin_port = htons(port);
                            if (memcmp(nid, network->local_node->id, NODE_ID_SIZE) != 0) {
                                network_discovery_note(network, nid, &a, port, cp);
                            }
                        }
                        remain -= (p - entry_start);
                        continue;
                    }
                }
                // Legacy fallback parse
                p = entry_start; entry_rem = remain;
                if (entry_rem < (size_t)(32 + 4 + 2 + 4)) break;
                uint8_t nid[NODE_ID_SIZE]; memcpy(nid, p, 32); p += 32; entry_rem -= 32;
                uint32_t ip_be = 0; memcpy(&ip_be, p, 4); p += 4; entry_rem -= 4;
                uint16_t port_be = 0; memcpy(&port_be, p, 2); p += 2; entry_rem -= 2;
                float cp_float = 0.0f; memcpy(&cp_float, p, 4); p += 4; entry_rem -= 4;
                struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = ip_be; a.sin_port = port_be;
                if (memcmp(nid, network->local_node->id, NODE_ID_SIZE) != 0) {
                    network_discovery_note(network, nid, &a, ntohs(port_be), cp_float);
                }
                remain -= (p - entry_start);
            }
            break;
        }
        case MSG_HASH_REQUEST: {
            // Remote hashing request: payload layout:
            // seed[32] | count(u32) | repeated { len(u32) | bytes[len] } [ | sig[32] if signing ]
            if (!network->local_node || !network->local_node->mining_algo) break;
            if (!payload || header->payload_len < 36) break;
            if (network->config && network->config->require_auth && !peer->is_authenticated) {
                fprintf(stderr, "Unauthorized MSG_HASH_REQUEST from %s\n", peer->addr_str);
                break;
            }
            // If signing is enabled, verify signature at end
            size_t paylen = header->payload_len;
            if (network->config && network->config->sign_messages && network->config->auth_token[0] != '\0') {
                if (paylen < 36 + SIG_LEN) { fprintf(stderr, "HASH_REQUEST too short for signature\n"); break; }
                const uint8_t *sig = payload + (paylen - SIG_LEN);
                uint8_t calc[SIG_LEN];
                if (hmac_sha256((const uint8_t*)network->config->auth_token, strlen(network->config->auth_token), payload, paylen - SIG_LEN, calc) != 0 || memcmp(sig, calc, SIG_LEN) != 0) {
                    fprintf(stderr, "HASH_REQUEST signature invalid from %s\n", peer->addr_str);
                    break;
                }
                paylen -= SIG_LEN;
            }
            const uint8_t *p = payload;
            uint8_t seed[32];
            memcpy(seed, p, 32); p += 32;
            uint32_t count = 0;
            memcpy(&count, p, 4); p += 4;
            if (count == 0 || count > MAX_HASH_BATCH) {
                fprintf(stderr, "HASH_REQUEST rejected: count=%u\n", count);
                break;
            }
            // Hash-specific rate limit tokens
            if (now > peer->rl_hash_last_refill) {
                long delta = now - peer->rl_hash_last_refill;
                long add = delta * RL_HASH_TOKENS_PER_SEC;
                if (add > 0) {
                    peer->rl_hash_tokens += (int)add;
                    if (peer->rl_hash_tokens > RL_HASH_TOKENS_PER_SEC) peer->rl_hash_tokens = RL_HASH_TOKENS_PER_SEC;
                    peer->rl_hash_last_refill = now;
                }
            }
            int cost = 1 + (int)(count / 256);
            peer->rl_hash_tokens -= cost;
            if (peer->rl_hash_tokens < 0) {
                fprintf(stderr, "Rate-limited HASH_REQUEST from %s (count=%u)\n", peer->addr_str, count);
                break;
            }
            const mining_algo_interface_t *algo = (const mining_algo_interface_t *)network->local_node->mining_algo;
            // Ensure dataset for the provided seed (only when changed)
            if (!g_remotehash_seed_valid || memcmp(g_remotehash_last_seed, seed, 32) != 0) {
                (void)algo->init_dataset(network->local_node->mining_ctx, seed, 32);
                memcpy(g_remotehash_last_seed, seed, 32);
                g_remotehash_seed_valid = 1;
            }
            // Parse inputs
            const uint8_t **inputs = (const uint8_t **)calloc(count, sizeof(uint8_t*));
            size_t *lens = (size_t *)calloc(count, sizeof(size_t));
            uint8_t **outputs = (uint8_t **)calloc(count, sizeof(uint8_t*));
            if (!inputs || !lens || !outputs) {
                free(inputs); free(lens); free(outputs);
                break;
            }
            for (uint32_t i = 0; i < count; i++) {
                if ((size_t)(p - payload) + 4 > header->payload_len) { count = i; break; }
                uint32_t len = 0; memcpy(&len, p, 4); p += 4;
                if (len == 0 || len > MAX_INPUT_SIZE) { count = i; break; }
                if ((size_t)(p - payload) + len > header->payload_len) { count = i; break; }
                lens[i] = len;
                if (len > 0) {
                    uint8_t *buf = (uint8_t*)malloc(len);
                    if (!buf) { lens[i] = 0; inputs[i] = NULL; }
                    else { memcpy(buf, p, len); inputs[i] = buf; }
                    p += len;
                } else {
                    inputs[i] = NULL;
                }
                outputs[i] = (uint8_t*)malloc(HASH_SIZE);
            }
            // Compute
            int rc = 0;
            if (count > 0) {
                rc = algo->compute_batch(network->local_node->mining_ctx, inputs, lens, outputs, (int)count);
                if (rc != 0) {
                    for (uint32_t i = 0; i < count; i++) {
                        if (inputs[i] && outputs[i]) {
                            (void)algo->compute_hash(network->local_node->mining_ctx, inputs[i], lens[i], outputs[i]);
                        }
                    }
                }
            }
            // Respond
            uint32_t resp_len = 4 + count * HASH_SIZE;
            uint8_t *resp = (uint8_t*)malloc(resp_len + ((network->config && network->config->sign_messages && network->config->auth_token[0] != '\0') ? SIG_LEN : 0));
            if (resp) {
                uint8_t *q = resp; memcpy(q, &count, 4); q += 4;
                for (uint32_t i = 0; i < count; i++) {
                    if (outputs[i]) memcpy(q, outputs[i], HASH_SIZE); else memset(q, 0, HASH_SIZE);
                    q += HASH_SIZE;
                }
                uint32_t send_len = resp_len;
                if (network->config && network->config->sign_messages && network->config->auth_token[0] != '\0') {
                    uint8_t tag[SIG_LEN];
                    hmac_sha256((const uint8_t*)network->config->auth_token, strlen(network->config->auth_token), resp, resp_len, tag);
                    memcpy(q, tag, SIG_LEN);
                    send_len += SIG_LEN;
                }
                network_send_message(peer, MSG_HASH_RESPONSE, resp, send_len);
                free(resp);
            }
            for (uint32_t i = 0; i < count; i++) { free((void*)inputs[i]); free(outputs[i]); }
            free(inputs); free(lens); free(outputs);
            (void)rc;
            break;
        }
        case MSG_HASH_RESPONSE: {
            // Expected payload: u32 count, followed by count * 32-byte hashes [| sig[32] if signing]
            if (!network->pending_hash_active || network->pending_hash_peer != peer) {
                // Unexpected response; ignore
                break;
            }
            if (!payload || header->payload_len < 4) {
                network->pending_hash_status = -1;
                network->pending_hash_active = 0;
                break;
            }
            uint32_t rcnt = 0; memcpy(&rcnt, payload, 4);
            if ((int)rcnt != network->pending_hash_expected) {
                network->pending_hash_status = -1;
                network->pending_hash_active = 0;
                break;
            }
            size_t need = 4 + (size_t)rcnt * HASH_SIZE;
            size_t have = header->payload_len;
            if (network->config && network->config->sign_messages && network->config->auth_token[0] != '\0') {
                if (have != need + SIG_LEN) {
                    network->pending_hash_status = -1;
                    network->pending_hash_active = 0;
                    break;
                }
                // verify signature over first 'need' bytes
                const uint8_t *sig = payload + need;
                uint8_t calc[SIG_LEN];
                if (hmac_sha256((const uint8_t*)network->config->auth_token, strlen(network->config->auth_token), payload, need, calc) != 0 || memcmp(sig, calc, SIG_LEN) != 0) {
                    network->pending_hash_status = -1;
                    network->pending_hash_active = 0;
                    break;
                }
            } else if (have != need) {
                network->pending_hash_status = -1;
                network->pending_hash_active = 0;
                break;
            }
            const uint8_t *q = payload + 4;
            for (int i = 0; i < (int)rcnt; i++) {
                memcpy(network->pending_hash_outputs[i], q, HASH_SIZE);
                q += HASH_SIZE;
            }
            network->pending_hash_status = 0;
            network->pending_hash_active = 0;
            break;
        }
        default:
            printf("Unknown message type: %d\n", header->msg_type);
            break;
    }
    
    return 0;
}

int network_process_events(network_t *network, int timeout_ms) {
    if (!network) return -1;
    
    fd_set readfds;
    FD_ZERO(&readfds);
    
    int max_fd = network->listen_fd;
    FD_SET(network->listen_fd, &readfds);

    // Periodic discovery beacon in MODE_AUTO
    if (network->discovery_fd >= 0 && network->config && network->config->mode == MODE_AUTO) {
        time_t nowb = time(NULL);
        if (nowb - network->last_discovery_beacon >= 3) {
            // Broadcast our presence (manual wire format)
            uint8_t pkt[4 + NODE_ID_SIZE + 2 + 4];
            uint8_t *pp = pkt;
            pp[0] = 'D'; pp[1] = 'I'; pp[2] = 'S'; pp[3] = 'C'; pp += 4;
            memcpy(pp, network->local_node->id, NODE_ID_SIZE); pp += NODE_ID_SIZE;
            uint16_t port_be = htons((uint16_t)network->config->port);
            memcpy(pp, &port_be, 2); pp += 2;
            uint32_t cp_q16 = (uint32_t)((network->local_node->capabilities.compute_power * 65536.0f) + 0.5f);
            uint32_t cp_be = htonl(cp_q16);
            memcpy(pp, &cp_be, 4); pp += 4;
            struct sockaddr_in baddr = {0};
            baddr.sin_family = AF_INET;
            baddr.sin_port = htons(DISCOVERY_PORT);
            baddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
            sendto(network->discovery_fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&baddr, sizeof(baddr));
            network->last_discovery_beacon = nowb;
        }
    }
    
    // Snapshot peers for select to avoid holding locks during I/O
    peer_t *peers_snapshot[MAX_PEERS]; int pc = 0;
    pthread_mutex_lock(&network->peers_lock);
    pc = network->peer_count; if (pc > MAX_PEERS) pc = MAX_PEERS;
    for (int i = 0; i < pc; i++) peers_snapshot[i] = network->peers[i];
    pthread_mutex_unlock(&network->peers_lock);
    for (int i = 0; i < pc; i++) {
        int fd = peers_snapshot[i]->socket_fd;
        FD_SET(fd, &readfds);
        if (fd > max_fd) max_fd = fd;
    }

    // Also monitor discovery socket
    if (network->discovery_fd >= 0) {
        FD_SET(network->discovery_fd, &readfds);
        if (network->discovery_fd > max_fd) max_fd = network->discovery_fd;
    }
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);
    if (activity < 0 && errno != EINTR) {
        perror("select");
        return -1;
    }
    
    if (FD_ISSET(network->listen_fd, &readfds)) {
        // Refill accept tokens
        time_t nowa = time(NULL);
        if (nowa > network->accept_last_refill) {
            long delta = nowa - network->accept_last_refill;
            long add = delta * RL_ACCEPT_TOKENS_PER_SEC;
            if (add > 0) {
                network->accept_tokens += (int)add;
                if (network->accept_tokens > RL_ACCEPT_TOKENS_PER_SEC) network->accept_tokens = RL_ACCEPT_TOKENS_PER_SEC;
                network->accept_last_refill = nowa;
            }
        }
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        int new_fd = accept(network->listen_fd, (struct sockaddr *)&addr, &addrlen);
        if (new_fd >= 0) {
            if (network->accept_tokens <= 0) {
                // Rate-limited: immediately close to avoid backlog exhaustion
                close(new_fd);
            } else {
                network->accept_tokens -= 1;
                peer_t *peer = peer_create(new_fd, &addr);
                if (peer) {
                    network_add_peer(network, peer);
                } else {
                    close(new_fd);
                }
            }
        }
    }
    
    // Handle incoming discovery beacons
    if (network->discovery_fd >= 0 && FD_ISSET(network->discovery_fd, &readfds)) {
        struct sockaddr_in src; socklen_t slen = sizeof(src);
        uint8_t rbuf[4 + NODE_ID_SIZE + 2 + 4]; ssize_t n = recvfrom(network->discovery_fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&src, &slen);
        if (n == (ssize_t)sizeof(rbuf) && rbuf[0]=='D' && rbuf[1]=='I' && rbuf[2]=='S' && rbuf[3]=='C') {
            const uint8_t *rp = rbuf + 4;
            if (memcmp(rp, network->local_node->id, NODE_ID_SIZE) != 0) {
                uint8_t nid[NODE_ID_SIZE]; memcpy(nid, rp, NODE_ID_SIZE); rp += NODE_ID_SIZE;
                uint16_t pbe = 0; memcpy(&pbe, rp, 2); rp += 2;
                uint32_t cpbe = 0; memcpy(&cpbe, rp, 4); rp += 4;
                float cp = (float)(ntohl(cpbe)) / 65536.0f;
                network_discovery_note(network, nid, &src, ntohs(pbe), cp);
            }
        }
    }

    // Periodically try to connect to best discovered peer if we have none
    if (network->config && network->config->mode == MODE_AUTO) {
        time_t nowc = time(NULL);
        if (network->peer_count == 0 && (nowc - network->last_connect_attempt) >= 3 && network->discovered_count > 0) {
            int best = -1;
            for (int i = 0; i < network->discovered_count; i++) {
                // Skip stale entries (> 15s)
                if ((nowc - network->discovered[i].last_seen) > 15) continue;
                if (best < 0) { best = i; continue; }
                if (memcmp(network->discovered[i].node_id, network->discovered[best].node_id, NODE_ID_SIZE) < 0) {
                    best = i;
                }
            }
            if (best >= 0) {
                char host[64]; inet_ntop(AF_INET, &network->discovered[best].addr.sin_addr, host, sizeof(host));
                int port = network->discovered[best].tcp_port ? network->discovered[best].tcp_port : network->config->port;
                char addrbuf[96]; snprintf(addrbuf, sizeof(addrbuf), "%s:%d", host, port);
                printf("Discovery: attempting connection to %s (best discovered)\n", addrbuf);
                if (network_connect_to_master(network, addrbuf) == 0) {
                    // If we connected to a smaller ID, we are worker; otherwise we remain master but still connected
                    if (memcmp(network->discovered[best].node_id, network->local_node->id, NODE_ID_SIZE) < 0) {
                        network->is_master = 0;
                    }
                }
                network->last_connect_attempt = nowc;
            }
        }
    }

    for (int i = 0; i < pc; i++) {
        peer_t *peer = peers_snapshot[i];
        if (FD_ISSET(peer->socket_fd, &readfds)) {
            // Peek header to ensure full header is available
            msg_header_t header;
            ssize_t pn = recv(peer->socket_fd, &header, sizeof(header), MSG_PEEK);
            if (pn <= 0) {
                network_remove_peer(network, peer);
                continue;
            }
            if (pn < (ssize_t)sizeof(header)) {
                // Wait for more data next loop
                continue;
            }
            if (header.magic != PROTOCOL_MAGIC || header.version != PROTOCOL_VERSION) {
                fprintf(stderr, "Protocol error from %s\n", peer->addr_str);
                network_remove_peer(network, peer);
                continue;
            }
            if (header.payload_len > MAX_PAYLOAD_LEN) {
                fprintf(stderr, "Payload too large from %s: %u bytes\n", peer->addr_str, header.payload_len);
                network_remove_peer(network, peer);
                continue;
            }
            size_t total = sizeof(header) + header.payload_len;
            // Peek entire frame
            uint8_t *frame = (uint8_t*)malloc(total);
            if (!frame) { network_remove_peer(network, peer); continue; }
            ssize_t fn = recv(peer->socket_fd, frame, total, MSG_PEEK);
            if (fn < (ssize_t)total) { free(frame); continue; }
            // Now consume the frame
            ssize_t rn = recv(peer->socket_fd, frame, total, 0);
            if (rn != (ssize_t)total) { free(frame); network_remove_peer(network, peer); continue; }
            // Validate checksum
            msg_header_t *hdr = (msg_header_t*)frame;
            uint8_t *payload = frame + sizeof(msg_header_t);
            if (hdr->payload_len > 0) {
                uint32_t sum = calculate_checksum(payload, hdr->payload_len);
                if (sum != hdr->checksum) {
                    fprintf(stderr, "Checksum mismatch from %s\n", peer->addr_str);
                    free(frame); network_remove_peer(network, peer); continue;
                }
            }
            // Any message counts as activity
            pthread_mutex_lock(&peer->lock);
            peer->last_seen = time(NULL);
            pthread_mutex_unlock(&peer->lock);
            network_handle_message(network, peer, hdr, payload);
            free(frame);
        }
    }
    
    // Periodic heartbeat broadcast to all peers
    {
        time_t nowh = time(NULL);
        if (nowh - network->last_heartbeat_sent >= 5) {
            peer_t *peers_snapshot2[MAX_PEERS]; int pc2 = 0;
            pthread_mutex_lock(&network->peers_lock);
            pc2 = network->peer_count; if (pc2 > MAX_PEERS) pc2 = MAX_PEERS;
            for (int i = 0; i < pc2; i++) peers_snapshot2[i] = network->peers[i];
            pthread_mutex_unlock(&network->peers_lock);
            for (int i = 0; i < pc2; i++) {
                network_send_message(peers_snapshot2[i], MSG_HEARTBEAT, NULL, 0);
            }
            network->last_heartbeat_sent = nowh;
        }
    }

    // Prune stale peers (no activity/heartbeat within 30s)
    {
        time_t nowp = time(NULL);
        // Snapshot and select removals to avoid iterating while mutating
        peer_t *peers_snapshot3[MAX_PEERS]; int pc3 = 0;
        pthread_mutex_lock(&network->peers_lock);
        pc3 = network->peer_count; if (pc3 > MAX_PEERS) pc3 = MAX_PEERS;
        for (int i = 0; i < pc3; i++) peers_snapshot3[i] = network->peers[i];
        pthread_mutex_unlock(&network->peers_lock);
        for (int i = 0; i < pc3; i++) {
            peer_t *p = peers_snapshot3[i];
            time_t ls;
            pthread_mutex_lock(&p->lock); ls = p->last_seen; pthread_mutex_unlock(&p->lock);
            if ((nowp - ls) > 30) {
                network_remove_peer(network, p);
            }
        }
    }
    
    return 0;
}

void network_print_stats(network_t *network) {
    if (!network) return;
    // Snapshot peers to avoid races
    peer_t *peers_snapshot[MAX_PEERS]; int pc = 0;
    pthread_mutex_lock(&network->peers_lock);
    pc = network->peer_count; if (pc > MAX_PEERS) pc = MAX_PEERS;
    for (int i = 0; i < pc; i++) peers_snapshot[i] = network->peers[i];
    pthread_mutex_unlock(&network->peers_lock);
    printf("=== Connected Devices ===\n");
    printf("Peers: %d | Role: %s\n", pc, network->is_master ? "Master" : "Worker");
    // Table header
    printf("%-3s %-16s %-21s %-10s %14s %8s %10s\n", "#", "NodeID", "Address", "Algo", "Hashrate(H/s)", "Shares", "LastSeen");
    printf("%-3s %-16s %-21s %-10s %14s %8s %10s\n", "---", "----------------", "---------------------", "----------", "--------------", "--------", "----------");
    time_t now = time(NULL);
    double peers_sum = 0.0;
    for (int i = 0; i < pc; i++) {
        peer_t *p = peers_snapshot[i];
        const char *algo = (p->remote_algo[0] ? p->remote_algo : "-");
        char hr_buf[32];
        if (p->remote_hashrate > 0.0 && (now - p->stats_last_update) <= 15) {
            snprintf(hr_buf, sizeof(hr_buf), "%.2f", p->remote_hashrate);
            peers_sum += p->remote_hashrate;
        } else {
            snprintf(hr_buf, sizeof(hr_buf), "-");
        }
        long last_seen = (long)(now - p->last_seen);
        printf("%-3d %.16s %-21s %-10s %14s %8lu %10lds\n",
               i + 1,
               p->node_id_str,
               p->addr_str,
               algo,
               hr_buf,
               (unsigned long)p->remote_shares,
               last_seen < 0 ? 0 : last_seen);
    }
    printf("\n");

    // Cluster hashrate summary (local + recent peers)
    double local_h = 0.0;
    if (network->local_node) {
        local_h = network->local_node->stats.hashrate;
    }
    double cluster = local_h + peers_sum;
    printf("Cluster Hashrate (H/s): %.2f  (local: %.2f, peers: %.2f)\n\n", cluster, local_h, peers_sum);
}

// Send local stats to peers
void network_broadcast_stats(network_t *network) {
    if (!network || network->peer_count == 0 || !network->local_node) return;

    // Update local hashrate estimate (same logic as node_print_stats)
    time_t now = time(NULL);
    time_t dt = now - network->local_node->last_hashrate_update;
    if (dt > 0) {
        uint64_t diff = network->local_node->stats.hashes_computed - network->local_node->hashes_at_last_update;
        network->local_node->stats.hashrate = (double)diff / (double)dt;
        network->local_node->last_hashrate_update = now;
        network->local_node->hashes_at_last_update = network->local_node->stats.hashes_computed;
    }

    const mining_algo_interface_t *algo = (const mining_algo_interface_t *)network->local_node->mining_algo;
    const char *algo_name = (algo && algo->name) ? algo->name : "-";

    struct __attribute__((packed)) stats_payload_s {
        char algo[32];
        double hashrate;
        uint64_t hashes;
        uint64_t shares;
        uint64_t uptime;
    } sp;
    memset(&sp, 0, sizeof(sp));
    strncpy(sp.algo, algo_name, sizeof(sp.algo) - 1);
    sp.hashrate = network->local_node->stats.hashrate;
    sp.hashes = network->local_node->stats.hashes_computed;
    sp.shares = network->local_node->stats.shares_found;
    sp.uptime = (uint64_t)(now - network->local_node->stats.started_at);

    // Snapshot peers and send without holding lock
    peer_t *peers_snapshot[MAX_PEERS]; int pc = 0;
    pthread_mutex_lock(&network->peers_lock);
    pc = network->peer_count; if (pc > MAX_PEERS) pc = MAX_PEERS;
    for (int i = 0; i < pc; i++) peers_snapshot[i] = network->peers[i];
    pthread_mutex_unlock(&network->peers_lock);
    for (int i = 0; i < pc; i++) network_send_message(peers_snapshot[i], MSG_STATS_UPDATE, &sp, (uint32_t)sizeof(sp));
}
