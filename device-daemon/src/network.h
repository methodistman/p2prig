#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include "node.h"
#include "config.h"
#include "storage.h"

#define MAX_PEERS 128
#define MAX_PENDING_CONNECTIONS 10
#define PACKET_BUFFER_SIZE 65536
#define MAX_DISCOVERED 128

// Protocol safety limits
#define MAX_PAYLOAD_LEN (256 * 1024)   // 256 KiB per message payload cap
#define MAX_HASH_BATCH 2048            // Max number of hashes per remote request
#define SIG_LEN 32                     // HMAC-SHA256 tag length
#define MAX_PEER_LIST_ENTRIES 128      // Max entries processed from peer list messages

// Basic rate-limiting (token bucket)
#define RL_MSG_TOKENS_PER_SEC 100      // generic tokens per peer per second
#define RL_HASH_TOKENS_PER_SEC 5       // hash request tokens per peer per second
#define RL_ACCEPT_TOKENS_PER_SEC 20    // inbound TCP accepts per second (global)

// Discovery
#define DISCOVERY_PORT 10000


// Protocol message types
typedef enum {
    MSG_HELLO = 1,           // Initial handshake
    MSG_HELLO_REPLY,         // Response to handshake
    MSG_CAPABILITIES,        // Announce node capabilities
    MSG_PEER_LIST,           // Share peer list
    MSG_WORKUNIT_REQUEST,    // Request work
    MSG_WORKUNIT_ASSIGN,     // Assign work to peer
    MSG_WORKUNIT_RESULT,     // Submit work result
    MSG_DATASET_REQUEST,     // Request dataset chunk
    MSG_DATASET_CHUNK,       // Send dataset chunk
    MSG_HEARTBEAT,           // Keep-alive
    MSG_GOODBYE,             // Disconnect notification
    MSG_STATS_UPDATE,        // Periodic stats update (hashrate, algo, etc.)
    MSG_HASH_REQUEST,        // Request batch hashes (remote hashing via dataset host)
    MSG_HASH_RESPONSE        // Batch hashes response
} msg_type_t;

// Message header
typedef struct {
    uint32_t magic;          // Protocol magic number
    uint16_t version;        // Protocol version
    uint16_t msg_type;       // Message type
    uint32_t payload_len;    // Payload length
    uint32_t checksum;       // Simple checksum
} __attribute__((packed)) msg_header_t;

#define PROTOCOL_MAGIC 0x4D494E45  // "MINE"
#define PROTOCOL_VERSION 1

// Peer information
typedef struct peer_s {
    int socket_fd;
    struct sockaddr_in addr;
    char addr_str[64];
    uint8_t node_id[NODE_ID_SIZE];
    char node_id_str[NODE_ID_SIZE * 2 + 1];
    node_capabilities_t capabilities;
    time_t last_seen;
    int is_master;
    int is_connected;
    int is_authenticated;  // set after successful HELLO (when auth required)
    pthread_mutex_t lock;  // protects last_seen and remote_* stats
    // Remote stats (populated via MSG_STATS_UPDATE)
    double remote_hashrate;
    uint64_t remote_hashes;
    uint64_t remote_shares;
    char remote_algo[32];
    time_t stats_last_update;

    // Per-peer rate limiting buckets
    int rl_msg_tokens; time_t rl_msg_last_refill;
    int rl_hash_tokens; time_t rl_hash_last_refill;

    // Whether this peer indicated it requires signed critical RPCs
    int requires_signing;
} peer_t;

// Discovered peer (from UDP discovery beacons)
typedef struct discovered_peer_s {
    uint8_t node_id[NODE_ID_SIZE];
    struct sockaddr_in addr;
    uint16_t tcp_port;
    float compute_power;
    time_t last_seen;
    time_t last_attempt;   // last connection attempt to this peer
} discovered_peer_t;

// Network context
typedef struct {
    config_t *config;
    node_t *local_node;
    int listen_fd;
    int discovery_fd;              // UDP discovery socket
    peer_t *peers[MAX_PEERS];
    int peer_count;
    int is_master;
    peer_t *dataset_host_peer;     // NULL => local node is dataset host
    uint8_t recv_buffer[PACKET_BUFFER_SIZE];
    time_t last_discovery_beacon;  // last time we broadcast a discovery beacon
    time_t last_connect_attempt;   // last time we tried to auto-connect to a discovered peer
    time_t last_heartbeat_sent;    // last time we sent heartbeats to peers
    discovered_peer_t discovered[MAX_DISCOVERED];
    int discovered_count;

    // Concurrency: protect peers[]/peer_count and discovered[]/discovered_count
    pthread_mutex_t peers_lock;
    pthread_mutex_t discovered_lock;

    // Accept rate limiting
    int accept_tokens; time_t accept_last_refill;

    // Work WAL for assignments/results
    wal_ctx_t *work_wal;

    // Pending remote hashing state (single outstanding request)
    int pending_hash_active;       // 1 while waiting for MSG_HASH_RESPONSE
    peer_t *pending_hash_peer;     // which peer we expect response from
    int pending_hash_expected;     // expected count of hashes
    uint8_t **pending_hash_outputs; // destination buffers for hashes
    int pending_hash_status;       // 0=ok, <0=error, >0=other codes
} network_t;

// Network lifecycle
network_t *network_create(config_t *config, node_t *local_node);
void network_destroy(network_t *network);
int network_start_listener(network_t *network);
int network_connect_to_master(network_t *network, const char *address);
int network_process_events(network_t *network, int timeout_ms);

// Auto-discovery/master election (MODE_AUTO)
int network_auto_discover_and_elect(network_t *network);

// Dataset host selection among peers + self
void network_select_dataset_host(network_t *network);
peer_t *network_get_dataset_host(network_t *network);

// Remote hashing via dataset host (batch request/response)
int network_request_remote_hashes(network_t *network, peer_t *host,
                                  const uint8_t seed[32],
                                  const uint8_t **inputs, size_t *input_lens,
                                  uint8_t **outputs, int count, int timeout_ms);

// Peer management
peer_t *peer_create(int socket_fd, struct sockaddr_in *addr);
void peer_destroy(peer_t *peer);
int network_add_peer(network_t *network, peer_t *peer);
void network_remove_peer(network_t *network, peer_t *peer);
peer_t *network_find_peer_by_id(network_t *network, uint8_t *node_id);

int network_send_message(peer_t *peer, msg_type_t type, const void *payload, uint32_t payload_len);
int network_handle_message(network_t *network, peer_t *peer, msg_header_t *header, uint8_t *payload);

// Signed helpers for work assignment/result
int network_send_workunit_assign(network_t *network, peer_t *peer,
                                 uint64_t work_id, uint64_t nonce_start, uint64_t nonce_end,
                                 const uint8_t data[], uint8_t flags);
int network_send_workunit_result(network_t *network, peer_t *peer,
                                 uint64_t work_id, uint64_t nonce,
                                 const uint8_t hash[32], uint8_t status);

// Statistics
void network_print_stats(network_t *network);
// Broadcast local node stats to peers
void network_broadcast_stats(network_t *network);
// Broadcast discovered peers list to connected peers
void network_broadcast_peer_list(network_t *network);

// Discovery helpers
void network_discovery_note(network_t *network, const uint8_t node_id[NODE_ID_SIZE],
                            const struct sockaddr_in *addr, uint16_t tcp_port, float compute_power);

#endif // NETWORK_H
