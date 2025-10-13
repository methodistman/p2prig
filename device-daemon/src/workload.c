#include "workload.h"
#include "mining.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

workload_manager_t *workload_manager_create(void) {
    workload_manager_t *wm = calloc(1, sizeof(workload_manager_t));
    if (!wm) {
        return NULL;
    }
    wm->next_work_id = 1;
    pthread_mutex_init(&wm->lock, NULL);
    return wm;
}

void workload_manager_destroy(workload_manager_t *wm) {
    if (!wm) {
        return;
    }
    
    pthread_mutex_lock(&wm->lock);
    for (int i = 0; i < wm->unit_count; i++) {
        free(wm->units[i]);
    }
    pthread_mutex_unlock(&wm->lock);
    pthread_mutex_destroy(&wm->lock);
    
    free(wm);
}

work_unit_t *workload_create_unit(workload_manager_t *wm, const uint8_t *data, 
                                   uint64_t nonce_start, uint64_t nonce_end) {
    if (!wm || wm->unit_count >= MAX_WORK_UNITS) {
        return NULL;
    }
    
    work_unit_t *unit = calloc(1, sizeof(work_unit_t));
    if (!unit) {
        return NULL;
    }
    
    pthread_mutex_lock(&wm->lock);
    unit->id = wm->next_work_id++;
    if (data) {
        memcpy(unit->data, data, WORK_UNIT_SIZE);
    }
    unit->nonce_start = nonce_start;
    unit->nonce_end = nonce_end;
    unit->status = WORK_STATUS_PENDING;
    
    wm->units[wm->unit_count++] = unit;
    pthread_mutex_unlock(&wm->lock);
    return unit;
}

work_unit_t *workload_get_next_pending(workload_manager_t *wm) {
    if (!wm) {
        return NULL;
    }
    
    pthread_mutex_lock(&wm->lock);
    work_unit_t *ret = NULL;
    for (int i = 0; i < wm->unit_count; i++) {
        if (wm->units[i]->status == WORK_STATUS_PENDING) {
            ret = wm->units[i];
            break;
        }
    }
    pthread_mutex_unlock(&wm->lock);
    
    return ret;
}

int workload_assign_unit(work_unit_t *unit, uint8_t *node_id) {
    if (!unit || !node_id) {
        return -1;
    }
    
    memcpy(unit->assigned_node_id, node_id, NODE_ID_SIZE);
    unit->status = WORK_STATUS_ASSIGNED;
    unit->assigned_at = time(NULL);
    
    return 0;
}

int workload_complete_unit(work_unit_t *unit) {
    if (!unit) {
        return -1;
    }
    
    unit->status = WORK_STATUS_COMPLETED;
    unit->completed_at = time(NULL);
    
    return 0;
}

// Thread-safe CAS-style operations
int workload_try_assign(workload_manager_t *wm, work_unit_t *unit, const uint8_t *node_id, time_t now) {
    if (!wm || !unit || !node_id) return -1;
    pthread_mutex_lock(&wm->lock);
    if (unit->status != WORK_STATUS_PENDING) { pthread_mutex_unlock(&wm->lock); return -1; }
    memcpy(unit->assigned_node_id, node_id, NODE_ID_SIZE);
    unit->assigned_at = now;
    unit->status = WORK_STATUS_ASSIGNED;
    pthread_mutex_unlock(&wm->lock);
    return 0;
}

int workload_requeue_if_timeout(workload_manager_t *wm, work_unit_t *unit, time_t assigned_at_expected) {
    if (!wm || !unit) return -1;
    pthread_mutex_lock(&wm->lock);
    if (unit->status == WORK_STATUS_ASSIGNED && unit->assigned_at == assigned_at_expected) {
        unit->status = WORK_STATUS_PENDING;
        memset(unit->assigned_node_id, 0, NODE_ID_SIZE);
        unit->assigned_at = 0;
        pthread_mutex_unlock(&wm->lock);
        return 0;
    }
    pthread_mutex_unlock(&wm->lock);
    return -1;
}

int workload_process(node_t *node) {
    if (!node || !node->is_mining || !node->mining_ctx || !node->mining_algo) {
        return 0;
    }
    
    const mining_algo_interface_t *algo = node->mining_algo;
    
    // Create a test work unit
    // In production, this would come from the master node or pool
    uint8_t input[72];  // Block header size
    memset(input, 0, sizeof(input));
    
    // Simulate block header with timestamp
    time_t now = time(NULL);
    memcpy(input, &now, sizeof(time_t));
    memcpy(input + 8, node->id, NODE_ID_SIZE > 32 ? 32 : NODE_ID_SIZE);
    
    // Compute some hashes
    uint8_t hash[HASH_SIZE];
    int hashes_per_batch = 100;
    
    for (int i = 0; i < hashes_per_batch; i++) {
        // Vary the nonce
        uint64_t nonce = node->stats.hashes_computed + i;
        memcpy(input + 64, &nonce, sizeof(nonce));
        
        // Compute hash
        if (algo->compute_hash(node->mining_ctx, input, sizeof(input), hash) == 0) {
            node->stats.hashes_computed++;
            
            // Check if we found a share (very low difficulty for testing)
            if (mining_check_difficulty(hash, 8)) {
                node->stats.shares_found++;
                
                char hash_str[HASH_SIZE * 2 + 1];
                mining_format_hash(hash, hash_str, sizeof(hash_str));
                printf("[Node %s] Share found! Hash: %s\n", node->id_str, hash_str);
            }
        }
    }
    
    // Small delay to prevent CPU spinning
    struct timespec ts = {0, 1000000};  // 1ms
    nanosleep(&ts, NULL);
    
    return 0;
}
