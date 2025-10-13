#ifndef WORKLOAD_H
#define WORKLOAD_H

#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include "node.h"

#define MAX_WORK_UNITS 1024
#define WORK_UNIT_SIZE 64  // bytes

typedef enum {
    WORK_STATUS_PENDING,
    WORK_STATUS_ASSIGNED,
    WORK_STATUS_COMPUTING,
    WORK_STATUS_COMPLETED,
    WORK_STATUS_FAILED
} work_status_t;

typedef struct {
    uint64_t id;
    uint8_t data[WORK_UNIT_SIZE];
    uint64_t nonce_start;
    uint64_t nonce_end;
    work_status_t status;
    uint8_t assigned_node_id[NODE_ID_SIZE];
    time_t assigned_at;
    time_t completed_at;
} work_unit_t;

typedef struct {
    work_unit_t *units[MAX_WORK_UNITS];
    int unit_count;
    uint64_t next_work_id;
    pthread_mutex_t lock; // protects units[], unit_count, next_work_id and unit state transitions
} workload_manager_t;

// Workload management
workload_manager_t *workload_manager_create(void);
void workload_manager_destroy(workload_manager_t *wm);

// Work unit operations
work_unit_t *workload_create_unit(workload_manager_t *wm, const uint8_t *data, uint64_t nonce_start, uint64_t nonce_end);
work_unit_t *workload_get_next_pending(workload_manager_t *wm);
int workload_assign_unit(work_unit_t *unit, uint8_t *node_id);
int workload_complete_unit(work_unit_t *unit);

// Thread-safe CAS-style operations
// Try to assign only if current status is PENDING; sets assigned_at and assigned_node_id atomically under lock
int workload_try_assign(workload_manager_t *wm, work_unit_t *unit, const uint8_t *node_id, time_t now);
// Requeue to PENDING only if unit is ASSIGNED and assigned_at still equals expected; prevents double-requeue
int workload_requeue_if_timeout(workload_manager_t *wm, work_unit_t *unit, time_t assigned_at_expected);

// Processing
int workload_process(node_t *node);

#endif // WORKLOAD_H
