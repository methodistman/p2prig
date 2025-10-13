#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <stddef.h>

// Atomic write: write to temp file, fsync, then rename to target.
int atomic_write_file(const char *path, const uint8_t *data, size_t len);

// Very small append-only WAL
typedef struct wal_ctx_s wal_ctx_t;

// Open WAL at path. Creates if missing. Returns NULL on error.
wal_ctx_t *wal_open(const char *path);

// Append a length-prefixed record and fsync. Returns 0 on success.
int wal_append(wal_ctx_t *wal, const uint8_t *rec, size_t len);

// Iterate existing WAL file from disk, invoking cb for each record.
// Returns 0 on success. cb should return 0 to continue, non-zero to stop with error.
int wal_iterate(const char *path,
                int (*cb)(const uint8_t *rec, size_t len, void *udata),
                void *udata);

// Flush and close WAL.
void wal_close(wal_ctx_t *wal);

#endif // STORAGE_H
