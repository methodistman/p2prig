#include "storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

static int fsync_dirname(const char *path) {
    // fsync the directory containing path
    const char *slash = strrchr(path, '/');
    char dpath[512];
    if (!slash) {
        strcpy(dpath, ".");
    } else {
        size_t n = (size_t)(slash - path);
        if (n >= sizeof(dpath)) n = sizeof(dpath) - 1;
        memcpy(dpath, path, n);
        dpath[n] = '\0';
    }
    int dfd = open(dpath, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return -1;
    int rc = fsync(dfd);
    close(dfd);
    return rc;
}

int atomic_write_file(const char *path, const uint8_t *data, size_t len) {
    if (!path || (!data && len > 0)) return -1;
    char tmppath[512];
    snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", path, getpid());
    int fd = open(tmppath, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(tmppath);
            return -1;
        }
        off += (size_t)n;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmppath); return -1; }
    if (close(fd) != 0) { unlink(tmppath); return -1; }
    if (rename(tmppath, path) != 0) { unlink(tmppath); return -1; }
    (void)fsync_dirname(path);
    return 0;
}

struct wal_ctx_s {
    int fd;
    char path[512];
};

static int wal_fsync_fd(int fd) { return fsync(fd); }

wal_ctx_t *wal_open(const char *path) {
    if (!path) return NULL;
    int fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0644);
    if (fd < 0) return NULL;
    wal_ctx_t *w = (wal_ctx_t *)calloc(1, sizeof(wal_ctx_t));
    if (!w) { close(fd); return NULL; }
    w->fd = fd;
    strncpy(w->path, path, sizeof(w->path) - 1);
    return w;
}

int wal_append(wal_ctx_t *wal, const uint8_t *rec, size_t len) {
    if (!wal || (!rec && len > 0)) return -1;
    uint32_t le = (uint32_t)len;
    // write length then record
    ssize_t n = write(wal->fd, &le, sizeof(le));
    if (n != (ssize_t)sizeof(le)) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t m = write(wal->fd, rec + off, len - off);
        if (m < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)m;
    }
    if (wal_fsync_fd(wal->fd) != 0) return -1;
    (void)fsync_dirname(wal->path);
    return 0;
}

int wal_iterate(const char *path, int (*cb)(const uint8_t *rec, size_t len, void *udata), void *udata) {
    if (!path || !cb) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    for (;;) {
        uint32_t le = 0; ssize_t n = read(fd, &le, sizeof(le));
        if (n == 0) break; // EOF
        if (n != (ssize_t)sizeof(le)) { close(fd); return -1; }
        uint8_t *buf = (uint8_t*)malloc(le);
        if (!buf) { close(fd); return -1; }
        size_t off = 0; while (off < le) {
            ssize_t m = read(fd, buf + off, le - off);
            if (m <= 0) { free(buf); close(fd); return -1; }
            off += (size_t)m;
        }
        int rc = cb(buf, le, udata);
        free(buf);
        if (rc != 0) { close(fd); return rc; }
    }
    close(fd);
    return 0;
}

void wal_close(wal_ctx_t *wal) {
    if (!wal) return;
    if (wal->fd >= 0) close(wal->fd);
    free(wal);
}
