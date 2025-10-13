#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

// Compute HMAC-SHA256 tag for data using key
// out must be 32 bytes
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t out[32]);

#endif // CRYPTO_H
