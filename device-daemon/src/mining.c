#include "mining.h"
#include <stdio.h>
#include <string.h>

// Forward declarations of algorithm interfaces
extern const mining_algo_interface_t randomx_interface;
extern const mining_algo_interface_t ghostrider_interface;

const mining_algo_interface_t *mining_get_algorithm(mining_algo_t algo) {
    switch (algo) {
        case ALGO_RANDOMX:
            return &randomx_interface;
        case ALGO_GHOSTRIDER:
            return &ghostrider_interface;
        default:
            return NULL;
    }
}

int mining_check_difficulty(const uint8_t *hash, uint32_t difficulty) {
    if (!hash) return 0;
    
    // Simple difficulty check: count leading zero bits
    // Real implementation would compare against target
    int zero_bits = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        if (hash[i] == 0) {
            zero_bits += 8;
        } else {
            // Count leading zeros in this byte
            uint8_t byte = hash[i];
            while ((byte & 0x80) == 0 && zero_bits < HASH_SIZE * 8) {
                zero_bits++;
                byte <<= 1;
            }
            break;
        }
    }
    
    return zero_bits >= (int)difficulty;
}

void mining_format_hash(const uint8_t *hash, char *output, size_t output_size) {
    if (!hash || !output || output_size < HASH_SIZE * 2 + 1) return;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(output + i * 2, "%02x", hash[i]);
    }
    output[HASH_SIZE * 2] = '\0';
}

uint64_t mining_hash_to_uint64(const uint8_t *hash) {
    if (!hash) return 0;
    
    uint64_t result = 0;
    for (int i = 0; i < 8 && i < HASH_SIZE; i++) {
        result |= ((uint64_t)hash[i]) << (i * 8);
    }
    return result;
}

// Compare two 256-bit little-endian values
// Returns 1 if a <= b, 0 otherwise
// For little-endian, compare from high bytes (index 31) down to low (index 0)
int mining_hash256_le_compare(const uint8_t a[32], const uint8_t b[32]) {
    if (!a || !b) return 0;
    
    // Compare from most significant byte (index 31) to least (index 0)
    for (int i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return 1;  // a < b, so a <= b
        if (a[i] > b[i]) return 0;  // a > b, so a > b
        // If equal, continue to next byte
    }
    
    // All bytes equal, so a == b, which means a <= b
    return 1;
}
