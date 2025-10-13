#include "config.h"
#include <string.h>

void config_init(config_t *config) {
    config->mode = MODE_AUTO;
    config->algorithm = ALGO_RANDOMX;
    config->port = DEFAULT_PORT;
    config->master_address[0] = '\0';
    config->num_threads = DEFAULT_THREADS;
    config->ram_mb = DEFAULT_RAM_MB;
    config->is_dataset_host = 0;
    
    // Pool defaults
    config->use_pool = 0;
    config->pool_host[0] = '\0';
    config->pool_port = 3333;  // Common Stratum port
    config->pool_user[0] = '\0';
    config->pool_pass[0] = '\0';

    // Auth defaults
    config->require_auth = 0;
    config->auth_token[0] = '\0';
    config->sign_messages = 0;
}
