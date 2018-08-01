#ifndef JAD8_H
#define JAD8_H
#include "algo-gate-api.h"
#include <stdint.h>

void jad8_hash(const char* input, char* output);
int scanhash_jad8( int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done );

#endif
