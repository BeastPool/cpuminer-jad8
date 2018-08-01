#include "jad8.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../bmw/sph_bmw.h"
#include "../jh/sph_jh.h"
#include "../keccak/sph_keccak.h"
#include "../skein/sph_skein.h"
#include "../luffa/sph_luffa.h"
#include "../shavite/sph_shavite.h"
#include "../simd/sph_simd.h"
#include "../echo/sph_echo.h"


void jad8_hash(const char* input, char* output)
{
   
    sph_bmw512_context       ctx_bmw;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;

    sph_luffa512_context		ctx_luffa1;
    sph_shavite512_context		ctx_shavite1;
    sph_simd512_context		ctx_simd1;
    sph_echo512_context		ctx_echo1;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];	

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, input, 80);
    sph_skein512_close (&ctx_skein, hashA);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashA, 64);
    sph_jh512_close(&ctx_jh, hashB);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashB, 64);
    sph_keccak512_close(&ctx_keccak, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);
	
    sph_luffa512_init (&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, hashB, 64);
    sph_luffa512_close (&ctx_luffa1, hashA);	
	
    sph_echo512_init (&ctx_echo1); 
    sph_echo512 (&ctx_echo1, hashA, 64);   
    sph_echo512_close(&ctx_echo1, hashB); 
  
    sph_simd512_init (&ctx_simd1); 
    sph_simd512 (&ctx_simd1, hashB, 64);   
    sph_simd512_close(&ctx_simd1, hashA);
	
    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, hashA, 64);   
    sph_shavite512_close(&ctx_shavite1, hashB);  
		

    memcpy(output, hashB, 32);
	
}

int scanhash_jad8( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done )
{
    uint32_t _ALIGN(64) endiandata[20];
    uint32_t _ALIGN(64) hash[8];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    const uint32_t first_nonce = pdata[19];
    const uint32_t Htarg = ptarget[7];

    uint32_t nonce = first_nonce;

    swab32_array( endiandata, pdata, 20 );

    do {
            be32enc(&endiandata[19], nonce);
            jad8_hash(endiandata, hash);
            if ( hash[7] <= Htarg && fulltest( hash, ptarget ) )
            {
                    pdata[19] = nonce;
                    *hashes_done = pdata[19] - first_nonce;
                    work_set_target_ratio(work, hash);
                    return 1;
            }
            nonce++;
    } while (nonce < max_nonce && !work_restart[thr_id].restart);

    pdata[19] = nonce;
    *hashes_done = pdata[19] - first_nonce + 1;
    return 0;
}


bool register_jad8_algo(algo_gate_t *gate)
{
  gate->scanhash = (void *)&scanhash_jad8;
  gate->hash = (void *)&jad8_hash;
  gate->optimizations = SSE2_OPT | AVX2_OPT;
  return true;
}
