/*
 * Generate independent PRINCEv2 fixtures using unmodified upstream C code.
 *
 * Check out https://github.com/rub-hgi/princev2 at
 * 0c6172dcd85f1fe6a269519093a79c7350fe6e55, then run from this repository:
 *
 * cc -std=gnu11 -O0 -I<upstream>/code tools/prince_reference_vectors.c \
 *   <upstream>/code/princev2.c <upstream>/code/key.c \
 *   <upstream>/code/block.c <upstream>/code/misc.c -o /tmp/prince-vectors
 * /tmp/prince-vectors
 *
 * The output must equal tests/data/princev2_upstream_vectors.json. No C
 * compiler or upstream checkout is needed when running the Rust tests.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "princev2.h"

static uint64_t random_state = UINT64_C(0x5052494e43455632);

/* SplitMix64, with unsigned wraparound and a fully specified initial state. */
static uint64_t next_random(void) {
    uint64_t z = (random_state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static void emit_vector(uint64_t k0, uint64_t k1, uint64_t plaintext,
                        int is_last) {
    princev2key_t key = key_new(k0, k1);
    uint64_t ciphertext = prince_encrypt(key, plaintext);
    assert(prince_decrypt(key, ciphertext) == plaintext);
    printf("    {\"key\":\"%016" PRIx64 "%016" PRIx64
           "\",\"plaintext\":\"%016" PRIx64
           "\",\"ciphertext\":\"%016" PRIx64 "\"}%s\n",
           k0, k1, plaintext, ciphertext, is_last ? "" : ",");
}

int main(void) {
    puts("{");
    puts("  \"upstream\": \"https://github.com/rub-hgi/princev2\",");
    puts("  \"commit\": \"0c6172dcd85f1fe6a269519093a79c7350fe6e55\",");
    puts("  \"source\": \"https://github.com/rub-hgi/princev2/blob/0c6172dcd85f1fe6a269519093a79c7350fe6e55/code/princev2.c\",");
    puts("  \"generator\": \"tools/prince_reference_vectors.c\",");
    puts("  \"compiler_flags\": \"-std=gnu11 -O0\",");
    puts("  \"key_encoding\": \"128-bit hexadecimal k0 || k1, most significant half first\",");
    puts("  \"random_generator\": \"SplitMix64; consecutive draws k0, k1, plaintext per vector\",");
    puts("  \"seed_hex\": \"5052494e43455632\",");
    puts("  \"fixed_vectors\": 5,");
    puts("  \"random_vectors\": 32,");
    puts("  \"vectors\": [");
    emit_vector(0, 0, 0, 0);
    emit_vector(UINT64_MAX, 0, 0, 0);
    emit_vector(0, UINT64_MAX, 0, 0);
    emit_vector(0, 0, UINT64_MAX, 0);
    emit_vector(UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
                UINT64_C(0x0123456789abcdef), 0);
    for (int i = 0; i < 32; i++) {
        /* Separate statements specify PRNG draw order in C. */
        uint64_t k0 = next_random();
        uint64_t k1 = next_random();
        uint64_t plaintext = next_random();
        emit_vector(k0, k1, plaintext, i == 31);
    }
    puts("  ]");
    puts("}");
    return 0;
}
