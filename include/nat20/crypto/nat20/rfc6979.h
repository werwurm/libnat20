/*
 * Copyright 2025 Aurora Operations, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

/**
 * @file rfc6979.h
 */

#include <nat20/crypto.h>
#include <nat20/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Big number represented in 32 bit machine words in little endian order.
 * I.e., each word is in machine byte order, but the word with the lowest
 * index always has the lowest significance.
 */
struct n20_bn_s {
    size_t word_count;
    uint32_t* words;
};

/** @brief Alias for @ref n20_bn_s. */
typedef struct n20_bn_s n20_bn_t;

extern void n20_bn_to_octets(uint8_t* octets, size_t octets_len, n20_bn_t const* bn);

extern n20_error_t n20_rfc6979_k_generation(n20_crypto_digest_context_t* ctx,
                                            n20_crypto_digest_algorithm_t digest_algorithm,
                                            n20_crypto_key_type_t key_type,
                                            n20_slice_t const* x_octets,
                                            n20_crypto_gather_list_t const* m_octets,
                                            n20_bn_t* k);

#ifdef __cplusplus
}
#endif
