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

/** @file */

#pragma once

#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/oid.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup n20_input_compression_macros Input Compression Macros
 *
 * Macros for configuring input compression settings.
 * By default SHA2-512 is used for OpenDICE input compression.
 * Set `N20_INPUT_COMPRESSION_SHA256=1` to use SHA2-256 instead.
 * @{
 */

#if defined(N20_INPUT_COMPRESSION_SHA256)
#define N20_FUNC_COMPRESSED_INPUT_SIZE 32
#define N20_FUNC_COMPRESSED_INPUT_ALGORITHM n20_crypto_digest_algorithm_sha2_256_e
#else
/**
 * @brief Size of the compressed input.
 *
 * This controls the size of @ref n20_compressed_input_t.
 */
#define N20_FUNC_COMPRESSED_INPUT_SIZE 64
/**
 * @brief Algorithm used for compressing the input.
 *
 * This controls the algorithm used for compressing @ref n20_compressed_input_t.
 *
 * @sa n20_compress_input
 */
#define N20_FUNC_COMPRESSED_INPUT_ALGORITHM n20_crypto_digest_algorithm_sha2_512_e
#endif

/** @} */

/**
 * @brief Compressed input type.
 *
 * This type is used to represent the compressed input data
 * for the OpenDICE protocol.
 *
 * The type is defined as a fixed-size array of 64 bytes by default.
 * It can be changed to 32 bytes by defining `N20_INPUT_COMPRESSION_SHA256=1`
 * at compile time.
 */
typedef uint8_t n20_compressed_input_t[N20_FUNC_COMPRESSED_INPUT_SIZE];

/**
 * @brief Certificate formats.
 * This enumeration defines the formats of certificates that can be used
 * in the OpenDICE context.
 * It is used to specify the format of the certificate when issuing
 * certificates in the OpenDICE framework.
 *
 * The numbers are used in communication protocols to identify
 * the requested certificate format. So they must be stable.
 */
enum n20_certificate_format_s {
    /**
     * @brief Default value indicating no specific certificate format.
     *
     * This is used as default initialization value or when no
     * specific format is requested.
     */
    n20_certificate_format_none_e = 0,
    /**
     * @brief X.509 certificate format.
     *
     * This is used to request an X.509 certificate with DER encoding.
     */
    n20_certificate_format_x509_e = 1,
    /**
     * @brief COSE certificate format.
     *
     * This is used to request a COSE (CBOR Object Signing and Encryption)
     * certificate with CBOR encoding. The issued certificate will be
     * a COSE Sign1 object containing a CWT (CBOR Web Token) with the
     * appropriate claims as specified by the OpenDICE profile.
     */
    n20_certificate_format_cose_e = 2,
};

/**
 * @brief Alias for @ref n20_certificate_format_s.
 */
typedef enum n20_certificate_format_s n20_certificate_format_t;

/**
 * @brief Compresses the input data.
 *
 * This function compressed the OpenDICE input using a cryptographic hash function.
 *
 * In this context "compression" refers to digesting the required fields
 * of the OpenDICE input and producing the fixed-sized output that is
 * used as salt in the key derivation of the CDI_Attest (See [1]).
 *
 * H(code hash, configuration hash (or descriptor), authority hash, mode, hidden)
 *
 * If @p input->configuration_hash is not set (size 0),
 * the configuration descriptor is used instead.
 *
 * H is SHA2-512 by default but can be changed to SHA2-256 at
 * compile time. By defining `N20_INPUT_COMPRESSION_SHA256=1`.
 *
 * [1]
 * https://pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md#asymmetric-key-pair-derivation
 *
 * @param crypto_ctx The crypto context.
 * @param input The OpenDICE input.
 * @param digest The compressed input digest.
 * @return n20_error_t
 */
extern n20_error_t n20_compress_input(n20_crypto_digest_context_t *crypto_ctx,
                                      n20_open_dice_input_t const *input,
                                      n20_compressed_input_t digest);

/**
 * @brief The CDI Identifier unique for a CDI (or UDS) public key.
 *
 * The identifier is derived from the public key using a cryptographic hash function.
 * It is always truncated to 20 bytes with the msb in the first byte
 * unset so that it can be used as a positive integer serial number in
 * an X509 certificate without exceeding the maximum allowed length.
 */
typedef uint8_t n20_cdi_id_t[20];

/**
 * @brief Derives the CDI Identifier from the public key.
 *
 * This function derives the CDI Identifier from the public key using
 * SHA2-512. The result is truncated to 20 bytes and the msb in the first byte
 * is unset so that it can be used as a positive integer serial number in
 * an X509 certificate without exceeding the maximum allowed length.
 *
 * For reproducibility, the raw public key bits should be used.
 * For NIST curves, the uncompressed format without the 0x04 prefix
 * should be used. For ED25519, the canonical 32 bytes compressed
 * format should be used.
 *
 * @param crypto_ctx The crypto digest context that must implement SHA2-512.
 * @param public_key The public key to derive the CDI Identifier from.
 * @param cdi_id The derived CDI Identifier.
 * @return n20_error_t
 */
extern n20_error_t n20_open_dice_cdi_id(n20_crypto_digest_context_t *crypto_ctx,
                                        n20_slice_t const public_key,
                                        n20_cdi_id_t cdi_id);

/**
 * @brief Derives a key from the given CDI secret.
 *
 * This function derives a key from the given CDI secret using
 * the given salt and tag. The derived key is returned in the
 * given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param cdi_secret_in The CDI secret to derive the key from.
 * @param derived_out The derived key.
 * @param key_type_in The type of the derived key.
 * @param salt_in The salt to use for the derivation.
 * @param tag_in The tag to use for the derivation.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_derive_key(n20_crypto_context_t *crypto_ctx,
                                  n20_crypto_key_t cdi_secret_in,
                                  n20_crypto_key_t *derived_out,
                                  n20_crypto_key_type_t key_type_in,
                                  n20_slice_t const salt_in,
                                  n20_slice_t const tag_in);

/**
 * @brief Derives the next level CDI secret from the given CDI secret.
 *
 * This function derives the next level CDI secret from the given
 * CDI secret using the given salt and tag. The derived key is
 * returned in the given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param current The current CDI secret to derive the key from.
 * @param next The derived key.
 * @param info The information to use for the derivation.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_next_level_cdi_attest(n20_crypto_context_t *crypto_ctx,
                                             n20_crypto_key_t current,
                                             n20_crypto_key_t *next,
                                             n20_compressed_input_t info);

/**
 * @brief Derives an attestation key from the given CDI secret.
 *
 * This function derives an attestation key from the given CDI
 * secret using the given salt and tag. The derived key is returned
 * in the given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param cdi_secret The CDI secret to derive the key from.
 * @param derived The derived key.
 * @param key_type The type of the derived key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_derive_attestation_key(n20_crypto_context_t *crypto_ctx,
                                              n20_crypto_key_t cdi_secret,
                                              n20_crypto_key_t *derived,
                                              n20_crypto_key_type_t key_type);

/**
 * @brief Initializes the algorithm identifier structure.
 *
 * This function initializes the algorithm identifier structure
 * with the given key type.
 *
 * @param algorithm_identifier The algorithm identifier structure to initialize.
 * @param key_type The type of the key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_init_algorithm_identifier(
    n20_x509_algorithm_identifier_t *algorithm_identifier, n20_crypto_key_type_t key_type);

/**
 * @brief Initializes the key info structure.
 *
 * This function initializes the key info structure with the
 * given key type and public key.
 *
 * @param key_info The key info structure to initialize.
 * @param key_type The type of the key.
 * @param public_key The public key to use.
 * @param public_key_size The size of the public key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_init_key_info(n20_x509_public_key_info_t *key_info,
                                     n20_crypto_key_type_t key_type,
                                     uint8_t const *public_key,
                                     size_t public_key_size);

typedef n20_error_t (*n20_signer_callback_t)(void *signer,
                                             n20_slice_t tbs,
                                             uint8_t *signature,
                                             size_t *signature_size);

typedef struct n20_signer_s {
    n20_crypto_context_t *crypto_ctx;
    n20_crypto_key_t signing_key;
    n20_signer_callback_t cb;
} n20_signer_t;

extern n20_error_t n20_prepare_x509_cert(n20_open_dice_cert_info_t const *cert_info,
                                         n20_signer_t *signer,
                                         n20_crypto_key_type_t issuer_key_type,
                                         uint8_t *attestation_certificate,
                                         size_t *attestation_certificate_size);

/**
 * @brief Issues a new attestation certificate.
 *
 * This function generates a new CDI secret from a CDI or UDS given
 * as opaque crypto key handle and context information. It uses the
 * crypto context to generate a new CDI secret and then issues a
 * new attestation certificate for the given CDI level.
 * To that end it uses the derived CDI secret to derive a new
 * attestation key pair and formats the attestation certificate
 * using the given context information to generate the OpenDICE input
 * extension.
 * The attestation certificate is then signed using the attestation
 * key pair of the given CDI level.
 * The attestation certificate is then returned in the given
 * buffer.
 * The size of the attestation certificate buffer is given as
 * pointer which is updated to the actual size of the attestation
 * certificate.
 *
 * Important: Because of the way the attestation certificate is
 * rendered, the resulting certificate is not written to the
 * beginning of the buffer but to the end. Thus the certificate
 * is located at
 * `attestation_certificate + in_buffer_size - out_buffer_size`.
 *
 * The function returns @ref n20_error_ok_e on success, or an error
 * code on failure.
 */
extern n20_error_t n20_opendice_attestation_key_and_certificate(
    n20_crypto_context_t *crypto_ctx,
    n20_crypto_key_t parent_secret,
    n20_crypto_key_t parent_attestation_key,
    n20_crypto_key_type_t parent_key_type,
    n20_crypto_key_type_t key_type,
    n20_open_dice_input_t const *context,
    n20_certificate_format_t certificate_format,
    uint8_t *attestation_certificate,
    size_t *attestation_certificate_size);

#ifdef __cplusplus
}
#endif
