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

#include <nat20/cbor.h>
#include <nat20/cose.h>
#include <nat20/crypto.h>
#include <nat20/cwt.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/oid.h>
#include <nat20/open_dice.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Buffer holding the utf-8 encoded string "CDI_Attest".
 */
uint8_t const CDI_ATTEST_STR[] = {
    0x43,
    0x44,
    0x49,
    0x5f,
    0x41,
    0x74,
    0x74,
    0x65,
    0x73,
    0x74,
};
n20_slice_t const CDI_ATTEST_STR_SLICE = {
    .buffer = CDI_ATTEST_STR,
    .size = 10,
};

/**
 * @brief Buffer holding the salt used for the asymmetric key derivation.
 *
 * This buffer is used to derive the asymmetric key pair from the
 * CDI secret. The buffer is 64 bytes long and is used as input to
 * the KDF function.
 */
uint8_t const ASYM_SALT[] = {
    0x63, 0xb6, 0xa0, 0x4d, 0x2c, 0x07, 0x7f, 0xc1, 0x0f, 0x63, 0x9f, 0x21, 0xda, 0x79, 0x38, 0x44,
    0x35, 0x6c, 0xc2, 0xb0, 0xb4, 0x41, 0xb3, 0xa7, 0x71, 0x24, 0x03, 0x5c, 0x03, 0xf8, 0xe1, 0xbe,
    0x60, 0x35, 0xd3, 0x1f, 0x28, 0x28, 0x21, 0xa7, 0x45, 0x0a, 0x02, 0x22, 0x2a, 0xb1, 0xb3, 0xcf,
    0xf1, 0x67, 0x9b, 0x05, 0xab, 0x1c, 0xa5, 0xd1, 0xaf, 0xfb, 0x78, 0x9c, 0xcd, 0x2b, 0x0b, 0x3b};
n20_slice_t const ASYM_SALT_SLICE = {
    .buffer = ASYM_SALT,
    .size = 64,
};

/*
 * Buffer holding the utf-8 encoded string "Key Pair Attest".
 */
uint8_t const ATTEST_KEY_PAIR_STR[] = {
    0x4b, 0x65, 0x79, 0x20, 0x50, 0x61, 0x69, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74};
n20_slice_t const ATTEST_KEY_PAIR_STR_SLICE = {
    .buffer = ATTEST_KEY_PAIR_STR,
    .size = 15,
};

/**
 * @brief Buffer holding the salt used for the ID derivation.
 *
 * This buffer is used to derive the ID from the attestation public key.
 & The buffer is 64 bytes long and is used as input to the KDF function.
 */
uint8_t const ID_SALT[] = {
    0xdb, 0xdb, 0xae, 0xbc, 0x80, 0x20, 0xda, 0x9f, 0xf0, 0xdd, 0x5a, 0x24, 0xc8, 0x3a, 0xa5, 0xa5,
    0x42, 0x86, 0xdf, 0xc2, 0x63, 0x03, 0x1e, 0x32, 0x9b, 0x4d, 0xa1, 0x48, 0x43, 0x06, 0x59, 0xfe,
    0x62, 0xcd, 0xb5, 0xb7, 0xe1, 0xe0, 0x0f, 0xc6, 0x80, 0x30, 0x67, 0x11, 0xeb, 0x44, 0x4a, 0xf7,
    0x72, 0x09, 0x35, 0x94, 0x96, 0xfc, 0xff, 0x1d, 0xb9, 0x52, 0x0b, 0xa5, 0x1c, 0x7b, 0x29, 0xea};

n20_slice_t const ID_SALT_SLICE = {
    .buffer = ID_SALT,
    .size = sizeof(ID_SALT),
};

/*
 * Buffer holding the utf-8 encoded string "ID".
 */
uint8_t const ID_STR[] = {
    0x49,
    0x44,
};

n20_slice_t const ID_STR_SLICE = {
    .buffer = ID_STR,
    .size = 2,
};

n20_error_t n20_compress_input(n20_crypto_digest_context_t *crypto_ctx,
                               n20_open_dice_input_t const *input,
                               n20_compressed_input_t digest) {
    // Check if the crypto context is valid
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    uint8_t mode = (uint8_t)input->mode;

    n20_slice_t input_list[] = {
        input->code_hash,
        input->configuration_hash,
        input->authority_hash,
        {.buffer = &mode, .size = 1},
        input->hidden,
    };

    if (input->configuration_hash.size == 0) {
        input_list[1] = input->configuration_descriptor;
    }

    n20_crypto_gather_list_t input_gather_list = {
        .count = 5,
        .list = &input_list[0],
    };

    size_t digest_size = N20_FUNC_COMPRESSED_INPUT_SIZE;
    n20_error_t err = crypto_ctx->digest(crypto_ctx,
                                         N20_FUNC_COMPRESSED_INPUT_ALGORITHM,
                                         &input_gather_list,
                                         1,
                                         digest,
                                         &digest_size);
    if (err != n20_error_ok_e) {
        return err;
    }

    return n20_error_ok_e;
}

n20_error_t n20_derive_key(n20_crypto_context_t *crypto_ctx,
                           n20_crypto_key_t cdi_secret,
                           n20_crypto_key_t *derived,
                           n20_crypto_key_type_t key_type,
                           n20_slice_t const salt,
                           n20_slice_t const tag) {
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }
    if (derived == NULL) {
        return n20_error_unexpected_null_key_handle_e;
    }

    n20_slice_t derivation_context_list[] = {salt, tag};

    n20_crypto_gather_list_t derivation_context = {
        .count = 2,
        .list = &derivation_context_list[0],
    };

    return crypto_ctx->kdf(crypto_ctx, cdi_secret, key_type, &derivation_context, derived);
}

n20_error_t n20_next_level_cdi_attest(n20_crypto_context_t *crypto_ctx,
                                      n20_crypto_key_t current,
                                      n20_crypto_key_t *next,
                                      n20_compressed_input_t info) {

    return n20_derive_key(crypto_ctx,
                          current,
                          next,
                          n20_crypto_key_type_cdi_e,
                          (n20_slice_t){.size = N20_FUNC_COMPRESSED_INPUT_SIZE, .buffer = &info[0]},
                          CDI_ATTEST_STR_SLICE);
}

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
n20_error_t n20_derive_attestation_key(n20_crypto_context_t *crypto_ctx,
                                       n20_crypto_key_t cdi_secret,
                                       n20_crypto_key_t *derived,
                                       n20_crypto_key_type_t key_type) {
    return n20_derive_key(
        crypto_ctx, cdi_secret, derived, key_type, ASYM_SALT_SLICE, ATTEST_KEY_PAIR_STR_SLICE);
}

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
n20_error_t n20_init_algorithm_identifier(n20_x509_algorithm_identifier_t *algorithm_identifier,
                                          n20_crypto_key_type_t key_type) {

    switch (key_type) {
        case n20_crypto_key_type_ed25519_e:
            algorithm_identifier->oid = &OID_ED25519;
            break;
        case n20_crypto_key_type_secp256r1_e:
            algorithm_identifier->oid = &OID_ECDSA_WITH_SHA256;
            break;
        case n20_crypto_key_type_secp384r1_e:
            algorithm_identifier->oid = &OID_ECDSA_WITH_SHA384;
            break;
        default:
            /* The key type is not supported. */
            return n20_error_crypto_invalid_key_type_e;
    }
    algorithm_identifier->params.variant = n20_x509_pv_none_e;
    algorithm_identifier->params.ec_curve = NULL;

    return n20_error_ok_e;
}

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
n20_error_t n20_init_key_info(n20_x509_public_key_info_t *key_info,
                              n20_crypto_key_type_t key_type,
                              uint8_t const *public_key,
                              size_t public_key_size) {
    switch (key_type) {
        case n20_crypto_key_type_ed25519_e:
            key_info->algorithm_identifier.oid = &OID_ED25519;
            key_info->algorithm_identifier.params.variant = n20_x509_pv_none_e;
            break;
        case n20_crypto_key_type_secp256r1_e:
            key_info->algorithm_identifier.oid = &OID_EC_PUBLIC_KEY;
            key_info->algorithm_identifier.params.variant = n20_x509_pv_ec_curve_e;
            key_info->algorithm_identifier.params.ec_curve = &OID_SECP256R1;
            break;
        case n20_crypto_key_type_secp384r1_e:
            key_info->algorithm_identifier.oid = &OID_EC_PUBLIC_KEY;
            key_info->algorithm_identifier.params.variant = n20_x509_pv_ec_curve_e;
            key_info->algorithm_identifier.params.ec_curve = &OID_SECP384R1;
            break;
        default:
            /* The key type is not supported. */
            return n20_error_crypto_invalid_key_type_e;
    }
    key_info->public_key_bits = public_key_size * 8;
    key_info->public_key = public_key;

    return n20_error_ok_e;
}

typedef n20_error_t (*n20_signer_callback_t)(void *signer,
                                             n20_slice_t tbs,
                                             uint8_t *signature,
                                             size_t *signature_size);

n20_error_t n20_signer_callback(void *ctx,
                                n20_slice_t tbs,
                                uint8_t *signature,
                                size_t *signature_size) {

    n20_signer_t *signer = (n20_signer_t *)ctx;

    n20_crypto_gather_list_t tbs_der_gather = {
        .count = 1,
        .list = &tbs,
    };

    return signer->crypto_ctx->sign(
        signer->crypto_ctx, signer->signing_key, &tbs_der_gather, signature, signature_size);
}

/**
 * @brief Prepares the X.509 certificate.
 *
 * This function prepares the X.509 certificate with the given
 * context information and signs it using the given signer.
 *
 * @param context The context information to use.
 * @param signer The signer to use.
 * @param issuer_key_type The type of the issuer key.
 * @param issuer_name The name of the issuer.
 * @param subject_key_type The type of the subject key.
 * @param subject_name The name of the subject.
 * @param public_key The public key to use.
 * @param public_key_size The size of the public key.
 * @param attestation_certificate The attestation certificate to use.
 * @param attestation_certificate_size The size of the attestation certificate.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
n20_error_t n20_prepare_x509_cert(n20_open_dice_cert_info_t const *cert_info,
                                  n20_signer_t *signer,
                                  n20_crypto_key_type_t issuer_key_type,
                                  uint8_t *attestation_certificate,
                                  size_t *attestation_certificate_size) {
    n20_error_t err = n20_error_ok_e;
    n20_x509_ext_key_usage_t key_usage = {0};
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);

    n20_x509_ext_basic_constraints_t basic_constraints = {
        .is_ca = 1,
        .has_path_length = false,
    };

    n20_x509_extension_t extensions[3] = {
        {
            .oid = &OID_OPEN_DICE_INPUT,
            .critical = 1,
            .content_cb = n20_x509_ext_open_dice_input_content,
            .context = (void *)&cert_info->open_dice_input,
        },
        {
            .oid = &OID_KEY_USAGE,
            .critical = 1,
            .content_cb = n20_x509_ext_key_usage_content,
            .context = &key_usage,
        },
        {
            .oid = &OID_BASIC_CONSTRAINTS,
            .critical = 1,
            .content_cb = n20_x509_ext_basic_constraints_content,
            .context = &basic_constraints,
        },
    };

    n20_x509_tbs_t tbs = {0};
    tbs.validity = (n20_x509_validity_t){
        .not_before = N20_STR_NULL,
        .not_after = N20_STR_NULL,
    };

    tbs.serial_number = cert_info->subject;

    err = n20_init_algorithm_identifier(&tbs.signature_algorithm, issuer_key_type);
    if (err != n20_error_ok_e) {
        return err;
    }

    err = n20_init_key_info(&tbs.subject_public_key_info,
                            cert_info->subject_public_key.algorithm,
                            cert_info->subject_public_key.key.buffer,
                            cert_info->subject_public_key.key.size);
    if (err != n20_error_ok_e) {
        return err;
    }

    tbs.issuer_name.element_count = 1;
    tbs.issuer_name.elements[0] = (n20_x509_rdn_t){&OID_SERIAL_NUMBER, .bytes = cert_info->issuer};

    tbs.subject_name.element_count = 1;
    tbs.subject_name.elements[0] =
        (n20_x509_rdn_t){&OID_SERIAL_NUMBER, .bytes = cert_info->subject};

    tbs.extensions = (n20_x509_extensions_t){
        .extensions_count = 3,
        .extensions = &extensions[0],
    };

    // Create a new stream for the attestation certificate
    n20_stream_t stream;
    n20_stream_init(&stream, attestation_certificate, *attestation_certificate_size);
    n20_x509_cert_tbs(&stream, &tbs);
    if (n20_stream_has_buffer_overflow(&stream) ||
        n20_stream_has_write_position_overflow(&stream)) {
        *attestation_certificate_size = n20_stream_byte_count(&stream);

        return n20_error_insufficient_buffer_size_e;
    }

    // Sign the to-be-signed part of the certificate.
    uint8_t signature[128];
    size_t signature_size = sizeof(signature);

    err = signer->cb(
        signer,
        (n20_slice_t){.size = n20_stream_byte_count(&stream), .buffer = n20_stream_data(&stream)},
        signature,
        &signature_size);
    if (err != n20_error_ok_e) {
        return err;
    }

    /* Reinitialize the stream. */
    n20_stream_init(&stream, attestation_certificate, *attestation_certificate_size);
    n20_x509_t cert = {
        .tbs = &tbs,
        .signature_algorithm = tbs.signature_algorithm,
        .signature_bits = signature_size * 8,
        .signature = signature,
    };

    n20_x509_cert(&stream, &cert);
    if (n20_stream_has_buffer_overflow(&stream) ||
        n20_stream_has_write_position_overflow(&stream)) {
        *attestation_certificate_size = n20_stream_byte_count(&stream);
        return n20_error_insufficient_buffer_size_e;
    }
    *attestation_certificate_size = n20_stream_byte_count(&stream);

    return n20_error_ok_e;
}

n20_error_t n20_open_dice_cdi_id(n20_crypto_digest_context_t *digest_ctx,
                                 n20_slice_t const public_key,
                                 n20_cdi_id_t cdi_id) {
    n20_error_t rc = digest_ctx->hkdf(digest_ctx,
                                      n20_crypto_digest_algorithm_sha2_512_e,
                                      public_key,
                                      ID_SALT_SLICE,
                                      ID_STR_SLICE,
                                      20,
                                      &cdi_id[0]);
    /* Ensure that the most significant bit is not set so that it
     * is a valid positive integer that can be represented as no
     * more than 20 bytes in ASN1.
     */
    cdi_id[0] &= 0x7F;
    return rc;
}

static void payload_callback_open_dice_cwt(n20_stream_t *s, void *payload_ctx) {
    n20_open_dice_cwt_write(s, (n20_open_dice_cert_info_t const *)payload_ctx);
}

n20_error_t n20_cose_sign1_payload(n20_crypto_context_t *crypto_ctx,
                                   n20_crypto_key_t const signing_key,
                                   n20_crypto_key_type_t signing_key_type,
                                   void (*payload_callback)(n20_stream_t *s, void *ctx),
                                   void *payload_ctx,
                                   uint8_t *cose_sign1,
                                   size_t *cose_sign1_size) {
    n20_stream_t s;

    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;  // Null crypto context
    }
    if (payload_callback == NULL || payload_ctx == NULL) {
        /* Null payload callback or context. */
        return n20_error_missing_callback_function_or_context_e;
    }
    if (cose_sign1_size == NULL) {
        return n20_error_crypto_unexpected_null_size_e;  // Null size pointer
    }
    if (cose_sign1 == NULL && *cose_sign1_size != 0) {
        /* Buffer cannot be NULL if size is not zero. */
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    int signing_key_algorithm_id;

    switch (signing_key_type) {
        case n20_crypto_key_type_secp256r1_e:
            signing_key_algorithm_id = n20_cose_algorithm_id_es256_e;
            break;
        case n20_crypto_key_type_ed25519_e:
            signing_key_algorithm_id = n20_cose_algorithm_id_eddsa_e;
            break;
        case n20_crypto_key_type_secp384r1_e:
            signing_key_algorithm_id = n20_cose_algorithm_id_es384_e;
            break;
        default:
            return n20_error_crypto_unknown_algorithm_e;  // Unsupported algorithm
    }

    size_t signature_size = n20_cose_get_signature_size(signing_key_algorithm_id);

    uint8_t *signature = cose_sign1 + *cose_sign1_size - signature_size;

    n20_stream_init(&s, cose_sign1, signature - cose_sign1);

    n20_slice_t tbs_gather_list[4] = {0};

    n20_cose_render_sign1_with_payload(
        &s, signing_key_algorithm_id, payload_callback, payload_ctx, tbs_gather_list);

    n20_crypto_gather_list_t sig_structure_gather_list = {
        .count = 4,
        .list = tbs_gather_list,
    };

    size_t sig_size_in_out = signature_size;
    n20_error_t err = crypto_ctx->sign(
        crypto_ctx, signing_key, &sig_structure_gather_list, signature, &sig_size_in_out);
    if (err != n20_error_ok_e) {
        return err;
    }
    if (sig_size_in_out != signature_size) {
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    *cose_sign1_size = n20_stream_byte_count(&s) + signature_size;

    return n20_error_ok_e;
}

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
n20_error_t n20_opendice_attestation_key_and_certificate(
    n20_crypto_context_t *crypto_ctx,
    n20_crypto_key_t parent_secret,
    n20_crypto_key_t parent_attestation_key,
    n20_crypto_key_type_t parent_key_type,
    n20_crypto_key_type_t key_type,
    n20_open_dice_input_t const *context,
    n20_certificate_format_t certificate_format,
    uint8_t *attestation_certificate,
    size_t *attestation_certificate_size) {

    /* Check if the crypto context is valid. */
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    n20_compressed_input_t input_digest = {0};

    n20_error_t err = n20_compress_input(&crypto_ctx->digest_ctx, context, input_digest);
    if (err != n20_error_ok_e) {
        return err;
    }

    n20_cdi_id_t issuer_serial_number = {0};

    uint8_t public_key_buffer[97];

    /* Get the public key of the parent attestation key. */
    uint8_t *public_key = &public_key_buffer[0];
    size_t public_key_size = sizeof(public_key_buffer);
    err = crypto_ctx->key_get_public_key(
        crypto_ctx, parent_attestation_key, public_key, &public_key_size);

    if (err != n20_error_ok_e) {
        return err;
    }

    err = n20_open_dice_cdi_id(&crypto_ctx->digest_ctx,
                               (n20_slice_t){.buffer = public_key, .size = public_key_size},
                               issuer_serial_number);

    if (err != n20_error_ok_e) {
        return err;
    }

    n20_crypto_key_t child_secret = NULL;

    err = n20_next_level_cdi_attest(crypto_ctx, parent_secret, &child_secret, input_digest);
    if (err != n20_error_ok_e) {
        return err;
    }

    n20_crypto_key_t child_attestation_key = NULL;
    err = n20_derive_attestation_key(crypto_ctx, child_secret, &child_attestation_key, key_type);

    /* Regardless of whether the last call was successful
     * the child secret is no longer needed. */
    crypto_ctx->key_free(crypto_ctx, child_secret);

    if (err != n20_error_ok_e) {
        return err;
    }

    /* Get the public key of the derived key.
     * Leave room for the optional uncompressed prefix. */
    public_key = &public_key_buffer[1];
    public_key_size = sizeof(public_key_buffer) - 1;
    err = crypto_ctx->key_get_public_key(
        crypto_ctx, child_attestation_key, public_key, &public_key_size);

    /* Regardless of whether the last call was successful
     * the child attestation key is no longer needed. */
    crypto_ctx->key_free(crypto_ctx, child_attestation_key);

    if (err != n20_error_ok_e) {
        return err;
    }

    n20_cdi_id_t subject_serial_number = {0};
    err = n20_open_dice_cdi_id(&crypto_ctx->digest_ctx,
                               (n20_slice_t){.buffer = public_key, .size = public_key_size},
                               subject_serial_number);
    if (err != n20_error_ok_e) {
        return err;
    }

    /* If the key type is one of the supported NIST curves,
     * prepend the "uncompressed" prefix 0x04. */
    switch (key_type) {
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e:
            public_key_buffer[0] = 0x04;
            public_key = &public_key_buffer[0];
            public_key_size += 1;
            break;
        case n20_crypto_key_type_ed25519_e:
            /* No prefix for Ed25519 keys */
            break;
        default:
            return n20_error_crypto_invalid_key_type_e;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.open_dice_input = *context;
    cert_info.issuer.buffer = issuer_serial_number;
    cert_info.issuer.size = sizeof(n20_cdi_id_t);
    cert_info.subject.buffer = subject_serial_number;
    cert_info.subject.size = sizeof(n20_cdi_id_t);

    cert_info.subject_public_key = (n20_open_dice_public_key_info_t){
        .key =
            {
                .buffer = public_key,
                .size = public_key_size,
            },
        .algorithm = key_type,
    };

    switch (certificate_format) {
        case n20_certificate_format_x509_e:
            return n20_prepare_x509_cert(&cert_info,
                                         &(n20_signer_t){
                                             .crypto_ctx = crypto_ctx,
                                             .signing_key = parent_attestation_key,
                                             .cb = n20_signer_callback,
                                         },
                                         parent_key_type,
                                         attestation_certificate,
                                         attestation_certificate_size);
        case n20_certificate_format_cose_e:
            return n20_cose_sign1_payload(crypto_ctx,
                                          parent_attestation_key,
                                          parent_key_type,
                                          payload_callback_open_dice_cwt,
                                          &cert_info,
                                          attestation_certificate,
                                          attestation_certificate_size);
        default:
            return n20_error_unsupported_certificate_format_e;
    }
}
