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

#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <nat20/service/gnostic.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>

void n20_gnostic_init(n20_gnostic_node_state_t *node_state,
                      n20_crypto_context_t *crypto_ctx,
                      n20_crypto_key_t client_min_cdis[N20_GNOSTIC_MAX_CLIENT_SLOTS]) {
    if (node_state == NULL) {
        return;
    }

    node_state->crypto_context = crypto_ctx;

    if (client_min_cdis == NULL) {
        // If no client CDIs are provided, initialize them to NULL.
        for (size_t i = 0; i < N20_GNOSTIC_MAX_CLIENT_SLOTS; ++i) {
            node_state->client_slots[i].min_cdi = NULL;
        }
        return;
    }

    // If client CDIs are provided, copy them into the client slots.
    for (size_t i = 0; i < N20_GNOSTIC_MAX_CLIENT_SLOTS; ++i) {
        node_state->client_slots[i].min_cdi = client_min_cdis[i];
    }
}

n20_error_t n20_gnostic_promote(n20_gnostic_node_state_t *node_state,
                                size_t client_slot_index,
                                n20_compressed_input_t compressed_context) {
    if (node_state == NULL) {
        return n20_error_unexpected_null_service_state_e;
    }

    if (client_slot_index >= N20_GNOSTIC_MAX_CLIENT_SLOTS) {
        return n20_error_client_slot_index_out_of_range_e;
    }

    if (node_state->client_slots[client_slot_index].min_cdi == NULL) {
        return n20_error_client_slot_empty_e;
    }

    n20_crypto_key_t *client_min_cdi = &node_state->client_slots[client_slot_index].min_cdi;
    n20_crypto_key_t next = NULL;

    n20_error_t error = n20_next_level_cdi_attest(
        node_state->crypto_context, *client_min_cdi, &next, compressed_context);
    if (error != n20_error_ok_e) {
        return error;
    }

    error = node_state->crypto_context->key_free(node_state->crypto_context, *client_min_cdi);
    if (error != n20_error_ok_e) {
        return error;
    }

    // Promote the given CDI to the specified client slot.
    *client_min_cdi = next;
    return n20_error_ok_e;
}

static n20_error_t n20_resolve_path(n20_crypto_context_t *crypto_ctx,
                                    n20_crypto_key_t parent_secret,
                                    n20_compressed_input_t *parent_path,
                                    size_t parent_path_size,
                                    n20_crypto_key_t *resolved_key) {
    n20_crypto_key_t current_secret = parent_secret;

    if (parent_path_size == 0 || parent_path == NULL) {
        *resolved_key = current_secret;
        return n20_error_ok_e;
    }

    size_t i = 0;

    n20_crypto_key_t next = NULL;
    n20_error_t error =
        n20_next_level_cdi_attest(crypto_ctx, current_secret, &next, parent_path[i]);
    if (error != n20_error_ok_e) {
        return error;
    }
    current_secret = next;
    ++i;

    while (i < parent_path_size) {
        error = n20_next_level_cdi_attest(crypto_ctx, current_secret, &next, parent_path[i]);
        crypto_ctx->key_free(crypto_ctx, current_secret);
        if (error != n20_error_ok_e) {
            return error;
        }
        current_secret = next;
        ++i;
    }

    *resolved_key = current_secret;
    return n20_error_ok_e;
}

n20_error_t n20_gnostic_issue_cdi_certificate(n20_gnostic_node_state_t *node_state,
                                              size_t client_slot_index,
                                              n20_crypto_key_type_t issuer_key_type,
                                              n20_crypto_key_type_t subject_key_type,
                                              n20_compressed_input_t *parent_path,
                                              size_t parent_path_size,
                                              n20_open_dice_input_t const *next_context,
                                              n20_certificate_format_t certificate_format,
                                              uint8_t *certificate_out,
                                              size_t *certificate_size_in_out) {

    if (node_state == NULL || node_state->crypto_context == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    if (next_context == NULL) {
        return n20_error_unexpected_null_open_dice_input_e;
    }

    n20_crypto_key_t issuer_secret = node_state->client_slots[client_slot_index].min_cdi;

    n20_error_t error = n20_resolve_path(
        node_state->crypto_context, issuer_secret, parent_path, parent_path_size, &issuer_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.open_dice_input = *next_context;

    error = n20_issue_certificate(node_state->crypto_context,
                                  issuer_secret,
                                  issuer_key_type,
                                  subject_key_type,
                                  &cert_info,
                                  certificate_format,
                                  certificate_out,
                                  certificate_size_in_out);

    if (parent_path_size > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, issuer_secret);
    }
    return error;
}

n20_error_t n20_gnostic_issue_eca_certificate(n20_gnostic_node_state_t *node_state,
                                              size_t client_slot_index,
                                              n20_crypto_key_type_t issuer_key_type,
                                              n20_crypto_key_type_t subject_key_type,
                                              n20_compressed_input_t *parent_path,
                                              size_t parent_path_size,
                                              n20_slice_t challenge,
                                              n20_certificate_format_t certificate_format,
                                              uint8_t *certificate_out,
                                              size_t *certificate_size_in_out) {

    if (node_state == NULL || node_state->crypto_context == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    n20_crypto_key_t parent_secret = node_state->client_slots[client_slot_index].min_cdi;

    n20_error_t error = n20_resolve_path(
        node_state->crypto_context, parent_secret, parent_path, parent_path_size, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_eca_e;
    cert_info.eca.nonce = challenge;

    error = n20_issue_certificate(node_state->crypto_context,
                                  parent_secret,
                                  issuer_key_type,
                                  subject_key_type,
                                  &cert_info,
                                  certificate_format,
                                  certificate_out,
                                  certificate_size_in_out);

    if (parent_path_size > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}

n20_error_t n20_gnostic_issue_eca_ee_certificate(n20_gnostic_node_state_t *node_state,
                                                 size_t client_slot_index,
                                                 n20_crypto_key_type_t issuer_key_type,
                                                 n20_crypto_key_type_t subject_key_type,
                                                 n20_compressed_input_t *parent_path,
                                                 size_t parent_path_size,
                                                 n20_string_slice_t name,
                                                 n20_slice_t key_usage,
                                                 n20_slice_t challenge,
                                                 n20_certificate_format_t certificate_format,
                                                 uint8_t *certificate_out,
                                                 size_t *certificate_size_in_out) {

    if (node_state == NULL || node_state->crypto_context == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    n20_crypto_key_t parent_secret = node_state->client_slots[client_slot_index].min_cdi;

    n20_error_t error = n20_resolve_path(
        node_state->crypto_context, parent_secret, parent_path, parent_path_size, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    cert_info.eca_ee.nonce = challenge;
    cert_info.eca_ee.name = name;

    if (key_usage.size >= 1) {
        if ((key_usage.buffer[0] & ~1) != 0) {
            return n20_error_unsupported_key_usage_e;
        }
        for (size_t i = 1; i < key_usage.size; ++i) {
            if (key_usage.buffer[i] != 0) {
                return n20_error_unsupported_key_usage_e;
            }
        }
    }

    N20_OPEN_DICE_KEY_USAGE_SET_DIGITAL_SIGNATURE(cert_info.key_usage);

    error = n20_issue_certificate(node_state->crypto_context,
                                  parent_secret,
                                  issuer_key_type,
                                  subject_key_type,
                                  &cert_info,
                                  certificate_format,
                                  certificate_out,
                                  certificate_size_in_out);

    if (parent_path_size > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}

n20_error_t n20_gnostic_eca_sign(n20_gnostic_node_state_t *node_state,
                                 size_t client_slot_index,
                                 n20_crypto_key_type_t key_type,
                                 n20_compressed_input_t *parent_path,
                                 size_t parent_path_size,
                                 n20_string_slice_t name,
                                 n20_slice_t key_usage,
                                 n20_slice_t message,
                                 uint8_t *signature,
                                 size_t *signature_size) {

    if (node_state == NULL || node_state->crypto_context == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    n20_crypto_key_t parent_secret = node_state->client_slots[client_slot_index].min_cdi;

    n20_error_t error = n20_resolve_path(
        node_state->crypto_context, parent_secret, parent_path, parent_path_size, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    if (key_usage.size >= 1) {
        if ((key_usage.buffer[0] & ~1) != 0) {
            return n20_error_unsupported_key_usage_e;
        }
        for (size_t i = 1; i < key_usage.size; ++i) {
            if (key_usage.buffer[i] != 0) {
                return n20_error_unsupported_key_usage_e;
            }
        }
    }

    error = n20_eca_ee_sign_message(node_state->crypto_context,
                                 parent_secret,
                                 key_type,
                                 name,
                                 key_usage,
                                 message,
                                 signature,
                                 signature_size);

    if (parent_path_size > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}
