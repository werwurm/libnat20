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

#include <getopt.h>
#include <nat20/cbor.h>
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/messages.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef N20_WITH_COSE
#include <nat20/cose.h>
#endif

static n20_error_t dispatch_promote_request(n20_gnostic_node_state_t *node_state,
                                            uint8_t *response_buffer,
                                            size_t *response_size_in_out,
                                            n20_msg_promote_request_t *request,
                                            size_t client_index) {

    if (request->compressed_context.size != sizeof(n20_compressed_input_t)) {
        // Handle error: invalid compressed context size
        return n20_error_incompatible_compressed_input_size_e;
    }

    n20_error_t rc = n20_gnostic_promote(
        node_state, client_index, (uint8_t *)request->compressed_context.buffer);
    if (rc != n20_error_ok_e) {
        // Handle error: promotion failed
        return rc;
    }

    // Prepare the response message.
    n20_msg_error_response_t response = {
        .error_code = n20_error_ok_e,
    };
    return n20_msg_error_response_write(&response, response_buffer, response_size_in_out);
    if (rc != n20_error_ok_e) {
        // Handle error: failed to write response
        return rc;
    }
}

static n20_error_t dispatch_issue_cdi_cert_request(n20_gnostic_node_state_t *node_state,
                                                   uint8_t *response_buffer,
                                                   size_t *response_size_in_out,
                                                   n20_msg_issue_cdi_cert_request_t *request,
                                                   size_t client_index) {

    n20_compressed_input_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];
    size_t parent_path_size = request->parent_path_length;

    if (parent_path_size > N20_STATELESS_MAX_PATH_LENGTH) {
        // Handle error: parent path size exceeds maximum
        return n20_error_parent_path_size_exceeds_max_e;
    }

    for (size_t i = 0; i < parent_path_size; ++i) {
        if (request->parent_path[i].size != sizeof(n20_compressed_input_t)) {
            // Handle error: invalid parent path size
            return n20_error_incompatible_compressed_input_size_e;
        }
        memcpy(&parent_path[i], request->parent_path[i].buffer, sizeof(n20_compressed_input_t));
    }

    size_t const total_buffer_size = *response_size_in_out;

    n20_error_t rc = n20_gnostic_issue_cdi_certificate(node_state,
                                                       client_index,
                                                       request->issuer_key_type,
                                                       request->subject_key_type,
                                                       parent_path,
                                                       parent_path_size,
                                                       &request->next_context,
                                                       request->certificate_format,
                                                       response_buffer,
                                                       response_size_in_out);
    if (rc != n20_error_ok_e) {
        // Handle error: issuing CDI certificate failed
        return rc;
    }

    if (*response_size_in_out > total_buffer_size) {
        // Handle error: response size exceeds buffer size
        return n20_error_insufficient_buffer_size_e;
    }

    n20_stream_t s;
    n20_stream_init(&s, response_buffer, total_buffer_size - *response_size_in_out);

    n20_cbor_write_header(&s, n20_cbor_type_bytes_e, *response_size_in_out);
    n20_cbor_write_int(&s, 21);
    n20_cbor_write_map_header(&s, 1);

    if (n20_stream_has_buffer_overflow(&s)) {
        return n20_error_insufficient_buffer_size_e;
    }

    *response_size_in_out += n20_stream_byte_count(&s);

    return n20_error_ok_e;
}

static n20_error_t dispatch_issue_eca_cert_request(n20_gnostic_node_state_t *node_state,
                                                   uint8_t *response_buffer,
                                                   size_t *response_size_in_out,
                                                   n20_msg_issue_eca_cert_request_t *request,
                                                   size_t client_index) {

    n20_compressed_input_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];
    size_t parent_path_size = request->parent_path_length;

    if (parent_path_size > N20_STATELESS_MAX_PATH_LENGTH) {
        // Handle error: parent path size exceeds maximum
        return n20_error_parent_path_size_exceeds_max_e;
    }

    for (size_t i = 0; i < parent_path_size; ++i) {
        if (request->parent_path[i].size != sizeof(n20_compressed_input_t)) {
            // Handle error: invalid parent path size
            return n20_error_incompatible_compressed_input_size_e;
        }
        memcpy(&parent_path[i], request->parent_path[i].buffer, sizeof(n20_compressed_input_t));
    }

    size_t const total_buffer_size = *response_size_in_out;

    n20_error_t rc = n20_gnostic_issue_eca_certificate(node_state,
                                                       client_index,
                                                       request->issuer_key_type,
                                                       request->subject_key_type,
                                                       parent_path,
                                                       parent_path_size,
                                                       request->challenge,
                                                       request->certificate_format,
                                                       response_buffer,
                                                       response_size_in_out);
    if (rc != n20_error_ok_e) {
        // Handle error: issuing ECA certificate failed
        return rc;
    }

    if (*response_size_in_out > total_buffer_size) {
        // Handle error: response size exceeds buffer size
        return n20_error_insufficient_buffer_size_e;
    }

    n20_stream_t s;
    n20_stream_init(&s, response_buffer, total_buffer_size - *response_size_in_out);

    n20_cbor_write_header(&s, n20_cbor_type_bytes_e, *response_size_in_out);
    n20_cbor_write_int(&s, 21);
    n20_cbor_write_map_header(&s, 1);

    if (n20_stream_has_buffer_overflow(&s)) {
        return n20_error_insufficient_buffer_size_e;
    }

    *response_size_in_out += n20_stream_byte_count(&s);

    return n20_error_ok_e;
}

static n20_error_t dispatch_issue_eca_ee_cert_request(n20_gnostic_node_state_t *node_state,
                                                      uint8_t *response_buffer,
                                                      size_t *response_size_in_out,
                                                      n20_msg_issue_eca_ee_cert_request_t *request,
                                                      size_t client_index) {

    n20_compressed_input_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];
    size_t parent_path_size = request->parent_path_length;

    if (parent_path_size > N20_STATELESS_MAX_PATH_LENGTH) {
        // Handle error: parent path size exceeds maximum
        return n20_error_parent_path_size_exceeds_max_e;
    }

    for (size_t i = 0; i < parent_path_size; ++i) {
        if (request->parent_path[i].size != sizeof(n20_compressed_input_t)) {
            // Handle error: invalid parent path size
            return n20_error_incompatible_compressed_input_size_e;
        }
        memcpy(&parent_path[i], request->parent_path[i].buffer, sizeof(n20_compressed_input_t));
    }

    size_t const total_buffer_size = *response_size_in_out;

    n20_error_t rc = n20_gnostic_issue_eca_ee_certificate(node_state,
                                                          client_index,
                                                          request->issuer_key_type,
                                                          request->subject_key_type,
                                                          parent_path,
                                                          parent_path_size,
                                                          request->name,
                                                          request->key_usage,
                                                          request->challenge,
                                                          request->certificate_format,
                                                          response_buffer,
                                                          response_size_in_out);
    if (rc != n20_error_ok_e) {
        // Handle error: issuing ECA certificate failed
        return rc;
    }

    if (*response_size_in_out > total_buffer_size) {
        // Handle error: response size exceeds buffer size
        return n20_error_insufficient_buffer_size_e;
    }

    n20_stream_t s;
    n20_stream_init(&s, response_buffer, total_buffer_size - *response_size_in_out);

    n20_cbor_write_header(&s, n20_cbor_type_bytes_e, *response_size_in_out);
    n20_cbor_write_int(&s, 21);
    n20_cbor_write_map_header(&s, 1);

    *response_size_in_out += n20_stream_byte_count(&s);

    if (n20_stream_has_buffer_overflow(&s)) {
        return n20_error_insufficient_buffer_size_e;
    }

    return n20_error_ok_e;
}

static n20_error_t dispatch_eca_ee_sign_request(n20_gnostic_node_state_t *node_state,
                                                uint8_t *response_buffer,
                                                size_t *response_size_in_out,
                                                n20_msg_eca_ee_sign_request_t *request,
                                                size_t client_index) {

    n20_compressed_input_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];
    size_t parent_path_size = request->parent_path_length;

    if (parent_path_size > N20_STATELESS_MAX_PATH_LENGTH) {
        // Handle error: parent path size exceeds maximum
        return n20_error_parent_path_size_exceeds_max_e;
    }

    for (size_t i = 0; i < parent_path_size; ++i) {
        if (request->parent_path[i].size != sizeof(n20_compressed_input_t)) {
            // Handle error: invalid parent path size
            return n20_error_incompatible_compressed_input_size_e;
        }
        memcpy(&parent_path[i], request->parent_path[i].buffer, sizeof(n20_compressed_input_t));
    }

    size_t const total_buffer_size = *response_size_in_out;

    n20_error_t rc = n20_gnostic_eca_sign(node_state,
                                          client_index,
                                          request->subject_key_type,
                                          parent_path,
                                          parent_path_size,
                                          request->name,
                                          request->key_usage,
                                          request->message,
                                          response_buffer,
                                          response_size_in_out);
    if (rc != n20_error_ok_e) {
        // Handle error: signing failed
        return rc;
    }

    n20_stream_t s;
    n20_stream_init(
        &s,
        response_buffer,
        total_buffer_size > *response_size_in_out ? total_buffer_size - *response_size_in_out : 0);

    n20_cbor_write_header(&s, n20_cbor_type_bytes_e, *response_size_in_out);
    n20_cbor_write_int(&s, 22);
    n20_cbor_write_map_header(&s, 1);

    *response_size_in_out += n20_stream_byte_count(&s);

    if (n20_stream_has_buffer_overflow(&s)) {
        return n20_error_insufficient_buffer_size_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_gnostic_message_dispatch(n20_gnostic_node_state_t *node_state,
                                         uint8_t *response_buffer,
                                         size_t *response_size_in_out,
                                         n20_slice_t message,
                                         size_t client_index) {

    // Print message in hex format for debugging.
    printf("Received message: ");
    for (size_t i = 0; i < message.size; ++i) {
        printf("%02x", message.buffer[i]);
    }
    printf("\n");

    n20_msg_request_t request;
    n20_error_t error = n20_msg_request_read(&request, message);
    if (error != n20_error_ok_e) {
        // Handle error: failed to read message
        printf("Parsing message of type: %d failed with error: %d\n", request.request_type, error);
        return error;
    }

    // Example message dispatch function.
    // This function would handle incoming messages and perform actions
    // based on the message type.
    printf("Dispatching message of type: %d\n", request.request_type);

    size_t const total_buffer_size = *response_size_in_out;

    switch (request.request_type) {
        case n20_msg_request_type_promote_e:
            error = dispatch_promote_request(node_state,
                                             response_buffer,
                                             response_size_in_out,
                                             &request.payload.promote,
                                             client_index);
            break;
        case n20_msg_request_type_issue_cdi_cert_e:
            error = dispatch_issue_cdi_cert_request(node_state,
                                                    response_buffer,
                                                    response_size_in_out,
                                                    &request.payload.issue_cdi_cert,
                                                    client_index);
            break;
        case n20_msg_request_type_issue_eca_cert_e:
            error = dispatch_issue_eca_cert_request(node_state,
                                                    response_buffer,
                                                    response_size_in_out,
                                                    &request.payload.issue_eca_cert,
                                                    client_index);
            break;
        case n20_msg_request_type_issue_eca_ee_cert_e:
            error = dispatch_issue_eca_ee_cert_request(node_state,
                                                       response_buffer,
                                                       response_size_in_out,
                                                       &request.payload.issue_eca_ee_cert,
                                                       client_index);
            break;
        case n20_msg_request_type_eca_ee_sign_e:
            error = dispatch_eca_ee_sign_request(node_state,
                                                 response_buffer,
                                                 response_size_in_out,
                                                 &request.payload.eca_ee_sign,
                                                 client_index);
            break;
        default:
            // Handle unknown request type
            error = n20_error_request_type_unknown_e;
            break;
    }
    if (error != n20_error_ok_e) {
        // Prepare an error response.
        n20_msg_error_response_t error_response = {.error_code = error};
        *response_size_in_out = total_buffer_size;  // Reset response size.
        return n20_msg_error_response_write(&error_response, response_buffer, response_size_in_out);
    }
    return n20_error_ok_e;
}
