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
#include <nat20/service/gnostic_message_dispatch.h>
#include <nat20/service/messages.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef N20_WITH_COSE
#include <nat20/cose.h>
#endif

#define DEFAULT_SOCKET_PATH "/tmp/gnostic_n20_service.sock"
#define BACKLOG 1

n20_error_t init_gnostic_node_with_bssl_crypto(n20_gnostic_node_state_t *node_state) {

    if (node_state == NULL) {
        return n20_error_unexpected_null_service_state_e;
    }

    *node_state = (n20_gnostic_node_state_t){0};

    // OpenSSL BSSL crypto context initialization.
    n20_crypto_context_t *crypto_bssl_context;
    n20_crypto_boringssl_open(&crypto_bssl_context);
    if (crypto_bssl_context == NULL) {
        return n20_error_crypto_no_resources_e;
    }

    n20_slice_t info = {.size = 18, .buffer = (uint8_t *)"example_info_value"};

    n20_slice_t salt = {.size = 18, .buffer = (uint8_t *)"example_salt_value"};

    n20_slice_t ikm = {.size = 22, .buffer = (uint8_t *)"example_uds_passphrase"};

    uint8_t uds[32] = {0};  // Example UDS passphrase buffer.

    n20_error_t rc = crypto_bssl_context->digest_ctx.hkdf(&crypto_bssl_context->digest_ctx,
                                                          n20_crypto_digest_algorithm_sha2_256_e,
                                                          ikm,
                                                          salt,
                                                          info,
                                                          32,
                                                          uds);
    if (rc != n20_error_ok_e) {
        n20_crypto_boringssl_close(crypto_bssl_context);
        return rc;
    }

    n20_slice_t uds_slice = {.size = sizeof(uds), .buffer = uds};

    n20_crypto_key_t uds_handle = NULL;

    rc = n20_crypto_boringssl_make_secret(crypto_bssl_context, &uds_slice, &uds_handle);
    if (rc != n20_error_ok_e) {
        n20_crypto_boringssl_close(crypto_bssl_context);
        return rc;
    }

    n20_crypto_key_t client_min_cdis[N20_GNOSTIC_MAX_CLIENT_SLOTS] = {0};
    client_min_cdis[0] = uds_handle;  // Example: Use the UDS as the first client CDI.

    n20_gnostic_init(node_state, crypto_bssl_context, client_min_cdis);

    return n20_error_ok_e;
}

#ifdef N20_WITH_COSE
static n20_error_t export_uds_public_key_as_cose(n20_gnostic_node_state_t *node_state,
                                                 n20_crypto_key_type_t key_type,
                                                 uint8_t *response_buffer,
                                                 size_t *response_size_in_out) {
    if (node_state == NULL || response_buffer == NULL || response_size_in_out == NULL) {
        return n20_error_insufficient_buffer_size_e;
    }

    // Get the UDS public key from the node state.
    n20_crypto_key_t uds_public_key = node_state->client_slots[0].min_cdi;

    n20_crypto_key_t derived_key = NULL;

    n20_error_t error = n20_derive_cdi_attestation_key(
        node_state->crypto_context, uds_public_key, &derived_key, key_type);
    if (error != n20_error_ok_e) {
        return error;
    }

    uint8_t public_key_buffer[97];
    uint8_t *public_key = &public_key_buffer[1];
    size_t public_key_size = sizeof(public_key_buffer) - 1;

    error = node_state->crypto_context->key_get_public_key(
        node_state->crypto_context, derived_key, public_key, &public_key_size);
    node_state->crypto_context->key_free(node_state->crypto_context, derived_key);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_cose_key_t cose_key = {0};

    switch (key_type) {
        case n20_crypto_key_type_ed25519_e:
            cose_key.algorithm_id = -8;
            cose_key.x.buffer = public_key;
            cose_key.x.size = public_key_size;
            break;
        case n20_crypto_key_type_secp256r1_e:
            cose_key.algorithm_id = -7;
            cose_key.x.buffer = public_key;
            cose_key.x.size = public_key_size / 2;
            cose_key.y.buffer = &public_key[public_key_size / 2];
            cose_key.y.size = public_key_size / 2;
            break;
        case n20_crypto_key_type_secp384r1_e:
            cose_key.algorithm_id = -35;
            cose_key.x.buffer = public_key;
            cose_key.x.size = public_key_size;
            cose_key.y.buffer = &public_key[public_key_size / 2];
            cose_key.y.size = public_key_size / 2;
            break;
        default:
            return n20_error_crypto_invalid_key_type_e;
    }

    n20_cose_key_ops_set(&cose_key.key_ops, n20_cose_key_op_sign_e);
    n20_cose_key_ops_set(&cose_key.key_ops, n20_cose_key_op_verify_e);

    n20_stream_t stream;
    n20_stream_init(&stream, response_buffer, *response_size_in_out);

    // Write the COSE key to the response buffer.
    n20_cose_write_key(&stream, &cose_key);

    if (n20_stream_has_write_position_overflow(&stream)) {
        // If the write position overflows, we need to return an error.
        return n20_error_write_position_overflow_e;
    }

    *response_size_in_out = n20_stream_byte_count(&stream);

    if (n20_stream_has_buffer_overflow(&stream)) {
        return n20_error_insufficient_buffer_size_e;
    }

    return n20_error_ok_e;
}
#endif

static n20_gnostic_node_state_t service_node_state = {0};

#ifdef N20_WITH_COSE
static void print_uds_public_keys(n20_gnostic_node_state_t *node_state) {
    if (node_state == NULL) {
        printf("Node state is NULL\n");
        return;
    }

    uint8_t key_formatting_buffer[256];
    size_t key_formatting_size = sizeof(key_formatting_buffer);

    n20_error_t error = export_uds_public_key_as_cose(
        node_state, n20_crypto_key_type_ed25519_e, key_formatting_buffer, &key_formatting_size);
    if (error != n20_error_ok_e) {
        printf("Failed to export UDS public key as COSE: %d\n", error);
        return;
    }

    printf("UDS Public Key ED25519 (COSE format): ");
    for (size_t i = 0; i < key_formatting_size; ++i) {
        printf("%02x",
               key_formatting_buffer[sizeof(key_formatting_buffer) - key_formatting_size + i]);
    }
    printf("\n");

    key_formatting_size = sizeof(key_formatting_buffer);
    error = export_uds_public_key_as_cose(
        node_state, n20_crypto_key_type_secp256r1_e, key_formatting_buffer, &key_formatting_size);
    if (error != n20_error_ok_e) {
        printf("Failed to export UDS public key as COSE: %d\n", error);
        return;
    }

    printf("UDS Public Key P256 (COSE format): ");
    for (size_t i = 0; i < key_formatting_size; ++i) {
        printf("%02x",
               key_formatting_buffer[sizeof(key_formatting_buffer) - key_formatting_size + i]);
    }
    printf("\n");

    key_formatting_size = sizeof(key_formatting_buffer);
    error = export_uds_public_key_as_cose(
        node_state, n20_crypto_key_type_secp384r1_e, key_formatting_buffer, &key_formatting_size);
    if (error != n20_error_ok_e) {
        printf("Failed to export UDS public key as COSE: %d\n", error);
        return;
    }

    printf("UDS Public Key P384 (COSE format): ");
    for (size_t i = 0; i < key_formatting_size; ++i) {
        printf("%02x",
               key_formatting_buffer[sizeof(key_formatting_buffer) - key_formatting_size + i]);
    }
    printf("\n");
}
#endif

static void write_uds_certs_to_paths(n20_gnostic_node_state_t *node_state,
                                     char const *uds_cert_path_ed25519,
                                     char const *uds_cert_path_p256,
                                     char const *uds_cert_path_p384) {
    // Implementation for writing UDS certificates to the specified paths

    uint8_t certificate[2048];
    size_t certificate_size = sizeof(certificate);

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_self_signed_e;

    if (uds_cert_path_ed25519 != NULL) {

        n20_error_t err = n20_issue_certificate(node_state->crypto_context,
                                                node_state->client_slots[0].min_cdi,
                                                n20_crypto_key_type_ed25519_e,
                                                n20_crypto_key_type_ed25519_e,
                                                &cert_info,
                                                n20_certificate_format_x509_e,
                                                certificate,
                                                &certificate_size);

        if (err != n20_error_ok_e) {
            printf("Failed to issue UDS certificate for ED25519: %d\n", err);
            return;
        }

        // Write certificate to the given path.
        FILE *file = fopen(uds_cert_path_ed25519, "wb");
        if (file == NULL) {
            printf("Failed to open UDS certificate file for ED25519: %s\n", uds_cert_path_ed25519);
            return;
        }
        fwrite(certificate + (sizeof(certificate) - certificate_size), certificate_size, 1, file);
        fclose(file);
    }

    if (uds_cert_path_p256 != NULL) {
        certificate_size = sizeof(certificate);
        n20_error_t err = n20_issue_certificate(node_state->crypto_context,
                                                node_state->client_slots[0].min_cdi,
                                                n20_crypto_key_type_secp256r1_e,
                                                n20_crypto_key_type_secp256r1_e,
                                                &cert_info,
                                                n20_certificate_format_x509_e,
                                                certificate,
                                                &certificate_size);

        if (err != n20_error_ok_e) {
            printf("Failed to issue UDS certificate for P256: %d\n", err);
            return;
        }

        // Write certificate to the given path.
        FILE *file = fopen(uds_cert_path_p256, "wb");
        if (file == NULL) {
            printf("Failed to open UDS certificate file for P256: %s\n", uds_cert_path_p256);
            return;
        }
        fwrite(certificate + (sizeof(certificate) - certificate_size), certificate_size, 1, file);
        fclose(file);
    }

    if (uds_cert_path_p384 != NULL) {
        certificate_size = sizeof(certificate);
        n20_error_t err = n20_issue_certificate(node_state->crypto_context,
                                                node_state->client_slots[0].min_cdi,
                                                n20_crypto_key_type_secp384r1_e,
                                                n20_crypto_key_type_secp384r1_e,
                                                &cert_info,
                                                n20_certificate_format_x509_e,
                                                certificate,
                                                &certificate_size);

        if (err != n20_error_ok_e) {
            printf("Failed to issue UDS certificate for P384: %d\n", err);
            return;
        }

        // Write certificate to the given path.
        FILE *file = fopen(uds_cert_path_p384, "wb");
        if (file == NULL) {
            printf("Failed to open UDS certificate file for P384: %s\n", uds_cert_path_p384);
            return;
        }
        fwrite(certificate + (sizeof(certificate) - certificate_size), certificate_size, 1, file);
        fclose(file);
    }
}

char const *usage_format_str =
    "Usage: %s [OPTIONS]\n"
    "\n"
    "A gnostic service that provides cryptographic operations and certificate issuance\n"
    "for DICE (Device Identifier Composition Engine) attestation.\n"
    "\n"
    "OPTIONS:\n"
    "  -s, --socket-path <path>\n"
    "                 Path to the Unix domain socket for client communication.\n"
    "                 Default: " DEFAULT_SOCKET_PATH
    "\n"
    "\n"
    "  -e, --uds-cert-path-ed25519 <path>\n"
    "                 Path where the UDS (Unique Device Secret) certificate for\n"
    "                 Ed25519 key type will be written in X.509 format.\n"
    "                 If not specified, no Ed25519 UDS certificate is written.\n"
    "\n"
    "  -p, --uds-cert-path-p256 <path>\n"
    "                 Path where the UDS certificate for P-256 (secp256r1)\n"
    "                 key type will be written in X.509 format.\n"
    "                 If not specified, no P-256 UDS certificate is written.\n"
    "\n"
    "  -d, --uds-cert-path-p384 <path>\n"
    "                 Path where the UDS certificate for P-384 (secp384r1)\n"
    "                 key type will be written in X.509 format.\n"
    "                 If not specified, no P-384 UDS certificate is written.\n"
    "\n"
    "DESCRIPTION:\n"
    "  The gnostic service starts a Unix domain socket server that accepts\n"
    "  cryptographic requests from clients. It supports DICE attestation\n"
    "  operations including:\n"
    "\n"
    "  - Promoting clients to the next attestation level\n"
    "  - Issuing CDI (Compound Device Identifier) certificates\n"
    "  - Issuing ECA (Endorsement Certificate Authority) certificates\n"
    "  - Issuing ECA End-Entity certificates\n"
    "  - Signing operations with ECA End-Entity keys\n"
    "\n"
    "  On startup, the service generates UDS public keys for Ed25519, P-256,\n"
    "  and P-384 algorithms and prints them in COSE format. If certificate\n"
    "  paths are provided, corresponding self-signed UDS certificates are\n"
    "  written to those files.\n";

int main(int argc, char *argv[]) {
    /* Parse command line with the following usage:
     * Use <binary name> --socket-path/-s <socket_path>
     * using getopt_long.
     */
    char *socket_path = DEFAULT_SOCKET_PATH;
    char *uds_cert_path_ed25519 = NULL;
    char *uds_cert_path_p256 = NULL;
    char *uds_cert_path_p384 = NULL;
    static struct option long_options[] = {{"socket-path", required_argument, 0, 's'},
                                           {"uds-cert-path-ed25519", required_argument, 0, 'e'},
                                           {"uds-cert-path-p256", required_argument, 0, 'p'},
                                           {"uds-cert-path-p384", required_argument, 0, 'd'},
                                           {0, 0, 0, 0}};
    int opt;
    while ((opt = getopt_long(argc, argv, "s:e:p:d:", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                socket_path = optarg;
                break;
            case 'e':
                uds_cert_path_ed25519 = optarg;
                break;
            case 'p':
                uds_cert_path_p256 = optarg;
                break;
            case 'd':
                uds_cert_path_p384 = optarg;
                break;
            default:
                fprintf(stderr, usage_format_str, argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Initialize the gnostic node state and crypto context.
    init_gnostic_node_with_bssl_crypto(&service_node_state);

#ifdef N20_WITH_COSE
    // Print the UDS public keys in COSE format.
    print_uds_public_keys(&service_node_state);
#endif

    write_uds_certs_to_paths(
        &service_node_state, uds_cert_path_ed25519, uds_cert_path_p256, uds_cert_path_p384);

    int server_fd;
    struct sockaddr_un addr;

    // Create socket
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Remove any existing socket file
    unlink(socket_path);

    // Set up the address structure
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, BACKLOG) == -1) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Listening on %s\n", socket_path);

    bool run = true;

    while (run) {
        // Accept loop (example, not handling clients here)
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) {
            perror("accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        printf("Client connected\n");
        uint8_t buffer[1024];
        uint8_t response_buffer[1024];
        size_t response_size = sizeof(buffer);
        n20_slice_t message = {.size = 0, .buffer = buffer};
        // Read message from client
        ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            perror("read");
            close(client_fd);
            continue;
        } else if (bytes_read == 0) {
            printf("Client disconnected\n");
            close(client_fd);
            continue;
        }
        message.size = (size_t)bytes_read;
        printf("Received message of size: %zu\n", message.size);
        // Dispatch the message
        n20_error_t error = n20_gnostic_message_dispatch(
            &service_node_state, response_buffer, &response_size, message, 0);
        if (error != n20_error_ok_e) {
            printf("Error dispatching message: %d\n", error);
            close(client_fd);
            continue;
        }
        // Write response back to client
        // The response is written to the end of the response_buffer.
        ssize_t bytes_written = write(
            client_fd, &response_buffer[sizeof(response_buffer) - response_size], response_size);
        if (bytes_written < 0) {
            perror("write");
        }
    }

    // Cleanup
    close(server_fd);
    unlink(socket_path);

    return 0;
}
