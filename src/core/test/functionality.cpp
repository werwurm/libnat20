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

#include <gtest/gtest.h>
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <nat20/testing/test_bssl_utils.h>
#include <nat20/testing/test_utils.h>
#include <nat20/types.h>
#include <openssl/x509.h>

#include "test_vectors.h"

uint8_t const test_cdi[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

/* Test code "hash" 32 repetitions of 0x0c */
std::vector<uint8_t> const TEST_CODE_HASH = {
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
};

/* Test authority "hash" 32 repetitions of 0x1a */
std::vector<uint8_t> const TEST_AUTHORITY_HASH = {
    0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10,
    0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10,
};

/* Test configuration "hash" 32 repetitions of 0x2d */
std::vector<uint8_t> const TEST_CONFIGURATION_HASH = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
};

std::vector<uint8_t> const TEST_CODE_DESCRIPTOR = {
    'C', 'o', 'd', 'e', ' ', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r'};

std::vector<uint8_t> const TEST_CONFIGURATION_DESCRIPTOR = {
    'C', 'o', 'n', 'f', 'i', 'g', ' ', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r'};

std::vector<uint8_t> const TEST_AUTHORITY_DESCRIPTOR = {'A', 'u', 't', 'h', 'o', 'r', 'i',
                                                        't', 'y', ' ', 'D', 'e', 's', 'c',
                                                        'r', 'i', 'p', 't', 'o', 'r'};

/* Test hidden data 32 repetitions of  0x04 */
std::vector<uint8_t> const TEST_HIDDEN = {
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
};

std::vector<uint8_t> const TEST_NONCE = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
};

n20_slice_t vec2slice(std::vector<uint8_t> const& vec) {
    return n20_slice_t{.size = vec.size(), .buffer = vec.data()};
}

n20_open_dice_input_t const TEST_OPEN_DICE_INPUT = {
    .code_hash = vec2slice(TEST_CODE_HASH),
    .code_descriptor = vec2slice(TEST_CODE_DESCRIPTOR),
    .configuration_hash = vec2slice(TEST_CONFIGURATION_HASH),
    .configuration_descriptor = vec2slice(TEST_CONFIGURATION_DESCRIPTOR),
    .authority_hash = vec2slice(TEST_AUTHORITY_HASH),
    .authority_descriptor = vec2slice(TEST_AUTHORITY_DESCRIPTOR),
    .mode = n20_open_dice_mode_normal_e,
    .profile_name = N20_STR_C("OpenDICE"),
    .hidden = vec2slice(TEST_HIDDEN),
};

class BsslTestFixtureBase : public ::testing::Test {
   protected:
    n20_crypto_context_t* crypto_ctx;

    void SetUp() override { EXPECT_EQ(n20_error_ok_e, n20_crypto_boringssl_open(&crypto_ctx)); }

    void TearDown() override { EXPECT_EQ(n20_error_ok_e, n20_crypto_boringssl_close(crypto_ctx)); }

   public:
    n20_crypto_key_t GetCdi() {
        n20_slice_t cdi_slice = {sizeof(test_cdi), const_cast<uint8_t*>(&test_cdi[0])};
        n20_crypto_key_t cdi_key = nullptr;
        EXPECT_EQ(n20_error_ok_e,
                  n20_crypto_boringssl_make_secret(crypto_ctx, &cdi_slice, &cdi_key));
        return cdi_key;
    }
};

// Test fixture
class FunctionalityX509Test
    : public BsslTestFixtureBase,
      public ::testing::WithParamInterface<std::tuple<std::string,
                                                      n20_crypto_key_type_t,
                                                      n20_crypto_key_type_t,
                                                      n20_cert_type_t,
                                                      std::vector<uint8_t>>> {};

INSTANTIATE_TEST_SUITE_P(FunctionalityTestInstance,
                         FunctionalityX509Test,
                         ::testing::ValuesIn(x509_test_vectors),
                         [](testing::TestParamInfo<FunctionalityX509Test::ParamType> const& info) {
                             return std::get<0>(info.param);
                         });

TEST_P(FunctionalityX509Test, IssueX509CertificateTest) {
    auto [test_name, issuer_key_type, subject_key_type, cert_type, want_cert] = GetParam();

    auto key_deleter = [this](void* key) { crypto_ctx->key_free(crypto_ctx, key); };

    // Get the root CDI from the crypto backend.
    n20_crypto_key_t issuer_secret = this->GetCdi();
    auto parent_secret_guard =
        std::unique_ptr<void, decltype(key_deleter)>(issuer_secret, key_deleter);

    // Derive the issuer key.
    n20_crypto_key_t issuer_key = nullptr;
    ASSERT_NE(issuer_secret, nullptr);
    auto parent_attestation_key_guard =
        std::unique_ptr<void, decltype(key_deleter)>(issuer_key, key_deleter);

    if (cert_type == n20_cert_type_eca_ee_e) {
        ASSERT_EQ(n20_error_ok_e,
                  n20_derive_eca_key(
                      crypto_ctx, issuer_secret, &issuer_key, issuer_key_type));
        ASSERT_NE(issuer_key, nullptr);

    } else {
        ASSERT_EQ(n20_error_ok_e,
                  n20_derive_cdi_attestation_key(
                      crypto_ctx, issuer_secret, &issuer_key, issuer_key_type));
        ASSERT_NE(issuer_key, nullptr);
    }
    // Assemble certificate info.

    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = cert_type;
    switch (cert_info.cert_type) {
        case n20_cert_type_self_signed_e:
            break;
        case n20_cert_type_cdi_e:
            cert_info.open_dice_input = TEST_OPEN_DICE_INPUT;
            break;
        case n20_cert_type_eca_e:
            cert_info.eca.nonce = vec2slice(TEST_NONCE);
            break;
        case n20_cert_type_eca_ee_e:
            cert_info.eca_ee.nonce = vec2slice(TEST_NONCE);
            cert_info.eca_ee.name = N20_STR_C("Test EE");
            break;
        default:
            GTEST_FAIL() << "Unsupported certificate type: " << cert_info.cert_type;
            return;
    }
    uint8_t certificate[2048] = {};
    size_t certificate_size = sizeof(certificate);

    ASSERT_EQ(n20_error_ok_e,
              n20_issue_certificate(crypto_ctx,
                                    issuer_secret,
                                    issuer_key_type,
                                    subject_key_type,
                                    &cert_info,
                                    n20_certificate_format_x509_e,
                                    certificate,
                                    &certificate_size))
        << "Expected buffer size: " << certificate_size;

    auto got_cert = std::vector<uint8_t>(&certificate[sizeof(certificate) - certificate_size],
                                         &certificate[sizeof(certificate)]);

    // Currently we are using ECDSA with random nonce (k) for signing with
    // secp256r1 and secp384r1 keys, so the signature will not match the
    // one in the test vectors.
    // We can only compare the certificate content without the signature
    // in these cases. For ed25519, the signature is deterministic
    // and will match the one in the test vectors.
    // The test vectors for secp256r1 and secp384r1 are truncated right
    // before the signature bitstring header.
    auto comp_got_cert = got_cert;

    if (issuer_key_type == n20_crypto_key_type_secp256r1_e ||
        issuer_key_type == n20_crypto_key_type_secp384r1_e) {
        comp_got_cert.resize(got_cert.size() > want_cert.size() ? want_cert.size()
                                                                : got_cert.size());
        // In the case of X.509 certificates we also have to adjust the
        // length in the sequence header, because the signature length
        // is not deterministic either.
        if (want_cert.size() > 3 && comp_got_cert.size() > 3) {
            comp_got_cert[3] = want_cert[3];
        }
    }

    ASSERT_EQ(want_cert, comp_got_cert)
        << hexdump_side_by_side("Expected:", want_cert, "Got:", got_cert) << hex(got_cert);
    ASSERT_EQ(want_cert.size(), comp_got_cert.size());

    size_t public_key_size = 0;
    crypto_ctx->key_get_public_key(crypto_ctx, issuer_key, nullptr, &public_key_size);

    std::vector<uint8_t> public_key_buffer(public_key_size + 1);
    uint8_t* public_key = public_key_buffer.data() + 1;
    crypto_ctx->key_get_public_key(crypto_ctx, issuer_key, public_key, &public_key_size);

    if (issuer_key_type == n20_crypto_key_type_secp256r1_e ||
        issuer_key_type == n20_crypto_key_type_secp384r1_e) {
        public_key_buffer[0] = 0x04;
        public_key = public_key_buffer.data();
        public_key_size += 1;
    }

    uint8_t const* p = got_cert.data();
    auto x509i = X509_PTR_t(d2i_X509(nullptr, &p, got_cert.size()));
    ASSERT_TRUE(!!x509i) << BsslError();
    X509_print_ex_fp(stdout, x509i.get(), 0, X509V3_EXT_DUMP_UNKNOWN);

    auto key = n20_crypto_key_to_evp_pkey_ptr(issuer_key_type, public_key, public_key_size);
    auto rc = X509_verify(x509i.get(), key.get());
    ASSERT_EQ(rc, 1) << BsslError();
}
