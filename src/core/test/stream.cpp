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
#include <nat20/oid.h>
#include <nat20/stream.h>

#include <cstdint>
#include <vector>

class StreamTest
    : public testing::TestWithParam<std::tuple<size_t, std::vector<std::vector<uint8_t>>, bool>> {};

std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_EMPTY = {};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_NULLPTR = {{}};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_NULLPTR_NULLPTR = {{}, {}};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_NULL = {{0x05, 0x00}};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_NULLPTR_NULL_NULLPTR = {
    {}, {0x05, 0x00}, {}};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_SEQUENCE = {
    {0x6e, 0x65, 0x73, 0x74, 0x65, 0x64},
    {0x13, 0x06},
    {0x66, 0x6c, 0x61, 0x74},
    {0x13, 0x04},
    {0xff},
    {0x01, 0x01},
    {0x30, 0x09},
    {0x30, 0x13}};

INSTANTIATE_TEST_CASE_P(N20StreamTest,
                        StreamTest,
                        testing::Values(std::tuple(1, BYTES_TO_PREPEND_EMPTY, false),
                                        std::tuple(2, BYTES_TO_PREPEND_EMPTY, false),
                                        std::tuple(1, BYTES_TO_PREPEND_NULLPTR, false),
                                        std::tuple(2, BYTES_TO_PREPEND_NULLPTR, false),
                                        std::tuple(1, BYTES_TO_PREPEND_NULLPTR_NULLPTR, false),
                                        std::tuple(2, BYTES_TO_PREPEND_NULLPTR_NULLPTR, false),
                                        std::tuple(1, BYTES_TO_PREPEND_NULL, true),
                                        std::tuple(2, BYTES_TO_PREPEND_NULL, false),
                                        std::tuple(3, BYTES_TO_PREPEND_NULL, false),
                                        std::tuple(1, BYTES_TO_PREPEND_NULLPTR_NULL_NULLPTR, true),
                                        std::tuple(2, BYTES_TO_PREPEND_NULLPTR_NULL_NULLPTR, false),
                                        std::tuple(3, BYTES_TO_PREPEND_NULLPTR_NULL_NULLPTR, false),
                                        std::tuple(1, BYTES_TO_PREPEND_SEQUENCE, true),
                                        std::tuple(2, BYTES_TO_PREPEND_SEQUENCE, true),
                                        std::tuple(10, BYTES_TO_PREPEND_SEQUENCE, true),
                                        std::tuple(20, BYTES_TO_PREPEND_SEQUENCE, true),
                                        std::tuple(21, BYTES_TO_PREPEND_SEQUENCE, false),
                                        std::tuple(22, BYTES_TO_PREPEND_SEQUENCE, false)));

TEST_P(StreamTest, StreamPrepend) {
    auto [buffer_size, bytes_to_prepend, has_overflow] = GetParam();

    // Reverse
    std::vector<std::vector<uint8_t>> bytes_to_prepend_copy(bytes_to_prepend);
    std::reverse(bytes_to_prepend_copy.begin(), bytes_to_prepend_copy.end());
    // Flatten
    std::vector<uint8_t> expected;
    for (auto const& bytes : bytes_to_prepend_copy) {
        for (auto const& byte : bytes) {
            expected.push_back(byte);
        }
    }

    n20_stream_t s;
    uint8_t buffer[buffer_size];
    n20_stream_init(&s, buffer, buffer_size);
    for (auto const& bytes : bytes_to_prepend) {
        n20_stream_prepend(&s, bytes.data(), bytes.size());
    }
    ASSERT_EQ(has_overflow, n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), expected.size());
    if (!has_overflow) {
        std::vector<uint8_t> got = std::vector<uint8_t>(
            n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
        ASSERT_EQ(expected, got);
    }
}

TEST(StreamTest, StreamCounterOverflow) {
    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));

    n20_stream_prepend(&s, nullptr, std::numeric_limits<uint64_t>::max());
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));

    n20_stream_prepend(&s, nullptr, 1);
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_TRUE(n20_stream_has_write_position_overflow(&s));

    n20_stream_prepend(&s, nullptr, std::numeric_limits<uint64_t>::max() - 1);
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_TRUE(n20_stream_has_write_position_overflow(&s));

    n20_stream_prepend(&s, nullptr, 1);
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_TRUE(n20_stream_has_write_position_overflow(&s));
}

class IStreamTest : public testing::Test {
   protected:
    void SetUp() override {
        // Initialize test data
        test_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    }

    std::vector<uint8_t> test_data;
};

TEST_F(IStreamTest, InitWithValidBuffer) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    EXPECT_EQ(stream.begin, test_data.data());
    EXPECT_EQ(stream.size, test_data.size());
    EXPECT_EQ(stream.read_position, 0);
    EXPECT_FALSE(stream.buffer_underrun);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
    EXPECT_EQ(n20_istream_read_position(&stream), 0);
}

TEST_F(IStreamTest, InitWithNullBuffer) {
    n20_istream_t stream;
    n20_istream_init(&stream, nullptr, 100);

    EXPECT_EQ(stream.begin, nullptr);
    EXPECT_EQ(stream.size, 100);
    EXPECT_EQ(stream.read_position, 0);
    EXPECT_TRUE(stream.buffer_underrun);

    uint8_t read_buffer[4];
    EXPECT_FALSE(n20_istream_read(&stream, read_buffer, sizeof(read_buffer)));
    EXPECT_FALSE(n20_istream_get(&stream, &read_buffer[0]));
    EXPECT_EQ(n20_istream_get_slice(&stream, 4), nullptr);
    EXPECT_EQ(n20_istream_read_position(&stream), 0);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, InitWithNullStream) {
    // Should not crash
    n20_istream_init(nullptr, test_data.data(), test_data.size());
}

TEST_F(IStreamTest, ReadSingleBytes) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    for (size_t i = 0; i < test_data.size(); ++i) {
        uint8_t byte;
        EXPECT_TRUE(n20_istream_read(&stream, &byte, 1));
        EXPECT_EQ(byte, test_data[i]);
        EXPECT_EQ(n20_istream_read_position(&stream), i + 1);
        EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
    }

    // Try to read beyond buffer
    uint8_t byte;
    EXPECT_FALSE(n20_istream_read(&stream, &byte, 1));
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
    EXPECT_EQ(n20_istream_read_position(&stream), test_data.size());
}

TEST_F(IStreamTest, ReadMultipleBytes) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    std::vector<uint8_t> buffer(4);
    EXPECT_TRUE(n20_istream_read(&stream, buffer.data(), 4));
    EXPECT_EQ(buffer, std::vector<uint8_t>({0x01, 0x02, 0x03, 0x04}));
    EXPECT_EQ(n20_istream_read_position(&stream), 4);

    buffer.resize(4);
    EXPECT_TRUE(n20_istream_read(&stream, buffer.data(), 4));
    EXPECT_EQ(buffer, std::vector<uint8_t>({0x05, 0x06, 0x07, 0x08}));
    EXPECT_EQ(n20_istream_read_position(&stream), 8);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, ReadExactlyBufferSize) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    std::vector<uint8_t> buffer(test_data.size());
    EXPECT_TRUE(n20_istream_read(&stream, buffer.data(), test_data.size()));
    EXPECT_EQ(buffer, test_data);
    EXPECT_EQ(n20_istream_read_position(&stream), test_data.size());
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, ReadBeyondBuffer) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    std::vector<uint8_t> buffer(test_data.size() + 1);
    std::vector<uint8_t> original_buffer = buffer;

    EXPECT_FALSE(n20_istream_read(&stream, buffer.data(), test_data.size() + 1));
    EXPECT_EQ(buffer, original_buffer);  // Buffer should remain unchanged
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
    EXPECT_EQ(n20_istream_read_position(&stream), test_data.size());
}

TEST_F(IStreamTest, ReadAfterUnderrun) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    // Cause underrun
    std::vector<uint8_t> buffer(test_data.size() + 1);
    EXPECT_FALSE(n20_istream_read(&stream, buffer.data(), test_data.size() + 1));
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));

    // Try to read again - should fail
    uint8_t byte;
    EXPECT_FALSE(n20_istream_read(&stream, &byte, 1));
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, ReadWithNullStream) {
    uint8_t buffer[4];
    EXPECT_FALSE(n20_istream_read(nullptr, buffer, 4));
}

TEST_F(IStreamTest, GetSingleByte) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    for (size_t i = 0; i < test_data.size(); ++i) {
        uint8_t byte;
        EXPECT_TRUE(n20_istream_get(&stream, &byte));
        EXPECT_EQ(byte, test_data[i]);
        EXPECT_EQ(n20_istream_read_position(&stream), i + 1);
    }

    // Try to get beyond buffer
    uint8_t byte;
    EXPECT_FALSE(n20_istream_get(&stream, &byte));
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, GetWithNullStream) {
    uint8_t byte;
    EXPECT_FALSE(n20_istream_get(nullptr, &byte));
}

TEST_F(IStreamTest, GetSliceValid) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    // Get first 4 bytes
    uint8_t const* slice = n20_istream_get_slice(&stream, 4);
    EXPECT_NE(slice, nullptr);
    EXPECT_EQ(slice, test_data.data());
    EXPECT_EQ(n20_istream_read_position(&stream), 4);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));

    // Verify slice content
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(slice[i], test_data[i]);
    }

    // Get remaining bytes
    slice = n20_istream_get_slice(&stream, 4);
    EXPECT_NE(slice, nullptr);
    EXPECT_EQ(slice, test_data.data() + 4);
    EXPECT_EQ(n20_istream_read_position(&stream), 8);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, GetSliceZeroSize) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    uint8_t const* slice = n20_istream_get_slice(&stream, 0);
    EXPECT_NE(slice, nullptr);
    EXPECT_EQ(slice, test_data.data());
    EXPECT_EQ(n20_istream_read_position(&stream), 0);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, GetSliceExactSize) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    uint8_t const* slice = n20_istream_get_slice(&stream, test_data.size());
    EXPECT_NE(slice, nullptr);
    EXPECT_EQ(slice, test_data.data());
    EXPECT_EQ(n20_istream_read_position(&stream), test_data.size());
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, GetSliceBeyondBuffer) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    uint8_t const* slice = n20_istream_get_slice(&stream, test_data.size() + 1);
    EXPECT_EQ(slice, nullptr);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
    EXPECT_EQ(n20_istream_read_position(&stream), test_data.size());
}

TEST_F(IStreamTest, GetSliceAfterUnderrun) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    // Cause underrun
    uint8_t const* slice = n20_istream_get_slice(&stream, test_data.size() + 1);
    EXPECT_EQ(slice, nullptr);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));

    // Try to get slice again - should fail
    slice = n20_istream_get_slice(&stream, 1);
    EXPECT_EQ(slice, nullptr);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, GetSliceWithNullStream) {
    uint8_t const* slice = n20_istream_get_slice(nullptr, 4);
    EXPECT_EQ(slice, nullptr);
}

TEST_F(IStreamTest, GetSliceOverflowProtection) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    // Move to near end of buffer
    n20_istream_get_slice(&stream, test_data.size() - 1);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));

    // Try to get slice that would cause overflow
    uint8_t const* slice = n20_istream_get_slice(&stream, SIZE_MAX);
    EXPECT_EQ(slice, nullptr);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
    EXPECT_EQ(n20_istream_read_position(&stream), test_data.size());
}

TEST_F(IStreamTest, HasBufferUnderrunWithNullStream) {
    EXPECT_TRUE(n20_istream_has_buffer_underrun(nullptr));
}

TEST_F(IStreamTest, ReadPositionWithNullStream) {
    EXPECT_EQ(n20_istream_read_position(nullptr), 0);
}

TEST_F(IStreamTest, MixedOperations) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    // Get single byte
    uint8_t byte;
    EXPECT_TRUE(n20_istream_get(&stream, &byte));
    EXPECT_EQ(byte, 0x01);
    EXPECT_EQ(n20_istream_read_position(&stream), 1);

    // Get slice
    uint8_t const* slice = n20_istream_get_slice(&stream, 3);
    EXPECT_NE(slice, nullptr);
    EXPECT_EQ(slice[0], 0x02);
    EXPECT_EQ(slice[1], 0x03);
    EXPECT_EQ(slice[2], 0x04);
    EXPECT_EQ(n20_istream_read_position(&stream), 4);

    // Read multiple bytes
    std::vector<uint8_t> buffer(4);
    EXPECT_TRUE(n20_istream_read(&stream, buffer.data(), 4));
    EXPECT_EQ(buffer, std::vector<uint8_t>({0x05, 0x06, 0x07, 0x08}));
    EXPECT_EQ(n20_istream_read_position(&stream), 8);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));

    // Try to read more - should fail
    EXPECT_FALSE(n20_istream_get(&stream, &byte));
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, EmptyBuffer) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), 0);  // Empty buffer

    uint8_t byte;
    EXPECT_FALSE(n20_istream_get(&stream, &byte));
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
    EXPECT_EQ(n20_istream_read_position(&stream), 0);

    uint8_t const* slice = n20_istream_get_slice(&stream, 1);
    EXPECT_EQ(slice, nullptr);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, NullBuffer) {
    n20_istream_t stream;
    n20_istream_init(&stream, nullptr, 0);  // Null buffer

    uint8_t byte;
    EXPECT_FALSE(n20_istream_get(&stream, &byte));
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
    EXPECT_EQ(n20_istream_read_position(&stream), 0);

    uint8_t const* slice = n20_istream_get_slice(&stream, 1);
    EXPECT_EQ(slice, nullptr);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
}


TEST_F(IStreamTest, ZeroSizeRead) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    std::vector<uint8_t> buffer(4, 0xFF);                      // Initialize with non-zero values
    EXPECT_TRUE(n20_istream_read(&stream, buffer.data(), 0));  // Zero-size read
    EXPECT_EQ(buffer, std::vector<uint8_t>({0xFF, 0xFF, 0xFF, 0xFF}));  // Buffer unchanged
    EXPECT_EQ(n20_istream_read_position(&stream), 0);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, ZeroSizeReadNullInit) {
    n20_istream_t stream;
    n20_istream_init(&stream, nullptr, 0);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));

    EXPECT_TRUE(n20_istream_read(&stream, nullptr, 0));  // Zero-size read
    EXPECT_EQ(n20_istream_read_position(&stream), 0);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
}

TEST_F(IStreamTest, ZeroSizeReadNullInitNonZeroBufferSize) {
    n20_istream_t stream;
    n20_istream_init(&stream, nullptr, 1);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));

    EXPECT_FALSE(n20_istream_read(&stream, nullptr, 0));  // Zero-size read
    EXPECT_EQ(n20_istream_read_position(&stream), 0);
    EXPECT_TRUE(n20_istream_has_buffer_underrun(&stream));
}

// Parameterized test for various buffer sizes and read patterns
class IStreamParameterizedTest : public testing::TestWithParam<std::tuple<size_t, size_t>> {
   protected:
    void SetUp() override {
        buffer_size = std::get<0>(GetParam());
        read_size = std::get<1>(GetParam());

        test_data.resize(buffer_size);
        for (size_t i = 0; i < buffer_size; ++i) {
            test_data[i] = static_cast<uint8_t>(i & 0xFF);
        }
    }

    std::vector<uint8_t> test_data;
    size_t buffer_size;
    size_t read_size;
};

TEST_P(IStreamParameterizedTest, ReadInChunks) {
    n20_istream_t stream;
    n20_istream_init(&stream, test_data.data(), test_data.size());

    std::vector<uint8_t> read_data;
    std::vector<uint8_t> chunk(read_size);

    while (n20_istream_read_position(&stream) < test_data.size()) {
        size_t remaining = test_data.size() - n20_istream_read_position(&stream);
        size_t to_read = std::min(read_size, remaining);

        bool success = n20_istream_read(&stream, chunk.data(), to_read);
        EXPECT_TRUE(success);

        read_data.insert(read_data.end(), chunk.begin(), chunk.begin() + to_read);
    }

    EXPECT_EQ(read_data, test_data);
    EXPECT_FALSE(n20_istream_has_buffer_underrun(&stream));
    EXPECT_EQ(n20_istream_read_position(&stream), test_data.size());
}

INSTANTIATE_TEST_SUITE_P(IStreamTests,
                         IStreamParameterizedTest,
                         testing::Values(std::make_tuple(1, 1),
                                         std::make_tuple(8, 1),
                                         std::make_tuple(8, 2),
                                         std::make_tuple(8, 4),
                                         std::make_tuple(16, 3),
                                         std::make_tuple(100, 7),
                                         std::make_tuple(1000, 64)));
