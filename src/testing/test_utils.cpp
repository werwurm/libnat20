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

#include <nat20/testing/test_utils.h>

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

std::string hexdump(std::vector<uint8_t> const& data) {
    if (data.empty()) {
        return "";
    }

    std::stringstream s;

    s << std::hex << std::setw(2) << std::setfill('0') << (int)data[0];

    for (size_t i = 1; i < data.size(); ++i) {
        if ((i & 0x0F) == 0) {
            s << "\n";
        } else if ((i & 0x07) == 0) {
            s << "  ";
        } else {
            s << " ";
        }
        s << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}

std::string hex(std::vector<uint8_t> const& data) {
    std::stringstream s;
    s << std::hex;
    for (size_t i = 0; i < data.size(); ++i) {
        s << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}

std::string hex_as_c_array(std::vector<uint8_t> const& data) {
    std::stringstream s;
    s << std::hex << "uint8_t data[] = {";
    for (size_t i = 0; i < data.size(); ++i) {
        s << "0x" << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i != data.size() - 1) {
            s << ",";
        }
    }
    s << "};\n";
    return s.str();
}

std::string hexdump_side_by_side(std::string const& label_a,
                                 std::vector<uint8_t> const& a,
                                 std::string const& label_b,
                                 std::vector<uint8_t> const& b) {
    std::stringstream s;
    size_t max_size = a.size() > b.size() ? a.size() : b.size();
    s << std::hex;

    // Column stride for column header alignment.
    // This is the distance from the beginning of the first
    // column to the beginning of the second column.
    constexpr size_t COLUMN_STRIDE = 52;
    s << "      " << label_a << std::string(COLUMN_STRIDE - label_a.size(), ' ') << label_b << "\n";

    size_t lines = (max_size + 15) / 16;
    for (size_t line = 0; line < lines; ++line) {
        s << std::setw(4) << std::setfill('0') << (line * 16) << ": ";
        for (size_t i = 0; i < 16; ++i) {
            size_t index = line * 16 + i;
            if (i == 8) {
                s << "  ";
            } else if (i != 0) {
                s << " ";
            }
            if (index < a.size()) {
                s << std::setw(2) << std::setfill('0') << (int)a[index];
            } else {
                s << "  ";
            }
        }
        s << "    ";
        for (size_t i = 0; i < 16; ++i) {
            size_t index = line * 16 + i;
            if (index < max_size) {
                if (i == 8) {
                    s << "  ";
                } else if (i != 0) {
                    s << " ";
                }
                if (index < b.size()) {
                    s << std::setw(2) << std::setfill('0') << (int)b[index];
                } else {
                    s << "  ";
                }
            }
        }
        s << "\n";
    }

    return s.str();
}
