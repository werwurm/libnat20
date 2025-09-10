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
 * @file constants.h
 */

/**
 * @brief Certificate formats.
 * This enumeration defines the formats of certificates that can be used
 * in the OpenDICE context.
 * It is used to specify the format of the certificate when issuing
 * certificates in the OpenDICE framework.
 *
 * The numbers are used in communication protocols to identify
 * the requested certificate format. Therefore, they must be stable.
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
};

/**
 * @brief Alias for @ref n20_certificate_format_s.
 */
typedef enum n20_certificate_format_s n20_certificate_format_t;
