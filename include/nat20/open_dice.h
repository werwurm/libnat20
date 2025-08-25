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

#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif
/** @file */

/**
 * @brief Mode inputs to the DICE.
 */
enum n20_open_dice_modes_s {
    /**
     * @brief No security features (e.g. verified boot) have been configured on the device.
     */
    n20_open_dice_mode_not_configured_e = 0,
    /**
     * @brief Device is operating normally with security features enabled.
     */
    n20_open_dice_mode_normal_e = 1,
    /**
     * @brief Device is in debug mode, which is a non-secure state.
     */
    n20_open_dice_mode_debug_e = 2,
    /**
     * @brief Device is in a debug or maintenance mode.
     */
    n20_open_dice_mode_recovery_e = 3,
};

/**
 * @brief Alias for @ref n20_open_dice_modes_s
 */
typedef enum n20_open_dice_modes_s n20_open_dice_modes_t;

/**
 * @brief OpenDICE input content context.
 *
 * This data structure is used to hold the internal representation
 * of the OpenDICE input content as defined in the Open Profile for DICE.
 * It is used by a variety of function to derive the CDI and
 * for formatting the OpenDICE input content in X.509 certificates
 * and CWT (CBOR web token) claims.
 *
 */
struct n20_open_dice_input_s {
    /**
     * @brief Digest of the code used as input to the DICE.
     *
     * This field is used during CDI derivation. It must be set to the digest
     * of the @ref code_descriptor if the latter is present.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t code_hash;

    /**
     * @brief Additional data used in the code input to the DICE.
     *
     * Implementation specific data about the code used to compute the CDI values.
     * If the data pointed to by @ref code_descriptor changes, this implies a change in the value
     * of @ref code_hash.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t code_descriptor;
    /**
     * @brief Digest of the configuration descriptor used as input to the DICE.
     *
     * This field is optional and may be set to @ref N20_SLICE_NULL to indicate that it is
     * to be omitted.
     * If present, it must be set to the digest of the configuration descriptor.
     * In this case this digest was used to compute the CDI secret.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t configuration_hash;
    /**
     * @brief The configuration data used to calculate the digest used for the configuration input
     * to the DICE.
     *
     * H( @ref configuration_descriptor ) must equal the value stored in @ref configuration_hash.
     * if @ref configuration_hash is present. Otherwise, this field holds the exact
     * 64 bytes of the configuration data used to calculate the CDI secret.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t configuration_descriptor;
    /**
     * @brief Digest of the authority used as input to the DICE.
     *
     * This field is used during CDI derivation. It must be set to the digest
     * of the @ref authority_descriptor if the latter is present.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t authority_hash;
    /**
     * @brief Additional data used in the authority input to the DICE.
     *
     * Implementation specific data about the authority used to compute the CDI values.
     * If the data pointed to by @ref authority_descriptor changes, this implies a change in the
     * value of @ref authority_hash.
     *
     * This field is included in the CDI certificate.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t authority_descriptor;
    /**
     * @brief The DICE mode input.
     *
     * @sa n20_open_dice_modes_s
     */
    n20_open_dice_modes_t mode;

    /**
     * @brief The DICE profile that defines the contents of this certificate.
     *
     * Must be a UTF-8 encoded string.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_string_slice_t profile_name;

    /**
     * @brief Hidden information about the device state.
     *
     * Hidden information is included in the CDI derivation
     * but not included in the certificate.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t hidden;
};

/**
 * @brief Alias for @ref n20_open_dice_input_s.
 */
typedef struct n20_open_dice_input_s n20_open_dice_input_t;

#ifdef __cplusplus
}
#endif
