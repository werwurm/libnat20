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

#include <nat20/functionality.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/messages.h>
#include <nat20/types.h>

n20_error_t n20_gnostic_message_dispatch(n20_gnostic_node_state_t *node_state,
                                         uint8_t *response_buffer,
                                         size_t *response_size_in_out,
                                         n20_slice_t message,
                                         size_t client_index);
