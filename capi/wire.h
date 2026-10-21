/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GAI_WIRE_H
#define GAI_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GAI_WIRE_ABI_VERSION 1u
#define GAI_WIRE_MAX_ITEMS 1048576u
#define GAI_WIRE_MAX_STRING 16777216u
#define GAI_WIRE_MAX_INPUT_BYTES 67108864u

typedef uint32_t gai_wire_status_t;
enum {
    GAI_WIRE_OK = 0,
    GAI_WIRE_INVALID_INPUT = 1,
    GAI_WIRE_INVALID_POLICY = 2,
    GAI_WIRE_INTERNAL_ERROR = 3
};

typedef uint32_t gai_wire_identifier_type_t;
enum {
    GAI_WIRE_GREENBONE_ID = 1,
    GAI_WIRE_AGENT_ID,
    GAI_WIRE_MACHINE_ID,
    GAI_WIRE_BIOS_UUID,
    GAI_WIRE_SSH_HOST_KEY,
    GAI_WIRE_TLS_PUBLIC_KEY_HASH,
    GAI_WIRE_CLOUD_IDENTIFIER,
    GAI_WIRE_IP,
    GAI_WIRE_FQDN,
    GAI_WIRE_MAC,
    GAI_WIRE_HOSTNAME
};

typedef struct {
    const char *data;
    size_t length;
} gai_wire_string_t;

typedef struct {
    gai_wire_string_t name;
    gai_wire_string_t value;
} gai_wire_scope_dimension_t;

typedef struct {
    uint32_t present; /* 0: absent; 1 with count 0: explicitly empty. */
    const gai_wire_scope_dimension_t *dimensions;
    size_t count;
} gai_wire_scope_t;

typedef struct {
    gai_wire_identifier_type_t type;
    gai_wire_string_t value;
    gai_wire_scope_t scope;
} gai_wire_identifier_t;

typedef struct {
    uint32_t present;
    int64_t seconds; /* Signed Unix seconds; no time_t dependency. */
    uint32_t nanoseconds;
} gai_wire_timestamp_t;

typedef struct {
    const gai_wire_identifier_t *identifiers;
    size_t identifier_count;
} gai_wire_observation_t;

typedef struct {
    gai_wire_string_t asset_key;
    const gai_wire_identifier_t *identifiers;
    size_t identifier_count;
    gai_wire_timestamp_t last_seen;
} gai_wire_candidate_t;

typedef struct {
    gai_wire_identifier_type_t type;
    double weight;
} gai_wire_fuzzy_member_t;

typedef struct {
    const gai_wire_identifier_type_t *strong_order;
    size_t strong_count;
    const gai_wire_fuzzy_member_t *fuzzy;
    size_t fuzzy_count;
} gai_wire_policy_t;

typedef uint32_t gai_wire_action_t;
enum {
    GAI_WIRE_CREATE = 1,
    GAI_WIRE_REUSE
};

typedef uint32_t gai_wire_stage_t;
enum {
    GAI_WIRE_STAGE_STRONG = 1,
    GAI_WIRE_STAGE_FUZZY
};

typedef struct {
    gai_wire_action_t action;
    gai_wire_stage_t stage;
    uint32_t needs_new_key;
    gai_wire_string_t selected_key;
    uint32_t has_selected_index;
    size_t selected_index;
} gai_wire_decision_t;

typedef struct {
    gai_wire_string_t message;
} gai_wire_error_t;

/* Inputs are borrowed for the call; output slots must not alias inputs.
 * Output slots are cleared on entry. error is optional. */
gai_wire_status_t gai_wire_decide(
    const gai_wire_observation_t *observation,
    const gai_wire_candidate_t *candidates, size_t candidate_count,
    const gai_wire_policy_t *policy,
    gai_wire_decision_t **decision, gai_wire_error_t **error);

/* Default policy and all returned objects are immutable, library-owned C allocations. */
gai_wire_status_t gai_wire_default_policy(
    gai_wire_policy_t **policy, gai_wire_error_t **error);
void gai_wire_policy_free(gai_wire_policy_t *policy);
void gai_wire_decision_free(gai_wire_decision_t *decision);
void gai_wire_error_free(gai_wire_error_t *error);
uint32_t gai_wire_abi_version(void);

#ifdef __cplusplus
}
#endif
#endif
