/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "wire.h"
#include "_cgo_export.h"
#include <stdlib.h>

static void free_string(gai_wire_string_t value) {
    free((void *)value.data);
}

gai_wire_status_t gai_wire_decide(
    const gai_wire_observation_t *observation,
    const gai_wire_candidate_t *candidates, size_t candidate_count,
    const gai_wire_policy_t *policy,
    gai_wire_decision_t **decision, gai_wire_error_t **error) {
    return gvmAssetIdentityDecide((gai_wire_observation_t *)observation,
        (gai_wire_candidate_t *)candidates, candidate_count,
        (gai_wire_policy_t *)policy, decision, error);
}

gai_wire_status_t gai_wire_default_policy(
    gai_wire_policy_t **policy, gai_wire_error_t **error) {
    return gvmAssetIdentityDefaultPolicy(policy, error);
}

void gai_wire_decision_free(gai_wire_decision_t *decision) {
    if (!decision) return;
    free_string(decision->selected_key);
    free(decision);
}

void gai_wire_policy_free(gai_wire_policy_t *policy) {
    if (!policy) return;
    free((void *)policy->strong_order);
    free((void *)policy->fuzzy);
    free(policy);
}

void gai_wire_error_free(gai_wire_error_t *error) {
    if (!error) return;
    free_string(error->message);
    free(error);
}

uint32_t gai_wire_abi_version(void) {
    return GAI_WIRE_ABI_VERSION;
}
