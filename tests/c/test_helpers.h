/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H
#include <cgreen/cgreen.h>
#include <gvm_asset_identity.h>
#include <string.h>

static inline gvm_asset_identity_policy_t *default_policy(void) {
    GError *error = NULL;
    gvm_asset_identity_policy_t *policy = gvm_asset_identity_policy_new_default(&error);
    assert_that(error, is_null);
    assert_that(policy, is_non_null);
    g_clear_error(&error);
    return policy;
}

static inline gvm_asset_identity_observation_t *observation(gvm_asset_identity_identifier_type_t type, const gchar *value) {
    gvm_asset_identity_observation_t *result = gvm_asset_identity_observation_new();
    g_ptr_array_add(result->identifiers, gvm_asset_identity_identifier_new(type, value));
    return result;
}

static inline GPtrArray *candidates_new(void) {
    return g_ptr_array_new_with_free_func((GDestroyNotify)gvm_asset_identity_candidate_free);
}

static inline gvm_asset_identity_candidate_t *candidate(const gchar *key, const gvm_asset_identity_observation_t *source) {
    gvm_asset_identity_candidate_t *result = gvm_asset_identity_candidate_new(key);
    for (guint i = 0; i < source->identifiers->len; i++) {
        const gvm_asset_identity_identifier_t *id = g_ptr_array_index(source->identifiers, i);
        gvm_asset_identity_identifier_t *copy = gvm_asset_identity_identifier_new(id->type, id->value);
        if (id->scope) copy->scope = g_hash_table_ref(id->scope);
        g_ptr_array_add(result->identifiers, copy);
    }
    return result;
}

static inline gvm_asset_identity_decision_t *decide(const gvm_asset_identity_observation_t *input,
    const GPtrArray *candidates, const gvm_asset_identity_policy_t *policy) {
    gvm_asset_identity_decision_t *result = NULL;
    GError *error = NULL;
    assert_that(gvm_asset_identity_decide(input, candidates, policy, &result, &error), is_true);
    assert_that(error, is_null);
    g_clear_error(&error);
    return result;
}

static inline void expect_failure(const gvm_asset_identity_observation_t *input,
    const GPtrArray *candidates, const gvm_asset_identity_policy_t *policy, gint code) {
    gvm_asset_identity_decision_t *result = NULL;
    GError *error = NULL;
    assert_that(gvm_asset_identity_decide(input, candidates, policy, &result, &error), is_false);
    assert_that(result, is_null);
    assert_that(error, is_non_null);
    assert_that(error->domain, is_equal_to(GVM_ASSET_IDENTITY_ERROR));
    assert_that(error->code, is_equal_to(code));
    assert_that(strlen(error->message), is_greater_than(0));
    g_clear_error(&error);
}
#endif
