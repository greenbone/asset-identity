/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "test_helpers.h"
#include <float.h>
#include <math.h>

Ensure(default_policy_is_copied_from_go) {
    gvm_asset_identity_policy_t *policy = default_policy();
    assert_that(gvm_asset_identity_abi_version(), is_equal_to(1));
    assert_that(policy->strong_order->len, is_equal_to(7));
    assert_that(g_array_index(policy->strong_order, gvm_asset_identity_identifier_type_t, 0), is_equal_to(GVM_ASSET_IDENTITY_GREENBONE_ID));
    assert_that(policy->fuzzy->len, is_equal_to(3));
    assert_that(g_array_index(policy->fuzzy, gvm_asset_identity_fuzzy_member_t, 0).type, is_equal_to(GVM_ASSET_IDENTITY_MAC));
    assert_that(g_array_index(policy->fuzzy, gvm_asset_identity_fuzzy_member_t, 0).weight == 1, is_true);
    assert_that(g_array_index(policy->fuzzy, gvm_asset_identity_fuzzy_member_t, 1).type, is_equal_to(GVM_ASSET_IDENTITY_HOSTNAME));
    gvm_asset_identity_policy_free(policy);
}

Ensure(invalid_weights_fail_even_on_strong_matches) {
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_GREENBONE_ID, "g");
    GPtrArray *rows = candidates_new(); g_ptr_array_add(rows, candidate("K", input));
    double weights[] = {0, -0.0, -1, NAN, INFINITY, -INFINITY, DBL_MAX, DBL_TRUE_MIN};
    gvm_asset_identity_policy_t *policy = default_policy();
    for (guint i = 0; i < G_N_ELEMENTS(weights); i++) {
        g_array_index(policy->fuzzy, gvm_asset_identity_fuzzy_member_t, 0).weight = weights[i];
        expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY);
    }
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(invalid_memberships_are_rejected) {
    gvm_asset_identity_observation_t *input = gvm_asset_identity_observation_new();
    GPtrArray *rows = candidates_new();
    gvm_asset_identity_policy_t *policy = gvm_asset_identity_policy_new();
    gvm_asset_identity_identifier_type_t order[] = {GVM_ASSET_IDENTITY_IP, GVM_ASSET_IDENTITY_IP};
    g_array_append_vals(policy->strong_order, order, 2);
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY);
    g_array_set_size(policy->strong_order, 1);
    gvm_asset_identity_fuzzy_member_t member = {GVM_ASSET_IDENTITY_IP, 1};
    g_array_append_val(policy->fuzzy, member);
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY);
    g_array_set_size(policy->strong_order, 0);
    g_array_append_val(policy->fuzzy, member);
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY);
    g_array_set_size(policy->fuzzy, 1);
    g_array_index(policy->fuzzy, gvm_asset_identity_fuzzy_member_t, 0).type = GVM_ASSET_IDENTITY_FQDN;
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY);
    g_array_index(policy->fuzzy, gvm_asset_identity_fuzzy_member_t, 0).type = 999;
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY);
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(candidate_keys_and_timestamps_are_validated) {
    gvm_asset_identity_observation_t *input = gvm_asset_identity_observation_new();
    GPtrArray *rows = candidates_new();
    gvm_asset_identity_policy_t *policy = default_policy();
    g_ptr_array_add(rows, gvm_asset_identity_candidate_new("K"));
    g_ptr_array_add(rows, gvm_asset_identity_candidate_new("K"));
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    g_ptr_array_remove_index(rows, 1);
    gvm_asset_identity_candidate_t *row = g_ptr_array_index(rows, 0);
    g_free(row->asset_key); row->asset_key = g_strdup("");
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    g_free(row->asset_key); row->asset_key = g_strdup("K");
    const gvm_asset_identity_timestamp_t times[] = {
        {TRUE, 253402300800LL, 0}, {TRUE, 0, -1}, {TRUE, 0, 1000000000},
        {TRUE, G_MAXINT64, 0}, {TRUE, G_MININT64, 0}, {FALSE, 1, 0}
    };
    for (guint i = 0; i < G_N_ELEMENTS(times); i++) {
        row->last_seen = times[i];
        expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    }
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(timestamp_endpoints_and_glib_booleans_are_supported) {
    gvm_asset_identity_policy_t *policy = default_policy();
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_AGENT_ID, "a");
    GPtrArray *rows = candidates_new();
    gvm_asset_identity_candidate_t *row = candidate("K", input);
    g_ptr_array_add(rows, row);
    const gvm_asset_identity_timestamp_t times[] = {
        {TRUE, -62135596800LL, 0}, {TRUE, 253402300799LL, 999999999},
        {2, 0, 0}, {-1, -1, 999999999}
    };
    for (guint i = 0; i < G_N_ELEMENTS(times); i++) {
        row->last_seen = times[i];
        gvm_asset_identity_decision_t *result = decide(input, rows, policy);
        assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_REUSE));
        assert_that(row->last_seen.present, is_equal_to(times[i].present));
        gvm_asset_identity_decision_free(result);
    }
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(null_pointers_and_container_contents_are_rejected) {
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_AGENT_ID, "a");
    GPtrArray *rows = candidates_new();
    gvm_asset_identity_policy_t *policy = default_policy();
    expect_failure(NULL, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    expect_failure(input, NULL, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    expect_failure(input, rows, NULL, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY);
    assert_that(gvm_asset_identity_decide(input, rows, policy, NULL, NULL), is_false);
    g_ptr_array_add(rows, NULL);
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    g_ptr_array_set_size(rows, 0);
    g_ptr_array_add(input->identifiers, NULL);
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    g_ptr_array_remove_index(input->identifiers, 1);
    gvm_asset_identity_identifier_t *id = g_ptr_array_index(input->identifiers, 0);
    id->type = 999;
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    id->type = GVM_ASSET_IDENTITY_AGENT_ID;
    g_free(id->value); id->value = NULL;
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    g_array_unref(policy->fuzzy); policy->fuzzy = g_array_new(FALSE, FALSE, 1);
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY);
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(invalid_scope_contents_are_rejected) {
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_AGENT_ID, "a");
    GPtrArray *rows = candidates_new();
    gvm_asset_identity_policy_t *policy = default_policy();
    gvm_asset_identity_identifier_t *id = g_ptr_array_index(input->identifiers, 0);
    id->scope = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert(id->scope, g_strdup(""), g_strdup("realm"));
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    g_hash_table_remove_all(id->scope);
    g_hash_table_insert(id->scope, g_strdup("issuer"), NULL);
    expect_failure(input, rows, policy, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

int main(void) {
    TestSuite *suite = create_test_suite();
    add_test(suite, default_policy_is_copied_from_go);
    add_test(suite, invalid_weights_fail_even_on_strong_matches);
    add_test(suite, invalid_memberships_are_rejected);
    add_test(suite, candidate_keys_and_timestamps_are_validated);
    add_test(suite, timestamp_endpoints_and_glib_booleans_are_supported);
    add_test(suite, null_pointers_and_container_contents_are_rejected);
    add_test(suite, invalid_scope_contents_are_rejected);
    return run_test_suite(suite, create_text_reporter());
}
