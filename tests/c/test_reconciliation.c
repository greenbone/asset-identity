/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "test_helpers.h"

Ensure(create_and_strong_reuse) {
    gvm_asset_identity_policy_t *policy = default_policy();
    const gvm_asset_identity_identifier_type_t types[] = {GVM_ASSET_IDENTITY_GREENBONE_ID, GVM_ASSET_IDENTITY_AGENT_ID};
    for (guint i = 0; i < G_N_ELEMENTS(types); i++) {
        gvm_asset_identity_observation_t *input = observation(types[i], "id");
        GPtrArray *rows = candidates_new();
        gvm_asset_identity_decision_t *result = decide(input, rows, policy);
        assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_CREATE));
        assert_that(result->needs_new_key, is_true);
        gvm_asset_identity_decision_free(result);
        g_ptr_array_add(rows, candidate("K", input));
        result = decide(input, rows, policy);
        assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_REUSE));
        assert_that(result->stage, is_equal_to(GVM_ASSET_IDENTITY_STAGE_STRONG));
        assert_that(result->selected_key, is_equal_to_string("K"));
        assert_that(result->has_selected_index, is_true);
        gvm_asset_identity_decision_free(result);
        g_ptr_array_unref(rows);
        gvm_asset_identity_observation_free(input);
    }
    gvm_asset_identity_policy_free(policy);
}

Ensure(custom_priority_preserves_original_indices) {
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_GREENBONE_ID, "g");
    GPtrArray *rows = candidates_new();
    g_ptr_array_add(rows, gvm_asset_identity_candidate_new("unmatched"));
    g_ptr_array_add(rows, candidate("G", input));
    g_ptr_array_add(input->identifiers, gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_AGENT_ID, "a"));
    g_ptr_array_add(rows, candidate("A", input));
    gvm_asset_identity_candidate_t *agent = g_ptr_array_index(rows, 2);
    g_ptr_array_remove_index(agent->identifiers, 0);
    gvm_asset_identity_policy_t *policy = gvm_asset_identity_policy_new();
    gvm_asset_identity_identifier_type_t order[] = {GVM_ASSET_IDENTITY_AGENT_ID, GVM_ASSET_IDENTITY_GREENBONE_ID};
    g_array_append_vals(policy->strong_order, order, 2);
    gvm_asset_identity_decision_t *result = decide(input, rows, policy);
    assert_that(result->selected_key, is_equal_to_string("A"));
    assert_that(result->selected_index, is_equal_to(2));
    gvm_asset_identity_decision_free(result);
    gvm_asset_identity_observation_free(input);
    g_ptr_array_unref(rows);
    gvm_asset_identity_policy_free(policy);
}

Ensure(strong_ranking_keeps_nanoseconds_missing_and_key_ties) {
    gvm_asset_identity_policy_t *policy = default_policy();
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_GREENBONE_ID, "g");
    GPtrArray *rows = candidates_new();
    gvm_asset_identity_candidate_t *a = candidate("A", input), *b = candidate("B", input), *c = candidate("C", input);
    b->last_seen = (gvm_asset_identity_timestamp_t){TRUE, -1, 1};
    c->last_seen = (gvm_asset_identity_timestamp_t){TRUE, -1, 2};
    g_ptr_array_add(rows, a); g_ptr_array_add(rows, b); g_ptr_array_add(rows, c);
    gvm_asset_identity_decision_t *result = decide(input, rows, policy);
    assert_that(result->selected_key, is_equal_to_string("C"));
    gvm_asset_identity_decision_free(result);
    b->last_seen.nanoseconds = 2;
    result = decide(input, rows, policy);
    assert_that(result->selected_key, is_equal_to_string("B"));
    gvm_asset_identity_decision_free(result);
    b->last_seen = c->last_seen = (gvm_asset_identity_timestamp_t){0};
    result = decide(input, rows, policy);
    assert_that(result->selected_key, is_equal_to_string("A"));
    gvm_asset_identity_decision_free(result);
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(strong_no_match_and_multiple_values) {
    gvm_asset_identity_policy_t *policy = default_policy();
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_GREENBONE_ID, "g");
    gvm_asset_identity_observation_t *weak = observation(GVM_ASSET_IDENTITY_IP, "192.0.2.1");
    GPtrArray *rows = candidates_new(); g_ptr_array_add(rows, candidate("weak", weak));
    gvm_asset_identity_decision_t *result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_CREATE));
    assert_that(result->stage, is_equal_to(GVM_ASSET_IDENTITY_STAGE_STRONG));
    gvm_asset_identity_decision_free(result);
    g_ptr_array_add(rows, candidate("strong", input));
    g_ptr_array_add(input->identifiers, gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_GREENBONE_ID, "other"));
    result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_REUSE));
    assert_that(result->selected_key, is_equal_to_string("strong"));
    assert_that(result->selected_index, is_equal_to(1));
    assert_that(result->needs_new_key, is_false);
    gvm_asset_identity_decision_free(result);
    gvm_asset_identity_observation_t *other = observation(GVM_ASSET_IDENTITY_GREENBONE_ID, "other");
    gvm_asset_identity_candidate_t *newer = candidate("newer", other);
    newer->last_seen = (gvm_asset_identity_timestamp_t){TRUE, 20, 0};
    g_ptr_array_add(rows, newer);
    result = decide(input, rows, policy);
    assert_that(result->selected_key, is_equal_to_string("newer"));
    assert_that(result->selected_index, is_equal_to(2));
    gvm_asset_identity_decision_free(result);
    gvm_asset_identity_observation_free(other);
    g_ptr_array_set_size(rows, 0);
    result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_CREATE));
    assert_that(result->needs_new_key, is_true);
    gvm_asset_identity_decision_free(result);
    gvm_asset_identity_observation_free(input); gvm_asset_identity_observation_free(weak);
    g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(fuzzy_containment_selects_keys_without_merges) {
    gvm_asset_identity_policy_t *policy = default_policy();
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_IP, "192.0.2.1");
    GPtrArray *rows = candidates_new();
    gvm_asset_identity_candidate_t *wide = candidate("wide", input), *narrow = candidate("narrow", input);
    g_ptr_array_add(wide->identifiers, gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_IP, "192.0.2.2"));
    wide->last_seen = (gvm_asset_identity_timestamp_t){TRUE, 20, 0};
    g_ptr_array_add(rows, wide);
    gvm_asset_identity_decision_t *result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_REUSE));
    gvm_asset_identity_decision_free(result);
    g_ptr_array_add(rows, narrow);
    result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_REUSE));
    assert_that(result->needs_new_key, is_false);
    assert_that(result->selected_key, is_equal_to_string("wide"));
    gvm_asset_identity_decision_free(result);
    g_ptr_array_remove_index(rows, 0);
    g_ptr_array_add(input->identifiers, gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_IP, "192.0.2.2"));
    result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_CREATE));
    assert_that(result->needs_new_key, is_true);
    assert_that(result->has_selected_index, is_false);
    gvm_asset_identity_decision_free(result);
    g_ptr_array_remove_index(input->identifiers, 0);
    g_ptr_array_add(input->identifiers, gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_IP, "192.0.2.3"));
    g_ptr_array_add(narrow->identifiers, gvm_asset_identity_identifier_new(GVM_ASSET_IDENTITY_IP, "192.0.2.3"));
    result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_CREATE));
    gvm_asset_identity_decision_free(result);
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(fuzzy_time_uses_epoch_whole_seconds_and_input_order) {
    gvm_asset_identity_policy_t *policy = default_policy();
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_IP, "192.0.2.1");
    GPtrArray *rows = candidates_new();
    gvm_asset_identity_candidate_t *z = candidate("Z", input), *a = candidate("A", input);
    a->last_seen = (gvm_asset_identity_timestamp_t){TRUE, 0, 999999999};
    g_ptr_array_add(rows, z); g_ptr_array_add(rows, a);
    gvm_asset_identity_decision_t *result = decide(input, rows, policy);
    assert_that(result->selected_key, is_equal_to_string("Z"));
    gvm_asset_identity_decision_free(result);
    z->last_seen = (gvm_asset_identity_timestamp_t){TRUE, -1, 999999999};
    result = decide(input, rows, policy);
    assert_that(result->selected_key, is_equal_to_string("A"));
    gvm_asset_identity_decision_free(result);
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

Ensure(scoped_semantic_equality_preserves_absent_and_empty) {
    gvm_asset_identity_policy_t *policy = default_policy();
    gvm_asset_identity_observation_t *input = observation(GVM_ASSET_IDENTITY_BIOS_UUID, "00112233445566778899AABBCCDDEEFF");
    gvm_asset_identity_identifier_t *id = g_ptr_array_index(input->identifiers, 0);
    id->scope = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert(id->scope, g_strdup("issuer"), g_strdup("realm"));
    gvm_asset_identity_candidate_t *row = candidate("K", input);
    gvm_asset_identity_identifier_t *other = g_ptr_array_index(row->identifiers, 0);
    g_free(other->value); other->value = g_strdup("{00112233-4455-6677-8899-aabbccddeeff}");
    GPtrArray *rows = candidates_new(); g_ptr_array_add(rows, row);
    gvm_asset_identity_decision_t *result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_REUSE));
    gvm_asset_identity_decision_free(result);
    g_hash_table_unref(other->scope); other->scope = NULL;
    g_hash_table_remove_all(id->scope);
    result = decide(input, rows, policy);
    assert_that(result->action, is_equal_to(GVM_ASSET_IDENTITY_CREATE));
    gvm_asset_identity_decision_free(result);
    gvm_asset_identity_observation_free(input); g_ptr_array_unref(rows); gvm_asset_identity_policy_free(policy);
}

int main(void) {
    TestSuite *suite = create_test_suite();
    add_test(suite, create_and_strong_reuse);
    add_test(suite, custom_priority_preserves_original_indices);
    add_test(suite, strong_ranking_keeps_nanoseconds_missing_and_key_ties);
    add_test(suite, strong_no_match_and_multiple_values);
    add_test(suite, fuzzy_containment_selects_keys_without_merges);
    add_test(suite, fuzzy_time_uses_epoch_whole_seconds_and_input_order);
    add_test(suite, scoped_semantic_equality_preserves_absent_and_empty);
    return run_test_suite(suite, create_text_reporter());
}
