/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "test_helpers.h"

Ensure (create_and_strong_reuse)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  const gvm_asset_identity_identifier_type_t types[] = {
    GVM_ASSET_IDENTITY_GREENBONE_ID, GVM_ASSET_IDENTITY_AGENT_ID};
  for (guint i = 0; i < G_N_ELEMENTS (types); i++)
    {
      gvm_asset_identity_observation_t *input = observation (types[i], "id");
      GPtrArray *rows = candidates_new ();
      gvm_asset_identity_decision_t *result = decide (input, rows, policy);
      assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
      assert_that (result->needs_new_key, is_true);
      gvm_asset_identity_decision_free (result);
      g_ptr_array_add (rows, candidate ("K", input));
      result = decide (input, rows, policy);
      assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_REUSE));
      assert_that (result->stage,
                   is_equal_to (GVM_ASSET_IDENTITY_STAGE_STRONG));
      assert_that (result->selected_key, is_equal_to_string ("K"));
      assert_that (result->has_selected_index, is_true);
      gvm_asset_identity_decision_free (result);
      g_ptr_array_unref (rows);
      gvm_asset_identity_observation_free (input);
    }
  gvm_asset_identity_policy_free (policy);
}

Ensure (custom_priority_preserves_original_indices)
{
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_GREENBONE_ID, "g");
  GPtrArray *rows = candidates_new ();
  g_ptr_array_add (rows, gvm_asset_identity_candidate_new ("unmatched"));
  g_ptr_array_add (rows, candidate ("G", input));
  g_ptr_array_add (input->identifiers, gvm_asset_identity_identifier_new (
                                         GVM_ASSET_IDENTITY_AGENT_ID, "a"));
  g_ptr_array_add (rows, candidate ("A", input));
  gvm_asset_identity_candidate_t *agent = g_ptr_array_index (rows, 2);
  g_ptr_array_remove_index (agent->identifiers, 0);
  gvm_asset_identity_policy_t *policy = gvm_asset_identity_policy_new ();
  gvm_asset_identity_identifier_type_t order[] = {
    GVM_ASSET_IDENTITY_AGENT_ID, GVM_ASSET_IDENTITY_GREENBONE_ID};
  g_array_append_vals (policy->strong_order, order, 2);
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  assert_that (result->selected_key, is_equal_to_string ("A"));
  assert_that (result->selected_index, is_equal_to (2));
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

Ensure (strong_ranking_keeps_nanoseconds_missing_and_key_ties)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_GREENBONE_ID, "g");
  GPtrArray *rows = candidates_new ();
  gvm_asset_identity_candidate_t *a = candidate ("A", input),
                                 *b = candidate ("B", input),
                                 *c = candidate ("C", input);
  b->last_seen = (gvm_asset_identity_timestamp_t){TRUE, -1, 1};
  c->last_seen = (gvm_asset_identity_timestamp_t){TRUE, -1, 2};
  g_ptr_array_add (rows, a);
  g_ptr_array_add (rows, b);
  g_ptr_array_add (rows, c);
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  assert_that (result->selected_key, is_equal_to_string ("C"));
  gvm_asset_identity_decision_free (result);
  b->last_seen.nanoseconds = 2;
  result = decide (input, rows, policy);
  assert_that (result->selected_key, is_equal_to_string ("B"));
  gvm_asset_identity_decision_free (result);
  b->last_seen = c->last_seen = (gvm_asset_identity_timestamp_t){0};
  result = decide (input, rows, policy);
  assert_that (result->selected_key, is_equal_to_string ("A"));
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

Ensure (strong_no_match_and_multiple_values)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_GREENBONE_ID, "g");
  gvm_asset_identity_observation_t *weak =
    observation (GVM_ASSET_IDENTITY_IP, "192.0.2.1");
  GPtrArray *rows = candidates_new ();
  g_ptr_array_add (rows, candidate ("weak", weak));
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  assert_that (result->stage, is_equal_to (GVM_ASSET_IDENTITY_STAGE_STRONG));
  gvm_asset_identity_decision_free (result);
  g_ptr_array_add (rows, candidate ("strong", input));
  g_ptr_array_add (input->identifiers,
                   gvm_asset_identity_identifier_new (
                     GVM_ASSET_IDENTITY_GREENBONE_ID, "other"));
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_REUSE));
  assert_that (result->selected_key, is_equal_to_string ("strong"));
  assert_that (result->selected_index, is_equal_to (1));
  assert_that (result->needs_new_key, is_false);
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_t *other =
    observation (GVM_ASSET_IDENTITY_GREENBONE_ID, "other");
  gvm_asset_identity_candidate_t *newer = candidate ("newer", other);
  newer->last_seen = (gvm_asset_identity_timestamp_t){TRUE, 20, 0};
  g_ptr_array_add (rows, newer);
  result = decide (input, rows, policy);
  assert_that (result->selected_key, is_equal_to_string ("newer"));
  assert_that (result->selected_index, is_equal_to (2));
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (other);
  g_ptr_array_set_size (rows, 0);
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  assert_that (result->needs_new_key, is_true);
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (input);
  gvm_asset_identity_observation_free (weak);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

Ensure (fuzzy_containment_returns_merge_plan)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_IP, "192.0.2.1");
  GPtrArray *rows = candidates_new ();
  gvm_asset_identity_candidate_t *wide = candidate ("wide", input),
                                 *narrow = candidate ("narrow", input);
  g_ptr_array_add (wide->identifiers, gvm_asset_identity_identifier_new (
                                        GVM_ASSET_IDENTITY_IP, "192.0.2.2"));
  wide->last_seen = (gvm_asset_identity_timestamp_t){TRUE, 20, 0};
  g_ptr_array_add (rows, wide);
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_REUSE));
  gvm_asset_identity_decision_free (result);
  g_ptr_array_add (rows, narrow);
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_REUSE));
  assert_that (result->needs_new_key, is_false);
  assert_that (result->selected_key, is_equal_to_string ("wide"));
  assert_that (result->merge_indices->len, is_equal_to (1));
  assert_that (g_array_index (result->merge_indices, gsize, 0),
               is_equal_to (1));
  gsize merge_index = g_array_index (result->merge_indices, gsize, 0);
  const gvm_asset_identity_candidate_t *merge_source =
    g_ptr_array_index (rows, merge_index);
  assert_that (merge_source->asset_key, is_equal_to_string ("narrow"));
  gvm_asset_identity_decision_free (result);
  g_ptr_array_remove_index (rows, 0);
  g_ptr_array_add (input->identifiers, gvm_asset_identity_identifier_new (
                                         GVM_ASSET_IDENTITY_IP, "192.0.2.2"));
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  assert_that (result->needs_new_key, is_true);
  assert_that (result->has_selected_index, is_false);
  gvm_asset_identity_decision_free (result);
  g_ptr_array_remove_index (input->identifiers, 0);
  g_ptr_array_add (input->identifiers, gvm_asset_identity_identifier_new (
                                         GVM_ASSET_IDENTITY_IP, "192.0.2.3"));
  g_ptr_array_add (narrow->identifiers, gvm_asset_identity_identifier_new (
                                          GVM_ASSET_IDENTITY_IP, "192.0.2.3"));
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

Ensure (fuzzy_time_uses_epoch_whole_seconds_and_input_order)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_IP, "192.0.2.1");
  GPtrArray *rows = candidates_new ();
  gvm_asset_identity_candidate_t *z = candidate ("Z", input),
                                 *a = candidate ("A", input);
  a->last_seen = (gvm_asset_identity_timestamp_t){TRUE, 0, 999999999};
  g_ptr_array_add (rows, z);
  g_ptr_array_add (rows, a);
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  assert_that (result->selected_key, is_equal_to_string ("Z"));
  gvm_asset_identity_decision_free (result);
  z->last_seen = (gvm_asset_identity_timestamp_t){TRUE, -1, 999999999};
  result = decide (input, rows, policy);
  assert_that (result->selected_key, is_equal_to_string ("A"));
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

Ensure (scoped_semantic_equality_preserves_absent_and_empty)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input = observation (
    GVM_ASSET_IDENTITY_BIOS_UUID, "00112233445566778899AABBCCDDEEFF");
  gvm_asset_identity_identifier_t *id =
    g_ptr_array_index (input->identifiers, 0);
  id->scope = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  g_hash_table_insert (id->scope, g_strdup ("issuer"), g_strdup ("realm"));
  gvm_asset_identity_candidate_t *row = candidate ("K", input);
  gvm_asset_identity_identifier_t *other =
    g_ptr_array_index (row->identifiers, 0);
  g_free (other->value);
  other->value = g_strdup ("{00112233-4455-6677-8899-aabbccddeeff}");
  GPtrArray *rows = candidates_new ();
  g_ptr_array_add (rows, row);
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_REUSE));
  gvm_asset_identity_decision_free (result);
  g_hash_table_unref (other->scope);
  other->scope = NULL;
  g_hash_table_remove_all (id->scope);
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

static void
check_raw_strong_match (gvm_asset_identity_identifier_type_t type,
                        const gchar *raw, const gchar *canonical)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *views[] = {observation (type, raw),
                                               observation (type, canonical)};
  for (guint i = 0; i < G_N_ELEMENTS (views); i++)
    {
      GPtrArray *rows = candidates_new ();
      g_ptr_array_add (rows, candidate ("existing", views[1 - i]));
      gvm_asset_identity_decision_t *result = decide (views[i], rows, policy);
      assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_REUSE));
      assert_that (result->stage,
                   is_equal_to (GVM_ASSET_IDENTITY_STAGE_STRONG));
      assert_that (result->selected_key, is_equal_to_string ("existing"));
      assert_that (result->selected_index, is_equal_to (0));
      assert_that (result->needs_new_key, is_false);
      gvm_asset_identity_decision_free (result);
      g_ptr_array_unref (rows);
    }
  assert_that (((gvm_asset_identity_identifier_t *) g_ptr_array_index (
                  views[0]->identifiers, 0))
                 ->value,
               is_equal_to_string (raw));
  assert_that (((gvm_asset_identity_identifier_t *) g_ptr_array_index (
                  views[1]->identifiers, 0))
                 ->value,
               is_equal_to_string (canonical));
  gvm_asset_identity_observation_free (views[0]);
  gvm_asset_identity_observation_free (views[1]);
  gvm_asset_identity_policy_free (policy);
}

Ensure (raw_ssh_scanner_value_matches_public_key)
{
  const gchar *key = "ecdsa-sha2-nistp256 "
                     "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOLm5"
                     "YQrOjEEK90g2FjNicABlxgBFRANn3KkM72mM3sDIyN/"
                     "q8Y6f9avo/1dMv847Y+mT2f4po92qekby06dbiU=";
  gchar *raw = g_strdup_printf ("22 %s", key);
  check_raw_strong_match (GVM_ASSET_IDENTITY_SSH_HOST_KEY, raw, key);
  g_free (raw);
}

Ensure (raw_tls_scanner_value_matches_public_key_hash)
{
  gchar *raw = NULL;
  GError *error = NULL;
  gboolean loaded =
    g_file_get_contents (TLS_SCANNER_CERTIFICATE_PATH, &raw, NULL, &error);
  assert_that (loaded, is_true);
  assert_that (error, is_null);
  if (loaded)
    {
      g_strchomp (raw); /* Remove the fixture file's line ending only. */
      check_raw_strong_match (
        GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH, raw,
        "spki-sha256:"
        "1667ab37ba6f84c9c7053970c7557507deccefdbb09c454d9d0ca0e4fe1c3319");
    }
  g_free (raw);
  g_clear_error (&error);
}

Ensure (malformed_scanner_values_return_input_errors)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  GPtrArray *rows = candidates_new ();
  const gvm_asset_identity_identifier_type_t types[] = {
    GVM_ASSET_IDENTITY_SSH_HOST_KEY, GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH};
  const gchar *values[] = {"22 ecdsa-sha2-nistp256 !!!!", "x509:!!!!"};
  for (guint i = 0; i < G_N_ELEMENTS (types); i++)
    {
      gvm_asset_identity_observation_t *input =
        observation (types[i], values[i]);
      expect_failure (input, rows, policy,
                      GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT);
      gvm_asset_identity_observation_free (input);
    }
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

Ensure (tls_requires_equal_public_key_sets)
{
  const gchar *a =
    "spki-sha256:"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const gchar *b =
    "spki-sha256:"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const gchar *c =
    "spki-sha256:"
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH, a);
  g_ptr_array_add (input->identifiers,
                   gvm_asset_identity_identifier_new (
                     GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH, b));
  GPtrArray *rows = candidates_new ();
  gvm_asset_identity_candidate_t *row = candidate ("K", input);
  g_ptr_array_add (rows, row);
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_REUSE));
  gvm_asset_identity_decision_free (result);
  g_ptr_array_remove_index (row->identifiers, 1);
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  assert_that (result->needs_new_key, is_true);
  gvm_asset_identity_decision_free (result);
  g_ptr_array_add (row->identifiers,
                   gvm_asset_identity_identifier_new (
                     GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH, b));
  g_ptr_array_add (row->identifiers,
                   gvm_asset_identity_identifier_new (
                     GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH, c));
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  gvm_asset_identity_decision_free (result);
  g_ptr_array_remove_index (row->identifiers, 2);
  g_ptr_array_add (row->identifiers,
                   gvm_asset_identity_identifier_new (
                     GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH, a));
  result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_REUSE));
  assert_that (result->selected_key, is_equal_to_string ("K"));
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

Ensure (create_returns_owned_merge_targets)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_IP, "192.0.2.1");
  g_ptr_array_add (input->identifiers,
                   gvm_asset_identity_identifier_new (
                     GVM_ASSET_IDENTITY_HOSTNAME, "host.example"));
  GPtrArray *rows = candidates_new ();
  g_ptr_array_add (rows, candidate ("K1", input));
  g_ptr_array_add (input->identifiers,
                   gvm_asset_identity_identifier_new (GVM_ASSET_IDENTITY_MAC,
                                                      "02:00:00:00:00:01"));
  g_ptr_array_add (rows, candidate ("K2", input));
  gvm_asset_identity_candidate_t *second = g_ptr_array_index (rows, 1);
  g_ptr_array_remove_index (second->identifiers, 1);
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  assert_that (result->has_selected_index, is_false);
  assert_that (result->merge_indices->len, is_equal_to (2));
  assert_that (g_array_index (result->merge_indices, gsize, 0),
               is_equal_to (0));
  assert_that (g_array_index (result->merge_indices, gsize, 1),
               is_equal_to (1));
  gvm_asset_identity_decision_free (result);
}

Ensure (weak_observation_keeps_conflicting_agent_records_separate)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_IP, "192.0.2.1");
  g_ptr_array_add (input->identifiers,
                   gvm_asset_identity_identifier_new (
                     GVM_ASSET_IDENTITY_HOSTNAME, "host.example"));
  GPtrArray *rows = candidates_new ();
  g_ptr_array_add (rows, candidate ("K1", input));
  g_ptr_array_add (input->identifiers,
                   gvm_asset_identity_identifier_new (GVM_ASSET_IDENTITY_MAC,
                                                      "02:00:00:00:00:01"));
  g_ptr_array_add (rows, candidate ("K2", input));
  gvm_asset_identity_candidate_t *first = g_ptr_array_index (rows, 0);
  gvm_asset_identity_candidate_t *second = g_ptr_array_index (rows, 1);
  g_ptr_array_remove_index (second->identifiers, 1);
  g_ptr_array_add (first->identifiers, gvm_asset_identity_identifier_new (
                                         GVM_ASSET_IDENTITY_AGENT_ID, "A"));
  g_ptr_array_add (second->identifiers, gvm_asset_identity_identifier_new (
                                          GVM_ASSET_IDENTITY_AGENT_ID, "B"));
  gvm_asset_identity_decision_t *result = decide (input, rows, policy);
  assert_that (result->action, is_equal_to (GVM_ASSET_IDENTITY_CREATE));
  assert_that (result->merge_indices->len, is_equal_to (0));
  gvm_asset_identity_decision_free (result);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

int
main (void)
{
  TestSuite *suite = create_test_suite ();
  add_test (suite, create_and_strong_reuse);
  add_test (suite, create_returns_owned_merge_targets);
  add_test (suite, weak_observation_keeps_conflicting_agent_records_separate);
  add_test (suite, custom_priority_preserves_original_indices);
  add_test (suite, strong_ranking_keeps_nanoseconds_missing_and_key_ties);
  add_test (suite, strong_no_match_and_multiple_values);
  add_test (suite, fuzzy_containment_returns_merge_plan);
  add_test (suite, fuzzy_time_uses_epoch_whole_seconds_and_input_order);
  add_test (suite, scoped_semantic_equality_preserves_absent_and_empty);
  add_test (suite, raw_ssh_scanner_value_matches_public_key);
  add_test (suite, raw_tls_scanner_value_matches_public_key_hash);
  add_test (suite, malformed_scanner_values_return_input_errors);
  add_test (suite, tls_requires_equal_public_key_sets);
  return run_test_suite (suite, create_text_reporter ());
}
