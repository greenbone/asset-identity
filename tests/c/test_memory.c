/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "test_helpers.h"

Ensure (results_outlive_inputs_and_other_results)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_IP, "2001:0DB8::1");
  GPtrArray *rows = candidates_new ();
  gvm_asset_identity_candidate_t *row = candidate ("K", input);
  row->last_seen = (gvm_asset_identity_timestamp_t){TRUE, -1, 123};
  g_ptr_array_add (rows, row);
  gvm_asset_identity_decision_t *first = decide (input, rows, policy),
                                *second = decide (input, rows, policy);
  assert_that (first != second, is_true);
  assert_that (first->selected_key != row->asset_key, is_true);
  assert_that (first->selected_key != second->selected_key, is_true);
  assert_that (((gvm_asset_identity_identifier_t *) g_ptr_array_index (
                  input->identifiers, 0))
                 ->value,
               is_equal_to_string ("2001:0DB8::1"));
  assert_that (row->last_seen.seconds, is_equal_to (-1));
  assert_that (row->last_seen.nanoseconds, is_equal_to (123));
  gvm_asset_identity_decision_free (first);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
  assert_that (second->selected_key, is_equal_to_string ("K"));
  gvm_asset_identity_decision_free (second);
}

Ensure (repeated_multiple_strong_values_keep_inputs_owned)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_GREENBONE_ID, "g1");
  g_ptr_array_add (
    input->identifiers,
    gvm_asset_identity_identifier_new (GVM_ASSET_IDENTITY_GREENBONE_ID, "g2"));
  gvm_asset_identity_identifier_t *id =
    g_ptr_array_index (input->identifiers, 0);
  id->scope = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  g_hash_table_insert (id->scope, g_strdup ("issuer"), g_strdup ("realm"));
  GPtrArray *rows = candidates_new ();
  gboolean valid = TRUE;
  for (guint i = 0; i < 1000; i++)
    {
      gvm_asset_identity_decision_t *result = NULL;
      GError *error = NULL;
      if (!gvm_asset_identity_decide (input, rows, policy, &result, &error))
        valid = FALSE;
      if (!result || result->action != GVM_ASSET_IDENTITY_CREATE)
        valid = FALSE;
      gvm_asset_identity_decision_free (result);
      g_clear_error (&error);
    }
  assert_that (valid, is_true);
  assert_that (g_hash_table_lookup (id->scope, "issuer"),
               is_equal_to_string ("realm"));
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
}

Ensure (repeated_reuse_and_error_cleanup)
{
  gvm_asset_identity_policy_t *policy = default_policy ();
  gvm_asset_identity_observation_t *input =
    observation (GVM_ASSET_IDENTITY_IP, "192.0.2.1");
  GPtrArray *rows = candidates_new ();
  g_ptr_array_add (rows, candidate ("A", input));
  g_ptr_array_add (rows, candidate ("B", input));
  gboolean valid = TRUE;
  for (guint i = 0; i < 1000; i++)
    {
      gvm_asset_identity_decision_t *result = NULL;
      GError *error = NULL;
      if (!gvm_asset_identity_decide (input, rows, policy, &result, &error))
        valid = FALSE;
      if (!result || result->action != GVM_ASSET_IDENTITY_REUSE)
        valid = FALSE;
      gvm_asset_identity_decision_free (result);
      g_clear_error (&error);
      result = NULL;
      if (gvm_asset_identity_decide (NULL, rows, policy, &result, &error)
          || result || !error)
        valid = FALSE;
      g_clear_error (&error);
    }
  assert_that (valid, is_true);
  gvm_asset_identity_observation_free (input);
  g_ptr_array_unref (rows);
  gvm_asset_identity_policy_free (policy);
  gvm_asset_identity_identifier_free (NULL);
  gvm_asset_identity_observation_free (NULL);
  gvm_asset_identity_candidate_free (NULL);
  gvm_asset_identity_policy_free (NULL);
  gvm_asset_identity_decision_free (NULL);
}

Ensure (default_policy_containers_are_independent)
{
  gvm_asset_identity_policy_t *first = default_policy (),
                              *second = default_policy ();
  g_array_set_size (first->strong_order, 0);
  g_array_set_size (first->fuzzy, 0);
  assert_that (second->strong_order->len, is_equal_to (7));
  assert_that (second->fuzzy->len, is_equal_to (4));
  gvm_asset_identity_policy_free (first);
  gvm_asset_identity_policy_free (second);
}

int
main (void)
{
  TestSuite *suite = create_test_suite ();
  add_test (suite, results_outlive_inputs_and_other_results);
  add_test (suite, repeated_multiple_strong_values_keep_inputs_owned);
  add_test (suite, repeated_reuse_and_error_cleanup);
  add_test (suite, default_policy_containers_are_independent);
  return run_test_suite (suite, create_text_reporter ());
}
