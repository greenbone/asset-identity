/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <gvm_asset_identity.h>

int
main (void)
{
  GError *error = NULL;
  gvm_asset_identity_policy_t *policy =
    gvm_asset_identity_policy_new_default (&error);
  if (!policy)
    {
      g_clear_error (&error);
      return 1;
    }
  gvm_asset_identity_observation_t *observation =
    gvm_asset_identity_observation_new ();
  GPtrArray *candidates = g_ptr_array_new_with_free_func (
    (GDestroyNotify) gvm_asset_identity_candidate_free);
  gvm_asset_identity_decision_t *decision = NULL;
  gboolean success = gvm_asset_identity_decide (observation, candidates, policy,
                                                &decision, &error);
  int failed =
    !success || !decision || decision->action != GVM_ASSET_IDENTITY_CREATE
    || !decision->needs_new_key || gvm_asset_identity_abi_version () != 1;
  gvm_asset_identity_decision_free (decision);
  g_clear_error (&error);
  gvm_asset_identity_observation_free (observation);
  g_ptr_array_unref (candidates);
  gvm_asset_identity_policy_free (policy);
  return failed;
}
