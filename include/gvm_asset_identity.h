/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GVM_ASSET_IDENTITY_H
#define GVM_ASSET_IDENTITY_H

#include <glib.h>

G_BEGIN_DECLS

#define GVM_ASSET_IDENTITY_ABI_VERSION 1u
#define GVM_ASSET_IDENTITY_ERROR (gvm_asset_identity_error_quark())

typedef enum {
    GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT = 1,
    GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY,
    GVM_ASSET_IDENTITY_ERROR_INTERNAL
} gvm_asset_identity_error_t;

typedef enum {
    GVM_ASSET_IDENTITY_GREENBONE_ID = 1,
    GVM_ASSET_IDENTITY_AGENT_ID,
    GVM_ASSET_IDENTITY_MACHINE_ID,
    GVM_ASSET_IDENTITY_BIOS_UUID,
    GVM_ASSET_IDENTITY_SSH_HOST_KEY,
    GVM_ASSET_IDENTITY_TLS_PUBLIC_KEY_HASH,
    GVM_ASSET_IDENTITY_CLOUD_IDENTIFIER,
    GVM_ASSET_IDENTITY_IP,
    GVM_ASSET_IDENTITY_FQDN,
    GVM_ASSET_IDENTITY_MAC,
    GVM_ASSET_IDENTITY_HOSTNAME
} gvm_asset_identity_identifier_type_t;

typedef struct {
    gvm_asset_identity_identifier_type_t type;
    gchar *value;
    GHashTable *scope; /* Owned string-to-string map; NULL differs from empty. */
} gvm_asset_identity_identifier_t;

typedef struct {
    gboolean present;
    gint64 seconds;
    gint32 nanoseconds;
} gvm_asset_identity_timestamp_t;

typedef struct {
    GPtrArray *identifiers; /* Owned gvm_asset_identity_identifier_t entries. */
} gvm_asset_identity_observation_t;

typedef struct {
    gchar *asset_key;
    GPtrArray *identifiers;
    gvm_asset_identity_timestamp_t last_seen;
} gvm_asset_identity_candidate_t;

typedef struct {
    gvm_asset_identity_identifier_type_t type;
    gdouble weight;
} gvm_asset_identity_fuzzy_member_t;

typedef struct {
    GArray *strong_order; /* gvm_asset_identity_identifier_type_t entries. */
    GArray *fuzzy; /* gvm_asset_identity_fuzzy_member_t entries, in accumulation order. */
} gvm_asset_identity_policy_t;

typedef enum {
    GVM_ASSET_IDENTITY_CREATE = 1,
    GVM_ASSET_IDENTITY_REUSE,
    GVM_ASSET_IDENTITY_REVIEW,
    GVM_ASSET_IDENTITY_CONFLICT
} gvm_asset_identity_action_t;

typedef enum {
    GVM_ASSET_IDENTITY_STAGE_NONE,
    GVM_ASSET_IDENTITY_STAGE_STRONG,
    GVM_ASSET_IDENTITY_STAGE_FUZZY
} gvm_asset_identity_stage_t;

typedef struct {
    gchar *reason;
    GArray *candidate_indices; /* gsize entries in original candidate order. */
    GPtrArray *identifiers;
} gvm_asset_identity_conflict_t;

typedef struct {
    gvm_asset_identity_action_t action;
    gvm_asset_identity_stage_t stage;
    gboolean needs_new_key;
    gchar *selected_key;
    gboolean has_selected_index;
    gsize selected_index;
    GArray *potential_merge_indices; /* gsize entries; never authorized merges. */
    GPtrArray *potential_merge_keys; /* Owned strings, parallel to indices. */
    gvm_asset_identity_conflict_t *conflict;
} gvm_asset_identity_decision_t;

/* Constructors return full ownership; child fields are owned by their parent. */
gvm_asset_identity_identifier_t *gvm_asset_identity_identifier_new(
    gvm_asset_identity_identifier_type_t type, const gchar *value);
void gvm_asset_identity_identifier_free(gvm_asset_identity_identifier_t *identifier);
gvm_asset_identity_observation_t *gvm_asset_identity_observation_new(void);
void gvm_asset_identity_observation_free(gvm_asset_identity_observation_t *observation);
gvm_asset_identity_candidate_t *gvm_asset_identity_candidate_new(const gchar *asset_key);
void gvm_asset_identity_candidate_free(gvm_asset_identity_candidate_t *candidate);
gvm_asset_identity_policy_t *gvm_asset_identity_policy_new(void);
gvm_asset_identity_policy_t *gvm_asset_identity_policy_new_default(GError **error);
void gvm_asset_identity_policy_free(gvm_asset_identity_policy_t *policy);

/* Inputs are borrowed, immutable during this call; output is independently owned.
 * On failure *decision is NULL. REVIEW, including its key proposal, is non-actionable. */
gboolean gvm_asset_identity_decide(
    const gvm_asset_identity_observation_t *observation,
    const GPtrArray *candidates, const gvm_asset_identity_policy_t *policy,
    gvm_asset_identity_decision_t **decision, GError **error);
void gvm_asset_identity_decision_free(gvm_asset_identity_decision_t *decision);
GQuark gvm_asset_identity_error_quark(void);
guint32 gvm_asset_identity_abi_version(void);

G_END_DECLS
#endif
