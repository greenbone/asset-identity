/*
 * SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "gvm_asset_identity.h"
#include "wire.h"
#include <string.h>

GQuark gvm_asset_identity_error_quark(void) {
    return g_quark_from_static_string("gvm-asset-identity-error");
}

guint32 gvm_asset_identity_abi_version(void) { return GVM_ASSET_IDENTITY_ABI_VERSION; }

gvm_asset_identity_identifier_t *gvm_asset_identity_identifier_new(
    gvm_asset_identity_identifier_type_t type, const gchar *value) {
    gvm_asset_identity_identifier_t *identifier = g_new0(gvm_asset_identity_identifier_t, 1);
    identifier->type = type;
    identifier->value = g_strdup(value);
    return identifier;
}

void gvm_asset_identity_identifier_free(gvm_asset_identity_identifier_t *identifier) {
    if (!identifier) return;
    g_free(identifier->value);
    if (identifier->scope) g_hash_table_unref(identifier->scope);
    g_free(identifier);
}

static GPtrArray *new_identifiers(void) {
    return g_ptr_array_new_with_free_func((GDestroyNotify)gvm_asset_identity_identifier_free);
}

gvm_asset_identity_observation_t *gvm_asset_identity_observation_new(void) {
    gvm_asset_identity_observation_t *observation = g_new0(gvm_asset_identity_observation_t, 1);
    observation->identifiers = new_identifiers();
    return observation;
}

void gvm_asset_identity_observation_free(gvm_asset_identity_observation_t *observation) {
    if (!observation) return;
    if (observation->identifiers) g_ptr_array_unref(observation->identifiers);
    g_free(observation);
}

gvm_asset_identity_candidate_t *gvm_asset_identity_candidate_new(const gchar *asset_key) {
    gvm_asset_identity_candidate_t *candidate = g_new0(gvm_asset_identity_candidate_t, 1);
    candidate->asset_key = g_strdup(asset_key);
    candidate->identifiers = new_identifiers();
    return candidate;
}

void gvm_asset_identity_candidate_free(gvm_asset_identity_candidate_t *candidate) {
    if (!candidate) return;
    g_free(candidate->asset_key);
    if (candidate->identifiers) g_ptr_array_unref(candidate->identifiers);
    g_free(candidate);
}

gvm_asset_identity_policy_t *gvm_asset_identity_policy_new(void) {
    gvm_asset_identity_policy_t *policy = g_new0(gvm_asset_identity_policy_t, 1);
    policy->strong_order = g_array_new(FALSE, FALSE, sizeof(gvm_asset_identity_identifier_type_t));
    policy->fuzzy = g_array_new(FALSE, FALSE, sizeof(gvm_asset_identity_fuzzy_member_t));
    return policy;
}

void gvm_asset_identity_policy_free(gvm_asset_identity_policy_t *policy) {
    if (!policy) return;
    if (policy->strong_order) g_array_unref(policy->strong_order);
    if (policy->fuzzy) g_array_unref(policy->fuzzy);
    g_free(policy);
}

static gboolean wire_error(gai_wire_status_t status, gai_wire_error_t *failure, GError **error) {
    if (status == GAI_WIRE_OK) return TRUE;
    g_set_error_literal(error, GVM_ASSET_IDENTITY_ERROR, (gint)status,
        failure ? failure->message.data : "internal library failure");
    return FALSE;
}

gvm_asset_identity_policy_t *gvm_asset_identity_policy_new_default(GError **error) {
    if (error && *error) return NULL;
    gai_wire_policy_t *value = NULL;
    gai_wire_error_t *failure = NULL;
    gai_wire_status_t status = gai_wire_default_policy(&value, &failure);
    gboolean success = wire_error(status, failure, error);
    gai_wire_error_free(failure);
    if (!success) return NULL;
    gvm_asset_identity_policy_t *policy = gvm_asset_identity_policy_new();
    for (gsize i = 0; i < value->strong_count; i++) {
        gvm_asset_identity_identifier_type_t type = value->strong_order[i];
        g_array_append_val(policy->strong_order, type);
    }
    for (gsize i = 0; i < value->fuzzy_count; i++) {
        gvm_asset_identity_fuzzy_member_t member = {value->fuzzy[i].type, value->fuzzy[i].weight};
        g_array_append_val(policy->fuzzy, member);
    }
    gai_wire_policy_free(value);
    return policy;
}

static gboolean fail(GError **error, gint code, const gchar *message) {
    g_set_error_literal(error, GVM_ASSET_IDENTITY_ERROR, code, message);
    return FALSE;
}

static gboolean wire_string(const gchar *text, gai_wire_string_t *value, GError **error) {
    if (!text) return fail(error, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT, "NULL string");
    gsize length = strnlen(text, GAI_WIRE_MAX_STRING + 1);
    if (length > GAI_WIRE_MAX_STRING)
        return fail(error, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT, "string exceeds length limit");
    *value = (gai_wire_string_t){text, length};
    return TRUE;
}

static void free_input_identifiers(const gai_wire_identifier_t *values, gsize count) {
    for (gsize i = 0; values && i < count; i++) g_free((gpointer)values[i].scope.dimensions);
    g_free((gpointer)values);
}

static gboolean wire_identifiers(const GPtrArray *identifiers,
    const gai_wire_identifier_t **values, gsize *count, GError **error) {
    if (!identifiers || identifiers->len > GAI_WIRE_MAX_ITEMS || (identifiers->len && !identifiers->pdata))
        return fail(error, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT, "invalid identifier array");
    *count = identifiers->len;
    gai_wire_identifier_t *items = g_new0(gai_wire_identifier_t, *count);
    *values = items;
    for (gsize i = 0; i < *count; i++) {
        const gvm_asset_identity_identifier_t *identifier = g_ptr_array_index(identifiers, i);
        if (!identifier) return fail(error, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT, "NULL identifier");
        items[i].type = identifier->type;
        if (!wire_string(identifier->value, &items[i].value, error)) return FALSE;
        if (!identifier->scope) continue;
        gsize size = g_hash_table_size(identifier->scope);
        if (size > GAI_WIRE_MAX_ITEMS)
            return fail(error, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT, "scope exceeds item limit");
        gai_wire_scope_dimension_t *dimensions = g_new0(gai_wire_scope_dimension_t, size);
        items[i].scope = (gai_wire_scope_t){1, dimensions, size};
        GHashTableIter iter;
        gpointer key, content;
        g_hash_table_iter_init(&iter, identifier->scope);
        gsize j = 0;
        while (g_hash_table_iter_next(&iter, &key, &content)) {
            if (!wire_string(key, &dimensions[j].name, error) || !wire_string(content, &dimensions[j].value, error)) return FALSE;
            j++;
        }
    }
    return TRUE;
}

static gboolean wire_policy(const gvm_asset_identity_policy_t *policy,
    gai_wire_policy_t *value, GError **error) {
    if (!policy || !policy->strong_order || !policy->fuzzy ||
        g_array_get_element_size(policy->strong_order) != sizeof(gvm_asset_identity_identifier_type_t) ||
        g_array_get_element_size(policy->fuzzy) != sizeof(gvm_asset_identity_fuzzy_member_t) ||
        policy->strong_order->len > GAI_WIRE_MAX_ITEMS || policy->fuzzy->len > GAI_WIRE_MAX_ITEMS ||
        (policy->strong_order->len && !policy->strong_order->data) ||
        (policy->fuzzy->len && !policy->fuzzy->data))
        return fail(error, GVM_ASSET_IDENTITY_ERROR_INVALID_POLICY, "invalid policy arrays");
    value->strong_count = policy->strong_order->len;
    guint32 *order = g_new(guint32, value->strong_count);
    value->strong_order = order;
    for (gsize i = 0; i < value->strong_count; i++)
        order[i] = g_array_index(policy->strong_order, gvm_asset_identity_identifier_type_t, i);
    value->fuzzy_count = policy->fuzzy->len;
    gai_wire_fuzzy_member_t *fuzzy = g_new0(gai_wire_fuzzy_member_t, value->fuzzy_count);
    value->fuzzy = fuzzy;
    for (gsize i = 0; i < value->fuzzy_count; i++) {
        gvm_asset_identity_fuzzy_member_t member = g_array_index(policy->fuzzy, gvm_asset_identity_fuzzy_member_t, i);
        fuzzy[i] = (gai_wire_fuzzy_member_t){member.type, member.weight};
    }
    return TRUE;
}

void gvm_asset_identity_decision_free(gvm_asset_identity_decision_t *decision) {
    if (!decision) return;
    g_free(decision->selected_key);
    if (decision->merge_indices) g_array_unref(decision->merge_indices);
    if (decision->merge_keys) g_ptr_array_unref(decision->merge_keys);
    g_free(decision);
}

static gvm_asset_identity_decision_t *copy_decision(const gai_wire_decision_t *value) {
    gvm_asset_identity_decision_t *decision = g_new0(gvm_asset_identity_decision_t, 1);
    decision->action = value->action;
    decision->stage = value->stage;
    decision->needs_new_key = value->needs_new_key;
    decision->has_selected_index = value->has_selected_index;
    decision->selected_index = value->selected_index;
    if (value->has_selected_index) decision->selected_key = g_strdup(value->selected_key.data);
    decision->merge_indices = g_array_new(FALSE, FALSE, sizeof(gsize));
    decision->merge_keys = g_ptr_array_new_with_free_func(g_free);
    for (size_t i = 0; i < value->merge_count; i++) {
        gsize index = value->merge_indices[i];
        g_array_append_val(decision->merge_indices, index);
        g_ptr_array_add(decision->merge_keys, g_strdup(value->merge_keys[i].data));
    }
    return decision;
}

gboolean gvm_asset_identity_decide(const gvm_asset_identity_observation_t *observation,
    const GPtrArray *candidates, const gvm_asset_identity_policy_t *policy,
    gvm_asset_identity_decision_t **decision, GError **error) {
    if (decision) *decision = NULL;
    if (error && *error) return FALSE;
    if (!decision || !observation || !candidates || candidates->len > GAI_WIRE_MAX_ITEMS || (candidates->len && !candidates->pdata))
        return fail(error, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT, "invalid observation, candidates or output");
    gai_wire_policy_t converted_policy = {0};
    gai_wire_observation_t converted_observation = {0};
    gai_wire_candidate_t *rows = g_new0(gai_wire_candidate_t, candidates->len);
    gai_wire_decision_t *result = NULL;
    gai_wire_error_t *failure = NULL;
    gboolean success = FALSE;
    if (!wire_policy(policy, &converted_policy, error)) goto cleanup;
    if (!wire_identifiers(observation->identifiers, &converted_observation.identifiers, &converted_observation.identifier_count, error)) goto cleanup;
    for (gsize i = 0; i < candidates->len; i++) {
        const gvm_asset_identity_candidate_t *candidate = g_ptr_array_index(candidates, i);
        if (!candidate) { fail(error, GVM_ASSET_IDENTITY_ERROR_INVALID_INPUT, "NULL candidate"); goto cleanup; }
        if (!wire_string(candidate->asset_key, &rows[i].asset_key, error)) goto cleanup;
        if (!wire_identifiers(candidate->identifiers, &rows[i].identifiers, &rows[i].identifier_count, error)) goto cleanup;
        rows[i].last_seen = (gai_wire_timestamp_t){candidate->last_seen.present != FALSE, candidate->last_seen.seconds, candidate->last_seen.nanoseconds};
    }
    gai_wire_status_t status = gai_wire_decide(&converted_observation, rows, candidates->len, &converted_policy, &result, &failure);
    success = wire_error(status, failure, error);
    if (success) *decision = copy_decision(result);
cleanup:
    gai_wire_error_free(failure);
    gai_wire_decision_free(result);
    free_input_identifiers(converted_observation.identifiers, converted_observation.identifier_count);
    for (gsize i = 0; i < candidates->len; i++) free_input_identifiers(rows[i].identifiers, rows[i].identifier_count);
    g_free(rows);
    g_free((gpointer)converted_policy.strong_order);
    g_free((gpointer)converted_policy.fuzzy);
    return success;
}
