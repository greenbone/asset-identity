// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

/*
#cgo pkg-config: glib-2.0
#cgo CFLAGS: -I${SRCDIR}/../include
#include "wire.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"sort"
	"time"
	"unsafe"

	"github.com/greenbone/asset-identity/identity"
)

type decoder struct{ remaining uint64 }

func (d *decoder) array(ptr unsafe.Pointer, count C.size_t, size, alignment uintptr) error {
	if uint64(count) > C.GAI_WIRE_MAX_ITEMS {
		return fmt.Errorf("array exceeds item limit")
	}
	bytes := uint64(count) * uint64(size)
	if bytes > d.remaining {
		return fmt.Errorf("input exceeds byte limit")
	}
	if count != 0 && (ptr == nil || uintptr(ptr)%alignment != 0) {
		return fmt.Errorf("invalid array pointer")
	}
	d.remaining -= bytes
	return nil
}

func (d *decoder) string(value C.gai_wire_string_t) (string, error) {
	if value.length > C.GAI_WIRE_MAX_STRING {
		return "", fmt.Errorf("string exceeds length limit")
	}
	if uint64(value.length) > d.remaining || (value.length != 0 && value.data == nil) {
		return "", fmt.Errorf("invalid string pointer or length")
	}
	d.remaining -= uint64(value.length)
	return string(unsafe.Slice((*byte)(unsafe.Pointer(value.data)), int(value.length))), nil
}

func identifierType(value C.gai_wire_identifier_type_t) (identity.IdentifierType, error) {
	switch value {
	case C.GAI_WIRE_GREENBONE_ID:
		return identity.TypeGreenboneID, nil
	case C.GAI_WIRE_AGENT_ID:
		return identity.TypeAgentID, nil
	case C.GAI_WIRE_MACHINE_ID:
		return identity.TypeMachineID, nil
	case C.GAI_WIRE_BIOS_UUID:
		return identity.TypeBIOSUUID, nil
	case C.GAI_WIRE_SSH_HOST_KEY:
		return identity.TypeSSHHostKey, nil
	case C.GAI_WIRE_TLS_PUBLIC_KEY_HASH:
		return identity.TypeTLSPublicKeyHash, nil
	case C.GAI_WIRE_CLOUD_IDENTIFIER:
		return identity.TypeCloudIdentifier, nil
	case C.GAI_WIRE_IP:
		return identity.TypeIP, nil
	case C.GAI_WIRE_FQDN:
		return identity.TypeFQDN, nil
	case C.GAI_WIRE_MAC:
		return identity.TypeMAC, nil
	case C.GAI_WIRE_HOSTNAME:
		return identity.TypeHostname, nil
	default:
		return "", fmt.Errorf("unknown identifier type %d", value)
	}
}

func encodedType(value identity.IdentifierType) C.gai_wire_identifier_type_t {
	for i := C.gai_wire_identifier_type_t(1); i <= C.GAI_WIRE_HOSTNAME; i++ {
		if typ, _ := identifierType(i); typ == value {
			return i
		}
	}
	panic("unsupported output identifier type")
}

func (d *decoder) scope(value C.gai_wire_scope_t) (identity.Scope, error) {
	if value.present > 1 {
		return nil, fmt.Errorf("invalid scope presence")
	}
	if value.present == 0 && (value.count != 0 || value.dimensions != nil) {
		return nil, fmt.Errorf("absent scope has dimensions")
	}
	if err := d.array(unsafe.Pointer(value.dimensions), value.count, C.sizeof_gai_wire_scope_dimension_t, unsafe.Alignof(C.gai_wire_scope_dimension_t{})); err != nil {
		return nil, err
	}
	if value.present == 0 {
		return nil, nil
	}
	scope := make(identity.Scope, int(value.count))
	for _, dimension := range unsafe.Slice(value.dimensions, int(value.count)) {
		name, err := d.string(dimension.name)
		if err != nil {
			return nil, err
		}
		content, err := d.string(dimension.value)
		if err != nil {
			return nil, err
		}
		if name == "" {
			return nil, fmt.Errorf("empty scope dimension name")
		}
		if _, exists := scope[name]; exists {
			return nil, fmt.Errorf("duplicate scope dimension %q", name)
		}
		scope[name] = content
	}
	return scope, nil
}

func (d *decoder) identifiers(ptr *C.gai_wire_identifier_t, count C.size_t) ([]identity.IdentifierValue, error) {
	if err := d.array(unsafe.Pointer(ptr), count, C.sizeof_gai_wire_identifier_t, unsafe.Alignof(C.gai_wire_identifier_t{})); err != nil {
		return nil, err
	}
	values := make([]identity.IdentifierValue, int(count))
	for i, value := range unsafe.Slice(ptr, int(count)) {
		typ, err := identifierType(value._type)
		if err != nil {
			return nil, err
		}
		text, err := d.string(value.value)
		if err != nil {
			return nil, err
		}
		scope, err := d.scope(value.scope)
		if err != nil {
			return nil, err
		}
		values[i] = identity.IdentifierValue{Type: typ, Value: text, Scope: scope}
	}
	return values, nil
}

func timestamp(value C.gai_wire_timestamp_t) (*time.Time, error) {
	if value.present > 1 {
		return nil, fmt.Errorf("invalid timestamp presence")
	}
	if value.present == 0 {
		if value.seconds != 0 || value.nanoseconds != 0 {
			return nil, fmt.Errorf("absent timestamp has a value")
		}
		return nil, nil
	}
	if value.nanoseconds >= 1000000000 || value.seconds < -62135596800 || value.seconds > 253402300799 {
		return nil, fmt.Errorf("invalid timestamp")
	}
	instant := time.Unix(int64(value.seconds), int64(value.nanoseconds)).UTC()
	return &instant, nil
}

func (d *decoder) candidates(ptr *C.gai_wire_candidate_t, count C.size_t) ([]identity.Candidate, error) {
	if err := d.array(unsafe.Pointer(ptr), count, C.sizeof_gai_wire_candidate_t, unsafe.Alignof(C.gai_wire_candidate_t{})); err != nil {
		return nil, err
	}
	values := make([]identity.Candidate, int(count))
	for i, value := range unsafe.Slice(ptr, int(count)) {
		key, err := d.string(value.asset_key)
		if err != nil {
			return nil, err
		}
		identifiers, err := d.identifiers(value.identifiers, value.identifier_count)
		if err != nil {
			return nil, err
		}
		seen, err := timestamp(value.last_seen)
		if err != nil {
			return nil, err
		}
		values[i] = identity.Candidate{AssetKey: key, Identifiers: identifiers, LastSeen: seen}
	}
	return values, nil
}

func (d *decoder) policy(value *C.gai_wire_policy_t) (identity.MatchPolicy, error) {
	var policy identity.MatchPolicy
	if err := d.array(unsafe.Pointer(value.strong_order), value.strong_count, C.sizeof_gai_wire_identifier_type_t, unsafe.Alignof(C.gai_wire_identifier_type_t(0))); err != nil {
		return policy, err
	}
	if err := d.array(unsafe.Pointer(value.fuzzy), value.fuzzy_count, C.sizeof_gai_wire_fuzzy_member_t, unsafe.Alignof(C.gai_wire_fuzzy_member_t{})); err != nil {
		return policy, err
	}
	for _, member := range unsafe.Slice(value.strong_order, int(value.strong_count)) {
		typ, err := identifierType(member)
		if err != nil {
			return policy, err
		}
		policy.StrongOrder = append(policy.StrongOrder, typ)
	}
	for _, member := range unsafe.Slice(value.fuzzy, int(value.fuzzy_count)) {
		typ, err := identifierType(member._type)
		if err != nil {
			return policy, err
		}
		policy.Fuzzy = append(policy.Fuzzy, identity.FuzzyMember{Type: typ, Weight: float64(member.weight)})
	}
	return policy, policy.Validate()
}

func allocate(count int, size uintptr) unsafe.Pointer {
	if count == 0 {
		return nil
	}
	ptr := C.calloc(C.size_t(count), C.size_t(size))
	if ptr == nil {
		panic("C allocation failed")
	}
	return ptr
}

func encodedString(value string) C.gai_wire_string_t {
	ptr := allocate(len(value)+1, 1)
	copy(unsafe.Slice((*byte)(ptr), len(value)), value)
	return C.gai_wire_string_t{data: (*C.char)(ptr), length: C.size_t(len(value))}
}

func encodedIndices(values []int) *C.size_t {
	ptr := (*C.size_t)(allocate(len(values), unsafe.Sizeof(C.size_t(0))))
	for i, value := range values {
		unsafe.Slice(ptr, len(values))[i] = C.size_t(value)
	}
	return ptr
}

func encodeIdentifiers(values []identity.IdentifierValue, ptr *C.gai_wire_identifier_t) {
	for i, value := range values {
		output := &unsafe.Slice(ptr, len(values))[i]
		output._type = encodedType(value.Type)
		output.value = encodedString(value.Value)
		if value.Scope == nil {
			continue
		}
		output.scope.present = 1
		output.scope.count = C.size_t(len(value.Scope))
		output.scope.dimensions = (*C.gai_wire_scope_dimension_t)(allocate(len(value.Scope), C.sizeof_gai_wire_scope_dimension_t))
		names := make([]string, 0, len(value.Scope))
		for name := range value.Scope {
			names = append(names, name)
		}
		sort.Strings(names)
		for j, name := range names {
			dimension := &unsafe.Slice(output.scope.dimensions, len(names))[j]
			dimension.name = encodedString(name)
			dimension.value = encodedString(value.Scope[name])
		}
	}
}

func encodeDecision(value identity.Decision, output *C.gai_wire_decision_t) {
	switch value.Action {
	case identity.ActionCreate:
		output.action = C.GAI_WIRE_CREATE
	case identity.ActionReuse:
		output.action = C.GAI_WIRE_REUSE
	case identity.ActionReview:
		output.action = C.GAI_WIRE_REVIEW
	case identity.ActionConflict:
		output.action = C.GAI_WIRE_CONFLICT
	default:
		panic("unsupported decision action")
	}
	switch value.Stage {
	case identity.StageNone:
		output.stage = C.GAI_WIRE_STAGE_NONE
	case identity.StageStrong:
		output.stage = C.GAI_WIRE_STAGE_STRONG
	case identity.StageFuzzy:
		output.stage = C.GAI_WIRE_STAGE_FUZZY
	default:
		panic("unsupported decision stage")
	}
	if value.NeedsNewKey {
		output.needs_new_key = 1
	}
	output.selected_key = encodedString(value.SelectedKey)
	if value.SelectedIndex != nil {
		output.has_selected_index = 1
		output.selected_index = C.size_t(*value.SelectedIndex)
	}
	output.potential_merge_count = C.size_t(len(value.PotentialMergeIndices))
	output.potential_merge_indices = encodedIndices(value.PotentialMergeIndices)
	output.potential_merge_keys = (*C.gai_wire_string_t)(allocate(len(value.PotentialMergeKeys), C.sizeof_gai_wire_string_t))
	for i, key := range value.PotentialMergeKeys {
		unsafe.Slice(output.potential_merge_keys, len(value.PotentialMergeKeys))[i] = encodedString(key)
	}
	if value.Conflict != nil {
		conflict := (*C.gai_wire_conflict_t)(allocate(1, C.sizeof_gai_wire_conflict_t))
		output.conflict = conflict
		conflict.reason = encodedString(value.Conflict.Reason)
		conflict.candidate_count = C.size_t(len(value.Conflict.CandidateIndices))
		conflict.candidate_indices = encodedIndices(value.Conflict.CandidateIndices)
		conflict.identifier_count = C.size_t(len(value.Conflict.Identifiers))
		conflict.identifiers = (*C.gai_wire_identifier_t)(allocate(len(value.Conflict.Identifiers), C.sizeof_gai_wire_identifier_t))
		encodeIdentifiers(value.Conflict.Identifiers, conflict.identifiers)
	}
}

func reportError(slot **C.gai_wire_error_t, message string) {
	if slot == nil {
		return
	}
	output := (*C.gai_wire_error_t)(C.calloc(1, C.sizeof_gai_wire_error_t))
	if output == nil {
		return
	}
	ptr := C.calloc(C.size_t(len(message)+1), 1)
	if ptr == nil {
		C.free(unsafe.Pointer(output))
		return
	}
	copy(unsafe.Slice((*byte)(ptr), len(message)), message)
	output.message = C.gai_wire_string_t{data: (*C.char)(ptr), length: C.size_t(len(message))}
	*slot = output
}

//export gvmAssetIdentityDecide
func gvmAssetIdentityDecide(observation *C.gai_wire_observation_t, candidates *C.gai_wire_candidate_t, count C.size_t, policy *C.gai_wire_policy_t, decision **C.gai_wire_decision_t, failure **C.gai_wire_error_t) (status C.gai_wire_status_t) {
	if failure != nil {
		*failure = nil
	}
	if decision != nil {
		*decision = nil
	}
	var output *C.gai_wire_decision_t
	defer func() {
		if recover() != nil {
			C.gai_wire_decision_free(output)
			if decision != nil {
				*decision = nil
			}
			reportError(failure, "internal library failure")
			status = C.GAI_WIRE_INTERNAL_ERROR
		}
	}()
	if observation == nil || policy == nil || decision == nil {
		reportError(failure, "observation, policy and decision output are required")
		return C.GAI_WIRE_INVALID_INPUT
	}
	d := decoder{remaining: C.GAI_WIRE_MAX_INPUT_BYTES}
	convertedPolicy, err := d.policy(policy)
	if err != nil {
		reportError(failure, err.Error())
		return C.GAI_WIRE_INVALID_POLICY
	}
	identifiers, err := d.identifiers(observation.identifiers, observation.identifier_count)
	if err != nil {
		reportError(failure, err.Error())
		return C.GAI_WIRE_INVALID_INPUT
	}
	convertedCandidates, err := d.candidates(candidates, count)
	if err != nil {
		reportError(failure, err.Error())
		return C.GAI_WIRE_INVALID_INPUT
	}
	value, err := identity.Decide(identity.Observation{Identifiers: identifiers}, convertedCandidates, convertedPolicy)
	if err != nil {
		reportError(failure, err.Error())
		if errors.Is(err, identity.ErrInvalidMatchPolicy) || errors.Is(err, identity.ErrUnresolvedMatchingRule) {
			return C.GAI_WIRE_INVALID_POLICY
		}
		return C.GAI_WIRE_INVALID_INPUT
	}
	output = (*C.gai_wire_decision_t)(allocate(1, C.sizeof_gai_wire_decision_t))
	encodeDecision(value, output)
	*decision = output
	return C.GAI_WIRE_OK
}

//export gvmAssetIdentityDefaultPolicy
func gvmAssetIdentityDefaultPolicy(policy **C.gai_wire_policy_t, failure **C.gai_wire_error_t) (status C.gai_wire_status_t) {
	if failure != nil {
		*failure = nil
	}
	if policy != nil {
		*policy = nil
	}
	var output *C.gai_wire_policy_t
	defer func() {
		if recover() != nil {
			C.gai_wire_policy_free(output)
			if policy != nil {
				*policy = nil
			}
			reportError(failure, "internal library failure")
			status = C.GAI_WIRE_INTERNAL_ERROR
		}
	}()
	if policy == nil {
		reportError(failure, "policy output is required")
		return C.GAI_WIRE_INVALID_INPUT
	}
	value := identity.GreenboneMatchPolicy()
	output = (*C.gai_wire_policy_t)(allocate(1, C.sizeof_gai_wire_policy_t))
	output.strong_count = C.size_t(len(value.StrongOrder))
	output.strong_order = (*C.gai_wire_identifier_type_t)(allocate(len(value.StrongOrder), C.sizeof_gai_wire_identifier_type_t))
	for i, typ := range value.StrongOrder {
		unsafe.Slice(output.strong_order, len(value.StrongOrder))[i] = encodedType(typ)
	}
	output.fuzzy_count = C.size_t(len(value.Fuzzy))
	output.fuzzy = (*C.gai_wire_fuzzy_member_t)(allocate(len(value.Fuzzy), C.sizeof_gai_wire_fuzzy_member_t))
	for i, member := range value.Fuzzy {
		unsafe.Slice(output.fuzzy, len(value.Fuzzy))[i] = C.gai_wire_fuzzy_member_t{_type: encodedType(member.Type), weight: C.double(member.Weight)}
	}
	*policy = output
	return C.GAI_WIRE_OK
}
