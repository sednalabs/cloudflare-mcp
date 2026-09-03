#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::*;
use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;
#[cfg(target_os = "linux")]
use crate::d1_migration_lease::{
    TEST_D1_DML_CUSTODY_AUTHORITY_SHA256, TEST_D1_DML_CUSTODY_GENERATION,
    acquire_d1_target_mutation_guard_at, acquire_d1_target_mutation_guard_for_test,
    provision_d1_dml_custody_at,
};
use crate::d1_target::normalize_d1_target;
use crate::d1_target_wide_mutation::{
    rederive_d1_target_wide_intended_plan, target_wide_plan_sha256,
};

const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
const OPERATION_ID: &str = "target-operation-0001";
const ATTEMPT_ID: &str = "target-attempt-000001";
const PROVIDER_ID: &str = "target-provider-00001";

fn target() -> D1TargetIdentity {
    normalize_d1_target("acct-1", DATABASE_ID).expect("canonical target")
}

fn ids() -> D1DmlAttemptIdentities<'static> {
    D1DmlAttemptIdentities {
        operation_id: OPERATION_ID,
        execution_attempt_id: ATTEMPT_ID,
        provider_request_id: PROVIDER_ID,
        custody_generation_sha256: crate::d1_dml_attempt_custody::TEST_CUSTODY_GENERATION_SHA256,
    }
}

fn rename_plan(name: &str, reason: Option<&str>) -> D1TargetWideIntendedPlan {
    rename_plan_for(&target(), name, reason)
}

fn rename_plan_for(
    target: &D1TargetIdentity,
    name: &str,
    reason: Option<&str>,
) -> D1TargetWideIntendedPlan {
    rederive_d1_target_wide_intended_plan(
        target,
        "d1_rename_database",
        &json!({"new_name": name}),
        reason,
    )
    .expect("canonical rename plan")
}

fn delete_plan(reason: Option<&str>) -> D1TargetWideIntendedPlan {
    rederive_d1_target_wide_intended_plan(
        &target(),
        "d1_delete_database",
        &json!({"delete_database": true}),
        reason,
    )
    .expect("canonical delete plan")
}

fn rebind_detached_plan(plan: &mut D1TargetWideIntendedPlan) {
    plan.plan_sha256 = target_wide_plan_sha256(&plan.plan);
    plan.consent_binding.plan = plan.plan.clone();
    plan.consent_binding.intended_plan_sha256 = plan.plan_sha256.clone();
}

#[cfg(target_os = "linux")]
fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    use std::os::unix::fs::PermissionsExt;

    fn visit(root: &Path, current: &Path, entries: &mut BTreeMap<PathBuf, (u32, Vec<u8>)>) {
        let mut children = fs::read_dir(current)
            .expect("read fixture directory")
            .map(|entry| entry.expect("read fixture entry").path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            let relative = child.strip_prefix(root).expect("relative fixture path");
            let metadata = fs::symlink_metadata(&child).expect("fixture metadata");
            let mode = metadata.permissions().mode() & 0o7777;
            if metadata.is_dir() {
                entries.insert(relative.to_path_buf(), (mode, Vec::new()));
                visit(root, &child, entries);
            } else {
                entries.insert(
                    relative.to_path_buf(),
                    (mode, fs::read(&child).expect("read fixture file")),
                );
            }
        }
    }

    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

#[cfg(target_os = "linux")]
fn plant_hostile_attempt_shard(root: &Path, target: &D1TargetIdentity, marker: &[u8]) {
    use std::os::unix::fs::PermissionsExt;

    let shard = root
        .join(format!(
            "d1-migration-target-{}",
            target.target_key_sha256()
        ))
        .join("dml-custody-v1")
        .join("attempt")
        .join("ff")
        .join("ff");
    fs::create_dir_all(&shard).expect("create hostile shard parents");
    let mut current = shard.as_path();
    while current != root {
        fs::set_permissions(current, fs::Permissions::from_mode(0o700))
            .expect("secure hostile shard parent");
        current = current.parent().expect("hostile shard parent");
    }
    let path = shard.join(format!("{}.json", "f".repeat(64)));
    fs::write(&path, marker).expect("write hostile shard");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure hostile shard");
}

fn prepare(plan: &D1TargetWideIntendedPlan) -> D1TargetWidePreparedProduct {
    prepare_d1_target_wide_attempt(&target(), plan, &plan.confirmation_token(), ids(), None)
        .expect("Prepared product")
}

fn classification(
    result: Result<D1TargetWidePreparedProduct, D1TargetWidePreparedError>,
) -> D1TargetWidePreparedClassification {
    result.expect_err("fixture must fail closed").classification
}

fn assert_no_terminal_authority(
    product: &D1TargetWidePreparedProduct,
    dispatch_status: D1TargetWideDispatchStatus,
) {
    assert_eq!(
        product.receipt().causal_authority,
        D1TargetWideCausalAuthority {
            dispatch_status,
            state_observation: D1TargetWideStateObservationStatus::NotObserved,
            causality: D1TargetWideCausalityStatus::Unproven,
            current_state_can_authorize: false,
            terminalization_authorized: false,
        }
    );
}

fn state(bytes: &[u8]) -> D1TargetWideAttemptState {
    serde_json::from_slice(bytes).expect("typed target-wide state")
}

fn unchecked_bytes(state: &D1TargetWideAttemptState) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(state).expect("serialize state");
    bytes.push(b'\n');
    bytes
}

#[test]
fn prepared_product_binds_complete_consent_and_distinct_opaque_identities() {
    let plan = rename_plan("synthetic-name", Some("reviewed reason"));
    let prepared = prepare(&plan);
    let replay = prepare_d1_target_wide_attempt(
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        Some(prepared.state_bytes()),
    )
    .expect("exact replay");
    assert_eq!(replay.state_bytes(), prepared.state_bytes());
    assert!(replay.receipt().exact_replay);
    assert_eq!(replay.receipt().phase, D1DmlAttemptPhase::Prepared);
    assert_eq!(
        replay.receipt().consent_version,
        TARGET_WIDE_CONSENT_VERSION
    );
    assert_eq!(
        replay.receipt().operation_version,
        TARGET_WIDE_OPERATION_VERSION
    );
    assert_eq!(replay.receipt().provider_calls, 0);
    assert_eq!(replay.receipt().provider_mutations, Some(0));
    assert!(!replay.receipt().automatic_retry_permitted);
    assert_no_terminal_authority(&replay, D1TargetWideDispatchStatus::NotReserved);

    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            "cf-d1-target-wide-wrong",
            ids(),
            None,
        )),
        D1TargetWidePreparedClassification::ConsentMismatch
    );
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            D1DmlAttemptIdentities {
                provider_request_id: OPERATION_ID,
                ..ids()
            },
            None,
        )),
        D1TargetWidePreparedClassification::OpaqueIdentityDuplicate
    );
}

#[test]
fn exact_prepared_dispatch_and_acknowledgement_transitions_are_monotonic() {
    let plan = rename_plan("synthetic-name", Some("reviewed reason"));
    let prepared = prepare(&plan);
    let reserved = prepare_d1_target_wide_dispatch_reservation_cas(
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        prepared.state_bytes(),
    )
    .expect("one dispatch reservation");
    assert_eq!(
        reserved.receipt().phase,
        D1DmlAttemptPhase::DispatchReserved
    );
    assert_eq!(reserved.receipt().dispatch_reservations, 1);
    assert_no_terminal_authority(
        &reserved,
        D1TargetWideDispatchStatus::ReservedWithoutDurableCallEvidence,
    );
    validate_d1_target_wide_attempt_successor(prepared.state_bytes(), reserved.state_bytes())
        .expect("Prepared to DispatchReserved CAS");
    assert!(
        prepare_d1_target_wide_dispatch_reservation_cas(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved.state_bytes(),
        )
        .is_err(),
        "a reserved attempt cannot reserve again"
    );

    let acknowledged = record_d1_target_wide_acknowledgement(
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        reserved.state_bytes(),
        D1DatabaseMutationLifecycle::succeeded(200),
        &"a".repeat(64),
        127,
    )
    .expect("acknowledgement product");
    assert_eq!(
        acknowledged.receipt().post_provider_outcome,
        Some(D1TargetWidePostProviderOutcome::Acknowledged)
    );
    assert_eq!(acknowledged.receipt().provider_calls, 1);
    assert_eq!(acknowledged.receipt().provider_mutations, Some(1));
    assert_no_terminal_authority(
        &acknowledged,
        D1TargetWideDispatchStatus::AuthenticatedAcknowledgement,
    );
    validate_d1_target_wide_attempt_successor(reserved.state_bytes(), acknowledged.state_bytes())
        .expect("DispatchReserved to acknowledged custody CAS");
    assert!(
        validate_d1_target_wide_attempt_successor(
            acknowledged.state_bytes(),
            acknowledged.state_bytes(),
        )
        .is_err(),
        "exact replay is not a second transition"
    );
    let replay = restore_bound_d1_target_wide_attempt(
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        acknowledged.state_bytes(),
    )
    .expect("bound post-provider replay");
    assert!(replay.receipt().exact_replay);
}

#[test]
fn response_loss_and_predispatch_failure_become_closed_reconciliation_products() {
    let plan = delete_plan(Some("reviewed reason"));
    let prepared = prepare(&plan);
    let reserved = prepare_d1_target_wide_dispatch_reservation_cas(
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        prepared.state_bytes(),
    )
    .expect("one dispatch reservation");
    for (lifecycle, dispatch_status) in [
        (
            D1DatabaseMutationLifecycle::pre_dispatch(),
            D1TargetWideDispatchStatus::RejectedBeforeApply,
        ),
        (
            D1DatabaseMutationLifecycle::attempted_without_response(),
            D1TargetWideDispatchStatus::UncertainAfterDispatch,
        ),
        (
            D1DatabaseMutationLifecycle::body_read_failed(200, true),
            D1TargetWideDispatchStatus::UncertainAfterDispatch,
        ),
    ] {
        let response_sha = (lifecycle.body_stage == "partially_read").then(|| "b".repeat(64));
        let response_size = response_sha.as_ref().map(|_| 17);
        let product = record_d1_target_wide_reconciliation_required(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            reserved.state_bytes(),
            lifecycle,
            response_sha.as_deref(),
            response_size,
            "cloudflare.synthetic_failure",
        )
        .expect("closed reconciliation product");
        assert_eq!(
            product.receipt().post_provider_outcome,
            Some(D1TargetWidePostProviderOutcome::ReconciliationRequired)
        );
        assert!(!product.receipt().automatic_retry_permitted);
        assert_no_terminal_authority(&product, dispatch_status);
        validate_d1_target_wide_attempt_successor(reserved.state_bytes(), product.state_bytes())
            .expect("post-provider reconciliation CAS");
    }
}

#[test]
fn target_final_state_negative_matrix_never_creates_causal_or_terminal_authority() {
    let rename = rename_plan("already-matching-name", Some("reviewed reason"));
    let rename_prepared = prepare(&rename);
    let rename_reserved = prepare_d1_target_wide_dispatch_reservation_cas(
        &target(),
        &rename,
        &rename.confirmation_token(),
        ids(),
        rename_prepared.state_bytes(),
    )
    .expect("rename reservation");
    let uncertain = record_d1_target_wide_reconciliation_required(
        &target(),
        &rename,
        &rename.confirmation_token(),
        ids(),
        rename_reserved.state_bytes(),
        D1DatabaseMutationLifecycle::attempted_without_response(),
        None,
        None,
        "cloudflare.synthetic_transport_loss",
    )
    .expect("uncertain post-dispatch custody");

    let delete = delete_plan(Some("reviewed reason"));
    let delete_prepared = prepare(&delete);
    let delete_reserved = prepare_d1_target_wide_dispatch_reservation_cas(
        &target(),
        &delete,
        &delete.confirmation_token(),
        ids(),
        delete_prepared.state_bytes(),
    )
    .expect("delete reservation");

    // The named final-state scenarios are deliberately not inputs to this
    // boundary. A pre-existing rename match, an already-absent delete target,
    // or an intervening actor therefore cannot change retained custody into
    // proof that this attempt caused the state.
    for (scenario, product, dispatch_status) in [
        (
            "pre_existing_matching_rename",
            &rename_reserved,
            D1TargetWideDispatchStatus::ReservedWithoutDurableCallEvidence,
        ),
        (
            "already_absent_delete",
            &delete_reserved,
            D1TargetWideDispatchStatus::ReservedWithoutDurableCallEvidence,
        ),
        (
            "intervening_actor",
            &uncertain,
            D1TargetWideDispatchStatus::UncertainAfterDispatch,
        ),
        (
            "no_call_reservation",
            &rename_reserved,
            D1TargetWideDispatchStatus::ReservedWithoutDurableCallEvidence,
        ),
        (
            "uncertain_outcome",
            &uncertain,
            D1TargetWideDispatchStatus::UncertainAfterDispatch,
        ),
    ] {
        assert_no_terminal_authority(product, dispatch_status);
        assert!(
            matches!(
                product.receipt().phase,
                D1DmlAttemptPhase::DispatchReserved | D1DmlAttemptPhase::ReconciliationRequired
            ),
            "{scenario} must retain unresolved custody"
        );
    }

    for (product, plan) in [(&rename_reserved, &rename), (&uncertain, &rename)] {
        let replay = restore_bound_d1_target_wide_attempt(
            &target(),
            plan,
            &plan.confirmation_token(),
            ids(),
            product.state_bytes(),
        )
        .expect("exact retained replay");
        assert_eq!(replay.state_bytes(), product.state_bytes());
        assert!(replay.receipt().exact_replay);
        assert!(!replay.receipt().causal_authority.terminalization_authorized);
        assert_eq!(
            replay.receipt().provider_calls,
            product.receipt().provider_calls
        );
    }
}

#[test]
fn target_wide_terminal_records_and_phases_are_outside_the_closed_state_schema() {
    let plan = rename_plan("synthetic-name", Some("reviewed reason"));
    let prepared = prepare(&plan);
    let reserved = prepare_d1_target_wide_dispatch_reservation_cas(
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        prepared.state_bytes(),
    )
    .expect("reservation");

    let mut terminal_record = serde_json::to_value(state(reserved.state_bytes())).expect("state");
    terminal_record["terminal"] = json!({"outcome": "applied"});
    let mut terminal_record_bytes = serde_json::to_vec(&terminal_record).expect("terminal record");
    terminal_record_bytes.push(b'\n');
    assert_eq!(
        classification(restore_bound_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            &terminal_record_bytes,
        )),
        D1TargetWidePreparedClassification::RestoredStateMalformed
    );

    for phase in [
        D1DmlAttemptPhase::TerminalApplied,
        D1DmlAttemptPhase::TerminalNotApplied,
    ] {
        let mut terminal_phase = state(reserved.state_bytes());
        terminal_phase.phase = phase;
        assert_eq!(
            classification(restore_bound_d1_target_wide_attempt(
                &target(),
                &plan,
                &plan.confirmation_token(),
                ids(),
                &unchecked_bytes(&terminal_phase),
            )),
            D1TargetWidePreparedClassification::RestoredStateContradictory
        );
    }
}

#[test]
fn detached_self_consistent_plan_and_token_never_replace_canonical_rederivation() {
    let canonical = rename_plan("synthetic-name", Some("reviewed reason"));
    let mut variants = Vec::new();

    let mut operation = canonical.clone();
    operation.consent_binding.operation = "d1_delete_database";
    variants.push(("operation", operation));

    let mut consent_version = canonical.clone();
    consent_version.consent_binding.consent_version += 1;
    variants.push(("consent version", consent_version));

    let mut operation_version = canonical.clone();
    operation_version.consent_binding.operation_version += 1;
    operation_version.plan.steps[0].target["operation_version"] =
        json!(TARGET_WIDE_OPERATION_VERSION + 1);
    rebind_detached_plan(&mut operation_version);
    variants.push(("operation version", operation_version));

    let mut validation_action = canonical.clone();
    validation_action.plan.steps[0].action = "validate_d1_database_delete";
    rebind_detached_plan(&mut validation_action);
    variants.push(("validation action", validation_action));

    let mut validation_target = canonical.clone();
    validation_target.plan.steps[0].target["normalized_target"]["account_id"] =
        json!("acct-detached");
    rebind_detached_plan(&mut validation_target);
    variants.push(("validation target", validation_target));

    let mut consent_target = canonical.clone();
    consent_target.consent_binding.normalized_target["account_id"] = json!("acct-detached");
    variants.push(("consent target", consent_target));

    let mut requested_change = canonical.clone();
    requested_change.consent_binding.requested_change = json!({"new_name": "detached-name"});
    variants.push(("requested change", requested_change));

    let mut reason = canonical.clone();
    reason.consent_binding.reason = Some("detached reason".to_string());
    variants.push(("reason", reason));

    let mut provider_method = canonical.clone();
    provider_method.plan.steps[5].target["method"] = json!("DELETE");
    rebind_detached_plan(&mut provider_method);
    variants.push(("provider method", provider_method));

    let mut provider_path = canonical.clone();
    provider_path.plan.steps[5].target["path"] = json!("/detached");
    rebind_detached_plan(&mut provider_path);
    variants.push(("provider path", provider_path));

    let mut provider_body = canonical.clone();
    provider_body.plan.steps[5].target["body"] = json!({"name": "detached-name"});
    rebind_detached_plan(&mut provider_body);
    variants.push(("provider body", provider_body));

    for (label, detached) in variants {
        assert_eq!(
            classification(prepare_d1_target_wide_attempt(
                &target(),
                &detached,
                &detached.confirmation_token(),
                ids(),
                None,
            )),
            D1TargetWidePreparedClassification::IntendedPlanInvalid,
            "{label} must not become authority by recomputing its digest and token"
        );
    }
}

#[test]
fn changed_target_operation_change_reason_plan_or_identity_conflicts_with_restored_state() {
    let plan = rename_plan("synthetic-name", Some("reviewed reason"));
    let prepared = prepare(&plan);
    let variants = [
        rename_plan("different-name", Some("reviewed reason")),
        rename_plan("synthetic-name", Some("different reason")),
        delete_plan(Some("reviewed reason")),
    ];
    for variant in variants {
        assert_eq!(
            classification(prepare_d1_target_wide_attempt(
                &target(),
                &variant,
                &variant.confirmation_token(),
                ids(),
                Some(prepared.state_bytes()),
            )),
            D1TargetWidePreparedClassification::ReplayConflict
        );
    }
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            D1DmlAttemptIdentities {
                operation_id: "target-operation-0002",
                ..ids()
            },
            Some(prepared.state_bytes()),
        )),
        D1TargetWidePreparedClassification::ReplayConflict
    );
    let other = normalize_d1_target("acct-2", DATABASE_ID).expect("other target");
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &other,
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(prepared.state_bytes()),
        )),
        D1TargetWidePreparedClassification::IntendedPlanInvalid
    );
}

#[test]
fn malformed_noncanonical_unsupported_and_contradictory_restores_fail_closed() {
    let plan = rename_plan("synthetic-name", None);
    let prepared = prepare(&plan);
    for malformed in [
        b"null\n".as_slice(),
        b"[]\n".as_slice(),
        b"true\n".as_slice(),
        b"7\n".as_slice(),
        b"\"text\"\n".as_slice(),
    ] {
        assert_eq!(
            classification(prepare_d1_target_wide_attempt(
                &target(),
                &plan,
                &plan.confirmation_token(),
                ids(),
                Some(malformed),
            )),
            D1TargetWidePreparedClassification::RestoredStateMalformed
        );
    }
    let mut unknown = serde_json::to_value(state(prepared.state_bytes())).expect("state value");
    unknown["unknown"] = json!(true);
    let mut unknown_bytes = serde_json::to_vec(&unknown).expect("unknown bytes");
    unknown_bytes.push(b'\n');
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(&unknown_bytes),
        )),
        D1TargetWidePreparedClassification::RestoredStateMalformed
    );
    let missing = b"{\"version\":1}\n";
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(missing),
        )),
        D1TargetWidePreparedClassification::RestoredStateMalformed
    );
    let duplicate = prepared
        .state_bytes()
        .strip_suffix(b"}\n")
        .expect("canonical object")
        .iter()
        .copied()
        .chain(b",\"version\":1}\n".iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(&duplicate),
        )),
        D1TargetWidePreparedClassification::RestoredStateMalformed
    );
    let oversized = vec![b' '; D1_DML_ATTEMPT_STATE_BYTE_CAP + 1];
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(&oversized),
        )),
        D1TargetWidePreparedClassification::RestoredStateTooLarge
    );
    let mut pretty = serde_json::to_vec_pretty(&state(prepared.state_bytes())).expect("pretty");
    pretty.push(b'\n');
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(&pretty),
        )),
        D1TargetWidePreparedClassification::RestoredStateNonCanonical
    );
    let mut unsupported = state(prepared.state_bytes());
    unsupported.version += 1;
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(&unchecked_bytes(&unsupported)),
        )),
        D1TargetWidePreparedClassification::RestoredStateUnsupported
    );
    let mut unsupported_consent = state(prepared.state_bytes());
    unsupported_consent.consent_version += 1;
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(&unchecked_bytes(&unsupported_consent)),
        )),
        D1TargetWidePreparedClassification::RestoredStateUnsupported
    );
    let mut unsupported_operation = state(prepared.state_bytes());
    unsupported_operation.operation_version += 1;
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(&unchecked_bytes(&unsupported_operation)),
        )),
        D1TargetWidePreparedClassification::RestoredStateUnsupported
    );
    let mut contradictory = state(prepared.state_bytes());
    contradictory.phase = D1DmlAttemptPhase::DispatchReserved;
    assert_eq!(
        classification(prepare_d1_target_wide_attempt(
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            Some(&unchecked_bytes(&contradictory)),
        )),
        D1TargetWidePreparedClassification::RestoredStateContradictory
    );
}

#[test]
fn outward_receipt_is_aggregate_safe() {
    let plan = rename_plan(
        "private-looking-name.example",
        Some("private-looking reason"),
    );
    let prepared = prepare(&plan);
    let receipt = serde_json::to_string(prepared.receipt()).expect("receipt JSON");
    for private in [
        "acct-1",
        DATABASE_ID,
        "private-looking-name.example",
        "private-looking reason",
        OPERATION_ID,
        ATTEMPT_ID,
        PROVIDER_ID,
        &plan.confirmation_token(),
    ] {
        assert!(!receipt.contains(private));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn local_prepared_install_converges_exact_partial_and_complete_state() {
    let plan = rename_plan("synthetic-name", Some("reviewed reason"));
    let (root, guard) =
        acquire_d1_target_mutation_guard_for_test("prepared-converges", "d1_rename_database");
    guard
        .ensure_target_wide_d1_dml_custody_layout()
        .expect("layout");
    let set = derive_claimant_set(&target(), &plan, ids()).expect("claimant set");
    let pending = set.pending(D1DmlIdentityNamespace::Operation);
    guard
        .create_d1_dml_identity_claimant(
            D1DmlIdentityNamespace::Operation,
            set.identity_sha256(D1DmlIdentityNamespace::Operation),
            pending.state_bytes(),
        )
        .expect("one exact partial claimant");

    let first = install_d1_target_wide_prepared_custody(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
    )
    .expect("partial custody converges");
    assert_eq!(first.receipt().phase, D1DmlAttemptPhase::Prepared);
    assert!(first.receipt().exact_replay);
    let second = install_d1_target_wide_prepared_custody(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
    )
    .expect("exact complete replay converges");
    assert_eq!(second.state_bytes(), first.state_bytes());
    let audit = guard
        .audit_d1_dml_custody_complete()
        .expect("complete audit recognizes strict target-wide Prepared custody");
    assert_eq!(audit.attempt_count, 1);
    assert_eq!(audit.attempt_phase_counts.prepared, 1);
    assert_eq!(audit.matched_claimant_set_count, 1);
    assert!(audit.reconciliation_required);
    drop(guard);
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[cfg(target_os = "linux")]
#[test]
fn local_prepared_install_converges_attempt_first_partial_state() {
    let plan = delete_plan(Some("reviewed reason"));
    let prepared = prepare(&plan);
    let binding = &prepared.receipt().attempt_binding_sha256;
    let (root, guard) =
        acquire_d1_target_mutation_guard_for_test("prepared-attempt-first", "d1_delete_database");
    guard
        .ensure_target_wide_d1_dml_custody_layout()
        .expect("layout");
    guard
        .create_d1_dml_attempt_state(binding, prepared.state_bytes())
        .expect("install exact attempt before claimant set");

    let converged = install_d1_target_wide_prepared_custody(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
    )
    .expect("attempt-first partial custody converges");
    assert_eq!(converged.state_bytes(), prepared.state_bytes());
    let audit = guard
        .audit_d1_dml_custody_complete()
        .expect("attempt-first complete audit");
    assert_eq!(audit.attempt_count, 1);
    assert_eq!(audit.matched_claimant_set_count, 1);
    assert_eq!(audit.unmatched_attempt_count, 0);
    assert!(audit.reconciliation_required);
    drop(guard);
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[cfg(target_os = "linux")]
#[test]
fn guard_target_mismatch_precedes_layout_and_preserves_hostile_namespaces_exactly() {
    let target_a = target();
    let target_b = normalize_d1_target("acct-2", "223e4567-e89b-42d3-a456-426614174000")
        .expect("second canonical target");
    let plan_b = rename_plan_for(&target_b, "target-b-name", Some("reviewed target B"));
    let (root, guard_a) =
        acquire_d1_target_mutation_guard_for_test("prepared-guard-mismatch", "d1_rename_database");
    provision_d1_dml_custody_at(
        root.clone(),
        &target_b.account_id,
        &target_b.database_id,
        TEST_D1_DML_CUSTODY_GENERATION,
        TEST_D1_DML_CUSTODY_AUTHORITY_SHA256,
    )
    .expect("explicitly provision independent target B custody");
    let guard_b = acquire_d1_target_mutation_guard_at(
        root.clone(),
        "d1_rename_database",
        &target_b.account_id,
        &target_b.database_id,
    )
    .expect("acquire independent target B guard");
    plant_hostile_attempt_shard(&root, &target_a, b"hostile target A\n");
    plant_hostile_attempt_shard(&root, &target_b, b"hostile target B\n");
    let before = snapshot_tree(&root);

    let error = install_d1_target_wide_prepared_custody(
        &guard_a,
        &target_b,
        &plan_b,
        &plan_b.confirmation_token(),
        ids(),
    )
    .expect_err("guard A must reject target B before any custody read or write")
    .structured_content
    .expect("structured guard mismatch");
    assert_eq!(
        error["error"]["code"],
        json!("d1.target_guard_target_mismatch")
    );
    assert_eq!(error["provider_calls"], json!(0));
    assert_eq!(error["provider_mutations"], json!(0));
    assert_eq!(error["local_mutations"], json!(0));
    assert_eq!(snapshot_tree(&root), before);

    drop((guard_a, guard_b));
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[cfg(target_os = "linux")]
#[test]
fn conflicting_claimant_and_unsafe_attempt_mode_fail_closed() {
    use std::os::unix::fs::PermissionsExt;

    let plan = rename_plan("synthetic-name", Some("reviewed reason"));
    let (root, guard) =
        acquire_d1_target_mutation_guard_for_test("prepared-conflict", "d1_rename_database");
    let prepared = install_d1_target_wide_prepared_custody(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
    )
    .expect("install baseline Prepared custody");

    let conflicting = rename_plan("different-name", Some("reviewed reason"));
    let error = install_d1_target_wide_prepared_custody(
        &guard,
        &target(),
        &conflicting,
        &conflicting.confirmation_token(),
        ids(),
    )
    .expect_err("same operation identity with changed intent must conflict");
    assert_eq!(
        error.structured_content.expect("structured")["provider_calls"],
        json!(0)
    );

    let binding = &prepared.receipt().attempt_binding_sha256;
    let attempt_path = root
        .join(format!(
            "d1-migration-target-{}",
            target().target_key_sha256()
        ))
        .join("dml-custody-v1")
        .join("attempt")
        .join(&binding[..2])
        .join(&binding[2..4])
        .join(format!("{binding}.json"));
    fs::set_permissions(&attempt_path, fs::Permissions::from_mode(0o644))
        .expect("make attempt mode unsafe");
    assert!(
        guard.read_d1_dml_attempt_state(binding).is_err(),
        "unsafe physical mode must block exact readback"
    );
    drop(guard);
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn strict_inspector_distinguishes_target_wide_from_row_dml_shape() {
    let plan = delete_plan(None);
    let prepared = prepare(&plan);
    let inspected = inspect_d1_target_wide_attempt_state(prepared.state_bytes())
        .expect("strict target-wide inspection");
    assert_eq!(inspected.receipt().target_operation, "d1_delete_database");
    assert!(inspect_d1_target_wide_attempt_state(b"[]\n").is_err());
    let value: Value = serde_json::from_slice(prepared.state_bytes()).expect("state JSON");
    assert_eq!(value["phase"], json!("prepared"));
}
