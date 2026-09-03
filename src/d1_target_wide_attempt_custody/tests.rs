use std::fs;

use serde_json::{Value, json};

use super::*;
use crate::d1_dml_identity_claimant::D1DmlIdentityNamespace;
#[cfg(target_os = "linux")]
use crate::d1_migration_lease::acquire_d1_target_mutation_guard_for_test;
use crate::d1_target::normalize_d1_target;
use crate::d1_target_wide_mutation::d1_target_wide_intended_plan;

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
    }
}

fn rename_plan(name: &str, reason: Option<&str>) -> D1TargetWideIntendedPlan {
    let target = target();
    d1_target_wide_intended_plan(
        "d1_rename_database",
        "validate_d1_database_rename",
        json!({"account_id": target.account_id, "database_id": target.database_id}),
        json!({"new_name": name}),
        reason.map(str::to_string),
        &target.target_key_sha256(),
        "apply_d1_database_patch",
        json!({"method": "PATCH", "path": "/synthetic", "body": {"name": name}}),
    )
}

fn delete_plan(reason: Option<&str>) -> D1TargetWideIntendedPlan {
    let target = target();
    d1_target_wide_intended_plan(
        "d1_delete_database",
        "validate_d1_database_delete",
        json!({"account_id": target.account_id, "database_id": target.database_id}),
        json!({"delete_database": true}),
        reason.map(str::to_string),
        &target.target_key_sha256(),
        "apply_d1_database_delete",
        json!({"method": "DELETE", "path": "/synthetic"}),
    )
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
    assert_eq!(replay.receipt().provider_calls, 0);
    assert_eq!(replay.receipt().provider_mutations, 0);
    assert!(!replay.receipt().automatic_retry_permitted);

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
