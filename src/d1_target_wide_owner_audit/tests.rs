#[cfg(target_os = "linux")]
use std::fs;

use serde_json::json;

use super::*;
use crate::d1_dml_attempt_custody::{
    D1DmlAttemptIdentities, D1DmlAttemptPhase, synthetic_d1_dml_attempt_for_complete_audit_phase,
};
use crate::d1_dml_identity_claimant::{
    D1DmlIdentityNamespace, derive_d1_dml_identity_claimant_set,
};
use crate::d1_migration_lease::acquire_d1_target_mutation_guard_for_test;
use crate::d1_target::normalize_d1_target;
use crate::d1_target_wide_attempt_custody::{
    D1TargetWidePreparedProduct, install_d1_target_wide_prepared_custody,
    prepare_d1_target_wide_attempt,
};
use crate::d1_target_wide_mutation::{
    D1TargetWideIntendedPlan, rederive_d1_target_wide_intended_plan,
};

const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
const OPERATION_ID: &str = "owner-operation-0001";
const ATTEMPT_ID: &str = "owner-attempt-000001";
const PROVIDER_ID: &str = "owner-provider-00001";

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

fn alternate_ids() -> D1DmlAttemptIdentities<'static> {
    D1DmlAttemptIdentities {
        operation_id: "owner-operation-0002",
        execution_attempt_id: "owner-attempt-000002",
        provider_request_id: "owner-provider-00002",
    }
}

fn plan(name: &str) -> D1TargetWideIntendedPlan {
    rederive_d1_target_wide_intended_plan(
        &target(),
        "d1_rename_database",
        &json!({"new_name": name}),
        Some("reviewed reason"),
    )
    .expect("canonical plan")
}

#[cfg(target_os = "linux")]
fn install_owner(
    label: &str,
) -> (
    std::path::PathBuf,
    D1TargetMutationGuard,
    D1TargetWideIntendedPlan,
    D1TargetWidePreparedProduct,
) {
    let (root, guard) = acquire_d1_target_mutation_guard_for_test(label, "d1_rename_database");
    let plan = plan("owner-name");
    let prepared = install_d1_target_wide_prepared_custody(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
    )
    .expect("install canonical Prepared owner");
    (root, guard, plan, prepared)
}

fn authorization_error_classification(result: CallToolResult) -> serde_json::Value {
    result.structured_content.expect("structured owner error")["error"]["classification"].clone()
}

#[cfg(target_os = "linux")]
fn install_surrounding_attempt(
    guard: &D1TargetMutationGuard,
    label: &str,
    phase: D1DmlAttemptPhase,
) {
    let operation_id = format!("terminal-operation-{label}");
    let execution_attempt_id = format!("terminal-attempt-{label}");
    let provider_request_id = format!("terminal-provider-{label}");
    let identities = D1DmlAttemptIdentities {
        operation_id: &operation_id,
        execution_attempt_id: &execution_attempt_id,
        provider_request_id: &provider_request_id,
    };
    let execute_plan_sha256 = format!("{:x}", Sha256::digest(label.as_bytes()));
    let set = derive_d1_dml_identity_claimant_set(&target(), &execute_plan_sha256, identities)
        .expect("derive surrounding claimant set");
    let attempt = synthetic_d1_dml_attempt_for_complete_audit_phase(
        &target().target_key_sha256(),
        &execute_plan_sha256,
        identities,
        phase,
    );
    guard
        .preflight_d1_dml_identity_claimant_set_capacity(&set)
        .expect("preflight surrounding claimants");
    for namespace in D1DmlIdentityNamespace::ALL {
        let pending = set.pending(namespace);
        let bound = set
            .bound(namespace, &attempt.receipt().attempt_binding_sha256)
            .expect("derive surrounding Bound claimant");
        guard
            .create_d1_dml_identity_claimant(
                namespace,
                set.identity_sha256(namespace),
                pending.state_bytes(),
            )
            .expect("install surrounding Pending claimant");
        guard
            .compare_exchange_d1_dml_identity_claimant(
                namespace,
                set.identity_sha256(namespace),
                pending.state_bytes(),
                bound.state_bytes(),
            )
            .expect("seal surrounding claimant");
    }
    guard
        .create_d1_dml_attempt_state(
            &attempt.receipt().attempt_binding_sha256,
            attempt.state_bytes(),
        )
        .expect("install surrounding terminal attempt");
}

#[cfg(target_os = "linux")]
fn owner_attempt_path(
    root: &std::path::Path,
    prepared: &D1TargetWidePreparedProduct,
) -> std::path::PathBuf {
    let binding = &prepared.receipt().attempt_binding_sha256;
    root.join(format!(
        "d1-migration-target-{}",
        target().target_key_sha256()
    ))
    .join("dml-custody-v1")
    .join("attempt")
    .join(&binding[..2])
    .join(&binding[2..4])
    .join(format!("{binding}.json"))
}

#[cfg(target_os = "linux")]
#[test]
fn canonical_owner_authorizes_only_local_dispatch_reservation_and_global_stays_closed() {
    let (root, guard, plan, prepared) = install_owner("owner-audit-canonical");
    assert!(
        guard.authorize_target_wide_d1_dml_custody().is_err(),
        "global target-wide authority must continue rejecting unresolved Prepared"
    );

    let authorization = authorize_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        &prepared,
    )
    .expect("one exact Prepared owner is eligible");
    let replay = authorize_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        &prepared,
    )
    .expect("exact owner authorization replay");
    assert_eq!(replay, authorization);
    assert_eq!(
        authorization.authorization_scope,
        D1TargetWideOwnerAuthorizationScope::DispatchReservationOnly
    );
    assert_eq!(
        authorization.provider_dispatch_authority,
        D1DmlCustodyAuditProviderAuthority::None
    );
    assert_eq!(authorization.complete_audit_attempt_count, 1);
    assert_eq!(authorization.surrounding_terminal_attempt_count, 0);
    assert_eq!(authorization.provider_calls, 0);
    assert_eq!(authorization.provider_mutations, 0);
    assert_eq!(authorization.local_mutations, 0);
    revalidate_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        &prepared,
        &authorization,
    )
    .expect("exact owner authority revalidates immediately before future CAS");

    let encoded = serde_json::to_string(&authorization).expect("authorization JSON");
    for secret_or_raw in [
        "acct-1",
        DATABASE_ID,
        OPERATION_ID,
        ATTEMPT_ID,
        PROVIDER_ID,
        "owner-name",
        "reviewed reason",
        plan.confirmation_token().as_str(),
    ] {
        assert!(!encoded.contains(secret_or_raw));
    }
    drop(guard);
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[cfg(target_os = "linux")]
#[test]
fn attempt_first_convergence_produces_the_same_owner_authority() {
    let (root, guard) = acquire_d1_target_mutation_guard_for_test(
        "owner-audit-attempt-first",
        "d1_rename_database",
    );
    let plan = plan("owner-name");
    let first =
        prepare_d1_target_wide_attempt(&target(), &plan, &plan.confirmation_token(), ids(), None)
            .expect("canonical Prepared product");
    guard
        .ensure_target_wide_d1_dml_custody_layout()
        .expect("layout");
    guard
        .create_d1_dml_attempt_state(&first.receipt().attempt_binding_sha256, first.state_bytes())
        .expect("install attempt first");
    let converged = install_d1_target_wide_prepared_custody(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
    )
    .expect("converge claimant set after attempt");
    authorize_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        &converged,
    )
    .expect("attempt-first owner authorizes after complete convergence");
    drop(guard);
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[cfg(target_os = "linux")]
#[test]
fn complete_terminal_surroundings_are_bound_and_stale_authority_fails_revalidation() {
    let (root, guard, plan, prepared) = install_owner("owner-audit-surroundings");
    let before = authorize_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        &prepared,
    )
    .expect("initial owner authority");
    install_surrounding_attempt(&guard, "clean-one", D1DmlAttemptPhase::TerminalApplied);
    let after = authorize_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        &prepared,
    )
    .expect("clean terminal surroundings remain eligible");
    assert_eq!(after.complete_audit_attempt_count, 2);
    assert_eq!(after.surrounding_terminal_attempt_count, 1);
    assert_ne!(after.authorization_sha256, before.authorization_sha256);
    let error = revalidate_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        &prepared,
        &before,
    )
    .expect_err("changed surrounding custody invalidates prior authorization");
    assert_eq!(
        authorization_error_classification(error),
        json!("authorization_changed")
    );
    drop(guard);
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[cfg(target_os = "linux")]
#[test]
fn nonterminal_surrounding_attempts_fail_closed() {
    for (label, phase) in [
        ("dispatch-reserved", D1DmlAttemptPhase::DispatchReserved),
        (
            "reconciliation-required",
            D1DmlAttemptPhase::ReconciliationRequired,
        ),
    ] {
        let fixture_label = format!("owner-audit-surrounding-{label}");
        let (root, guard, plan, prepared) = install_owner(&fixture_label);
        install_surrounding_attempt(&guard, label, phase);
        let error = authorize_d1_target_wide_prepared_owner(
            &guard,
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            &prepared,
        )
        .expect_err("nonterminal surrounding custody is never owner authority");
        assert_eq!(
            authorization_error_classification(error),
            json!("complete_audit_contradictory")
        );
        drop(guard);
        fs::remove_dir_all(root).expect("remove nonterminal fixture");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn partial_foreign_and_multiple_prepared_owners_fail_closed() {
    let partial_plan = plan("partial-owner");
    let partial = prepare_d1_target_wide_attempt(
        &target(),
        &partial_plan,
        &partial_plan.confirmation_token(),
        ids(),
        None,
    )
    .expect("partial product");
    let (partial_root, partial_guard) =
        acquire_d1_target_mutation_guard_for_test("owner-audit-partial", "d1_rename_database");
    partial_guard
        .ensure_target_wide_d1_dml_custody_layout()
        .expect("layout");
    partial_guard
        .create_d1_dml_attempt_state(
            &partial.receipt().attempt_binding_sha256,
            partial.state_bytes(),
        )
        .expect("install unmatched attempt");
    let partial_error = authorize_d1_target_wide_prepared_owner(
        &partial_guard,
        &target(),
        &partial_plan,
        &partial_plan.confirmation_token(),
        ids(),
        &partial,
    )
    .expect_err("partial graph is never authority");
    assert_eq!(
        authorization_error_classification(partial_error),
        json!("complete_audit_contradictory")
    );
    drop(partial_guard);
    fs::remove_dir_all(partial_root).expect("remove partial fixture");

    let (root, guard, installed_plan, installed) = install_owner("owner-audit-foreign");
    let foreign_plan = plan("foreign-owner");
    let foreign = prepare_d1_target_wide_attempt(
        &target(),
        &foreign_plan,
        &foreign_plan.confirmation_token(),
        alternate_ids(),
        None,
    )
    .expect("foreign canonical product");
    let foreign_error = authorize_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &foreign_plan,
        &foreign_plan.confirmation_token(),
        alternate_ids(),
        &foreign,
    )
    .expect_err("foreign Prepared owner is not physical authority");
    assert_eq!(
        authorization_error_classification(foreign_error),
        json!("owner_attempt_missing_or_conflicting")
    );

    install_d1_target_wide_prepared_custody(
        &guard,
        &target(),
        &foreign_plan,
        &foreign_plan.confirmation_token(),
        alternate_ids(),
    )
    .expect("install second complete Prepared owner");
    let multiple_error = authorize_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &installed_plan,
        &installed_plan.confirmation_token(),
        ids(),
        &installed,
    )
    .expect_err("multiple unresolved owners are never authority");
    assert_eq!(
        authorization_error_classification(multiple_error),
        json!("complete_audit_contradictory")
    );
    drop(guard);
    fs::remove_dir_all(root).expect("remove fixture root");
}

#[cfg(target_os = "linux")]
#[test]
fn malformed_restored_and_unsafe_owner_artifacts_fail_closed_without_raw_output() {
    use std::os::unix::fs::PermissionsExt;

    for (label, bytes) in [
        ("null", b"null\n".as_slice()),
        ("array", b"[]\n".as_slice()),
        ("primitive", b"false\n".as_slice()),
        ("malformed", b"{\n".as_slice()),
    ] {
        let fixture_label = format!("owner-audit-restored-{label}");
        let (root, guard, plan, prepared) = install_owner(&fixture_label);
        fs::write(owner_attempt_path(&root, &prepared), bytes).expect("replace restored bytes");
        let error = authorize_d1_target_wide_prepared_owner(
            &guard,
            &target(),
            &plan,
            &plan.confirmation_token(),
            ids(),
            &prepared,
        )
        .expect_err("non-object or malformed restored state is never authority");
        let structured = error.structured_content.expect("aggregate error");
        assert_eq!(
            structured["error"]["classification"],
            json!("complete_audit_unavailable")
        );
        let encoded = serde_json::to_string(&structured).expect("error JSON");
        assert!(!encoded.contains(OPERATION_ID));
        assert!(!encoded.contains(DATABASE_ID));
        drop(guard);
        fs::remove_dir_all(root).expect("remove restored fixture");
    }

    let (root, guard, plan, prepared) = install_owner("owner-audit-unsafe-mode");
    fs::set_permissions(
        owner_attempt_path(&root, &prepared),
        fs::Permissions::from_mode(0o644),
    )
    .expect("make owner mode unsafe");
    let error = authorize_d1_target_wide_prepared_owner(
        &guard,
        &target(),
        &plan,
        &plan.confirmation_token(),
        ids(),
        &prepared,
    )
    .expect_err("unsafe owner mode is never authority");
    assert_eq!(
        authorization_error_classification(error),
        json!("complete_audit_unavailable")
    );
    drop(guard);
    fs::remove_dir_all(root).expect("remove unsafe-mode fixture");
}
