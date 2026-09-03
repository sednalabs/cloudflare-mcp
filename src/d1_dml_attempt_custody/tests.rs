use serde_json::{Value, json};

use super::*;
use crate::d1_catalog_evidence::{
    D1_CATALOG_PROVIDER_BYTE_CAP, D1_CATALOG_PROVIDER_ROW_CAP, D1CatalogEvidenceProduct,
    D1CatalogObservationFrame, D1CatalogProjectionRow, derive_d1_catalog_evidence_plan,
    prove_d1_catalog_product,
};
use crate::d1_exact_plan_composition::{
    D1ExactPlanCompositionProduct, compose_d1_exact_write_plan,
};
use crate::d1_execute_write::{D1WriteStatementKind, derive_d1_execute_write_plan};
use crate::d1_reserved_relation_graph::{D1WriteOperationForm, derive_d1_reserved_relation_graph};

const DATABASE_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
const OPERATION_ID: &str = "operation-opaque-0001";
const ATTEMPT_ID: &str = "execution-attempt-0001";
const REQUEST_ID: &str = "provider-request-0001";

struct Fixture {
    target: D1TargetIdentity,
    composition: D1ExactPlanCompositionProduct,
}

fn fixture() -> Fixture {
    fixture_with_sql("INSERT INTO items(value) VALUES (?)")
}

fn fixture_with_sql(sql: &str) -> Fixture {
    let target = target("acct-1", DATABASE_ID);
    let catalog = verified_catalog(&target, vec![table(1, "d1_migrations"), table(2, "items")]);
    let graph = derive_d1_reserved_relation_graph(&catalog, &["d1_migrations".to_string()])
        .expect("reserved graph");
    let (plan, plan_sha256) = derive_d1_execute_write_plan(
        &target.account_id,
        &target.database_id,
        &target.target_key_sha256(),
        &"b".repeat(64),
        D1WriteStatementKind::Insert,
        sql,
        &[json!(1)],
        100,
    );
    let composition = compose_d1_exact_write_plan(
        &target,
        &plan,
        &plan_sha256,
        "items",
        D1WriteOperationForm::Insert,
        &catalog,
        &graph,
    )
    .expect("exact composition");
    Fixture {
        target,
        composition,
    }
}

fn target(account_id: &str, database_id: &str) -> D1TargetIdentity {
    normalize_d1_target(account_id, database_id).expect("canonical target")
}

fn ids() -> D1DmlAttemptIdentities<'static> {
    D1DmlAttemptIdentities {
        operation_id: OPERATION_ID,
        execution_attempt_id: ATTEMPT_ID,
        provider_request_id: REQUEST_ID,
        custody_generation_sha256: super::TEST_CUSTODY_GENERATION_SHA256,
    }
}

fn provider(
    classification: D1DmlProviderTerminalClassification,
) -> D1DmlProviderTerminalAssertion<'static> {
    D1DmlProviderTerminalAssertion {
        classification,
        evidence_sha256: "c7f5d535682bd811b78a9e24713c7d3d5ceb4d7f610e029bf1e8e6b716e1728a", // DevSkim: ignore DS173237 -- synthetic SHA-256 fixture, not a credential
    }
}

fn readback(
    classification: D1DmlReadbackTerminalClassification,
) -> D1DmlReadbackTerminalAssertion<'static> {
    D1DmlReadbackTerminalAssertion {
        classification,
        readback_plan_sha256: "6228db33999b0b4c59b8cfcfa2770b1e32e9a7c46bf7bbaf52d0faed35df4740", // DevSkim: ignore DS173237 -- synthetic SHA-256 fixture, not a credential
        evidence_sha256: "8093454f4277a9c50ce2cd7c931e650c3639b88e00d2dfb0034e8a2117c49d2a", // DevSkim: ignore DS173237 -- synthetic SHA-256 fixture, not a credential
    }
}

fn prepare(fixture: &Fixture) -> D1DmlAttemptCustodyProduct {
    prepare_d1_dml_attempt(&fixture.target, &fixture.composition, ids(), None)
        .expect("prepared custody")
}

fn reserve_dispatch(fixture: &Fixture, state: &[u8]) -> D1DmlAttemptCustodyProduct {
    prepare_d1_dml_dispatch_reservation_cas(&fixture.target, &fixture.composition, ids(), state)
        .expect("dispatch reservation proposal")
}

#[test]
fn durable_successor_validator_accepts_one_addition_and_rejects_replay_or_reverse() {
    let fixture = fixture();
    let prepared = prepare(&fixture);
    let reserved = reserve_dispatch(&fixture, prepared.state_bytes());
    validate_d1_dml_attempt_successor(prepared.state_bytes(), reserved.state_bytes())
        .expect("Prepared to DispatchReserved is one exact durable successor");
    assert!(
        validate_d1_dml_attempt_successor(prepared.state_bytes(), prepared.state_bytes()).is_err(),
        "exact replay is not a CAS successor"
    );
    assert!(
        validate_d1_dml_attempt_successor(reserved.state_bytes(), prepared.state_bytes()).is_err(),
        "reverse transition is not monotonic"
    );
}

#[test]
fn complete_audit_rederives_the_full_attempt_binding() {
    let fixture = fixture();
    let prepared = prepare(&fixture);
    validate_d1_dml_attempt_audit_binding(prepared.receipt())
        .expect("canonical attempt binding rederives");
    let mut drift = prepared.receipt().clone();
    drift.attempt_binding_sha256 = "d".repeat(64);
    assert!(
        validate_d1_dml_attempt_audit_binding(&drift).is_err(),
        "canonical-looking attempt-binding drift fails closed"
    );
}

fn classification(
    result: Result<D1DmlAttemptCustodyProduct, D1DmlAttemptCustodyError>,
) -> D1DmlAttemptCustodyClassification {
    result.expect_err("fixture must fail closed").classification
}

fn schema_sentinels() -> Value {
    json!({
        "foreign_key_id_storage_class": "not_applicable",
        "foreign_key_id_value_hex": "",
        "foreign_key_id": -1,
        "foreign_key_seq_storage_class": "not_applicable",
        "foreign_key_seq_value_hex": "",
        "foreign_key_seq": -1,
        "parent_name_storage_class": "not_applicable",
        "parent_name_hex": "",
        "from_column_storage_class": "not_applicable",
        "from_column_hex": "",
        "to_column_storage_class": "not_applicable",
        "to_column_is_null": 1,
        "to_column_hex": "",
        "on_update_storage_class": "not_applicable",
        "on_update_hex": "",
        "on_delete_storage_class": "not_applicable",
        "on_delete_hex": "",
        "match_storage_class": "not_applicable",
        "match_hex": "",
    })
}

fn table(schema_rowid: i64, name: &str) -> Value {
    let definition = format!("CREATE TABLE {name}(id INTEGER PRIMARY KEY, value TEXT)");
    let mut value = json!({
        "schema_rowid": schema_rowid,
        "fact_order": 0,
        "fact_kind": "relation",
        "relation_type_storage_class": "text",
        "relation_type_value_hex": hex("table"),
        "relation_type": "table",
        "relation_name_storage_class": "text",
        "relation_name_hex": hex(name),
        "owner_name_storage_class": "text",
        "owner_name_hex": hex(name),
        "schema_sql_storage_class": "text",
        "table_sql_token_source_is_null": 0,
        "table_sql_token_source_hex": hex(&definition),
        "table_virtual_token_hit": 0,
        "table_replace_token_hit": 0,
        "conservative_blocker": "",
    });
    value
        .as_object_mut()
        .expect("table row")
        .extend(schema_sentinels().as_object().expect("sentinels").clone());
    value
}

fn verified_catalog(target: &D1TargetIdentity, rows: Vec<Value>) -> D1CatalogEvidenceProduct {
    let mut rows = rows
        .into_iter()
        .map(|row| serde_json::from_value::<D1CatalogProjectionRow>(row).expect("typed row"))
        .collect::<Vec<_>>();
    rows.sort();
    let body = serde_json::to_vec(&json!({
        "version": 5,
        "results_truncated": false,
        "meta": {
            "query_succeeded": true,
            "served_by_primary": true,
            "changed_db": false,
            "changes": 0,
            "rows_written": 0,
        },
        "rows": rows,
    }))
    .expect("catalog body");
    let (plan, plan_sha256) = derive_d1_catalog_evidence_plan(target).expect("catalog plan");
    let first = frame(
        target,
        &plan_sha256,
        "dispatch-first-0001",
        "read-first-00000001",
        &body,
    );
    let second = frame(
        target,
        &plan_sha256,
        "dispatch-second-001",
        "read-second-0000001",
        &body,
    );
    prove_d1_catalog_product(target, &plan, &plan_sha256, &first, &second)
        .expect("verified catalog")
}

fn frame<'a>(
    target: &'a D1TargetIdentity,
    plan_sha256: &'a str,
    dispatch_id: &'a str,
    read_id: &'a str,
    body: &'a [u8],
) -> D1CatalogObservationFrame<'a> {
    D1CatalogObservationFrame::from_adapter_observation(
        target,
        plan_sha256,
        dispatch_id,
        read_id,
        D1_CATALOG_PROVIDER_ROW_CAP,
        D1_CATALOG_PROVIDER_BYTE_CAP,
        true,
        body.len(),
        body,
    )
}

fn hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn state(bytes: &[u8]) -> D1DmlAttemptState {
    serde_json::from_slice(bytes).expect("typed canonical state")
}

fn unchecked_state_bytes(state: &D1DmlAttemptState) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(state).expect("state JSON");
    bytes.push(b'\n');
    bytes
}

#[test]
fn absent_attempt_prepares_and_exact_predispatch_replay_converges() {
    let fixture = fixture();
    let prepared = prepare(&fixture);
    assert_eq!(prepared.receipt().phase, D1DmlAttemptPhase::Prepared);
    assert_eq!(prepared.receipt().dispatch_reservations, 0);
    assert!(!prepared.receipt().dispatch_atomic_compare_exchange_required);
    assert_eq!(prepared.receipt().dispatch_expected_state_sha256, None);
    assert_eq!(prepared.receipt().dispatch_successor_state_sha256, None);
    assert_eq!(
        prepared.receipt().retry_decision,
        D1DmlAttemptRetryDecision::DispatchNotYetCrossed
    );
    assert!(prepared.state_bytes().ends_with(b"\n"));
    assert!(prepared.state_bytes().len() < D1_DML_ATTEMPT_STATE_BYTE_CAP);

    let replay = prepare_d1_dml_attempt(
        &fixture.target,
        &fixture.composition,
        ids(),
        Some(prepared.state_bytes()),
    )
    .expect("exact predispatch replay");
    assert_eq!(replay.state_bytes(), prepared.state_bytes());
    assert_eq!(
        replay.receipt().transition,
        D1DmlAttemptTransition::ExactReplay
    );
    assert!(replay.receipt().exact_replay);
    assert!(!replay.receipt().dispatch_atomic_compare_exchange_required);
}

#[test]
fn opaque_identity_bounds_duplicates_and_conflicting_replay_deny() {
    let fixture = fixture();
    let invalid = D1DmlAttemptIdentities {
        operation_id: "short",
        ..ids()
    };
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            invalid,
            None,
        )),
        D1DmlAttemptCustodyClassification::OpaqueIdentityInvalid
    );
    let duplicate = D1DmlAttemptIdentities {
        provider_request_id: ATTEMPT_ID,
        ..ids()
    };
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            duplicate,
            None,
        )),
        D1DmlAttemptCustodyClassification::OpaqueIdentityDuplicate
    );

    let prepared = prepare(&fixture);
    let conflicting = D1DmlAttemptIdentities {
        provider_request_id: "provider-request-0002",
        ..ids()
    };
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            conflicting,
            Some(prepared.state_bytes()),
        )),
        D1DmlAttemptCustodyClassification::ReplayConflict
    );

    let changed_plan = fixture_with_sql("INSERT INTO items(value) VALUES (? + 1)");
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &changed_plan.target,
            &changed_plan.composition,
            ids(),
            Some(prepared.state_bytes()),
        )),
        D1DmlAttemptCustodyClassification::ReplayConflict
    );
    let stale_target = target("acct-2", DATABASE_ID);
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &stale_target,
            &fixture.composition,
            ids(),
            Some(prepared.state_bytes()),
        )),
        D1DmlAttemptCustodyClassification::CompositionProductMismatch
    );
}

#[test]
fn dispatch_reservation_is_a_non_authorizing_exact_cas_proposal() {
    let fixture = fixture();
    let prepared = prepare(&fixture);
    let reservation = reserve_dispatch(&fixture, prepared.state_bytes());
    assert_eq!(
        reservation.receipt().phase,
        D1DmlAttemptPhase::DispatchReserved
    );
    assert_eq!(reservation.receipt().dispatch_reservations, 1);
    assert!(
        reservation
            .receipt()
            .dispatch_atomic_compare_exchange_required
    );
    assert_eq!(
        reservation.receipt().dispatch_expected_state_sha256,
        Some(hash_bytes(prepared.state_bytes()))
    );
    assert_eq!(
        reservation.receipt().dispatch_successor_state_sha256,
        Some(hash_bytes(reservation.state_bytes()))
    );
    assert!(!reservation.receipt().exact_replay);
    assert_eq!(
        reservation.receipt().retry_decision,
        D1DmlAttemptRetryDecision::DoNotRedispatchSameAttempt
    );
    let receipt_json = serde_json::to_string(reservation.receipt()).expect("reservation receipt");
    assert!(!receipt_json.contains("authorized"));

    let stale_prepared = reserve_dispatch(&fixture, prepared.state_bytes());
    assert_eq!(stale_prepared, reservation);
    assert!(
        stale_prepared
            .receipt()
            .dispatch_atomic_compare_exchange_required
    );

    let replay = reserve_dispatch(&fixture, reservation.state_bytes());
    assert_eq!(
        replay.receipt().phase,
        D1DmlAttemptPhase::ReconciliationRequired
    );
    assert_eq!(replay.receipt().dispatch_reservations, 1);
    assert!(!replay.receipt().exact_replay);
    assert!(!replay.receipt().dispatch_atomic_compare_exchange_required);
    assert_eq!(
        replay.receipt().ambiguity,
        Some(D1DmlAttemptAmbiguity::DispatchReplay)
    );

    let later = reserve_dispatch(&fixture, replay.state_bytes());
    assert_eq!(later.state_bytes(), replay.state_bytes());
    assert!(!later.receipt().dispatch_atomic_compare_exchange_required);
    assert!(later.receipt().exact_replay);
}

#[test]
fn every_transport_or_response_ambiguity_quarantines_without_redispatch() {
    let fixture = fixture();
    for ambiguity in [
        D1DmlAttemptAmbiguity::TransportUncertain,
        D1DmlAttemptAmbiguity::ResponseMissing,
        D1DmlAttemptAmbiguity::ResponseIncomplete,
        D1DmlAttemptAmbiguity::ResponseMalformed,
        D1DmlAttemptAmbiguity::ResponseContradictory,
    ] {
        let prepared = prepare(&fixture);
        let dispatched = reserve_dispatch(&fixture, prepared.state_bytes());
        let ambiguous = record_d1_dml_attempt_ambiguity(
            &fixture.target,
            &fixture.composition,
            ids(),
            dispatched.state_bytes(),
            ambiguity,
        )
        .expect("ambiguity custody");
        assert_eq!(
            ambiguous.receipt().phase,
            D1DmlAttemptPhase::ReconciliationRequired
        );
        assert_eq!(ambiguous.receipt().ambiguity, Some(ambiguity));
        assert!(
            !ambiguous
                .receipt()
                .dispatch_atomic_compare_exchange_required
        );
        assert_eq!(
            ambiguous.receipt().retry_decision,
            D1DmlAttemptRetryDecision::DoNotRedispatchSameAttempt
        );

        let replay = record_d1_dml_attempt_ambiguity(
            &fixture.target,
            &fixture.composition,
            ids(),
            ambiguous.state_bytes(),
            ambiguity,
        )
        .expect("exact ambiguity replay");
        assert_eq!(replay.state_bytes(), ambiguous.state_bytes());
        assert!(replay.receipt().exact_replay);
    }
}

#[test]
fn ambiguity_and_terminal_assertion_replays_are_exact_or_conflicting() {
    let fixture = fixture();
    let dispatched = reserve_dispatch(&fixture, prepare(&fixture).state_bytes());
    let ambiguous = record_d1_dml_attempt_ambiguity(
        &fixture.target,
        &fixture.composition,
        ids(),
        dispatched.state_bytes(),
        D1DmlAttemptAmbiguity::ResponseMissing,
    )
    .expect("ambiguity");
    assert_eq!(
        classification(record_d1_dml_attempt_ambiguity(
            &fixture.target,
            &fixture.composition,
            ids(),
            ambiguous.state_bytes(),
            D1DmlAttemptAmbiguity::ResponseMalformed,
        )),
        D1DmlAttemptCustodyClassification::AmbiguityConflict
    );

    let provider_once = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        ambiguous.state_bytes(),
        provider(D1DmlProviderTerminalClassification::SucceededChanged),
    )
    .expect("provider terminal evidence");
    let provider_replay = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        provider_once.state_bytes(),
        provider(D1DmlProviderTerminalClassification::SucceededChanged),
    )
    .expect("provider evidence replay");
    assert_eq!(provider_replay.state_bytes(), provider_once.state_bytes());
    assert_eq!(
        provider_replay.receipt().transition,
        D1DmlAttemptTransition::ProviderAssertionReplay
    );
    assert_eq!(
        classification(record_d1_dml_provider_terminal_assertion(
            &fixture.target,
            &fixture.composition,
            ids(),
            provider_once.state_bytes(),
            provider(D1DmlProviderTerminalClassification::RejectedTerminal),
        )),
        D1DmlAttemptCustodyClassification::EvidenceConflict
    );
}

#[test]
fn terminal_ambiguity_replay_requires_an_exact_incumbent() {
    let fixture = fixture();
    let reservation = reserve_dispatch(&fixture, prepare(&fixture).state_bytes());

    let provider_only = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        reservation.state_bytes(),
        provider(D1DmlProviderTerminalClassification::SucceededChanged),
    )
    .expect("provider assertion");
    let terminal_without_ambiguity = record_d1_dml_readback_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        provider_only.state_bytes(),
        readback(D1DmlReadbackTerminalClassification::ExpectedStateObserved),
    )
    .expect("terminal without ambiguity");
    assert_eq!(
        classification(record_d1_dml_attempt_ambiguity(
            &fixture.target,
            &fixture.composition,
            ids(),
            terminal_without_ambiguity.state_bytes(),
            D1DmlAttemptAmbiguity::ResponseMissing,
        )),
        D1DmlAttemptCustodyClassification::AmbiguityConflict
    );

    let ambiguous = record_d1_dml_attempt_ambiguity(
        &fixture.target,
        &fixture.composition,
        ids(),
        reservation.state_bytes(),
        D1DmlAttemptAmbiguity::ResponseMissing,
    )
    .expect("incumbent ambiguity");
    let provider_after_ambiguity = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        ambiguous.state_bytes(),
        provider(D1DmlProviderTerminalClassification::SucceededChanged),
    )
    .expect("provider assertion after ambiguity");
    let terminal_with_ambiguity = record_d1_dml_readback_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        provider_after_ambiguity.state_bytes(),
        readback(D1DmlReadbackTerminalClassification::ExpectedStateObserved),
    )
    .expect("terminal with ambiguity");

    let exact = record_d1_dml_attempt_ambiguity(
        &fixture.target,
        &fixture.composition,
        ids(),
        terminal_with_ambiguity.state_bytes(),
        D1DmlAttemptAmbiguity::ResponseMissing,
    )
    .expect("exact terminal ambiguity replay");
    assert_eq!(exact.state_bytes(), terminal_with_ambiguity.state_bytes());
    assert!(exact.receipt().exact_replay);
    assert_eq!(
        classification(record_d1_dml_attempt_ambiguity(
            &fixture.target,
            &fixture.composition,
            ids(),
            terminal_with_ambiguity.state_bytes(),
            D1DmlAttemptAmbiguity::ResponseMalformed,
        )),
        D1DmlAttemptCustodyClassification::AmbiguityConflict
    );
}

#[test]
fn separately_typed_terminal_assertions_converge_in_both_insertion_orders() {
    let fixture = fixture();
    let dispatched = reserve_dispatch(&fixture, prepare(&fixture).state_bytes());

    let provider_first = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        dispatched.state_bytes(),
        provider(D1DmlProviderTerminalClassification::SucceededChanged),
    )
    .expect("provider first");
    assert_eq!(
        provider_first.receipt().phase,
        D1DmlAttemptPhase::DispatchReserved
    );
    assert!(provider_first.receipt().provider_assertion_present);
    assert!(!provider_first.receipt().readback_assertion_present);
    assert_eq!(provider_first.receipt().terminal_outcome, None);
    let provider_then_readback = record_d1_dml_readback_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        provider_first.state_bytes(),
        readback(D1DmlReadbackTerminalClassification::ExpectedStateObserved),
    )
    .expect("readback second");

    let readback_first = record_d1_dml_readback_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        dispatched.state_bytes(),
        readback(D1DmlReadbackTerminalClassification::ExpectedStateObserved),
    )
    .expect("readback first");
    assert_eq!(
        readback_first.receipt().phase,
        D1DmlAttemptPhase::DispatchReserved
    );
    assert!(!readback_first.receipt().provider_assertion_present);
    assert!(readback_first.receipt().readback_assertion_present);
    assert_eq!(readback_first.receipt().terminal_outcome, None);
    let readback_then_provider = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        readback_first.state_bytes(),
        provider(D1DmlProviderTerminalClassification::SucceededChanged),
    )
    .expect("provider second");

    for terminal in [&provider_then_readback, &readback_then_provider] {
        assert_eq!(terminal.receipt().phase, D1DmlAttemptPhase::TerminalApplied);
        assert_eq!(
            terminal.receipt().terminal_outcome,
            Some(D1DmlAttemptTerminalOutcome::Applied)
        );
        assert_eq!(
            terminal.receipt().retry_decision,
            D1DmlAttemptRetryDecision::TerminalReplayOnly
        );
        assert!(!terminal.receipt().dispatch_atomic_compare_exchange_required);
    }
    assert_eq!(
        provider_then_readback.state_bytes(),
        readback_then_provider.state_bytes()
    );
    assert_eq!(
        provider_then_readback.receipt().state_sha256,
        readback_then_provider.receipt().state_sha256
    );
}

#[test]
fn rejected_and_absent_assertions_propose_only_terminal_not_applied() {
    let fixture = fixture();
    let dispatched = reserve_dispatch(&fixture, prepare(&fixture).state_bytes());
    let rejected = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        dispatched.state_bytes(),
        provider(D1DmlProviderTerminalClassification::RejectedTerminal),
    )
    .expect("terminal rejection");
    assert_eq!(rejected.receipt().terminal_outcome, None);
    let terminal = record_d1_dml_readback_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        rejected.state_bytes(),
        readback(D1DmlReadbackTerminalClassification::ExpectedStateAbsent),
    )
    .expect("absence readback");
    assert_eq!(
        terminal.receipt().phase,
        D1DmlAttemptPhase::TerminalNotApplied
    );
    assert_eq!(
        terminal.receipt().terminal_outcome,
        Some(D1DmlAttemptTerminalOutcome::NotApplied)
    );
}

#[test]
fn contradictory_terminal_assertions_require_reconciliation() {
    let fixture = fixture();
    for (provider_classification, readback_classification) in [
        (
            D1DmlProviderTerminalClassification::SucceededChanged,
            D1DmlReadbackTerminalClassification::ExpectedStateAbsent,
        ),
        (
            D1DmlProviderTerminalClassification::RejectedTerminal,
            D1DmlReadbackTerminalClassification::ExpectedStateObserved,
        ),
    ] {
        let dispatched = reserve_dispatch(&fixture, prepare(&fixture).state_bytes());
        let provider_state = record_d1_dml_provider_terminal_assertion(
            &fixture.target,
            &fixture.composition,
            ids(),
            dispatched.state_bytes(),
            provider(provider_classification),
        )
        .expect("provider evidence");
        let contradiction = record_d1_dml_readback_terminal_assertion(
            &fixture.target,
            &fixture.composition,
            ids(),
            provider_state.state_bytes(),
            readback(readback_classification),
        )
        .expect("contradictory evidence is durably quarantined");
        assert_eq!(
            contradiction.receipt().phase,
            D1DmlAttemptPhase::ReconciliationRequired
        );
        assert!(contradiction.receipt().provider_assertion_present);
        assert!(contradiction.receipt().readback_assertion_present);
        assert_eq!(contradiction.receipt().terminal_outcome, None);
        assert_eq!(
            contradiction.receipt().retry_decision,
            D1DmlAttemptRetryDecision::DoNotRedispatchSameAttempt
        );
    }
}

#[test]
fn post_dispatch_assertions_cannot_precede_reservation_and_digests_are_closed() {
    let fixture = fixture();
    let prepared = prepare(&fixture);
    assert_eq!(
        classification(record_d1_dml_attempt_ambiguity(
            &fixture.target,
            &fixture.composition,
            ids(),
            prepared.state_bytes(),
            D1DmlAttemptAmbiguity::ResponseMissing,
        )),
        D1DmlAttemptCustodyClassification::TransitionBeforeDispatch
    );
    assert_eq!(
        classification(record_d1_dml_provider_terminal_assertion(
            &fixture.target,
            &fixture.composition,
            ids(),
            prepared.state_bytes(),
            provider(D1DmlProviderTerminalClassification::SucceededChanged),
        )),
        D1DmlAttemptCustodyClassification::TransitionBeforeDispatch
    );
    assert_eq!(
        classification(record_d1_dml_readback_terminal_assertion(
            &fixture.target,
            &fixture.composition,
            ids(),
            prepared.state_bytes(),
            readback(D1DmlReadbackTerminalClassification::ExpectedStateObserved),
        )),
        D1DmlAttemptCustodyClassification::TransitionBeforeDispatch
    );

    let dispatched = reserve_dispatch(&fixture, prepared.state_bytes());
    let malformed_provider = D1DmlProviderTerminalAssertion {
        classification: D1DmlProviderTerminalClassification::SucceededChanged,
        evidence_sha256: "A".repeat(64).leak(),
    };
    assert_eq!(
        classification(record_d1_dml_provider_terminal_assertion(
            &fixture.target,
            &fixture.composition,
            ids(),
            dispatched.state_bytes(),
            malformed_provider,
        )),
        D1DmlAttemptCustodyClassification::EvidenceDigestInvalid
    );
}

#[test]
fn response_loss_before_and_after_provider_acceptance_never_redispatches() {
    let fixture = fixture();
    let prepared = prepare(&fixture);
    let lost_before_dispatch = prepare_d1_dml_attempt(
        &fixture.target,
        &fixture.composition,
        ids(),
        Some(prepared.state_bytes()),
    )
    .expect("predispatch response loss replay");
    let only_crossing = reserve_dispatch(&fixture, lost_before_dispatch.state_bytes());
    assert!(
        only_crossing
            .receipt()
            .dispatch_atomic_compare_exchange_required
    );

    let accepted = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        only_crossing.state_bytes(),
        provider(D1DmlProviderTerminalClassification::SucceededChanged),
    )
    .expect("provider acceptance evidence");
    let lost_after_acceptance = prepare_d1_dml_attempt(
        &fixture.target,
        &fixture.composition,
        ids(),
        Some(accepted.state_bytes()),
    )
    .expect("restored provider evidence");
    assert!(lost_after_acceptance.receipt().provider_assertion_present);
    assert!(
        !lost_after_acceptance
            .receipt()
            .dispatch_atomic_compare_exchange_required
    );

    let replayed_dispatch = reserve_dispatch(&fixture, lost_after_acceptance.state_bytes());
    assert_eq!(
        replayed_dispatch.receipt().phase,
        D1DmlAttemptPhase::ReconciliationRequired
    );
    assert!(replayed_dispatch.receipt().provider_assertion_present);
    assert!(
        !replayed_dispatch
            .receipt()
            .dispatch_atomic_compare_exchange_required
    );
    let reconciled = record_d1_dml_readback_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        replayed_dispatch.state_bytes(),
        readback(D1DmlReadbackTerminalClassification::ExpectedStateObserved),
    )
    .expect("independent readback resolves response loss");
    assert_eq!(
        reconciled.receipt().phase,
        D1DmlAttemptPhase::TerminalApplied
    );
}

#[test]
fn restored_negative_state_product_matrix_fails_closed() {
    let fixture = fixture();
    let prepared = prepare(&fixture);
    for bytes in [
        Vec::new(),
        b"null\n".to_vec(),
        b"[]\n".to_vec(),
        b"1\n".to_vec(),
        b"{\n".to_vec(),
    ] {
        let expected = if bytes.is_empty() {
            D1DmlAttemptCustodyClassification::RestoredStateRequired
        } else {
            D1DmlAttemptCustodyClassification::RestoredStateMalformed
        };
        assert_eq!(
            classification(prepare_d1_dml_attempt(
                &fixture.target,
                &fixture.composition,
                ids(),
                Some(&bytes),
            )),
            expected
        );
    }
    let oversized = vec![b'x'; D1_DML_ATTEMPT_STATE_BYTE_CAP + 1];
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&oversized),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateTooLarge
    );

    let mut unknown = serde_json::to_value(state(prepared.state_bytes())).expect("state value");
    unknown["unknown"] = json!(true);
    let mut unknown_bytes = serde_json::to_vec(&unknown).expect("unknown state");
    unknown_bytes.push(b'\n');
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&unknown_bytes),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateMalformed
    );

    let mut missing = serde_json::to_value(state(prepared.state_bytes())).expect("state value");
    missing
        .as_object_mut()
        .expect("state object")
        .remove("phase");
    let mut missing_bytes = serde_json::to_vec(&missing).expect("missing state");
    missing_bytes.push(b'\n');
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&missing_bytes),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateMalformed
    );

    let mut duplicate = b"{\"version\":1,".to_vec();
    duplicate.extend_from_slice(&prepared.state_bytes()[1..]);
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&duplicate),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateMalformed
    );

    let parsed = state(prepared.state_bytes());
    let mut pretty = serde_json::to_vec_pretty(&parsed).expect("pretty state");
    pretty.push(b'\n');
    for noncanonical in [
        pretty,
        prepared.state_bytes()[..prepared.state_bytes().len() - 1].to_vec(),
    ] {
        assert_eq!(
            classification(prepare_d1_dml_attempt(
                &fixture.target,
                &fixture.composition,
                ids(),
                Some(&noncanonical),
            )),
            D1DmlAttemptCustodyClassification::RestoredStateNonCanonical
        );
    }

    let mut unsupported = parsed.clone();
    unsupported.version = 2;
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&unchecked_state_bytes(&unsupported)),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateUnsupported
    );

    let mut contradictory = parsed.clone();
    contradictory.phase = D1DmlAttemptPhase::DispatchReserved;
    let contradictory_bytes = unchecked_state_bytes(&contradictory);
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&contradictory_bytes),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateContradictory
    );

    let dispatched = reserve_dispatch(&fixture, prepared.state_bytes());
    let mut excessive = state(dispatched.state_bytes());
    excessive.dispatch_reservations = 2;
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&unchecked_state_bytes(&excessive)),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateContradictory
    );

    let provider_state = record_d1_dml_provider_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        dispatched.state_bytes(),
        provider(D1DmlProviderTerminalClassification::SucceededChanged),
    )
    .expect("provider state");
    let mut nested_drift = state(provider_state.state_bytes());
    nested_drift
        .provider_assertion
        .as_mut()
        .expect("provider assertion")
        .attempt_binding_sha256 = "d".repeat(64);
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&unchecked_state_bytes(&nested_drift)),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateContradictory
    );

    let terminal = record_d1_dml_readback_terminal_assertion(
        &fixture.target,
        &fixture.composition,
        ids(),
        provider_state.state_bytes(),
        readback(D1DmlReadbackTerminalClassification::ExpectedStateObserved),
    )
    .expect("terminal state");
    let mut contradictory_terminal = state(terminal.state_bytes());
    contradictory_terminal.terminal_outcome = Some(D1DmlAttemptTerminalOutcome::NotApplied);
    assert_eq!(
        classification(prepare_d1_dml_attempt(
            &fixture.target,
            &fixture.composition,
            ids(),
            Some(&unchecked_state_bytes(&contradictory_terminal)),
        )),
        D1DmlAttemptCustodyClassification::RestoredStateContradictory
    );
}

#[test]
fn malformed_or_predecessor_state_is_rejected_by_every_consumer() {
    let fixture = fixture();
    let prepared = prepare(&fixture);
    let mut predecessor = state(prepared.state_bytes());
    predecessor.version = 0;
    let bytes = unchecked_state_bytes(&predecessor);

    let results = [
        prepare_d1_dml_attempt(&fixture.target, &fixture.composition, ids(), Some(&bytes)),
        prepare_d1_dml_dispatch_reservation_cas(
            &fixture.target,
            &fixture.composition,
            ids(),
            &bytes,
        ),
        record_d1_dml_attempt_ambiguity(
            &fixture.target,
            &fixture.composition,
            ids(),
            &bytes,
            D1DmlAttemptAmbiguity::ResponseMissing,
        ),
        record_d1_dml_provider_terminal_assertion(
            &fixture.target,
            &fixture.composition,
            ids(),
            &bytes,
            provider(D1DmlProviderTerminalClassification::SucceededChanged),
        ),
        record_d1_dml_readback_terminal_assertion(
            &fixture.target,
            &fixture.composition,
            ids(),
            &bytes,
            readback(D1DmlReadbackTerminalClassification::ExpectedStateObserved),
        ),
    ];
    for result in results {
        assert_eq!(
            classification(result),
            D1DmlAttemptCustodyClassification::RestoredStateUnsupported
        );
    }
}

#[test]
fn receipt_and_errors_are_aggregate_and_content_free() {
    let fixture = fixture();
    let product = prepare(&fixture);
    let receipt = serde_json::to_string(product.receipt()).expect("receipt JSON");
    for private in [
        OPERATION_ID,
        ATTEMPT_ID,
        REQUEST_ID,
        "acct-1",
        DATABASE_ID,
        "items",
        "INSERT",
        "value",
    ] {
        assert!(!receipt.contains(private));
    }

    let error = prepare_d1_dml_attempt(
        &fixture.target,
        &fixture.composition,
        D1DmlAttemptIdentities {
            operation_id: "private invalid identity",
            ..ids()
        },
        None,
    )
    .expect_err("invalid identity");
    let error_json = serde_json::to_string(&error).expect("error JSON");
    assert!(!error_json.contains("private invalid identity"));
}
