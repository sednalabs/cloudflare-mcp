//! Pure D1 row-write claimant/attempt exclusivity.
//!
//! This is intentionally a small, non-persistent foundation. It binds one
//! active attempt to the exact canonical [`D1RowWritePlan`], requires three
//! pairwise-distinct opaque identities, converges exact replay, and rejects a
//! conflicting replay. Persistence/CAS, provider evidence, terminal witness
//! consumption, and dispatch remain later authority boundaries.

use crate::d1_dml_custody_genesis::D1DmlCustodyGenesisAuthority;
use crate::d1_opaque_identity::valid_d1_opaque_identity;
use crate::d1_row_write_plan::D1RowWritePlan;
use crate::d1_target::{D1TargetIdentity, normalize_d1_target};
use crate::tools::sha256_bytes_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1RowWriteCustodyError {
    TargetNotCanonical,
    GenesisTargetMismatch,
    GenesisBindingMismatch,
    PlanTargetMismatch,
    IdentityMalformed,
    IdentityReused,
    ConflictingReplay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1RowWriteAttemptPhase {
    Prepared,
    DispatchReserved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1RowWriteAttemptClaim {
    target_key_sha256: String,
    plan_sha256: String,
    operation_id_sha256: String,
    execution_attempt_id_sha256: String,
    provider_request_id_sha256: String,
    phase: D1RowWriteAttemptPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum D1RowWriteClaimDecision {
    New,
    ExactReplay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D1RowWriteCustodyState {
    target_key_sha256: String,
    genesis_sha256: String,
    generation_sha256: String,
    authority_sha256: String,
    active_attempt: Option<D1RowWriteAttemptClaim>,
}

impl D1RowWriteCustodyState {
    pub(crate) fn new(
        target: &D1TargetIdentity,
        genesis: &D1DmlCustodyGenesisAuthority,
    ) -> Result<Self, D1RowWriteCustodyError> {
        let normalized = normalize_d1_target(&target.account_id, &target.database_id)
            .map_err(|_| D1RowWriteCustodyError::TargetNotCanonical)?;
        if normalized != *target {
            return Err(D1RowWriteCustodyError::TargetNotCanonical);
        }
        if target.target_key_sha256() != genesis.target_key_sha256() {
            return Err(D1RowWriteCustodyError::GenesisTargetMismatch);
        }
        Ok(Self {
            target_key_sha256: target.target_key_sha256(),
            genesis_sha256: genesis.genesis_sha256().to_string(),
            generation_sha256: genesis.custody_generation_sha256().to_string(),
            authority_sha256: genesis.authority_sha256().to_string(),
            active_attempt: None,
        })
    }

    pub(crate) fn claim_attempt(
        &mut self,
        target: &D1TargetIdentity,
        genesis: &D1DmlCustodyGenesisAuthority,
        plan: &D1RowWritePlan,
        operation_id: &str,
        execution_attempt_id: &str,
        provider_request_id: &str,
    ) -> Result<(D1RowWriteClaimDecision, D1RowWriteAttemptClaim), D1RowWriteCustodyError> {
        let normalized = normalize_d1_target(&target.account_id, &target.database_id)
            .map_err(|_| D1RowWriteCustodyError::TargetNotCanonical)?;
        if normalized != *target {
            return Err(D1RowWriteCustodyError::TargetNotCanonical);
        }
        if target.target_key_sha256() != self.target_key_sha256
            || target.target_key_sha256() != genesis.target_key_sha256()
        {
            return Err(D1RowWriteCustodyError::GenesisTargetMismatch);
        }
        if self.genesis_sha256 != genesis.genesis_sha256()
            || self.generation_sha256 != genesis.custody_generation_sha256()
            || self.authority_sha256 != genesis.authority_sha256()
        {
            return Err(D1RowWriteCustodyError::GenesisBindingMismatch);
        }
        if plan.target_key_sha256() != self.target_key_sha256 {
            return Err(D1RowWriteCustodyError::PlanTargetMismatch);
        }
        if !valid_d1_opaque_identity(operation_id)
            || !valid_d1_opaque_identity(execution_attempt_id)
            || !valid_d1_opaque_identity(provider_request_id)
        {
            return Err(D1RowWriteCustodyError::IdentityMalformed);
        }
        if operation_id == execution_attempt_id
            || operation_id == provider_request_id
            || execution_attempt_id == provider_request_id
        {
            return Err(D1RowWriteCustodyError::IdentityReused);
        }
        let candidate = D1RowWriteAttemptClaim {
            target_key_sha256: self.target_key_sha256.clone(),
            plan_sha256: plan.plan_sha256().to_string(),
            operation_id_sha256: sha256_bytes_hex(operation_id.as_bytes()),
            execution_attempt_id_sha256: sha256_bytes_hex(execution_attempt_id.as_bytes()),
            provider_request_id_sha256: sha256_bytes_hex(provider_request_id.as_bytes()),
            phase: D1RowWriteAttemptPhase::Prepared,
        };
        if let Some(active) = self.active_attempt.as_ref() {
            if same_claimant(active, &candidate) {
                return Ok((D1RowWriteClaimDecision::ExactReplay, active.clone()));
            }
            return Err(D1RowWriteCustodyError::ConflictingReplay);
        }
        self.active_attempt = Some(candidate.clone());
        Ok((D1RowWriteClaimDecision::New, candidate))
    }

    pub(crate) fn reserve_dispatch(
        &mut self,
        claim: &D1RowWriteAttemptClaim,
    ) -> Result<D1RowWriteAttemptClaim, D1RowWriteCustodyError> {
        let Some(active) = self.active_attempt.as_mut() else {
            return Err(D1RowWriteCustodyError::ConflictingReplay);
        };
        if active != claim {
            return Err(D1RowWriteCustodyError::ConflictingReplay);
        }
        active.phase = D1RowWriteAttemptPhase::DispatchReserved;
        Ok(active.clone())
    }
}

fn same_claimant(left: &D1RowWriteAttemptClaim, right: &D1RowWriteAttemptClaim) -> bool {
    left.target_key_sha256 == right.target_key_sha256
        && left.plan_sha256 == right.plan_sha256
        && left.operation_id_sha256 == right.operation_id_sha256
        && left.execution_attempt_id_sha256 == right.execution_attempt_id_sha256
        && left.provider_request_id_sha256 == right.provider_request_id_sha256
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d1_dml_custody_genesis::derive_d1_dml_custody_genesis;
    use crate::d1_execute_write::D1WriteStatementKind;
    use crate::d1_row_write_plan::derive_d1_row_write_plan;
    use crate::d1_target::normalize_d1_target;
    use serde_json::json;

    fn target() -> D1TargetIdentity {
        normalize_d1_target("acct-1", "123e4567-e89b-42d3-a456-426614174000")
            .expect("fixture target")
    }

    fn setup() -> (
        D1DmlCustodyGenesisAuthority,
        D1RowWritePlan,
        D1RowWriteCustodyState,
    ) {
        let target = target();
        let (genesis, _) =
            derive_d1_dml_custody_genesis(&target, "custody-generation-0001", &"a".repeat(64))
                .expect("genesis");
        let plan = derive_d1_row_write_plan(
            &target,
            &"b".repeat(64),
            D1WriteStatementKind::Update,
            "UPDATE t SET enabled = ?",
            &[json!(true)],
            1,
        )
        .expect("plan");
        let state = D1RowWriteCustodyState::new(&target, &genesis).expect("state");
        (genesis, plan, state)
    }

    const OPERATION: &str = "operation-00000001";
    const ATTEMPT: &str = "attempt-000000001";
    const PROVIDER: &str = "provider-request-001";

    #[test]
    fn exact_replay_converges_to_one_claim_and_dispatch_reservation() {
        let (genesis, plan, mut state) = setup();
        let target = target();
        let (decision, claim) = state
            .claim_attempt(&target, &genesis, &plan, OPERATION, ATTEMPT, PROVIDER)
            .expect("new claim");
        assert_eq!(decision, D1RowWriteClaimDecision::New);
        let reserved = state.reserve_dispatch(&claim).expect("reserve once");
        assert_eq!(reserved.phase, D1RowWriteAttemptPhase::DispatchReserved);
        let (replay, same) = state
            .claim_attempt(&target, &genesis, &plan, OPERATION, ATTEMPT, PROVIDER)
            .expect("exact replay");
        assert_eq!(replay, D1RowWriteClaimDecision::ExactReplay);
        assert_eq!(same.phase, D1RowWriteAttemptPhase::DispatchReserved);
        assert_eq!(same.operation_id_sha256, claim.operation_id_sha256);
    }

    #[test]
    fn conflicting_replay_and_duplicate_identities_fail_closed() {
        let (genesis, plan, mut state) = setup();
        let target = target();
        state
            .claim_attempt(&target, &genesis, &plan, OPERATION, ATTEMPT, PROVIDER)
            .expect("new claim");
        assert_eq!(
            state.claim_attempt(
                &target,
                &genesis,
                &plan,
                OPERATION,
                ATTEMPT,
                "provider-request-002"
            ),
            Err(D1RowWriteCustodyError::ConflictingReplay)
        );
        assert_eq!(
            state.claim_attempt(&target, &genesis, &plan, OPERATION, OPERATION, PROVIDER),
            Err(D1RowWriteCustodyError::IdentityReused)
        );
    }

    #[test]
    fn claim_requires_exact_genesis_and_plan_target_binding() {
        let (genesis, plan, mut state) = setup();
        let other_target = normalize_d1_target("acct-2", "123e4567-e89b-42d3-a456-426614174000")
            .expect("fixture target");
        assert_eq!(
            state.claim_attempt(&other_target, &genesis, &plan, OPERATION, ATTEMPT, PROVIDER),
            Err(D1RowWriteCustodyError::GenesisTargetMismatch)
        );
        let forged = D1TargetIdentity {
            account_id: " acct-1".to_string(),
            database_id: "123e4567-e89b-42d3-a456-426614174000".to_string(),
        };
        assert_eq!(
            D1RowWriteCustodyState::new(&forged, &genesis),
            Err(D1RowWriteCustodyError::TargetNotCanonical)
        );
    }
}
