//! Semantic authority for terminal D1 migration outcomes and manifest prefixes.
//!
//! Durable receipts do not carry a manifest length, so receipt parsing enforces
//! the strongest relationship available from the receipt alone. Terminal
//! requests additionally bind that relationship to the exact supplied manifest.

pub(crate) fn valid_receipt_outcome_prefixes(
    outcome: &str,
    original_prefix_length: usize,
    current_prefix_length: usize,
) -> bool {
    match outcome {
        "not_committed" => current_prefix_length == original_prefix_length,
        "partial_state_converged" | "full_state_converged" => {
            original_prefix_length < current_prefix_length
        }
        _ => false,
    }
}

pub(crate) fn valid_manifest_outcome_prefixes(
    outcome: &str,
    original_prefix_length: usize,
    current_prefix_length: usize,
    manifest_length: usize,
) -> bool {
    if !valid_receipt_outcome_prefixes(outcome, original_prefix_length, current_prefix_length)
        || original_prefix_length > manifest_length
        || current_prefix_length > manifest_length
    {
        return false;
    }
    match outcome {
        "not_committed" => true,
        "partial_state_converged" => current_prefix_length < manifest_length,
        "full_state_converged" => current_prefix_length == manifest_length,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_semantics_enforce_the_strongest_manifest_independent_relationship() {
        let cases = [
            ("not_committed", 0, 0, true),
            ("not_committed", 1, 1, true),
            ("not_committed", 0, 1, false),
            ("not_committed", 2, 1, false),
            ("partial_state_converged", 0, 1, true),
            ("partial_state_converged", 1, 2, true),
            ("partial_state_converged", 1, 1, false),
            ("partial_state_converged", 2, 1, false),
            ("full_state_converged", 0, 1, true),
            ("full_state_converged", 1, 2, true),
            ("full_state_converged", 1, 1, false),
            ("full_state_converged", 2, 1, false),
            ("unknown", 0, 0, false),
        ];
        for (outcome, original, current, expected) in cases {
            assert_eq!(
                valid_receipt_outcome_prefixes(outcome, original, current),
                expected,
                "{outcome}: {original}->{current}"
            );
        }
    }

    #[test]
    fn manifest_semantics_enforce_the_complete_outcome_prefix_product() {
        let cases = [
            ("not_committed", 0, 0, 0, true),
            ("not_committed", 0, 0, 2, true),
            ("not_committed", 1, 1, 2, true),
            ("not_committed", 0, 1, 2, false),
            ("not_committed", 3, 3, 2, false),
            ("partial_state_converged", 0, 1, 2, true),
            ("partial_state_converged", 1, 2, 3, true),
            ("partial_state_converged", 0, 0, 2, false),
            ("partial_state_converged", 0, 2, 2, false),
            ("partial_state_converged", 0, 3, 2, false),
            ("full_state_converged", 0, 1, 1, true),
            ("full_state_converged", 1, 2, 2, true),
            ("full_state_converged", 0, 0, 0, false),
            ("full_state_converged", 0, 1, 2, false),
            ("full_state_converged", 0, 3, 2, false),
            ("unknown", 0, 0, 0, false),
        ];
        for (outcome, original, current, manifest, expected) in cases {
            assert_eq!(
                valid_manifest_outcome_prefixes(outcome, original, current, manifest),
                expected,
                "{outcome}: {original}->{current} of {manifest}"
            );
        }
    }
}
