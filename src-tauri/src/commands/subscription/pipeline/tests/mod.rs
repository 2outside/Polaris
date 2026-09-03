use super::*;

fn error_kind(value: &Value) -> &str {
    value
        .get("errorKind")
        .and_then(Value::as_str)
        .expect("classified pipeline error must include errorKind")
}

#[test]
fn explicit_parser_sources_keep_their_stable_kinds() {
    assert_eq!(
        error_kind(&classified_parse_submit_error(
            SubscriptionParseSubmitError::Busy
        )),
        "parse_busy"
    );
    assert_eq!(
        error_kind(&classified_parse_submit_error(
            SubscriptionParseSubmitError::InputBudgetExceeded
        )),
        "parse_limit"
    );
    assert_eq!(
        error_kind(&classified_subscription_parse_error(
            SubscriptionParseError::limit("budget")
        )),
        "parse_limit"
    );
    assert_eq!(
        error_kind(&classified_subscription_parse_error(
            SubscriptionParseError::parse("syntax")
        )),
        "parse"
    );
    assert_eq!(
        error_kind(&classified_provider_fatal_error(&ProviderFatalError {
            kind: ProviderFatalErrorKind::ParseBusy,
            message: "executor busy".to_string(),
        })),
        "parse_busy"
    );
    assert_eq!(
        error_kind(&classified_provider_fatal_error(&ProviderFatalError {
            kind: ProviderFatalErrorKind::ParseLimit,
            message: "provider limit".to_string(),
        })),
        "parse_limit"
    );
}

#[test]
fn production_provider_output_cap_matches_aggregation_reservation() {
    let source = polaris_source_probe::crate_file!("src/commands/subscription/pipeline.rs");
    assert!(
        source.contains("max_output_bytes: SUBSCRIPTION_PARSE_INPUT_BYTES"),
        "production provider output must be capped before its aggregate reservation, not at a later 64 MiB boundary"
    );
    assert!(
        source.contains("submit_weighted(aggregate_input_bytes, move ||"),
        "aggregation must reserve the exact retained output"
    );
}

#[test]
fn total_operation_timeout_is_not_a_network_timeout() {
    let error = operation_timeout_error();
    assert_eq!(error_kind(&error), "operation_timeout");
    assert_eq!(error["code"], "SUBSCRIPTION_OPERATION_TIMEOUT");
}
