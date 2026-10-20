use aauth_rust_resource::Decision;

#[test]
fn manually_constructed_coverage_error_does_not_invent_a_required_list() {
    let response = Decision::<()>::SignatureFailure(aauth_rust_resource::SignatureFailure::Proof(
        aauth_rust_signature_key::Error::InvalidInput,
    ))
    .into_response();
    assert_eq!(response.headers()["signature-error"], "error=invalid_input");
}

#[test]
fn clock_skew_responses_use_the_supplied_verifier_time_for_date() {
    let response =
        Decision::<()>::SignatureFailure(aauth_rust_resource::SignatureFailure::ClockSkew {
            server_time: 1000,
        })
        .into_response();
    assert_eq!(response.headers()["signature-error"], "error=clock_skew");
    assert_eq!(response.headers()["date"], "Thu, 01 Jan 1970 00:16:40 GMT");
}
