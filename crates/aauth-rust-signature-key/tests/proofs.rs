use aauth_rust_jose::{Jwk, Jws, SigningKey};
use std::net::IpAddr;
use std::time::Duration;

use aauth_rust_signature_key::{
    AssertionCache, CacheRequest, CachedDocument, DiscoveryFetch, EgressLimits, Error, KeyCache,
    KeyCacheAnswer, KeyCacheStore, KeyMaterial, PreparedRequest, RequestSignature,
    ServerKeyBinding, accept_pinned_peer, accept_response, admit_fetch, admit_redirect,
    choose_presented_scheme, origin_is_allowed, origin_pseudonym, present_issued_cid,
    recognized_tokens, select_presented_scheme, sign_request, sign_requests, signature_error_code,
};
use http::Request;
use serde_json::json;

fn request() -> Request<Vec<u8>> {
    Request::builder()
        .uri("https://resource.example/whoami?x=1")
        .body(Vec::new())
        .unwrap()
}
fn signed() -> (Request<Vec<u8>>, SigningKey) {
    let key = SigningKey::from_seed([7; 32]);
    let mut req = request();
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    (req, key)
}

#[test]
fn hwk_signature_covers_the_actual_target_and_key() {
    let (req, key) = signed();
    let prepared = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    prepared.verify(&key.public_jwk()).unwrap();
    assert!(matches!(prepared.key(), KeyMaterial::Hwk(_)));
    for uri in [
        "https://resource.example/other?x=1",
        "https://other.example/whoami?x=1",
        "https://resource.example/whoami?x=2",
    ] {
        let (mut changed, key) = signed();
        *changed.uri_mut() = uri.parse().unwrap();
        assert!(
            PreparedRequest::prepare(&changed, "sig", 1000, 60)
                .unwrap()
                .verify(&key.public_jwk())
                .is_err()
        );
    }
}

#[test]
fn rfc9421_base_is_independently_checkable() {
    let (req, _) = signed();
    let prepared = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    let key_header = req.headers()["signature-key"].to_str().unwrap();
    let expected = format!(
        "\"@method\": GET\n\"@authority\": resource.example\n\"@path\": /whoami\n\"@query\": ?x=1\n\"signature-key\": {key_header}\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created=1000"
    );
    assert_eq!(prepared.signature_base(), expected.as_bytes());
}

#[test]
fn required_coverage_and_label_correlation_fail_closed() {
    let (mut req, _) = signed();
    req.headers_mut().insert(
        "signature-input",
        "sig=(\"@method\" \"@authority\" \"@path\" \"@query\");created=1000"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .err()
            .unwrap(),
        Error::InvalidInput
    );
    let (req, _) = signed();
    assert!(PreparedRequest::prepare(&req, "missing", 1000, 60).is_err());
}

#[test]
fn signature_time_has_exact_boundaries() {
    let (req, _) = signed();
    for now in [940, 1000, 1060] {
        PreparedRequest::prepare(&req, "sig", now, 60).unwrap();
    }
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 939, 60)
            .err()
            .unwrap(),
        Error::ClockSkew
    );
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1061, 60)
            .err()
            .unwrap(),
        Error::InvalidSignature
    );
}

#[test]
fn unknown_unselected_scheme_does_not_break_selected_proof() {
    let (mut req, key) = signed();
    // Re-sign the full key header including an unselected future scheme.
    let header = format!(
        "{}, other=future;value=token",
        req.headers()["signature-key"].to_str().unwrap()
    );
    req.headers_mut()
        .insert("signature-key", header.parse().unwrap());
    let base = PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .signature_base()
        .to_vec();
    use base64::Engine;
    req.headers_mut().insert(
        "signature",
        format!(
            "sig=:{}:",
            base64::engine::general_purpose::STANDARD.encode(key.sign(&base))
        )
        .parse()
        .unwrap(),
    );
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
}

#[test]
fn inline_key_cannot_carry_a_kid_or_infer_an_algorithm() {
    for suffix in [";kid=\"ambiguous\"", ""] {
        let (mut req, _) = signed();
        let mut value = format!(
            "{}{suffix}",
            req.headers()["signature-key"].to_str().unwrap()
        );
        if suffix.is_empty() {
            value = value.replace(";alg=\"Ed25519\"", "");
        }
        req.headers_mut()
            .insert("signature-key", value.parse().unwrap());
        assert!(PreparedRequest::prepare(&req, "sig", 1000, 60).is_err());
    }
}

#[test]
fn nonempty_body_and_malformed_selected_key_are_refused() {
    let (mut req, _) = signed();
    *req.body_mut() = b"unprotected".to_vec();
    assert!(PreparedRequest::prepare(&req, "sig", 1000, 60).is_err());
    let (mut req, _) = signed();
    req.headers_mut()
        .append("signature-key", "sig=hwk".parse().unwrap());
    assert!(PreparedRequest::prepare(&req, "sig", 1000, 60).is_err());
}

#[test]
fn authority_normalizes_case_and_default_port_per_rfc9421() {
    let key = SigningKey::from_seed([7; 32]);
    for (uri, normalized, expected) in [
        (
            "https://RESOURCE.example:443/whoami",
            "https://resource.example/whoami",
            "resource.example",
        ),
        (
            "https://RESOURCE.example:8443/whoami",
            "https://resource.example:8443/whoami",
            "resource.example:8443",
        ),
        (
            "https://[2001:DB8::1]:443/whoami",
            "https://[2001:db8::1]/whoami",
            "[2001:db8::1]",
        ),
    ] {
        let mut req = Request::builder().uri(uri).body(Vec::new()).unwrap();
        sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
        let proof = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
        let base = std::str::from_utf8(proof.signature_base()).unwrap();
        assert!(
            base.contains(&format!("\"@authority\": {expected}\n")),
            "{base}"
        );
        *req.uri_mut() = normalized.parse().unwrap();
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .unwrap()
            .verify(&key.public_jwk())
            .unwrap();
    }
    for bad in [
        "https://:443/whoami",
        "https://resource.example:notaport/whoami",
        "https://resource.example:65536/whoami",
        "https://user@resource.example/whoami",
    ] {
        let mut req = Request::builder().uri(bad).body(Vec::new()).unwrap();
        assert!(
            sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).is_err(),
            "accepted {bad}"
        );
    }
}

#[test]
fn port_zero_is_refused_as_an_unusable_request_target() {
    for uri in [
        "https://resource.example:0/",
        "https://resource.example:0000/",
        "https://[::1]:0/",
    ] {
        let uri: http::Uri = uri.parse().unwrap();
        assert_eq!(
            aauth_rust_signature_key::canonical_authority(&uri),
            Err(Error::InvalidUri)
        );
    }
}

#[test]
fn malformed_fields_are_not_missing_coverage_errors() {
    for (field, value, code) in [
        ("signature-input", "sig=(", "invalid_signature"),
        (
            "signature-input",
            "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\")",
            "invalid_signature",
        ),
        ("signature-key", "sig=", "invalid_key"),
        ("signature-key", "sig=1", "invalid_key"),
        ("signature-key", "other=hwk", "invalid_signature"),
        ("signature", "sig=", "invalid_signature"),
    ] {
        let (mut req, _) = signed();
        req.headers_mut().insert(field, value.parse().unwrap());
        assert_eq!(
            PreparedRequest::prepare(&req, "sig", 1000, 60)
                .err()
                .unwrap()
                .code(),
            code,
            "{field}: {value}"
        );
    }
}

#[test]
fn local_signing_errors_explain_body_uri_and_clock_units() {
    let key = SigningKey::from_seed([7; 32]);
    let material = || KeyMaterial::Hwk(key.public_jwk());
    let mut req = request();
    *req.body_mut() = vec![1; 1_048_577];
    assert!(
        sign_request(&mut req, &key, material(), 1000)
            .unwrap_err()
            .to_string()
            .contains("body")
    );
    let mut req = request();
    *req.uri_mut() = "http://resource.example/whoami".parse().unwrap();
    assert!(
        sign_request(&mut req, &key, material(), 1000)
            .unwrap_err()
            .to_string()
            .contains("HTTPS")
    );
    let (req, _) = signed();
    assert!(
        PreparedRequest::prepare(&req, "sig", 1_000_000, 60)
            .err()
            .unwrap()
            .to_string()
            .contains("seconds")
    );
}

#[test]
fn expires_cannot_precede_or_equal_created() {
    let (mut req, _) = signed();
    req.headers_mut().insert("signature-input","sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created=1020;expires=1010".parse().unwrap());
    assert!(PreparedRequest::prepare(&req, "sig", 1000, 60).is_err());
}

fn resign(req: &mut Request<Vec<u8>>, key: &SigningKey) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let base = PreparedRequest::prepare(req, "sig", 1000, 60)
        .unwrap()
        .signature_base()
        .to_vec();
    req.headers_mut().insert(
        "signature",
        format!("sig=:{}:", STANDARD.encode(key.sign(&base)))
            .parse()
            .unwrap(),
    );
}

#[test]
fn multiple_field_lines_and_authorization_are_signed_as_combined_values() {
    let key = SigningKey::from_seed([7; 32]);
    let mut req = request();
    req.headers_mut()
        .insert("authorization", "AAuth session".parse().unwrap());
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    req.headers_mut()
        .append("signature-key", "other=future;value=token".parse().unwrap());
    req.headers_mut().append(
        "signature-input",
        "other=(\"@path\");created=1000".parse().unwrap(),
    );
    req.headers_mut()
        .append("signature", "other=:AA==:".parse().unwrap());
    resign(&mut req, &key);
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
    req.headers_mut()
        .insert("authorization", "AAuth changed".parse().unwrap());
    assert!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .unwrap()
            .verify(&key.public_jwk())
            .is_err()
    );
}

#[test]
fn signature_alg_parameter_is_ignored_but_keyid_is_explicitly_unsupported() {
    let (mut req, key) = signed();
    let input = format!(
        "{};alg=\"not-the-key-algorithm\"",
        req.headers()["signature-input"].to_str().unwrap()
    );
    req.headers_mut()
        .insert("signature-input", input.parse().unwrap());
    resign(&mut req, &key);
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
    req.headers_mut().insert(
        "signature-input",
        format!("{input};keyid=\"ap-1\"").parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .err()
            .unwrap()
            .code(),
        "invalid_signature"
    );
}

#[test]
fn keyid_must_equal_the_kid_carried_by_signature_key() {
    let key = SigningKey::from_seed([3; 32]);
    let token = Jws::sign(
        &json!({"alg":"Ed25519","typ":"aa-agent+jwt","kid":"ap-1"}),
        b"{}",
        &key,
    )
    .unwrap();
    let mut req = request();
    sign_request(&mut req, &key, KeyMaterial::Jwt(token), 1000).unwrap();
    let base = req.headers()["signature-input"]
        .to_str()
        .unwrap()
        .to_owned();
    req.headers_mut().insert(
        "signature-input",
        format!("{base};keyid=\"ap-1\"").parse().unwrap(),
    );
    resign(&mut req, &key);
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
    req.headers_mut().insert(
        "signature-input",
        format!("{base};keyid=\"other\"").parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::UnsupportedKeyId
    );
    req.headers_mut().insert(
        "signature-input",
        format!("{base};keyid=1").parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::InvalidSignature
    );

    let mut service = Request::builder()
        .method("POST")
        .uri("https://as.example/token")
        .header("content-type", "application/json")
        .body(b"{}".to_vec())
        .unwrap();
    sign_request(
        &mut service,
        &key,
        KeyMaterial::JwksUri {
            id: "https://ps.example".into(),
            dwk: "aauth-person.json".into(),
            kid: "ps-key".into(),
        },
        1000,
    )
    .unwrap();
    let service_base = service.headers()["signature-input"]
        .to_str()
        .unwrap()
        .to_owned();
    service.headers_mut().insert(
        "signature-input",
        format!("{service_base};keyid=\"ps-key\"").parse().unwrap(),
    );
    resign_with(&mut service, &key, &["jwks_uri"]);
    PreparedRequest::prepare_with_schemes(&service, "sig", 1000, 60, &["jwks_uri"])
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
    service.headers_mut().insert(
        "signature-input",
        format!("{service_base};keyid=\"other\"").parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&service, "sig", 1000, 60, &["jwks_uri"])
            .unwrap_err(),
        Error::UnsupportedKeyId
    );
}

fn resign_with(req: &mut Request<Vec<u8>>, key: &SigningKey, schemes: &[&str]) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let base = PreparedRequest::prepare_with_schemes(req, "sig", 1000, 60, schemes)
        .unwrap()
        .signature_base()
        .to_vec();
    req.headers_mut().insert(
        "signature",
        format!("sig=:{}:", STANDARD.encode(key.sign(&base)))
            .parse()
            .unwrap(),
    );
}

#[test]
fn hwk_rejects_private_material_and_wrong_alg_type_but_allows_extensions() {
    for suffix in [
        ";k=\"secret\"",
        ";p=\"secret\"",
        ";q=\"secret\"",
        ";dp=\"secret\"",
        ";dq=\"secret\"",
        ";qi=\"secret\"",
        ";oth=\"secret\"",
    ] {
        let (mut req, _) = signed();
        let value = format!(
            "{}{suffix}",
            req.headers()["signature-key"].to_str().unwrap()
        );
        req.headers_mut()
            .insert("signature-key", value.parse().unwrap());
        assert_eq!(
            PreparedRequest::prepare(&req, "sig", 1000, 60)
                .err()
                .unwrap()
                .code(),
            "invalid_key",
            "{suffix}"
        );
    }
    let (mut req, _) = signed();
    let value = req.headers()["signature-key"]
        .to_str()
        .unwrap()
        .replace("alg=\"Ed25519\"", "alg=1");
    req.headers_mut()
        .insert("signature-key", value.parse().unwrap());
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .err()
            .unwrap()
            .code(),
        "invalid_key"
    );
    let (mut req, key) = signed();
    let value = format!(
        "{}, sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"{}\";alg=\"future\";alg=\"Ed25519\";extension=?1",
        req.headers()["signature-key"].to_str().unwrap(),
        key.public_jwk().x
    );
    req.headers_mut()
        .insert("signature-key", value.parse().unwrap());
    resign(&mut req, &key);
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
}

#[test]
fn oversized_non_ascii_and_non_integer_signature_fields_get_invalid_signature() {
    for field in ["signature-input", "signature"] {
        for value in [vec![b'x'; 16385], vec![0xff]] {
            let (mut req, _) = signed();
            req.headers_mut()
                .insert(field, http::HeaderValue::from_bytes(&value).unwrap());
            assert_eq!(
                PreparedRequest::prepare(&req, "sig", 1000, 60)
                    .err()
                    .unwrap()
                    .code(),
                "invalid_signature"
            );
        }
    }
    let (mut req, _) = signed();
    let input = req.headers()["signature-input"]
        .to_str()
        .unwrap()
        .replace("created=1000", "created=1000.5");
    req.headers_mut()
        .insert("signature-input", input.parse().unwrap());
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .err()
            .unwrap()
            .code(),
        "invalid_signature"
    );
}

#[test]
fn repeated_signature_input_lines_use_the_last_member_and_verify_its_base() {
    let (mut req, key) = signed();
    let input = req.headers()["signature-input"].clone();
    req.headers_mut().append("signature-input", input.clone());
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
    // Repetition itself changes nothing; changing the selected last member does.
    req.headers_mut().append(
        "signature-input",
        input
            .to_str()
            .unwrap()
            .replace("created=1000", "created=1001")
            .parse()
            .unwrap(),
    );
    let proof = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    assert_eq!(
        proof.verify(&key.public_jwk()),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn local_clock_range_rejects_contemporary_milliseconds_at_sign_and_prepare() {
    let key = SigningKey::from_seed([7; 32]);
    for now in [0, 1_800_000_000, (1_i64 << 33) - 1] {
        let mut req = request();
        sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), now).unwrap();
        PreparedRequest::prepare(&req, "sig", now, 60)
            .unwrap()
            .verify(&key.public_jwk())
            .unwrap();
    }
    for now in [-1, 1_i64 << 33, 1_800_000_000_000, i64::MAX] {
        let mut req = request();
        assert_eq!(
            sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), now),
            Err(Error::InvalidClock)
        );
        let (req, _) = signed();
        assert_eq!(
            PreparedRequest::prepare(&req, "sig", now, 60)
                .err()
                .unwrap(),
            Error::InvalidClock
        );
    }
}

#[test]
fn authorization_coverage_is_the_rfc9421_value_not_raw_outer_whitespace() {
    let key = SigningKey::from_seed([7; 32]);
    let mut req = request();
    req.headers_mut()
        .insert("authorization", "AAuth session".parse().unwrap());
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    let base = PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .signature_base()
        .to_vec();
    for value in [" AAuth session", "AAuth session ", "\tAAuth session\t"] {
        req.headers_mut()
            .insert("authorization", value.parse().unwrap());
        let prepared = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
        assert_eq!(prepared.signature_base(), base);
        prepared.verify(&key.public_jwk()).unwrap();
    }
    req.headers_mut()
        .insert("authorization", "AAuth changed".parse().unwrap());
    assert!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .unwrap()
            .verify(&key.public_jwk())
            .is_err()
    );
    req.headers_mut()
        .insert("authorization", "AAuth".parse().unwrap());
    req.headers_mut()
        .append("authorization", "session".parse().unwrap());
    let combined = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    assert!(
        std::str::from_utf8(combined.signature_base())
            .unwrap()
            .contains("\"authorization\": AAuth, session\n")
    );
    assert!(combined.verify(&key.public_jwk()).is_err());
}

#[test]
fn buffered_body_signing_covers_a_known_sha256_digest_and_content_type() {
    let key = SigningKey::from_seed([7; 32]);
    let mut req = Request::builder()
        .method("POST")
        .uri("https://resource.example/whoami")
        .header("content-type", "text/plain")
        .header("content-digest", "stale")
        .body(b"hello".to_vec())
        .unwrap();
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    assert_eq!(
        req.headers()["content-digest"],
        "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
    );
    let prepared = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    prepared.verify(&key.public_jwk()).unwrap();
    let base = String::from_utf8(prepared.signature_base().to_vec()).unwrap();
    assert!(
        base.contains("\"content-digest\": sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:")
    );
    assert!(base.contains("\"content-type\": text/plain"));
    for body in [b"other".to_vec(), Vec::new()] {
        let mut changed = req.clone();
        *changed.body_mut() = body;
        assert!(
            PreparedRequest::prepare(&changed, "sig", 1000, 60).is_err(),
            "body substitution accepted"
        );
    }
    let mut changed = req.clone();
    changed
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    assert!(
        PreparedRequest::prepare(&changed, "sig", 1000, 60)
            .unwrap()
            .verify(&key.public_jwk())
            .is_err()
    );
}

#[test]
fn bodies_and_supplied_empty_digests_require_covered_valid_sha256() {
    let (mut req, _) = signed();
    *req.body_mut() = b"hello".to_vec();
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::InvalidInput
    );
    let (mut req, _) = signed();
    req.headers_mut().insert(
        "content-digest",
        "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::InvalidInput
    );
    let key = SigningKey::from_seed([7; 32]);
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
    for digest in [
        "sha-256=\"bad\"",
        "sha-256=:AAAA:",
        "sha-512=:AAAA:",
        "malformed",
    ] {
        let mut changed = req.clone();
        changed
            .headers_mut()
            .insert("content-digest", digest.parse().unwrap());
        assert_eq!(
            PreparedRequest::prepare(&changed, "sig", 1000, 60)
                .unwrap_err()
                .code(),
            "invalid_signature"
        );
    }
    req.headers_mut().remove("content-digest");
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .unwrap_err()
            .code(),
        "invalid_signature"
    );
}

#[test]
fn buffered_body_limit_accepts_one_mib_and_refuses_more() {
    let key = SigningKey::from_seed([7; 32]);
    let mut req = request();
    *req.body_mut() = vec![1; 1_048_576];
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
    req.body_mut().push(1);
    assert!(
        sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000)
            .unwrap_err()
            .to_string()
            .contains("1048576")
    );
    assert!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .unwrap_err()
            .to_string()
            .contains("1048576")
    );
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .unwrap_err()
            .code(),
        "invalid_request"
    );
}

#[test]
fn empty_covered_field_values_are_signed_distinctly_from_missing_fields() {
    let key = SigningKey::from_seed([7; 32]);
    for empty in ["", " \t "] {
        let mut req = request();
        *req.body_mut() = b"hello".to_vec();
        req.headers_mut()
            .insert("content-type", empty.parse().unwrap());
        sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
        let proof = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
        assert!(
            std::str::from_utf8(proof.signature_base())
                .unwrap()
                .contains("\"content-type\": \n")
        );
        proof.verify(&key.public_jwk()).unwrap();
        req.headers_mut().remove("content-type");
        assert!(PreparedRequest::prepare(&req, "sig", 1000, 60).is_err());
    }
}

#[test]
fn empty_field_lines_keep_their_positions_in_the_canonical_combination() {
    let key = SigningKey::from_seed([7; 32]);
    let mut req = request();
    for value in ["", "AAuth credential", ""] {
        req.headers_mut()
            .append("authorization", value.parse().unwrap());
    }
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    let proof = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    assert!(
        std::str::from_utf8(proof.signature_base())
            .unwrap()
            .contains("\"authorization\": , AAuth credential, \n")
    );
    proof.verify(&key.public_jwk()).unwrap();
    req.headers_mut().remove("authorization");
    req.headers_mut()
        .insert("authorization", "AAuth credential".parse().unwrap());
    assert!(
        PreparedRequest::prepare(&req, "sig", 1000, 60)
            .unwrap()
            .verify(&key.public_jwk())
            .is_err()
    );
}

#[test]
fn replacing_both_body_and_matching_digest_still_requires_a_new_signature() {
    let key = SigningKey::from_seed([7; 32]);
    let mut req = request();
    *req.body_mut() = b"hello".to_vec();
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    req.body_mut().clear();
    req.headers_mut().insert(
        "content-digest",
        "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
            .parse()
            .unwrap(),
    );
    let proof = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    assert_eq!(
        proof.verify(&key.public_jwk()).unwrap_err(),
        Error::InvalidSignature
    );
}

#[test]
fn an_empty_digest_does_not_make_content_type_a_body_requirement() {
    let key = SigningKey::from_seed([7; 32]);
    let mut req = request();
    req.headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    req.headers_mut().insert(
        "content-digest",
        "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
            .parse()
            .unwrap(),
    );
    sign_request(&mut req, &key, KeyMaterial::Hwk(key.public_jwk()), 1000).unwrap();
    assert!(
        !req.headers()["signature-input"]
            .to_str()
            .unwrap()
            .contains("content-type")
    );
    req.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .verify(&key.public_jwk())
        .unwrap();
}

#[test]
fn jwks_uri_service_proof_is_explicit_and_binds_identity_and_body() {
    // Signature-Key jwks-uri-scheme; Core ps-to-as-token-request.
    let key = SigningKey::from_seed([8; 32]);
    let mut req = Request::builder()
        .method("POST")
        .uri("https://as.example/token")
        .header("content-type", "application/json")
        .body(b"{}".to_vec())
        .unwrap();
    let material = KeyMaterial::JwksUri {
        id: "https://ps.example".into(),
        dwk: "aauth-person.json".into(),
        kid: "ps-key".into(),
    };
    sign_request(&mut req, &key, material, 1000).unwrap();
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::UnsupportedScheme
    );
    let proof =
        PreparedRequest::prepare_with_schemes(&req, "sig", 1000, 60, &["jwks_uri"]).unwrap();
    proof.verify(&key.public_jwk()).unwrap();
    assert!(matches!(proof.key(), KeyMaterial::JwksUri { id, dwk, kid }
        if id == "https://ps.example" && dwk == "aauth-person.json" && kid == "ps-key"));
    assert!(
        proof
            .verify(&SigningKey::from_seed([9; 32]).public_jwk())
            .is_err()
    );
    let header = req.headers()["signature-key"]
        .to_str()
        .unwrap()
        .replace("ps.example", "foreign.example");
    req.headers_mut()
        .insert("signature-key", header.parse().unwrap());
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&req, "sig", 1000, 60, &["jwks_uri"])
            .unwrap()
            .verify(&key.public_jwk()),
        Err(Error::InvalidSignature)
    );
    req.body_mut().push(b' ');
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&req, "sig", 1000, 60, &["jwks_uri"]).unwrap_err(),
        Error::InvalidDigest
    );
}

#[test]
fn jwks_uri_parameters_cannot_inject_headers_or_discovery_paths() {
    let key = SigningKey::from_seed([8; 32]);
    for (id, dwk, kid) in [
        ("http://ps.example", "aauth-person.json", "k"),
        ("https://ps.example/path", "aauth-person.json", "k"),
        ("https://ps.example", "../private", "k"),
        ("https://ps.example", "aauth-person.json", ""),
        (
            "https://ps.example",
            "aauth-person.json",
            "k\nInjected: value",
        ),
    ] {
        assert_eq!(
            sign_request(
                &mut request(),
                &key,
                KeyMaterial::JwksUri {
                    id: id.into(),
                    dwk: dwk.into(),
                    kid: kid.into()
                },
                1000
            ),
            Err(Error::InvalidKey)
        );
    }
}

fn jkt_assertion(
    identity: &SigningKey,
    confirmation: &aauth_rust_jose::Jwk,
    iat: i64,
    exp: i64,
    issuer: &str,
    jti: Option<&str>,
    typ: &str,
) -> String {
    let mut payload = json!({
        "iss": issuer,
        "iat": iat,
        "exp": exp,
        "cnf": {"jwk": confirmation},
    });
    if let Some(jti) = jti {
        payload["jti"] = json!(jti);
    }
    Jws::sign(
        &json!({"alg":"Ed25519","typ":typ,"jwk":identity.public_jwk()}),
        &serde_json::to_vec(&payload).unwrap(),
        identity,
    )
    .unwrap()
}

fn jkt_request(cache: bool, jti: Option<&str>) -> (Request<Vec<u8>>, SigningKey, SigningKey) {
    let identity = SigningKey::from_seed([4; 32]);
    let ephemeral = SigningKey::from_seed([5; 32]);
    let issuer = format!(
        "urn:jkt:sha-256:{}",
        identity.public_jwk().thumbprint().unwrap()
    );
    let jwt = jkt_assertion(
        &identity,
        &ephemeral.public_jwk(),
        1000,
        2000,
        &issuer,
        jti,
        "jkt-s256+jwt",
    );
    let mut req = request();
    sign_request(
        &mut req,
        &ephemeral,
        KeyMaterial::JktJwt { jwt, cache },
        1000,
    )
    .unwrap();
    (req, identity, ephemeral)
}

fn verify_presented_jkt(
    jwt: &str,
    signer: &SigningKey,
) -> Result<aauth_rust_signature_key::JktDelegation, Error> {
    let (mut req, _, _) = jkt_request(false, None);
    req.headers_mut().insert(
        "signature-key",
        format!("sig=jkt-jwt;jwt=\"{jwt}\"").parse().unwrap(),
    );
    resign_with(&mut req, signer, &["jkt-jwt"]);
    PreparedRequest::prepare_with_schemes(&req, "sig", 1000, 60, &["jkt-jwt"])
        .unwrap()
        .verify_jkt_jwt(1000)
}

#[test]
fn jkt_jwt_delegates_signing_and_binds_the_enclave_thumbprint() {
    let (req, identity, ephemeral) = jkt_request(false, None);
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::UnsupportedScheme
    );
    let prepared =
        PreparedRequest::prepare_with_schemes(&req, "sig", 1000, 60, &["jkt-jwt"]).unwrap();
    let delegation = prepared.verify_jkt_jwt(1000).unwrap();
    assert_eq!(
        delegation.issuer,
        format!(
            "urn:jkt:sha-256:{}",
            identity.public_jwk().thumbprint().unwrap()
        )
    );
    assert_eq!(delegation.confirmation.x, ephemeral.public_jwk().x);
    assert_eq!(delegation.identity.x, identity.public_jwk().x);
    assert_eq!(delegation.confirmation.alg, "Ed25519");
    assert_eq!(delegation.identity.alg, "Ed25519");
    assert!(!delegation.cache);
    assert!(delegation.jti.is_none());
    assert_eq!(prepared.verify_jkt_jwt(1999).unwrap().expires_at, 2000);
    assert_eq!(
        prepared.verify_jkt_jwt(2000).unwrap_err(),
        Error::ExpiredJwt
    );

    let mut wrong_http = req.clone();
    resign_with(&mut wrong_http, &identity, &["jkt-jwt"]);
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&wrong_http, "sig", 1000, 60, &["jkt-jwt"])
            .unwrap()
            .verify_jkt_jwt(1000)
            .unwrap_err(),
        Error::InvalidSignature
    );

    assert_eq!(
        sign_request(
            &mut request(),
            &identity,
            KeyMaterial::JktJwt {
                jwt: req.headers()["signature-key"]
                    .to_str()
                    .unwrap()
                    .split_once("jwt=\"")
                    .unwrap()
                    .1
                    .trim_end_matches('"')
                    .into(),
                cache: false
            },
            1000
        )
        .unwrap_err(),
        Error::InvalidKey
    );

    let mut missing = req.clone();
    missing
        .headers_mut()
        .insert("signature-key", "sig=jkt-jwt".parse().unwrap());
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&missing, "sig", 1000, 60, &["jkt-jwt"]).unwrap_err(),
        Error::InvalidKey
    );
    let mut malformed = req.clone();
    malformed.headers_mut().insert(
        "signature-key",
        "sig=jkt-jwt;jwt=\"not-a-jwt\"".parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&malformed, "sig", 1000, 60, &["jkt-jwt"])
            .unwrap()
            .verify_jkt_jwt(1000)
            .unwrap_err(),
        Error::InvalidJwt
    );

    let (cached, _, _) = jkt_request(true, Some("delegation-1"));
    let cached_proof =
        PreparedRequest::prepare_with_schemes(&cached, "sig", 1000, 60, &["jkt-jwt"])
            .unwrap()
            .verify_jkt_jwt(1000)
            .unwrap();
    assert!(cached_proof.cache);
    assert_eq!(cached_proof.jti.as_deref(), Some("delegation-1"));
    assert!(
        cached.headers()["signature-key"]
            .to_str()
            .unwrap()
            .ends_with(";cache")
    );

    let identity = SigningKey::from_seed([4; 32]);
    let ephemeral = SigningKey::from_seed([5; 32]);
    let issuer = format!(
        "urn:jkt:sha-256:{}",
        identity.public_jwk().thumbprint().unwrap()
    );
    let without_jti = jkt_assertion(
        &identity,
        &ephemeral.public_jwk(),
        1000,
        2000,
        &issuer,
        None,
        "jkt-s256+jwt",
    );
    assert_eq!(
        sign_request(
            &mut request(),
            &ephemeral,
            KeyMaterial::JktJwt {
                jwt: without_jti,
                cache: true
            },
            1000
        )
        .unwrap_err(),
        Error::InvalidJwt
    );
    let mut assigned = cached.clone();
    let header = assigned.headers()["signature-key"]
        .to_str()
        .unwrap()
        .to_owned();
    assigned.headers_mut().insert(
        "signature-key",
        header.replace(";cache", ";cache=?1").parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&assigned, "sig", 1000, 60, &["jkt-jwt"])
            .unwrap_err(),
        Error::InvalidKey
    );

    let skewed = jkt_assertion(
        &identity,
        &ephemeral.public_jwk(),
        1061,
        2000,
        &issuer,
        None,
        "jkt-s256+jwt",
    );
    let mut skewed_req = request();
    sign_request(
        &mut skewed_req,
        &ephemeral,
        KeyMaterial::JktJwt {
            jwt: skewed,
            cache: false,
        },
        1000,
    )
    .unwrap();
    let skewed_proof =
        PreparedRequest::prepare_with_schemes(&skewed_req, "sig", 1000, 60, &["jkt-jwt"]).unwrap();
    assert_eq!(
        skewed_proof.verify_jkt_jwt(1000).unwrap_err(),
        Error::ClockSkew
    );
    let on_window = jkt_assertion(
        &identity,
        &ephemeral.public_jwk(),
        1060,
        2000,
        &issuer,
        None,
        "jkt-s256+jwt",
    );
    let mut on_window_req = request();
    sign_request(
        &mut on_window_req,
        &ephemeral,
        KeyMaterial::JktJwt {
            jwt: on_window,
            cache: false,
        },
        1000,
    )
    .unwrap();
    PreparedRequest::prepare_with_schemes(&on_window_req, "sig", 1000, 60, &["jkt-jwt"])
        .unwrap()
        .verify_jkt_jwt(1000)
        .unwrap();

    let wrong_iss = jkt_assertion(
        &identity,
        &ephemeral.public_jwk(),
        1000,
        2000,
        "urn:jkt:sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        None,
        "jkt-s256+jwt",
    );
    assert_eq!(
        sign_request(
            &mut request(),
            &ephemeral,
            KeyMaterial::JktJwt {
                jwt: wrong_iss,
                cache: false
            },
            1000
        )
        .unwrap_err(),
        Error::InvalidJwt
    );
    let wrong_typ = jkt_assertion(
        &identity,
        &ephemeral.public_jwk(),
        1000,
        2000,
        &issuer,
        None,
        "jkt-s512+jwt",
    );
    assert_eq!(
        sign_request(
            &mut request(),
            &ephemeral,
            KeyMaterial::JktJwt {
                jwt: wrong_typ,
                cache: false
            },
            1000
        )
        .unwrap_err(),
        Error::InvalidJwt
    );

    let mut no_jwk = json!({"alg":"Ed25519","typ":"jkt-s256+jwt"});
    let compact = Jws::sign(&no_jwk, b"{}", &identity).unwrap();
    assert_eq!(
        sign_request(
            &mut request(),
            &ephemeral,
            KeyMaterial::JktJwt {
                jwt: compact,
                cache: false
            },
            1000
        )
        .unwrap_err(),
        Error::InvalidJwt
    );
    no_jwk = json!({"alg":"Ed25519","typ":"jkt-s256+jwt","jwk":identity.public_jwk()});
    let mut claims = json!({"iss":issuer,"iat":1000,"exp":2000});
    let compact = Jws::sign(&no_jwk, &serde_json::to_vec(&claims).unwrap(), &identity).unwrap();
    assert_eq!(
        sign_request(
            &mut request(),
            &ephemeral,
            KeyMaterial::JktJwt {
                jwt: compact,
                cache: false
            },
            1000
        )
        .unwrap_err(),
        Error::InvalidJwt,
        "cnf is required"
    );
    claims["cnf"] = json!({"jwk":{"kty":"OKP","crv":"Ed25519","x":ephemeral.public_jwk().x}});
    let compact = Jws::sign(&no_jwk, &serde_json::to_vec(&claims).unwrap(), &identity).unwrap();
    assert_eq!(
        sign_request(
            &mut request(),
            &ephemeral,
            KeyMaterial::JktJwt {
                jwt: compact,
                cache: false
            },
            1000
        )
        .unwrap_err(),
        Error::UnsupportedAlgorithm,
        "confirmation alg is required"
    );

    let other = SigningKey::from_seed([9; 32]);
    let forged = Jws::sign(
        &json!({"alg":"Ed25519","typ":"jkt-s256+jwt","jwk":identity.public_jwk()}),
        &serde_json::to_vec(&json!({
            "iss": issuer,
            "iat": 1000,
            "exp": 2000,
            "cnf": {"jwk": ephemeral.public_jwk()}
        }))
        .unwrap(),
        &other,
    )
    .unwrap();
    assert_eq!(
        verify_presented_jkt(&forged, &ephemeral).unwrap_err(),
        Error::InvalidJwt,
        "header jwk is the root of trust"
    );
    let omitted_typ = Jws::sign(
        &json!({"alg":"Ed25519","jwk":identity.public_jwk()}),
        &serde_json::to_vec(&json!({
            "iss": issuer,
            "iat": 1000,
            "exp": 2000,
            "cnf": {"jwk": ephemeral.public_jwk()}
        }))
        .unwrap(),
        &identity,
    )
    .unwrap();
    assert_eq!(
        verify_presented_jkt(&omitted_typ, &ephemeral).unwrap_err(),
        Error::InvalidJwt,
        "typ is required"
    );
    let payload = serde_json::to_vec(&json!({
        "iss": issuer,
        "iat": 1000,
        "exp": 2000,
        "cnf": {"jwk": ephemeral.public_jwk()}
    }))
    .unwrap();
    let omitted_alg = format!(
        "{}.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"typ":"jkt-s256+jwt","jwk":{}}"#),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 64])
    );
    assert_eq!(
        verify_presented_jkt(&omitted_alg, &ephemeral).unwrap_err(),
        Error::UnsupportedAlgorithm,
        "alg is required"
    );
    let omitted_iat = Jws::sign(
        &json!({"alg":"Ed25519","typ":"jkt-s256+jwt","jwk":identity.public_jwk()}),
        &serde_json::to_vec(&json!({
            "iss": issuer,
            "exp": 2000,
            "cnf": {"jwk": ephemeral.public_jwk()}
        }))
        .unwrap(),
        &identity,
    )
    .unwrap();
    assert_eq!(
        verify_presented_jkt(&omitted_iat, &ephemeral).unwrap_err(),
        Error::InvalidJwt,
        "iat is required"
    );
    let omitted_exp = Jws::sign(
        &json!({"alg":"Ed25519","typ":"jkt-s256+jwt","jwk":identity.public_jwk()}),
        &serde_json::to_vec(&json!({
            "iss": issuer,
            "iat": 1000,
            "cnf": {"jwk": ephemeral.public_jwk()}
        }))
        .unwrap(),
        &identity,
    )
    .unwrap();
    assert_eq!(
        verify_presented_jkt(&omitted_exp, &ephemeral).unwrap_err(),
        Error::InvalidJwt,
        "exp is required"
    );
    let sha512 = jkt_assertion(
        &identity,
        &ephemeral.public_jwk(),
        1000,
        2000,
        "urn:jkt:sha-512:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        None,
        "jkt-s256+jwt",
    );
    assert_eq!(
        verify_presented_jkt(&sha512, &ephemeral).unwrap_err(),
        Error::InvalidJwt,
        "jkt-s256+jwt requires the sha-256 issuer prefix"
    );
    let mut ec_cnf = ephemeral.public_jwk();
    ec_cnf.kty = "EC".into();
    ec_cnf.crv = "P-256".into();
    ec_cnf.alg = "ES256".into();
    ec_cnf.y = ec_cnf.x.clone();
    let delegated = Jws::sign(
        &json!({"alg":"Ed25519","typ":"jkt-s256+jwt","jwk":identity.public_jwk()}),
        &serde_json::to_vec(&json!({
            "iss": issuer,
            "iat": 1000,
            "exp": 2000,
            "cnf": {"jwk": ec_cnf}
        }))
        .unwrap(),
        &identity,
    )
    .unwrap();
    assert_eq!(
        verify_presented_jkt(&delegated, &ephemeral).unwrap_err(),
        Error::UnsupportedAlgorithm,
        "jkt confirmation is Ed25519"
    );

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let foreign = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"jkt-s256+jwt"}"#),
        URL_SAFE_NO_PAD.encode(b"{}"),
        URL_SAFE_NO_PAD.encode([1u8; 64])
    );
    assert_eq!(
        sign_request(
            &mut request(),
            &ephemeral,
            KeyMaterial::JktJwt {
                jwt: foreign,
                cache: false
            },
            1000
        )
        .unwrap_err(),
        Error::UnsupportedAlgorithm
    );
}

fn self_compact(key: &SigningKey, header: serde_json::Value, payload: serde_json::Value) -> String {
    Jws::sign(&header, &serde_json::to_vec(&payload).unwrap(), key).unwrap()
}

fn self_request(compact: &str, key: &SigningKey) -> Request<Vec<u8>> {
    let mut req = request();
    sign_request(
        &mut req,
        key,
        KeyMaterial::SelfJwt {
            jwt: compact.into(),
        },
        1000,
    )
    .unwrap();
    req
}

#[test]
fn self_jwt_uses_the_discovered_key_and_rejects_confirmation() {
    use std::cell::Cell;

    let key = SigningKey::from_seed([6; 32]);
    let issuer = "https://Issuer.example";
    let dwk = "aauth-resource.json";
    let kid = "r1";
    let header = json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid});
    let payload = json!({"iss": issuer, "dwk": dwk, "exp": 2000, "aud": "https://agent.example"});
    let compact = self_compact(&key, header, payload);
    let req = self_request(&compact, &key);
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::UnsupportedScheme
    );
    assert!(
        !req.headers()["signature-key"]
            .to_str()
            .unwrap()
            .contains("cache")
    );
    let calls = Cell::new(0u32);
    let metadata = format!(r#"{{"issuer":"{issuer}"}}"#);
    let public = key.public_jwk();
    let resolver = |iss: &str, document: &str, key_id: &str| {
        calls.set(calls.get() + 1);
        if iss == issuer && document == dwk && key_id == kid {
            Ok(public.clone())
        } else {
            Err(Error::UnknownKey)
        }
    };
    let prepared =
        PreparedRequest::prepare_with_schemes(&req, "sig", 1000, 60, &["self-jwt"]).unwrap();
    let assertion = prepared
        .verify_self_jwt(metadata.as_bytes(), &resolver, 1000, "aa-event+jwt")
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(assertion.issuer, issuer);
    assert_eq!(assertion.discovery_document, dwk);
    assert_eq!(assertion.key_id, kid);
    assert_eq!(assertion.expires_at, 2000);
    assert_eq!(assertion.compact, compact);
    assert!(assertion.cache_identifier().is_none());
    let mut copied = assertion.payload();
    copied[0] = b'x';
    assert_ne!(copied, assertion.payload());
    assert_eq!(
        prepared
            .verify_self_jwt(metadata.as_bytes(), &resolver, 1999, "aa-event+jwt")
            .unwrap()
            .expires_at,
        2000
    );

    let mut wrong_http = req.clone();
    resign_with(
        &mut wrong_http,
        &SigningKey::from_seed([9; 32]),
        &["self-jwt"],
    );
    calls.set(0);
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&wrong_http, "sig", 1000, 60, &["self-jwt"])
            .unwrap()
            .verify_self_jwt(metadata.as_bytes(), &resolver, 1000, "aa-event+jwt")
            .unwrap_err(),
        Error::InvalidSignature
    );
    assert_eq!(calls.get(), 1);

    assert_eq!(
        sign_request(
            &mut request(),
            &SigningKey::from_seed([9; 32]),
            KeyMaterial::SelfJwt {
                jwt: compact.clone()
            },
            1000
        )
        .unwrap_err(),
        Error::InvalidKey
    );

    let refuse = |_: &str, _: &str, _: &str| -> Result<_, Error> {
        panic!("resolver ran before the JWT was acceptable");
    };
    let reject = |compact: String, now: i64, want: Error| {
        let mut forged = req.clone();
        forged.headers_mut().insert(
            "signature-key",
            format!("sig=self-jwt;jwt=\"{compact}\"").parse().unwrap(),
        );
        assert_eq!(
            PreparedRequest::prepare_with_schemes(&forged, "sig", now, 60, &["self-jwt"])
                .unwrap()
                .verify_self_jwt(metadata.as_bytes(), &refuse, now, "aa-event+jwt")
                .unwrap_err(),
            want
        );
    };
    let confirmed = self_compact(
        &key,
        json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
        json!({"iss": issuer, "dwk": dwk, "exp": 2000, "cnf": {"jwk": key.public_jwk()}}),
    );
    assert_eq!(
        sign_request(
            &mut request(),
            &key,
            KeyMaterial::SelfJwt {
                jwt: confirmed.clone()
            },
            1000
        )
        .unwrap_err(),
        Error::InvalidJwt
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"dwk": dwk, "exp": 2000}),
        ),
        1000,
        Error::InvalidJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"iss": "http://Issuer.example", "dwk": dwk, "exp": 2000}),
        ),
        1000,
        Error::InvalidJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"iss": "https://Issuer.example/path", "dwk": dwk, "exp": 2000}),
        ),
        1000,
        Error::InvalidJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"iss": issuer, "dwk": "../private", "exp": 2000}),
        ),
        1000,
        Error::InvalidJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt"}),
            json!({"iss": issuer, "dwk": dwk, "exp": 2000}),
        ),
        1000,
        Error::InvalidJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-other+jwt","kid":kid}),
            json!({"iss": issuer, "dwk": dwk, "exp": 2000}),
        ),
        1000,
        Error::InvalidJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"iss": issuer, "dwk": dwk, "exp": 2000, "cnf": {"jwk": key.public_jwk()}}),
        ),
        1000,
        Error::InvalidJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"iss": issuer, "dwk": dwk, "exp": 1000}),
        ),
        1000,
        Error::ExpiredJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"iss": issuer, "dwk": dwk, "iat": 1061, "exp": 2000}),
        ),
        1000,
        Error::ClockSkew,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"iss": issuer, "exp": 2000}),
        ),
        1000,
        Error::InvalidJwt,
    );
    reject(
        self_compact(
            &key,
            json!({"alg":"Ed25519","typ":"aa-event+jwt","kid":kid}),
            json!({"iss": issuer, "dwk": dwk}),
        ),
        1000,
        Error::InvalidJwt,
    );
    calls.set(0);
    assert_eq!(
        prepared
            .verify_self_jwt(b"{}", &resolver, 1000, "aa-event+jwt")
            .unwrap_err(),
        Error::IssuerMissing
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(
        prepared
            .verify_self_jwt(
                br#"{"issuer":"https://other.example"}"#,
                &resolver,
                1000,
                "aa-event+jwt",
            )
            .unwrap_err(),
        Error::IssuerMismatch
    );
    assert_eq!(calls.get(), 0);

    let mut missing = req.clone();
    missing
        .headers_mut()
        .insert("signature-key", "sig=self-jwt".parse().unwrap());
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&missing, "sig", 1000, 60, &["self-jwt"])
            .unwrap_err(),
        Error::InvalidKey
    );
    let mut malformed = req.clone();
    malformed.headers_mut().insert(
        "signature-key",
        "sig=self-jwt;jwt=\"not-a-jwt\"".parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&malformed, "sig", 1000, 60, &["self-jwt"])
            .unwrap()
            .verify_self_jwt(metadata.as_bytes(), &refuse, 1000, "aa-event+jwt")
            .unwrap_err(),
        Error::InvalidJwt
    );
    for suffix in [";cache", ";cache=?1", ";cache=?0"] {
        let mut cached = req.clone();
        let header = format!(
            "{}{suffix}",
            cached.headers()["signature-key"].to_str().unwrap()
        );
        cached
            .headers_mut()
            .insert("signature-key", header.parse().unwrap());
        assert_eq!(
            PreparedRequest::prepare_with_schemes(&cached, "sig", 1000, 60, &["self-jwt"])
                .unwrap_err(),
            Error::InvalidKey,
            "{suffix}"
        );
    }

    calls.set(0);
    let unknown = prepared
        .verify_self_jwt(
            metadata.as_bytes(),
            &|iss: &str, document: &str, key_id: &str| {
                calls.set(calls.get() + 1);
                let _ = (iss, document, key_id);
                Err(Error::UnknownKey)
            },
            1000,
            "aa-event+jwt",
        )
        .unwrap_err();
    assert_eq!(unknown, Error::UnknownKey);
    assert_eq!(calls.get(), 1);
    let mut unsupported = key.public_jwk();
    unsupported.alg = "ES512".into();
    assert_eq!(
        prepared
            .verify_self_jwt(
                metadata.as_bytes(),
                &|_: &str, _: &str, _: &str| Ok(unsupported.clone()),
                1000,
                "aa-event+jwt"
            )
            .unwrap_err(),
        Error::UnsupportedAlgorithm
    );
    calls.set(0);
    assert_eq!(
        prepared
            .verify_self_jwt(metadata.as_bytes(), &resolver, 1000, "")
            .unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn direct_jwks_keeps_the_url_bytes_as_the_signer_identity() {
    use std::cell::RefCell;

    let key = SigningKey::from_seed([3; 32]);
    let url = "https://client.example/keys.jwks";
    let kid = "key-1";
    let mut req = request();
    sign_request(
        &mut req,
        &key,
        KeyMaterial::Jwks {
            url: url.into(),
            kid: kid.into(),
        },
        1000,
    )
    .unwrap();
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::UnsupportedScheme
    );
    assert!(
        req.headers()["signature-key"]
            .to_str()
            .unwrap()
            .contains(url)
    );
    let seen = RefCell::new(String::new());
    let seen_kid = RefCell::new(String::new());
    let public = key.public_jwk();
    let resolver = |presented: &str, key_id: &str| {
        *seen.borrow_mut() = presented.to_owned();
        *seen_kid.borrow_mut() = key_id.to_owned();
        if presented == url && key_id == kid {
            Ok(public.clone())
        } else {
            Err(Error::UnknownKey)
        }
    };
    let prepared = PreparedRequest::prepare_with_schemes(&req, "sig", 1000, 60, &["jwks"]).unwrap();
    let identity = prepared.verify_jwks(&resolver).unwrap();
    assert_eq!(identity.url, url);
    assert_eq!(identity.key_id, kid);
    assert_eq!(identity.key.x, public.x);
    assert_eq!(seen.borrow().as_str(), url);

    for other in [
        "https://Client.example/keys.jwks",
        "https://client.example:443/keys.jwks",
        "https://client.example/keys.jwks/",
        "https://client.example/Keys.jwks",
        "https://client.example/../keys.jwks",
        "https://client.example/keys.jwks?v=1",
    ] {
        let mut variant = request();
        sign_request(
            &mut variant,
            &key,
            KeyMaterial::Jwks {
                url: other.into(),
                kid: kid.into(),
            },
            1000,
        )
        .unwrap();
        let proof =
            PreparedRequest::prepare_with_schemes(&variant, "sig", 1000, 60, &["jwks"]).unwrap();
        assert!(matches!(proof.key(), KeyMaterial::Jwks { url, .. } if url == other));
        assert_eq!(proof.verify_jwks(&resolver).unwrap_err(), Error::UnknownKey);
        assert_eq!(seen.borrow().as_str(), other);
        assert_eq!(seen_kid.borrow().as_str(), kid);
    }

    let mut wrong_http = req.clone();
    resign_with(&mut wrong_http, &SigningKey::from_seed([9; 32]), &["jwks"]);
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&wrong_http, "sig", 1000, 60, &["jwks"])
            .unwrap()
            .verify_jwks(&resolver)
            .unwrap_err(),
        Error::InvalidSignature
    );

    for (bad_url, bad_kid) in [
        ("http://client.example/keys.jwks", kid),
        ("https://user@client.example/keys.jwks", kid),
        ("https://client.example/keys.jwks#frag", kid),
        ("https://client.example:0/keys.jwks", kid),
        (url, ""),
        ("", kid),
    ] {
        assert_eq!(
            sign_request(
                &mut request(),
                &key,
                KeyMaterial::Jwks {
                    url: bad_url.into(),
                    kid: bad_kid.into(),
                },
                1000
            )
            .unwrap_err(),
            Error::InvalidKey,
            "{bad_url} {bad_kid}"
        );
    }
    for header in [
        "sig=jwks;kid=\"key-1\"",
        "sig=jwks;url=\"https://client.example/keys.jwks\"",
    ] {
        let mut missing = req.clone();
        missing
            .headers_mut()
            .insert("signature-key", header.parse().unwrap());
        assert_eq!(
            PreparedRequest::prepare_with_schemes(&missing, "sig", 1000, 60, &["jwks"])
                .unwrap_err(),
            Error::InvalidKey,
            "{header}"
        );
    }
    let mut unsupported = key.public_jwk();
    unsupported.alg = "ES512".into();
    assert_eq!(
        prepared
            .verify_jwks(&|_: &str, _: &str| Ok(unsupported.clone()))
            .unwrap_err(),
        Error::UnsupportedAlgorithm
    );
    let mut ec = key.public_jwk();
    ec.kty = "EC".into();
    ec.crv = "P-256".into();
    ec.alg = "ES256".into();
    ec.y = ec.x.clone();
    assert_eq!(
        prepared
            .verify_jwks(&|_: &str, _: &str| Ok(ec.clone()))
            .unwrap_err(),
        Error::UnsupportedAlgorithm
    );
}

fn hwk_proof(header: &str, len: usize, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Request<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut req = request();
    req.headers_mut()
        .insert("signature-key", header.parse().unwrap());
    req.headers_mut().insert(
        "signature-input",
        "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created=1000"
            .parse()
            .unwrap(),
    );
    req.headers_mut().insert(
        "signature",
        format!("sig=:{}:", STANDARD.encode(vec![1u8; len]))
            .parse()
            .unwrap(),
    );
    let base = PreparedRequest::prepare(&req, "sig", 1000, 60)
        .unwrap()
        .signature_base()
        .to_vec();
    req.headers_mut().insert(
        "signature",
        format!("sig=:{}:", STANDARD.encode(sign(&base)))
            .parse()
            .unwrap(),
    );
    req
}

fn hwk_error(header: &str) -> Error {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut req = request();
    req.headers_mut()
        .insert("signature-key", header.parse().unwrap());
    req.headers_mut().insert(
        "signature-input",
        "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created=1000"
            .parse()
            .unwrap(),
    );
    req.headers_mut().insert(
        "signature",
        format!("sig=:{}:", STANDARD.encode([1u8; 64]))
            .parse()
            .unwrap(),
    );
    PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err()
}

#[test]
fn ec_and_rsa_header_keys_require_their_parameters_and_verify() {
    use ring::signature::KeyPair;

    let rng = ring::rand::SystemRandom::new();
    let p256_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let p256 = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        p256_doc.as_ref(),
        &rng,
    )
    .unwrap();
    let p256_pub = p256.public_key().as_ref();
    assert_eq!(p256_pub.len(), 65);
    assert_eq!(p256_pub[0], 0x04);
    let x256 = base64_url(&p256_pub[1..33]);
    let y256 = base64_url(&p256_pub[33..]);
    let es256 = format!(r#"sig=hwk;kty="EC";crv="P-256";x="{x256}";y="{y256}";alg="ES256""#);
    let req = hwk_proof(&es256, 64, |base| {
        p256.sign(&rng, base).unwrap().as_ref().to_vec()
    });
    let prepared = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    let KeyMaterial::Hwk(jwk) = prepared.key().clone() else {
        panic!("ec key");
    };
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv, "P-256");
    assert_eq!(jwk.x, x256);
    assert_eq!(jwk.y, y256);
    assert_eq!(jwk.alg, "ES256");
    prepared.verify(&jwk).unwrap();
    let mut flipped = req.clone();
    flipped.headers_mut().insert(
        "signature",
        format!("sig=:{}:", base64_std(&[2u8; 64])).parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare(&flipped, "sig", 1000, 60)
            .unwrap()
            .verify(&jwk)
            .unwrap_err(),
        Error::InvalidSignature
    );

    let p384_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let p384 = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        p384_doc.as_ref(),
        &rng,
    )
    .unwrap();
    let p384_pub = p384.public_key().as_ref();
    assert_eq!(p384_pub.len(), 97);
    let x384 = base64_url(&p384_pub[1..49]);
    let y384 = base64_url(&p384_pub[49..]);
    let es384 = format!(r#"sig=hwk;kty="EC";crv="P-384";x="{x384}";y="{y384}";alg="ES384""#);
    let req = hwk_proof(&es384, 96, |base| {
        p384.sign(&rng, base).unwrap().as_ref().to_vec()
    });
    let prepared = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
    let KeyMaterial::Hwk(jwk) = prepared.key().clone() else {
        panic!("p384 key");
    };
    assert_eq!(jwk.alg, "ES384");
    assert_eq!(jwk.crv, "P-384");
    prepared.verify(&jwk).unwrap();
    assert_eq!(
        hwk_error(&format!(
            r#"sig=hwk;kty="EC";crv="P-256";x="{x384}";y="{y384}";alg="ES384""#
        )),
        Error::InvalidKey
    );

    for header in [
        format!(r#"sig=hwk;crv="P-256";x="{x256}";y="{y256}";alg="ES256""#),
        format!(r#"sig=hwk;kty="EC";x="{x256}";y="{y256}";alg="ES256""#),
        format!(r#"sig=hwk;kty="EC";crv="P-256";y="{y256}";alg="ES256""#),
        format!(r#"sig=hwk;kty="EC";crv="P-256";x="{x256}";alg="ES256""#),
        format!(r#"sig=hwk;kty="EC";crv="P-384";x="{x256}";y="{y256}";alg="ES256""#),
        format!(r#"sig=hwk;kty="OKP";crv="Ed25519";x="{x256}";y="{y256}";alg="Ed25519""#),
    ] {
        assert_eq!(hwk_error(&header), Error::InvalidKey, "{header}");
    }
    assert_eq!(
        hwk_error(&format!(
            r#"sig=hwk;kty="EC";crv="P-256";x="{x256}";y="{y256}""#
        )),
        Error::UnsupportedAlgorithm
    );
    assert_eq!(
        hwk_error(&format!(
            r#"sig=hwk;kty="EC";crv="P-521";x="{x256}";y="{y256}";alg="ES512""#
        )),
        Error::UnsupportedAlgorithm
    );

    let rsa = ring::rsa::KeyPair::from_der(include_bytes!("fixtures/rsa-2048.der")).unwrap();
    let public = ring::signature::RsaPublicKeyComponents::<Vec<u8>>::from(rsa.public());
    let modulus = base64_url(&public.n);
    let exponent = base64_url(&public.e);
    let rs256 = format!(r#"sig=hwk;kty="RSA";n="{modulus}";e="{exponent}";alg="RS256""#);
    let ps256 = format!(r#"sig=hwk;kty="RSA";n="{modulus}";e="{exponent}";alg="PS256""#);
    let pkcs1 = hwk_proof(&rs256, rsa.public().modulus_len(), |base| {
        let mut signature = vec![0u8; rsa.public().modulus_len()];
        rsa.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &rng,
            base,
            &mut signature,
        )
        .unwrap();
        signature
    });
    let prepared = PreparedRequest::prepare(&pkcs1, "sig", 1000, 60).unwrap();
    let KeyMaterial::Hwk(jwk) = prepared.key().clone() else {
        panic!("rsa key");
    };
    assert_eq!(jwk.kty, "RSA");
    assert_eq!(jwk.n, modulus);
    assert_eq!(jwk.e, exponent);
    assert_eq!(jwk.alg, "RS256");
    prepared.verify(&jwk).unwrap();
    let pss = hwk_proof(&ps256, rsa.public().modulus_len(), |base| {
        let mut signature = vec![0u8; rsa.public().modulus_len()];
        rsa.sign(&ring::signature::RSA_PSS_SHA256, &rng, base, &mut signature)
            .unwrap();
        signature
    });
    let prepared = PreparedRequest::prepare(&pss, "sig", 1000, 60).unwrap();
    let KeyMaterial::Hwk(jwk) = prepared.key().clone() else {
        panic!("pss key");
    };
    assert_eq!(jwk.alg, "PS256");
    prepared.verify(&jwk).unwrap();
    let pkcs1_under_ps256 = hwk_proof(&ps256, rsa.public().modulus_len(), |base| {
        let mut signature = vec![0u8; rsa.public().modulus_len()];
        rsa.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &rng,
            base,
            &mut signature,
        )
        .unwrap();
        signature
    });
    let prepared = PreparedRequest::prepare(&pkcs1_under_ps256, "sig", 1000, 60).unwrap();
    let KeyMaterial::Hwk(jwk) = prepared.key().clone() else {
        panic!("padding");
    };
    assert_eq!(prepared.verify(&jwk).unwrap_err(), Error::InvalidSignature);

    assert_eq!(public.n.len(), 256);
    assert_ne!(public.n[0], 0);
    assert_ne!(public.e[0], 0);
    let mut exponent_value = 0u64;
    for byte in &public.e {
        exponent_value = (exponent_value << 8) | u64::from(*byte);
    }
    assert!(exponent_value >= 3 && exponent_value % 2 == 1);
    let mut padded_n = vec![0];
    padded_n.extend_from_slice(&public.n);
    let mut padded_e = vec![0];
    padded_e.extend_from_slice(&public.e);
    let mut short = vec![0u8; 255];
    short[0] = 0x80;
    let mut minimum = vec![0u8; 256];
    minimum[0] = 0x80;
    let mut longest = vec![0u8; 1024];
    longest[0] = 0x80;
    let mut oversized = vec![0u8; 1025];
    oversized[0] = 0x80;
    for header in [
        format!(
            r#"sig=hwk;kty="RSA";n="{}";e="{exponent}";alg="RS256""#,
            base64_url(&padded_n)
        ),
        format!(
            r#"sig=hwk;kty="RSA";n="{modulus}";e="{}";alg="RS256""#,
            base64_url(&padded_e)
        ),
        format!(
            r#"sig=hwk;kty="RSA";n="{}";e="Aw";alg="RS256""#,
            base64_url(&short)
        ),
        format!(
            r#"sig=hwk;kty="RSA";n="{}";e="Aw";alg="RS256""#,
            base64_url(&oversized)
        ),
        format!(r#"sig=hwk;kty="RSA";n="{modulus}";e="AQ";alg="RS256""#),
        format!(r#"sig=hwk;kty="RSA";n="{modulus}";e="Ag";alg="RS256""#),
        format!(r#"sig=hwk;kty="RSA";n="{modulus}";e="AA";alg="RS256""#),
    ] {
        assert_eq!(hwk_error(&header), Error::InvalidKey, "{header}");
    }
    for (raw, len) in [(minimum, 256usize), (longest, 1024)] {
        let header = format!(
            r#"sig=hwk;kty="RSA";n="{}";e="Aw";alg="RS256""#,
            base64_url(&raw)
        );
        let mut req = request();
        req.headers_mut()
            .insert("signature-key", header.parse().unwrap());
        req.headers_mut().insert(
            "signature-input",
            "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created=1000"
                .parse()
                .unwrap(),
        );
        req.headers_mut().insert(
            "signature",
            format!("sig=:{}:", base64_std(&vec![1u8; len]))
                .parse()
                .unwrap(),
        );
        let prepared = PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap();
        let KeyMaterial::Hwk(jwk) = prepared.key().clone() else {
            panic!("boundary modulus");
        };
        assert_eq!(jwk.signature_len().unwrap(), len);
    }

    for header in [
        format!(r#"sig=hwk;n="{modulus}";e="{exponent}";alg="RS256""#),
        format!(r#"sig=hwk;kty="RSA";e="{exponent}";alg="RS256""#),
        format!(r#"sig=hwk;kty="RSA";n="{modulus}";alg="RS256""#),
        format!(r#"sig=hwk;kty="RSA";n="{modulus}";e="{exponent}";alg="Ed25519""#),
    ] {
        assert_eq!(hwk_error(&header), Error::InvalidKey, "{header}");
    }
    assert_eq!(
        hwk_error(&format!(
            r#"sig=hwk;kty="RSA";n="{modulus}";e="{exponent}""#
        )),
        Error::UnsupportedAlgorithm
    );
    assert_eq!(
        hwk_error(&format!(
            r#"sig=hwk;kty="RSA";n="{modulus}";e="{exponent}";alg="RSA""#
        )),
        Error::UnsupportedAlgorithm
    );
}

#[test]
fn x509_checks_the_chain_and_selects_one_algorithm() {
    let url = "https://Client.example/certs/leaf.pem";
    let seed = [9u8; 32];
    let leaf_key = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
        &pkcs8_pem(&ed25519_pkcs8(&seed)),
        &rcgen::PKCS_ED25519,
    )
    .unwrap();
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_cert("ca.example", &ca_key);
    let leaf = issued(
        "leaf.example",
        &leaf_key,
        &ca,
        &ca_key,
        (1970, 1, 1),
        (2099, 1, 1),
    );
    let trust = ca.der().as_ref().to_vec();
    let der = leaf.der().as_ref().to_vec();
    let x5t = sha256(&der);
    let pem = leaf.pem();
    let mut req = request();
    sign_request(
        &mut req,
        &SigningKey::from_seed(seed),
        KeyMaterial::X509 {
            x5u: url.into(),
            x5t: x5t.clone(),
        },
        1000,
    )
    .unwrap();
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1000, 60).unwrap_err(),
        Error::UnsupportedScheme
    );
    let prepared = prepare_x509(&req).unwrap();
    let identity = prepared
        .verify_x509(&pem, &[trust.as_slice()], 1000)
        .unwrap();
    assert_eq!(identity.url, url);
    assert_eq!(identity.thumbprint, x5t);
    assert_eq!(identity.key.alg, "Ed25519");
    assert_eq!(identity.key.kty, "OKP");
    assert_eq!(identity.key.crv, "Ed25519");

    let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let other = ca_cert("other.example", &other_key);
    assert_eq!(
        prepared
            .verify_x509(&pem, &[other.der().as_ref()], 1000)
            .unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        prepared
            .verify_x509(&pem, &[der.as_slice()], 1000)
            .unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        prepared.verify_x509(&pem, &[], 1000).unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        prepared
            .verify_x509("not a certificate", &[trust.as_slice()], 1000)
            .unwrap_err(),
        Error::InvalidKey
    );

    let mut wrong_thumb = req.clone();
    wrong_thumb.headers_mut().insert(
        "signature-key",
        x509_header(url, &[7u8; 32]).parse().unwrap(),
    );
    assert_eq!(
        prepare_x509(&wrong_thumb)
            .unwrap()
            .verify_x509(&pem, &[trust.as_slice()], 1000)
            .unwrap_err(),
        Error::InvalidKey
    );
    let mut bad_sig = req.clone();
    bad_sig.headers_mut().insert(
        "signature",
        format!("sig=:{}:", base64_std(&[2u8; 64])).parse().unwrap(),
    );
    assert_eq!(
        prepare_x509(&bad_sig)
            .unwrap()
            .verify_x509(&pem, &[trust.as_slice()], 1000)
            .unwrap_err(),
        Error::InvalidSignature
    );

    let expired = issued(
        "expired.example",
        &leaf_key,
        &ca,
        &ca_key,
        (1970, 1, 1),
        (1970, 1, 2),
    );
    let expired_der = expired.der().as_ref().to_vec();
    let mut expired_req = request();
    sign_request(
        &mut expired_req,
        &SigningKey::from_seed(seed),
        KeyMaterial::X509 {
            x5u: url.into(),
            x5t: sha256(&expired_der),
        },
        1000,
    )
    .unwrap();
    assert_eq!(
        prepare_x509(&expired_req)
            .unwrap()
            .verify_x509(&expired.pem(), &[trust.as_slice()], 86_401)
            .unwrap_err(),
        Error::InvalidKey
    );
    let pending = issued(
        "pending.example",
        &leaf_key,
        &ca,
        &ca_key,
        (2090, 1, 1),
        (2099, 1, 1),
    );
    let pending_der = pending.der().as_ref().to_vec();
    let mut pending_req = request();
    sign_request(
        &mut pending_req,
        &SigningKey::from_seed(seed),
        KeyMaterial::X509 {
            x5u: url.into(),
            x5t: sha256(&pending_der),
        },
        1000,
    )
    .unwrap();
    assert_eq!(
        prepare_x509(&pending_req)
            .unwrap()
            .verify_x509(&pending.pem(), &[trust.as_slice()], 1000)
            .unwrap_err(),
        Error::InvalidKey
    );

    let x5t_b64 = base64_std(&x5t);
    for header in [
        format!("sig=x509;x5t=:{x5t_b64}:"),
        format!("sig=x509;x5u=\"{url}\""),
        format!("sig=x509;x5u=\"http://client.example/cert.pem\";x5t=:{x5t_b64}:"),
        format!("sig=x509;x5u=\"https://client.example/cert.pem#frag\";x5t=:{x5t_b64}:"),
        format!("sig=x509;x5u=\"https://user@client.example/cert.pem\";x5t=:{x5t_b64}:"),
        format!("sig=x509;x5u=\"{url}\";x5t=\"{x5t_b64}\""),
        format!("sig=x509;x5u=\"{url}\";x5t=:AA:"),
    ] {
        assert_eq!(
            prepare_x509(&x509_request(&header, &[1u8; 64])).unwrap_err(),
            Error::InvalidKey,
            "{header}"
        );
    }

    let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let root = ca_cert("root.example", &root_key);
    let mid_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut mid_params = rcgen::CertificateParams::new(vec!["mid.example".into()]).unwrap();
    mid_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    stamp(&mut mid_params, (1970, 1, 1), (2099, 1, 1));
    let mid = mid_params.signed_by(&mid_key, &root, &root_key).unwrap();
    let chained = issued(
        "chained.example",
        &leaf_key,
        &mid,
        &mid_key,
        (1970, 1, 1),
        (2099, 1, 1),
    );
    let chained_der = chained.der().as_ref().to_vec();
    let chained_thumb = sha256(&chained_der);
    let mut chained_req = request();
    sign_request(
        &mut chained_req,
        &SigningKey::from_seed(seed),
        KeyMaterial::X509 {
            x5u: url.into(),
            x5t: chained_thumb.clone(),
        },
        1000,
    )
    .unwrap();
    let chained_pem = format!("{}{}", chained.pem(), mid.pem());
    let chained_proof = prepare_x509(&chained_req).unwrap();
    let chained_id = chained_proof
        .verify_x509(&chained_pem, &[root.der().as_ref()], 1000)
        .unwrap();
    assert_eq!(chained_id.thumbprint, chained_thumb);
    assert_eq!(
        chained_proof
            .verify_x509(&chained.pem(), &[root.der().as_ref()], 1000)
            .unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        chained_proof
            .verify_x509(
                &format!("{}{}", mid.pem(), chained.pem()),
                &[root.der().as_ref()],
                1000,
            )
            .unwrap_err(),
        Error::InvalidKey
    );

    ec_certificate(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rcgen::PKCS_ECDSA_P256_SHA256,
        "ES256",
        "P-256",
        64,
    );
    ec_certificate(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        "ES384",
        "P-384",
        96,
    );

    let rsa_key = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
        &pkcs8_pem(&rsa_pkcs8(include_bytes!("fixtures/rsa-2048.der"))),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let rsa_leaf = issued(
        "rsa.example",
        &rsa_key,
        &ca,
        &ca_key,
        (1970, 1, 1),
        (2099, 1, 1),
    );
    let rsa_header = x509_header(url, &sha256(rsa_leaf.der().as_ref()));
    for len in [64, 256] {
        assert_eq!(
            prepare_x509(&x509_request(&rsa_header, &vec![1u8; len]))
                .unwrap()
                .verify_x509(&rsa_leaf.pem(), &[trust.as_slice()], 1000)
                .unwrap_err(),
            Error::UnsupportedAlgorithm,
            "rsa signature length {len}"
        );
    }
}

fn ec_certificate(
    signing: &'static ring::signature::EcdsaSigningAlgorithm,
    cert_alg: &'static rcgen::SignatureAlgorithm,
    alg: &str,
    crv: &str,
    len: usize,
) {
    let rng = ring::rand::SystemRandom::new();
    let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(signing, &rng).unwrap();
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(signing, doc.as_ref(), &rng).unwrap();
    let key =
        rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&pkcs8_pem(doc.as_ref()), cert_alg).unwrap();
    let ca_key = rcgen::KeyPair::generate_for(cert_alg).unwrap();
    let ca = ca_cert("ec-ca.example", &ca_key);
    let leaf = issued(
        "ec-leaf.example",
        &key,
        &ca,
        &ca_key,
        (1970, 1, 1),
        (2099, 1, 1),
    );
    let header = x509_header(
        "https://client.example/ec.pem",
        &sha256(leaf.der().as_ref()),
    );
    let req = x509_proof(&header, len, |base| {
        pair.sign(&rng, base).unwrap().as_ref().to_vec()
    });
    let identity = prepare_x509(&req)
        .unwrap()
        .verify_x509(&leaf.pem(), &[ca.der().as_ref()], 1000)
        .unwrap();
    assert_eq!(identity.key.alg, alg);
    assert_eq!(identity.key.crv, crv);
    assert_eq!(identity.url, "https://client.example/ec.pem");
    let wrong_len = if len == 64 { 96 } else { 64 };
    assert_eq!(
        prepare_x509(&x509_request(&header, &vec![1u8; wrong_len]))
            .unwrap()
            .verify_x509(&leaf.pem(), &[ca.der().as_ref()], 1000)
            .unwrap_err(),
        Error::InvalidSignature
    );
}

fn ca_cert(name: &str, key: &rcgen::KeyPair) -> rcgen::Certificate {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    stamp(&mut params, (1970, 1, 1), (2099, 1, 1));
    params.self_signed(key).unwrap()
}

fn issued(
    name: &str,
    key: &rcgen::KeyPair,
    issuer: &rcgen::Certificate,
    issuer_key: &rcgen::KeyPair,
    before: (i32, u8, u8),
    after: (i32, u8, u8),
) -> rcgen::Certificate {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    stamp(&mut params, before, after);
    params.signed_by(key, issuer, issuer_key).unwrap()
}

fn stamp(params: &mut rcgen::CertificateParams, before: (i32, u8, u8), after: (i32, u8, u8)) {
    params.not_before = rcgen::date_time_ymd(before.0, before.1, before.2);
    params.not_after = rcgen::date_time_ymd(after.0, after.1, after.2);
}

fn prepare_x509(req: &Request<Vec<u8>>) -> Result<PreparedRequest, Error> {
    PreparedRequest::prepare_with_schemes(req, "sig", 1000, 60, &["x509"])
}

fn x509_header(url: &str, x5t: &[u8]) -> String {
    format!("sig=x509;x5u=\"{url}\";x5t=:{}:", base64_std(x5t))
}

fn x509_request(header: &str, signature: &[u8]) -> Request<Vec<u8>> {
    let mut req = request();
    req.headers_mut()
        .insert("signature-key", header.parse().unwrap());
    req.headers_mut().insert(
        "signature-input",
        "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created=1000"
            .parse()
            .unwrap(),
    );
    req.headers_mut().insert(
        "signature",
        format!("sig=:{}:", base64_std(signature)).parse().unwrap(),
    );
    req
}

fn x509_proof(header: &str, len: usize, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Request<Vec<u8>> {
    let base = prepare_x509(&x509_request(header, &vec![1u8; len]))
        .unwrap()
        .signature_base()
        .to_vec();
    x509_request(header, &sign(&base))
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn rsa_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    let algorithm = der_tlv(
        0x30,
        &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        ],
    );
    let mut body = der_tlv(0x02, &[0x00]);
    body.extend(algorithm);
    body.extend(der_tlv(0x04, pkcs1));
    der_tlv(0x30, &body)
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(body);
    out
}

fn ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der
}

fn pkcs8_pem(der: &[u8]) -> String {
    let encoded = base64_std(der);
    let mut body = String::new();
    for chunk in encoded.as_bytes().chunks(64) {
        body.push_str(std::str::from_utf8(chunk).unwrap());
        body.push('\n');
    }
    format!("-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n")
}

#[test]
fn multiple_signatures_cover_the_complete_signature_key_dictionary() {
    let first = SigningKey::from_seed([4; 32]);
    let second = SigningKey::from_seed([5; 32]);
    let first_x = first.public_jwk().x;
    let second_x = second.public_jwk().x;
    assert_ne!(first_x, second_x);
    let mut req = request();
    sign_requests(
        &mut req,
        &[
            RequestSignature {
                label: "sig1",
                key: &first,
                material: KeyMaterial::Hwk(first.public_jwk()),
            },
            RequestSignature {
                label: "sig2",
                key: &second,
                material: KeyMaterial::Hwk(second.public_jwk()),
            },
        ],
        1_000,
    )
    .unwrap();
    let key_header = req
        .headers()
        .get("signature-key")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(key_header.starts_with("sig1=hwk"));
    assert!(key_header.contains(", sig2=hwk"));
    assert_eq!(key_header.matches(second_x.as_str()).count(), 1);
    let input = req
        .headers()
        .get("signature-input")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(input.matches("\"signature-key\"").count(), 2);
    let proof1 = PreparedRequest::prepare(&req, "sig1", 1_000, 60).unwrap();
    proof1.verify(&first.public_jwk()).unwrap();
    let proof2 = PreparedRequest::prepare(&req, "sig2", 1_000, 60).unwrap();
    proof2.verify(&second.public_jwk()).unwrap();
    assert_eq!(
        proof1.verify(&second.public_jwk()).unwrap_err(),
        Error::InvalidSignature
    );

    let mut tampered = req.clone();
    tampered.headers_mut().insert(
        "signature-key",
        key_header.replacen(&second_x, &first_x, 1).parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare(&tampered, "sig1", 1_000, 60)
            .unwrap()
            .verify(&first.public_jwk())
            .unwrap_err(),
        Error::InvalidSignature
    );
    assert_eq!(
        PreparedRequest::prepare(&tampered, "sig2", 1_000, 60)
            .unwrap()
            .verify(&second.public_jwk())
            .unwrap_err(),
        Error::InvalidSignature
    );
    assert_eq!(
        sign_requests(&mut request(), &[], 1_000).unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(
        sign_requests(
            &mut request(),
            &[
                RequestSignature {
                    label: "sig1",
                    key: &first,
                    material: KeyMaterial::Hwk(first.public_jwk()),
                },
                RequestSignature {
                    label: "sig1",
                    key: &second,
                    material: KeyMaterial::Hwk(second.public_jwk()),
                },
            ],
            1_000,
        )
        .unwrap_err(),
        Error::InvalidInput
    );
    let mut bad_label = request();
    assert_eq!(
        sign_requests(
            &mut bad_label,
            &[RequestSignature {
                label: "Sig",
                key: &first,
                material: KeyMaterial::Hwk(first.public_jwk()),
            }],
            1_000,
        )
        .unwrap_err(),
        Error::InvalidInput
    );
    assert!(bad_label.headers().get("signature-key").is_none());
}

#[test]
fn client_ignores_unknown_accept_tokens_and_signature_error_members() {
    let known = ["hwk", "jwt", "cached", "jwks_uri"];
    let recognized = recognized_tokens("future, hwk, jwt", &known).unwrap();
    assert_eq!(recognized, ["hwk", "jwt"]);
    assert!(
        recognized_tokens("future, later", &known)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        recognized_tokens("es256, Ed25519, HS256", &["Ed25519", "ES256"]).unwrap(),
        ["Ed25519"]
    );
    assert_eq!(
        choose_presented_scheme("cached, future, jwt", &known, None).unwrap(),
        Some("jwt".into())
    );
    assert_eq!(
        choose_presented_scheme("cached, future", &known, None).unwrap(),
        None
    );
    assert_eq!(
        choose_presented_scheme("cached, jwt", &known, Some("issued-cid")).unwrap(),
        Some("cached".into())
    );
    assert_eq!(
        signature_error_code("error=unsupported_algorithm, note=1, detail=:AA:; retry=?1").unwrap(),
        "unsupported_algorithm"
    );
    assert_eq!(
        signature_error_code("error=cache_miss").unwrap(),
        "cache_miss"
    );
    assert_eq!(
        signature_error_code("note=1").unwrap_err(),
        Error::InvalidInput
    );
}

#[test]
fn key_cache_expires_and_refuses_a_refetch_inside_one_minute() {
    assert_eq!(KeyCache::open(0).unwrap_err(), Error::InvalidInput);
    let mut cache = KeyCache::open(2).unwrap();
    let issuer = CachedDocument::JwksUriIssuer {
        issuer: "https://issuer.example",
        dwk: "aauth-access.json",
    };
    let other = CachedDocument::JwksUriIssuer {
        issuer: "https://other.example",
        dwk: "aauth-access.json",
    };
    let third = CachedDocument::JwksUriIssuer {
        issuer: "https://third.example",
        dwk: "aauth-access.json",
    };
    let url = CachedDocument::JwksUrl("https://keys.example/jwks?v=1");
    assert_eq!(cache.lookup(issuer, 1_000).unwrap(), KeyCacheAnswer::Fetch);
    assert_eq!(
        cache
            .store(issuer, br#"{"keys":[]}"#, Some("max-age=30"), 1_000)
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 1_030,
            fresh: true
        }
    );
    assert!(matches!(
        cache.lookup(issuer, 1_029).unwrap(),
        KeyCacheAnswer::Fresh {
            expires_at: 1_030,
            ..
        }
    ));
    assert_eq!(
        cache.lookup(issuer, 1_030).unwrap(),
        KeyCacheAnswer::Wait { until: 1_060 }
    );
    assert_eq!(
        cache
            .store(issuer, br#"{"keys":[1]}"#, Some("max-age=30"), 1_059)
            .unwrap(),
        KeyCacheStore::Wait { until: 1_060 }
    );
    assert!(matches!(
        cache.lookup(issuer, 1_059).unwrap(),
        KeyCacheAnswer::Wait { until: 1_060 }
    ));
    assert_eq!(cache.lookup(issuer, 1_060).unwrap(), KeyCacheAnswer::Fetch);
    cache
        .store(issuer, br#"{"keys":[2]}"#, Some("max-age=10"), 1_060)
        .unwrap();
    assert_eq!(cache.lookup(other, 1_060).unwrap(), KeyCacheAnswer::Fetch);
    cache
        .store(other, br#"{"keys":[]}"#, Some("max-age=100"), 1_060)
        .unwrap();
    assert_eq!(cache.lookup(third, 1_060).unwrap(), KeyCacheAnswer::Full);
    assert_eq!(
        cache
            .store(third, br#"{"keys":[]}"#, Some("max-age=100"), 1_060)
            .unwrap(),
        KeyCacheStore::Full
    );
    assert_eq!(cache.lookup(url, 1_060).unwrap(), KeyCacheAnswer::Full);
    assert_eq!(cache.lookup(issuer, 1_120).unwrap(), KeyCacheAnswer::Fetch);
    assert_eq!(cache.lookup(third, 1_120).unwrap(), KeyCacheAnswer::Fetch);
    assert_eq!(
        cache
            .store(url, br#"{"keys":[]}"#, Some("max-age=1"), 4_000)
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 4_001,
            fresh: true
        }
    );
    assert_eq!(
        cache.lookup(url, 4_001).unwrap(),
        KeyCacheAnswer::Wait { until: 4_060 }
    );
    assert_eq!(
        cache
            .store(issuer, br#"{"keys":[]}"#, Some("no-store"), 5_000)
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 5_000,
            fresh: false
        }
    );
    assert_eq!(
        cache.lookup(issuer, 5_000).unwrap(),
        KeyCacheAnswer::Wait { until: 5_060 }
    );
    assert_eq!(
        cache.store(other, br#"{"keys":[]}"#, None, 6_000).unwrap(),
        KeyCacheStore::Stored {
            expires_at: 6_300,
            fresh: true
        }
    );
    assert_eq!(
        cache
            .store(
                other,
                br#"{"keys":[]}"#,
                Some("s-maxage=15, max-age=90"),
                6_400
            )
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 6_415,
            fresh: true
        }
    );
    assert_eq!(
        cache
            .store(url, br#"{"keys":[]}"#, Some("No-Cache, public"), 7_000)
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 7_000,
            fresh: false
        }
    );
    assert_eq!(
        cache
            .store(url, b"x", Some("max-age=foo"), 8_000)
            .unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(
        cache
            .lookup(
                CachedDocument::JwksUriIssuer {
                    issuer: "http://issuer.example",
                    dwk: "aauth-access.json",
                },
                8_000
            )
            .unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        cache
            .store(issuer, &vec![b'a'; 65_537], Some("max-age=60"), 9_000)
            .unwrap_err(),
        Error::InvalidInput
    );
    let mut roles = KeyCache::open(2).unwrap();
    let access = CachedDocument::JwksUriIssuer {
        issuer: "https://shared.example",
        dwk: "aauth-access.json",
    };
    let person = CachedDocument::JwksUriIssuer {
        issuer: "https://shared.example",
        dwk: "aauth-person.json",
    };
    assert_eq!(
        roles
            .store(
                access,
                br#"{"keys":[{"kid":"a"}]}"#,
                Some("max-age=30"),
                1_000
            )
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 1_030,
            fresh: true
        }
    );
    assert_eq!(
        roles
            .store(
                person,
                br#"{"keys":[{"kid":"p"}]}"#,
                Some("max-age=30"),
                1_000
            )
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 1_030,
            fresh: true
        }
    );
    match roles.lookup(access, 1_000).unwrap() {
        KeyCacheAnswer::Fresh { body, .. } => assert_eq!(body, br#"{"keys":[{"kid":"a"}]}"#),
        other => panic!("access document was not kept: {other:?}"),
    }
    match roles.lookup(person, 1_000).unwrap() {
        KeyCacheAnswer::Fresh { body, .. } => assert_eq!(body, br#"{"keys":[{"kid":"p"}]}"#),
        other => panic!("person document was not stored: {other:?}"),
    }
    assert_eq!(
        roles
            .lookup(
                CachedDocument::JwksUriIssuer {
                    issuer: "https://shared.example",
                    dwk: "",
                },
                1_000
            )
            .unwrap_err(),
        Error::InvalidKey
    );
    let mut responses = KeyCache::open(4).unwrap();
    let quote = CachedDocument::JwksUrl("https://quote.example/jwks");
    assert_eq!(
        responses
            .store_response(
                quote,
                br#"{"keys":[]}"#,
                aauth_rust_signature_key::FetchedHeaders {
                    cache_control: Some("max-age=\"60\""),
                    ..aauth_rust_signature_key::FetchedHeaders::default()
                },
                8_100
            )
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 8_160,
            fresh: true
        }
    );
    assert_eq!(
        responses
            .store_response(
                quote,
                b"{}",
                aauth_rust_signature_key::FetchedHeaders {
                    cache_control: Some("max-age=\"no\""),
                    ..aauth_rust_signature_key::FetchedHeaders::default()
                },
                8_200
            )
            .unwrap_err(),
        Error::InvalidInput
    );
    let aged = CachedDocument::JwksUrl("https://age.example/jwks");
    assert_eq!(
        responses
            .store_response(
                aged,
                br#"{"keys":[]}"#,
                aauth_rust_signature_key::FetchedHeaders {
                    cache_control: Some("max-age=40"),
                    age: Some("10"),
                    ..aauth_rust_signature_key::FetchedHeaders::default()
                },
                8_300
            )
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 8_330,
            fresh: true
        }
    );
    assert!(matches!(
        responses.lookup(aged, 8_329).unwrap(),
        KeyCacheAnswer::Fresh {
            expires_at: 8_330,
            ..
        }
    ));
    let spent = CachedDocument::JwksUrl("https://spent.example/jwks");
    assert_eq!(
        responses
            .store_response(
                spent,
                br#"{"keys":[]}"#,
                aauth_rust_signature_key::FetchedHeaders {
                    cache_control: Some("max-age=5"),
                    age: Some("9"),
                    ..aauth_rust_signature_key::FetchedHeaders::default()
                },
                8_400
            )
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 8_400,
            fresh: false
        }
    );
    assert_eq!(
        responses.lookup(spent, 8_400).unwrap(),
        KeyCacheAnswer::Wait { until: 8_460 }
    );
    let dated = CachedDocument::JwksUrl("https://dated.example/jwks");
    assert_eq!(
        responses
            .store_response(
                dated,
                br#"{"keys":[]}"#,
                aauth_rust_signature_key::FetchedHeaders {
                    age: Some("15"),
                    expires: Some("Sun, 06 Nov 1994 08:50:37 GMT"),
                    date: Some("Sun, 06 Nov 1994 08:49:37 GMT"),
                    ..aauth_rust_signature_key::FetchedHeaders::default()
                },
                1_700_000_000
            )
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 1_700_000_045,
            fresh: true
        }
    );
    assert_eq!(
        responses
            .store_response(
                CachedDocument::JwksUrl("https://baddate.example/jwks"),
                br#"{"keys":[]}"#,
                aauth_rust_signature_key::FetchedHeaders {
                    expires: Some("not-a-date"),
                    ..aauth_rust_signature_key::FetchedHeaders::default()
                },
                1_700_000_100
            )
            .unwrap_err(),
        Error::InvalidInput
    );
    let mut capped = KeyCache::open(1).unwrap();
    assert_eq!(
        capped
            .store(
                CachedDocument::JwksUrl("https://keys.example/jwks"),
                br#"{"keys":[]}"#,
                Some("max-age=200000"),
                10
            )
            .unwrap(),
        KeyCacheStore::Stored {
            expires_at: 86_410,
            fresh: true
        }
    );
    assert_eq!(
        capped
            .store(
                CachedDocument::JwksUrl("https://keys.example/jwks"),
                br#"{"keys":[]}"#,
                Some("s-maxage=90000, max-age=10"),
                20
            )
            .unwrap(),
        KeyCacheStore::Wait { until: 70 }
    );
}

#[test]
fn egress_admission_pins_a_public_address_and_a_parsed_origin_is_not_authorization() {
    let five = Duration::from_secs(5);
    assert_eq!(
        EgressLimits::bounded(0, five).unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(
        EgressLimits::bounded(65_537, five).unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(
        EgressLimits::bounded(1024, Duration::ZERO).unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(
        EgressLimits::bounded(1024, Duration::from_secs(31)).unwrap_err(),
        Error::InvalidInput
    );
    let limits = EgressLimits::bounded(1024, five).unwrap();
    let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
    let metadata = "https://issuer.example/.well-known/aauth-agent.json";
    let pinned = admit_fetch(
        &limits,
        DiscoveryFetch::Metadata { url: metadata },
        public_ip,
    )
    .unwrap();
    assert_eq!(pinned.address, public_ip);
    assert_eq!(pinned.timeout, five);
    assert_eq!(pinned.max_response_bytes, 1024);
    accept_pinned_peer(&pinned, public_ip).unwrap();
    assert_eq!(
        accept_pinned_peer(&pinned, "1.1.1.1".parse().unwrap()).unwrap_err(),
        Error::InvalidKey
    );
    accept_response(&pinned, 1024).unwrap();
    assert_eq!(
        accept_response(&pinned, 1025).unwrap_err(),
        Error::InvalidInput
    );
    for refused in [
        "0.0.0.0",
        "10.0.0.1",
        "100.100.100.200",
        "127.0.0.1",
        "169.254.1.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "172.16.5.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fec0::1",
        "fd00::1",
        "ff00::1",
        "2001:db8::1",
        "::ffff:0.0.0.0",
        "::ffff:127.0.0.1",
        "::7f00:1",
        "64:ff9b::7f00:1",
        "64:ff9b:1:7f00:0:100::",
        "64:ff9b:1:808:8:800::",
        "64:ff9b:1:808:8:800:7f00:1",
        "2002:7f00:1::",
        "2001::80ff:fffe",
    ] {
        let address: IpAddr = refused.parse().unwrap();
        assert_eq!(
            admit_fetch(&limits, DiscoveryFetch::Metadata { url: metadata }, address).unwrap_err(),
            Error::InvalidKey,
            "{refused}"
        );
    }
    admit_fetch(
        &limits,
        DiscoveryFetch::Metadata { url: metadata },
        "172.32.5.1".parse().unwrap(),
    )
    .unwrap();
    admit_fetch(
        &limits,
        DiscoveryFetch::Metadata { url: metadata },
        "::ffff:8.8.8.8".parse().unwrap(),
    )
    .unwrap();
    for admitted in [
        "64:ff9b::808:808",
        "2002:808:808::",
        "::808:808",
        "2001::f7f7:f7f7",
        "2001:4860:4860::8888",
    ] {
        let address: IpAddr = admitted.parse().unwrap();
        admit_fetch(&limits, DiscoveryFetch::Metadata { url: metadata }, address).unwrap();
    }
    let mut unbounded = limits.clone();
    unbounded.max_response_bytes = usize::MAX;
    assert_eq!(
        admit_fetch(
            &unbounded,
            DiscoveryFetch::Metadata { url: metadata },
            public_ip
        )
        .unwrap_err(),
        Error::InvalidInput
    );
    let mut forever = limits.clone();
    forever.timeout = Duration::MAX;
    assert_eq!(
        admit_fetch(
            &forever,
            DiscoveryFetch::Metadata { url: metadata },
            public_ip
        )
        .unwrap_err(),
        Error::InvalidInput
    );
    let mut allowed = limits.clone();
    allowed.allow_restricted_addresses = true;
    admit_fetch(
        &allowed,
        DiscoveryFetch::Metadata { url: metadata },
        "10.1.2.3".parse().unwrap(),
    )
    .unwrap();
    for refused in [
        "http://issuer.example/jwks",
        "https://user:pass@issuer.example/jwks",
        "https://issuer.example/jwks#frag",
    ] {
        assert_eq!(
            admit_fetch(&limits, DiscoveryFetch::Jwks { url: refused }, public_ip).unwrap_err(),
            Error::InvalidKey,
            "{refused}"
        );
    }
    let redirected = admit_redirect(
        &pinned,
        "https://Issuer.example/jwks",
        "9.9.9.9".parse().unwrap(),
    )
    .unwrap();
    assert_eq!(redirected.address, "9.9.9.9".parse::<IpAddr>().unwrap());
    assert_eq!(
        admit_redirect(&pinned, "https://other.example/jwks", public_ip).unwrap_err(),
        Error::InvalidKey
    );
    let port_change = admit_redirect(
        &redirected,
        "https://issuer.example:8443/jwks",
        "9.9.9.9".parse().unwrap(),
    )
    .unwrap();
    let third = admit_redirect(
        &port_change,
        "https://issuer.example/keys",
        "9.9.9.9".parse().unwrap(),
    )
    .unwrap();
    assert_eq!(
        admit_redirect(&third, "https://issuer.example/more", public_ip).unwrap_err(),
        Error::InvalidInput
    );
    let same = DiscoveryFetch::JwksFromMetadata {
        metadata_url: metadata,
        jwks_url: "https://issuer.example/jwks",
    };
    admit_fetch(&limits, same, public_ip).unwrap();
    let cross = DiscoveryFetch::JwksFromMetadata {
        metadata_url: metadata,
        jwks_url: "https://keys.example/jwks",
    };
    assert_eq!(
        admit_fetch(&limits, cross, public_ip).unwrap_err(),
        Error::InvalidKey
    );
    let mut cross_ok = limits.clone();
    cross_ok.allow_cross_origin_jwks = true;
    admit_fetch(&cross_ok, cross, public_ip).unwrap();
    assert_eq!(
        admit_redirect(
            &admit_fetch(&cross_ok, cross, public_ip).unwrap(),
            "https://elsewhere.example/jwks",
            public_ip
        )
        .unwrap_err(),
        Error::InvalidKey
    );
    let origin = origin_pseudonym("https://attacker.example").unwrap();
    assert_eq!(origin.id(), "https://attacker.example");
    assert!(!origin_is_allowed(&origin, &[]));
    assert!(!origin_is_allowed(&origin, &["https://good.example"]));
    assert!(origin_is_allowed(&origin, &["https://attacker.example"]));
    assert_eq!(
        origin_pseudonym("https://attacker.example/path").unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        origin_pseudonym("http://attacker.example").unwrap_err(),
        Error::InvalidKey
    );
}

#[test]
fn pseudonym_keys_are_distinct_for_distinct_servers() {
    let mut binding = ServerKeyBinding::open();
    let one = SigningKey::from_seed([1; 32]).public_jwk();
    let two = SigningKey::from_seed([2; 32]).public_jwk();
    assert_ne!(one.thumbprint().unwrap(), two.thumbprint().unwrap());
    binding.admit("https://one.example/a?x=1", &one).unwrap();
    binding.admit("https://ONE.example:443/b", &one).unwrap();
    assert_eq!(
        binding.admit("https://two.example", &one).unwrap_err(),
        Error::InvalidKey
    );
    binding.admit("https://one.example/again", &one).unwrap();
    binding.admit("https://two.example/z", &two).unwrap();
    assert_eq!(
        binding.admit("https://one.example:8443", &one).unwrap_err(),
        Error::InvalidKey
    );
    let third = SigningKey::from_seed([3; 32]).public_jwk();
    binding.admit("https://one.example:8443/c", &third).unwrap();
    assert_eq!(
        binding.admit("https://one.example", &third).unwrap_err(),
        Error::InvalidKey
    );
    let fourth = SigningKey::from_seed([4; 32]).public_jwk();
    binding.admit("https://one.example", &fourth).unwrap();
    let mut ec = one.clone();
    ec.kty = "EC".into();
    ec.crv = "P-256".into();
    ec.alg = "ES256".into();
    assert_eq!(
        binding.admit("https://fresh.example", &ec).unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        binding.admit("http://one.example", &two).unwrap_err(),
        Error::InvalidUri
    );
    binding.admit("https://two.example", &two).unwrap();
}

fn cache_request(
    identity: &SigningKey,
    confirmation: &Jwk,
    jti: Option<&str>,
    assertion_exp: i64,
    retain_until: i64,
) -> Result<CacheRequest, Error> {
    let mut payload = json!({
        "iss": "https://ps.example",
        "sub": "person-1",
        "exp": assertion_exp,
        "cnf": {"jwk": confirmation},
    });
    if let Some(jti) = jti {
        payload["jti"] = json!(jti);
    }
    let compact = Jws::sign(
        &json!({"alg":"Ed25519","typ":"jwt"}),
        &serde_json::to_vec(&payload).unwrap(),
        identity,
    )
    .map_err(|_| Error::InvalidJwt)?;
    CacheRequest::verified_jwt("sig", &compact, &identity.public_jwk(), retain_until, 1_000)
}

#[test]
fn assertion_cache_resolves_a_sealed_identifier_and_keeps_misses_distinct() {
    let marker = "jti-cache-marker-9f3a";
    let key = SigningKey::from_seed([4; 32]);
    let public = key.public_jwk();
    let mut cache = AssertionCache::open([7; 32], 16, 8).unwrap();
    let shown = format!("{cache:?}");
    assert!(!shown.contains("070707"));
    assert_eq!(
        AssertionCache::open([7; 32], 0, 1).unwrap_err(),
        Error::InvalidKey
    );
    let grant = cache
        .issue_requested(
            true,
            cache_request(&key, &public, Some(marker), 5_000, 4_000).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(grant.expires <= 5_000);
    assert_eq!(grant.expires, 4_000);
    assert_ne!(grant.cid, marker);
    assert!(!grant.cid.contains(marker));
    let header = grant.field_value().unwrap();
    assert!(header.starts_with("sig="));
    assert!(header.contains(&format!("jti=\"{marker}\"")));
    assert!(header.contains("expires=4000"));
    let again = cache
        .issue_requested(
            true,
            cache_request(&key, &public, Some(marker), 5_000, 4_000).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_ne!(grant.cid, again.cid);
    assert!(!again.cid.contains(marker));

    let req = cached_request(&key, &grant.cid);
    assert_eq!(
        PreparedRequest::prepare(&req, "sig", 1_000, 60).unwrap_err(),
        Error::UnsupportedScheme
    );
    let prepared =
        PreparedRequest::prepare_with_schemes(&req, "sig", 1_000, 60, &["cached"]).unwrap();
    let resolved = prepared.verify_cached(&cache, 1_000).unwrap();
    assert_eq!(resolved.jti, marker);
    assert_eq!(resolved.scheme, "jwt");
    assert_eq!(resolved.issuer, "https://ps.example");
    assert_eq!(resolved.subject.as_deref(), Some("person-1"));
    assert_eq!(resolved.assertion_sha256.len(), 32);
    assert_eq!(
        prepared
            .verify_cached_sealed(&AssertionCache::open([7; 32], 16, 8).unwrap(), 1_000)
            .unwrap()
            .issuer,
        "https://ps.example"
    );
    let peer = AssertionCache::open([7; 32], 16, 8).unwrap();
    assert_eq!(
        prepared.verify_cached_sealed(&peer, 1_000).unwrap().jti,
        marker
    );
    let stranger = AssertionCache::open([8; 32], 16, 8).unwrap();
    assert_eq!(
        prepared.verify_cached_sealed(&stranger, 1_000).unwrap_err(),
        Error::CacheMiss
    );

    let foreign = cached_request(&SigningKey::from_seed([5; 32]), &grant.cid);
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&foreign, "sig", 1_000, 60, &["cached"])
            .unwrap()
            .verify_cached(&cache, 1_000)
            .unwrap_err(),
        Error::InvalidSignature
    );
    let mut bad_sig = req.clone();
    bad_sig.headers_mut().insert(
        "signature",
        format!("sig=:{}:", base64_std(&[3u8; 64])).parse().unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&bad_sig, "sig", 1_000, 60, &["cached"])
            .unwrap()
            .verify_cached(&cache, 1_000)
            .unwrap_err(),
        Error::InvalidSignature
    );
    let mut tampered = req.clone();
    tampered.headers_mut().insert(
        "signature-key",
        format!("sig=cached;cid=\"{}a\"", grant.cid)
            .parse()
            .unwrap(),
    );
    assert_eq!(
        PreparedRequest::prepare_with_schemes(&tampered, "sig", 1_000, 60, &["cached"])
            .unwrap()
            .verify_cached(&cache, 1_000)
            .unwrap_err(),
        Error::CacheMiss
    );
    assert_eq!(Error::CacheMiss.code(), "cache_miss");

    let retained = cache
        .issue_requested(
            true,
            cache_request(&key, &public, Some(marker), 5_000, 1_500).unwrap(),
        )
        .unwrap()
        .unwrap();
    let retained_req = cached_request(&key, &retained.cid);
    let retained_proof =
        PreparedRequest::prepare_with_schemes(&retained_req, "sig", 1_000, 60, &["cached"])
            .unwrap();
    retained_proof.verify_cached(&cache, 1_500).unwrap();
    assert_eq!(
        retained_proof.verify_cached(&cache, 1_501).unwrap_err(),
        Error::CacheMiss
    );
    let expiring = cache
        .issue_requested(
            true,
            cache_request(&key, &public, Some(marker), 2_000, 2_000).unwrap(),
        )
        .unwrap()
        .unwrap();
    let expiring_req = cached_request(&key, &expiring.cid);
    let expiring_proof =
        PreparedRequest::prepare_with_schemes(&expiring_req, "sig", 1_000, 60, &["cached"])
            .unwrap();
    expiring_proof.verify_cached(&cache, 1_999).unwrap();
    assert_eq!(
        expiring_proof.verify_cached(&cache, 2_000).unwrap_err(),
        Error::ExpiredJwt
    );
    assert_eq!(
        expiring_proof.verify_cached(&cache, 2_001).unwrap_err(),
        Error::CacheMiss
    );

    assert!(cache.evict(&grant.cid));
    assert_eq!(
        prepared.verify_cached(&cache, 1_000).unwrap_err(),
        Error::CacheMiss
    );
    assert_eq!(
        prepared.verify_cached_sealed(&cache, 1_000).unwrap().jti,
        marker
    );

    assert!(
        cache
            .issue_requested(
                false,
                cache_request(&key, &public, Some(marker), 5_000, 4_000).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        cache_request(&key, &public, None, 5_000, 4_000).unwrap_err(),
        Error::InvalidJwt
    );
    assert_eq!(
        cache
            .issue_requested(
                true,
                cache_request(&key, &public, Some(marker), 2_000, 2_001).unwrap()
            )
            .unwrap_err(),
        Error::InvalidKey
    );
    assert!(
        cache
            .issue_requested(
                true,
                cache_request(&key, &public, Some(marker), 1_000 + 86_401, 2_000).unwrap()
            )
            .unwrap()
            .is_none()
    );

    let mut bounded = AssertionCache::open([7; 32], 1, 1).unwrap();
    assert!(
        bounded
            .issue_requested(
                true,
                cache_request(&key, &public, Some(marker), 5_000, 4_000).unwrap()
            )
            .unwrap()
            .is_some()
    );
    assert!(
        bounded
            .issue_requested(
                true,
                cache_request(&key, &public, Some(marker), 5_000, 4_000).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert!(
        bounded
            .issue_requested(
                true,
                cache_request(&key, &public, Some("after-expiry"), 9_000, 8_000)
                    .unwrap()
                    .at(4_000)
            )
            .unwrap()
            .is_some()
    );
    let other = SigningKey::from_seed([6; 32]);
    let other_public = other.public_jwk();
    let mut per_key = AssertionCache::open([7; 32], 4, 1).unwrap();
    assert!(
        per_key
            .issue_requested(
                true,
                cache_request(&key, &public, Some(marker), 5_000, 4_000).unwrap()
            )
            .unwrap()
            .is_some()
    );
    assert!(
        per_key
            .issue_requested(
                true,
                cache_request(&key, &public, Some(marker), 5_000, 4_000).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert!(
        per_key
            .issue_requested(
                true,
                cache_request(&other, &other_public, Some(marker), 5_000, 4_000).unwrap()
            )
            .unwrap()
            .is_some()
    );

    assert_eq!(
        select_presented_scheme(&["cached", "jwt"], None),
        Some("jwt")
    );
    assert_eq!(select_presented_scheme(&["cached"], None), None);
    assert_eq!(
        select_presented_scheme(&["cached", "jwt"], Some(&grant.cid)),
        Some("cached")
    );
    present_issued_cid(Some(grant.cid.as_str()), &grant.cid).unwrap();
    assert_eq!(
        present_issued_cid(None, &grant.cid).unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        present_issued_cid(Some(grant.cid.as_str()), &format!("{}a", grant.cid)).unwrap_err(),
        Error::InvalidKey
    );

    let jose = serde_json::json!({"alg": "Ed25519"});
    let with_jti = Jws::sign(
        &jose,
        format!(r#"{{"exp":5000,"jti":"{marker}"}}"#).as_bytes(),
        &key,
    )
    .unwrap();
    let without_jti = Jws::sign(&jose, br#"{"exp":5000}"#, &key).unwrap();
    let cached_jwt = x509_request(&format!(r#"sig=jwt;jwt="{with_jti}";cache"#), &[1u8; 64]);
    let prepared_jwt = PreparedRequest::prepare(&cached_jwt, "sig", 1_000, 60).unwrap();
    assert!(prepared_jwt.cache_requested());
    assert_eq!(
        PreparedRequest::prepare(
            &x509_request(&format!(r#"sig=jwt;jwt="{without_jti}";cache"#), &[1u8; 64]),
            "sig",
            1_000,
            60,
        )
        .unwrap_err(),
        Error::InvalidJwt
    );
    assert_eq!(
        PreparedRequest::prepare(
            &x509_request(&format!(r#"sig=jwt;jwt="{with_jti}";cache=?1"#), &[1u8; 64],),
            "sig",
            1_000,
            60,
        )
        .unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        PreparedRequest::prepare_with_schemes(
            &x509_request("sig=cached", &[1u8; 64]),
            "sig",
            1_000,
            60,
            &["cached"],
        )
        .unwrap_err(),
        Error::InvalidKey
    );
}

fn cached_request(key: &SigningKey, cid: &str) -> Request<Vec<u8>> {
    let mut req = request();
    sign_request(
        &mut req,
        key,
        KeyMaterial::Cached {
            cid: cid.to_owned(),
        },
        1_000,
    )
    .unwrap();
    req
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(bytes)
}
