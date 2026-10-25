use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_signature_key::{Error, KeyMaterial, PreparedRequest, sign_request};
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
