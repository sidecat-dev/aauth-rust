use aauth_rust_jose::SigningKey;
use aauth_rust_signature_key::{Error, KeyMaterial, PreparedRequest, sign_request};
use http::Request;

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
fn body_and_ambiguous_header_instances_are_refused() {
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
    *req.body_mut() = b"body".to_vec();
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
