use aauth_rust_core::ApprovedMission;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

fn decode(bytes: &[u8]) -> Result<ApprovedMission, aauth_rust_core::MissionError> {
    ApprovedMission::decode(
        &URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
        &URL_SAFE_NO_PAD.encode(bytes),
    )
}

#[test]
fn current_mission_keeps_exact_additive_and_legacy_bytes() {
    for exact in [
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","description":"Read the approved revision"}"#,
        "{\n \"agent\":\"aauth:Reader@ap.example\",\"approved_at\":\"2026-10-21T14:00:00+02:00\",\"expires_at\":\"2026-10-21T12:01:00.9Z\",\"description\":\"Read\",\"extension\":{\"opaque\":[null,true]}}",
        r#"{"approver":"https://legacy.example","agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","description":"Read"}"#,
    ] {
        let mission = decode(exact.as_bytes()).expect("valid current/additive mission");
        assert_eq!(mission.exact_json(), exact.as_bytes());
        assert_eq!(mission.encoded(), URL_SAFE_NO_PAD.encode(exact));
        assert_eq!(mission.agent(), "aauth:Reader@ap.example");
        assert_eq!(mission.approved_at(), 1_792_584_000);
        if exact.contains("expires_at") {
            assert_eq!(mission.expires_at(), Some(1_792_584_060));
        }
        let changed = format!("{exact} ");
        assert!(ApprovedMission::decode(mission.s256(), &URL_SAFE_NO_PAD.encode(changed)).is_err());
    }
}

#[test]
fn malformed_mission_identity_and_known_members_are_refused() {
    for exact in [
        r#"{"agent":"bad","approved_at":"2026-10-21T12:00:00Z","description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","agent":"aauth:Other@ap.example","approved_at":"2026-10-21T12:00:00Z","description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-02-30T12:00:00Z","description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":true,"description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","expires_at":null,"description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","description":""}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"1969-12-31T23:59:59Z","description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","expires_at":"2026-10-21T12:00:00Z","description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","expires_at":"2026-10-21T11:59:59Z","description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","expires_at":"2026-10-21T12:00:00.9Z","description":"Read"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z"}"#,
        r#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","description":"Read","extension":{"x":1,"x":2}}"#,
    ] {
        assert!(decode(exact.as_bytes()).is_err(), "accepted {exact}");
    }
    let exact = br#"{"agent":"aauth:Reader@ap.example","approved_at":"2026-10-21T12:00:00Z","description":"Read"}"#;
    let valid = decode(exact).unwrap();
    assert!(ApprovedMission::decode(&format!("{}=", valid.s256()), valid.encoded()).is_err());
    assert!(ApprovedMission::decode(valid.s256(), &format!("{}=", valid.encoded())).is_err());
    let epoch = br#"{"agent":"aauth:Reader@ap.example","approved_at":"1970-01-01T00:00:00Z","expires_at":"1970-01-01T00:00:01Z","description":"Read"}"#;
    let opened = decode(epoch).unwrap();
    assert_eq!(opened.approved_at(), 0);
    assert_eq!(opened.expires_at(), Some(1));
    assert_eq!(opened.description(), "Read");
}
