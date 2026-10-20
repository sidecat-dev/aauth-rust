use aauth_jose::SigningKey;
use aauth_signature_key::{KeyMaterial, PreparedRequest, Error, sign_request};
use http::Request;

fn request() -> Request<Vec<u8>> {
    Request::builder().uri("https://resource.example/whoami?x=1").body(Vec::new()).unwrap()
}
fn signed() -> (Request<Vec<u8>>,SigningKey) {
    let key=SigningKey::from_seed([7;32]); let mut req=request();
    sign_request(&mut req,&key,KeyMaterial::Hwk(key.public_jwk()),1000).unwrap();
    (req,key)
}

#[test]
fn hwk_signature_covers_the_actual_target_and_key() {
    let (req,key)=signed();
    let prepared=PreparedRequest::prepare(&req,"sig",1000,60).unwrap();
    prepared.verify(&key.public_jwk()).unwrap();
    assert!(matches!(prepared.key(),KeyMaterial::Hwk(_)));
    for uri in ["https://resource.example/other?x=1","https://other.example/whoami?x=1","https://resource.example/whoami?x=2"] {
        let (mut changed,key)=signed(); *changed.uri_mut()=uri.parse().unwrap();
        assert!(PreparedRequest::prepare(&changed,"sig",1000,60).unwrap().verify(&key.public_jwk()).is_err());
    }
}

#[test]
fn rfc9421_base_is_independently_checkable() {
    let (req,_)=signed();
    let prepared=PreparedRequest::prepare(&req,"sig",1000,60).unwrap();
    let key_header=req.headers()["signature-key"].to_str().unwrap();
    let expected=format!("\"@method\": GET\n\"@authority\": resource.example\n\"@path\": /whoami\n\"@query\": ?x=1\n\"signature-key\": {key_header}\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created=1000");
    assert_eq!(prepared.signature_base(),expected.as_bytes());
}

#[test]
fn required_coverage_and_label_correlation_fail_closed() {
    let (mut req,_)=signed();
    req.headers_mut().insert("signature-input", "sig=(\"@method\" \"@authority\" \"@path\" \"@query\");created=1000".parse().unwrap());
    assert_eq!(PreparedRequest::prepare(&req,"sig",1000,60).err().unwrap(),Error::InvalidInput);
    let (req,_)=signed();
    assert!(PreparedRequest::prepare(&req,"missing",1000,60).is_err());
}

#[test]
fn signature_time_has_exact_boundaries() {
    let (req,_)=signed();
    for now in [940,1000,1060] {PreparedRequest::prepare(&req,"sig",now,60).unwrap();}
    assert_eq!(PreparedRequest::prepare(&req,"sig",939,60).err().unwrap(),Error::ClockSkew);
    assert_eq!(PreparedRequest::prepare(&req,"sig",1061,60).err().unwrap(),Error::InvalidSignature);
}

#[test]
fn unknown_unselected_scheme_does_not_break_selected_proof() {
    let (mut req,key)=signed();
    // Re-sign the full key header including an unselected future scheme.
    let header=format!("{}, other=future;value=token",req.headers()["signature-key"].to_str().unwrap());
    req.headers_mut().insert("signature-key",header.parse().unwrap());
    let base=PreparedRequest::prepare(&req,"sig",1000,60).unwrap().signature_base().to_vec();
    use base64::Engine;
    req.headers_mut().insert("signature",format!("sig=:{}:",base64::engine::general_purpose::STANDARD.encode(key.sign(&base))).parse().unwrap());
    PreparedRequest::prepare(&req,"sig",1000,60).unwrap().verify(&key.public_jwk()).unwrap();
}

#[test]
fn inline_key_cannot_carry_a_kid_or_infer_an_algorithm() {
    for suffix in [";kid=\"ambiguous\"", ""] {
        let (mut req,_)=signed();
        let mut value=format!("{}{suffix}",req.headers()["signature-key"].to_str().unwrap());
        if suffix.is_empty() {value=value.replace(";alg=\"Ed25519\"", "");}
        req.headers_mut().insert("signature-key",value.parse().unwrap());
        assert!(PreparedRequest::prepare(&req,"sig",1000,60).is_err());
    }
}

#[test]
fn body_and_ambiguous_header_instances_are_refused() {
    let (mut req,_)=signed(); *req.body_mut()=b"unprotected".to_vec();
    assert!(PreparedRequest::prepare(&req,"sig",1000,60).is_err());
    let (mut req,_)=signed(); req.headers_mut().append("signature-key","sig=hwk".parse().unwrap());
    assert!(PreparedRequest::prepare(&req,"sig",1000,60).is_err());
}
