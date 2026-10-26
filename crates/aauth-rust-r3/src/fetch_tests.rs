use std::io;
use std::sync::{Mutex, atomic::{AtomicI64, AtomicUsize, Ordering}};
use std::time::{Duration, Instant};
use aauth_rust_jose::SigningKey;
use http::{Request, Response};
use crate::*;

const DOC: &[u8] = br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}"#;
const PROPOSAL: &[u8] = br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"parameters":{"id":1}}"#;

struct Body { bytes: Vec<u8>, offset: usize, read: std::sync::Arc<AtomicUsize>, deadline:Instant }
impl FetchBody for Body {
    fn read(&mut self, out: &mut [u8], deadline: Instant) -> io::Result<usize> {
        assert!(deadline > Instant::now());
        assert_eq!(deadline,self.deadline);
        let size = out.len().min(self.bytes.len()-self.offset);
        out[..size].copy_from_slice(&self.bytes[self.offset..self.offset+size]);
        self.offset += size;
        self.read.fetch_add(size, Ordering::SeqCst);
        Ok(size)
    }
}
struct Wire { calls: AtomicUsize, requests: Mutex<Vec<Request<Vec<u8>>>>, status:u16, headers:Vec<(&'static str,&'static str)>, bytes:Vec<u8>, read:std::sync::Arc<AtomicUsize> }
impl FetchTransport for Wire {
    fn send(&self, request:Request<Vec<u8>>, deadline:Instant)->io::Result<FetchResponse>{
        assert!(deadline>Instant::now());self.calls.fetch_add(1,Ordering::SeqCst);
        self.requests.lock().unwrap().push(request);
        let mut response=Response::builder().status(self.status);
        for (name,value) in &self.headers {response=response.header(*name,*value);}
        Ok(response.body(Box::new(Body{bytes:self.bytes.clone(),offset:0,read:self.read.clone(),deadline}) as Box<dyn FetchBody>).unwrap())
    }
}
fn wire(bytes:&[u8])->Wire { Wire {calls:AtomicUsize::new(0),requests:Mutex::new(Vec::new()),status:200,headers:vec![("content-type","application/json; charset=utf-8")],bytes:bytes.to_vec(),read:Default::default()} }
fn identity(role:&str)->FetchIdentity {FetchIdentity{issuer:"https://issuer.example".into(),discovery_document:role.into(),key_id:"fetch-key".into()}}

#[test]
fn fetch_signs_once_with_current_role_clock_and_classifies_bytes() -> Result<(),Box<dyn std::error::Error>> {
    let registry=standard_registry()?;let key=SigningKey::from_seed([71;32]);let now=AtomicI64::new(1788120000);let clock=||now.load(Ordering::SeqCst);
    for role in ["aauth-person.json","aauth-access.json"] {
        let wire=wire(PROPOSAL);let admissions=AtomicUsize::new(0);
        let admit=|uri:&str,deadline:Instant| {assert!(uri.ends_with("/looks-like-a-class"));assert!(deadline>Instant::now());assert_eq!(wire.calls.load(Ordering::SeqCst),0);admissions.fetch_add(1,Ordering::SeqCst);Ok(())};
        let client=FetchClient::new(FetchConfig{registry:&registry,signing_key:&key,identity:identity(role),clock:&clock,admit:&admit,transport:&wire,limits:FetchLimits::default()})?;
        now.fetch_add(1,Ordering::SeqCst);
        let reference=Reference::new("https://resource.example/looks-like-a-class",digest(PROPOSAL))?;
        let fetched=client.fetch_artifact(&reference)?;
        assert_eq!(fetched.kind(),ArtifactKind::Proposal);assert_eq!(fetched.exact_bytes(),PROPOSAL);assert_eq!(admissions.load(Ordering::SeqCst),1);assert_eq!(wire.calls.load(Ordering::SeqCst),1);
        let requests=wire.requests.lock().unwrap();let request=&requests[0];assert_eq!(request.method(),"GET");assert!(request.body().is_empty());assert_eq!(request.headers()["accept-encoding"],"identity");assert!(!request.headers().contains_key("cookie"));assert!(request.headers()["signature-key"].to_str()?.contains(role));assert!(request.headers()["signature-input"].to_str()?.contains(&format!("created={}",clock())));
        aauth_rust_signature_key::PreparedRequest::prepare_with_schemes(request,"sig",clock(),300,&["jwks_uri"])?.verify(&key.public_jwk())?;
    }Ok(())
}

#[test]
fn fetch_refuses_egress_and_invalid_roles_before_transport() -> Result<(),Box<dyn std::error::Error>> {
    let registry=standard_registry()?;let key=SigningKey::from_seed([72;32]);let clock=||1788120000;let wire=wire(DOC);
    let deny=|_:&str,_:Instant|Err(io::Error::new(io::ErrorKind::PermissionDenied,"egress refused"));
    let client=FetchClient::new(FetchConfig{registry:&registry,signing_key:&key,identity:identity("aauth-person.json"),clock:&clock,admit:&deny,transport:&wire,limits:FetchLimits::default()})?;
    assert!(matches!(client.fetch_document(&Reference::new("https://resource.example/one",digest(DOC))?),Err(e) if !e.is_document_error()));assert_eq!(wire.calls.load(Ordering::SeqCst),0);
    assert!(FetchClient::new(FetchConfig{registry:&registry,signing_key:&key,identity:identity("aauth-resource.json"),clock:&clock,admit:&deny,transport:&wire,limits:FetchLimits::default()}).is_err());Ok(())
}

#[test]
fn elapsed_admission_deadline_never_reaches_transport() -> Result<(),Box<dyn std::error::Error>> {
    let registry=standard_registry()?;let key=SigningKey::from_seed([74;32]);let clock=||1788120000;let wire=wire(DOC);
    let late=|_:&str,deadline:Instant|{while Instant::now()<deadline{std::thread::yield_now();}Ok(())};
    let client=FetchClient::new(FetchConfig{registry:&registry,signing_key:&key,identity:identity("aauth-person.json"),clock:&clock,admit:&late,transport:&wire,limits:FetchLimits{maximum_document_bytes:1024,timeout:Duration::from_millis(1)}})?;
    assert!(matches!(client.fetch_document(&Reference::new("https://resource.example/one",digest(DOC))?),Err(FetchError::Transport(e)) if e.kind()==io::ErrorKind::TimedOut));assert_eq!(wire.calls.load(Ordering::SeqCst),0);Ok(())
}

#[test]
fn fetch_bounds_body_before_allocation_and_types_failures() -> Result<(),Box<dyn std::error::Error>> {
    let registry=standard_registry()?;let key=SigningKey::from_seed([73;32]);let clock=||1788120000;let admit=|_:&str,_:Instant|Ok(());
    for (status,headers,body,cap,document_error) in [
        (302,vec![("location","https://other.example")],DOC,1024,true),
        (404,vec![],DOC,1024,true),(410,vec![],DOC,1024,true),
        (401,vec![],DOC,1024,false),(503,vec![],DOC,1024,false),
        (200,vec![("content-type","text/plain")],DOC,1024,true),
        (200,vec![("content-type","application/json"),("content-type","application/json")],DOC,1024,true),
        (200,vec![("content-type","application/json"),("content-encoding","gzip")],DOC,1024,true),
        (200,vec![("content-type","application/json")],DOC,8,true),
        (200,vec![("content-type","application/json")],PROPOSAL,1024,true),
    ] {
        let mut wire=wire(body);wire.status=status;wire.headers=headers;
        let client=FetchClient::new(FetchConfig{registry:&registry,signing_key:&key,identity:identity("aauth-access.json"),clock:&clock,admit:&admit,transport:&wire,limits:FetchLimits{maximum_document_bytes:cap,timeout:Duration::from_secs(10)}})?;
        let result=client.fetch_document(&Reference::new("https://resource.example/one",digest(DOC))?);
        assert!(matches!(result,Err(ref e) if e.is_document_error()==document_error));assert_eq!(wire.calls.load(Ordering::SeqCst),1);assert!(wire.read.load(Ordering::SeqCst)<=cap+1);
    }Ok(())
}

#[test]
fn artifact_parser_checks_digest_and_never_guesses_from_uri() -> Result<(),Error> {
    let r=standard_registry()?;
    let reference=Reference::new("https://resource.example/proposal",digest(DOC))?;
    assert_eq!(r.parse_referenced_artifact(&reference,DOC)?.kind(),ArtifactKind::Document);
    assert!(r.parse_referenced_artifact(&reference,PROPOSAL).is_err());
    let reference=Reference::new("https://resource.example/document",digest(PROPOSAL))?;
    assert_eq!(r.parse_referenced_artifact(&reference,PROPOSAL)?.kind(),ArtifactKind::Proposal);
    assert!(r.parse_referenced_document(&reference,PROPOSAL).is_err());Ok(())
}
