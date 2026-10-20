//! Direct Agent-identity Resource. Proof and token checks precede host policy.
use aauth_core::{AgentKeyResolver,AgentToken,TokenError,VerifiedAgentToken};
use aauth_signature_key::{Error,KeyMaterial,PreparedRequest};
use http::{Request,Response,StatusCode};

pub enum SignatureFailure {Proof(Error),Token(TokenError)}
impl std::fmt::Display for SignatureFailure {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{match self{Self::Proof(e)=>e.fmt(f),Self::Token(e)=>e.fmt(f)}}
}
pub enum Decision {
    AgentTokenRequired,
    SignatureFailure(SignatureFailure),
    Forbidden,
    Granted(VerifiedAgentToken),
}
impl Decision {
    /// Minimal HTTP mapping; a host supplies application response bodies.
    pub fn into_response(self)->Response<Vec<u8>>{
        let mut response=Response::new(Vec::new());
        match self {
            Self::AgentTokenRequired=>{
                *response.status_mut()=StatusCode::UNAUTHORIZED;
                response.headers_mut().insert("aauth-requirement","requirement=agent-token".parse().unwrap());
            },
            Self::Forbidden=>{*response.status_mut()=StatusCode::FORBIDDEN;},
            Self::Granted(token)=>{*response.body_mut()=token.claims().sub.as_bytes().to_vec();},
            Self::SignatureFailure(failure)=>{
                *response.status_mut()=StatusCode::UNAUTHORIZED;
                let mut error=format!("error={failure}");
                if matches!(failure,SignatureFailure::Proof(Error::InvalidInput)){
                    error.push_str(", required_input=(\"@method\" \"@authority\" \"@path\" \"signature-key\")");
                }
                response.headers_mut().insert("signature-error",error.parse().unwrap());
                if matches!(failure,SignatureFailure::Proof(Error::UnsupportedAlgorithm)|SignatureFailure::Token(TokenError::UnsupportedAlgorithm)){
                    response.headers_mut().insert("accept-signature-alg","Ed25519".parse().unwrap());
                }
                if matches!(failure,SignatureFailure::Proof(Error::UnsupportedScheme)){
                    response.headers_mut().insert("aauth-requirement","requirement=agent-token".parse().unwrap());
                }
            }
        }
        response
    }
}

pub struct AgentIdentityResource<K,P>{keys:K,policy:P}
impl<K:AgentKeyResolver,P:Fn(&VerifiedAgentToken)->bool> AgentIdentityResource<K,P>{
    pub fn new(keys:K,policy:P)->Self{Self{keys,policy}}
    pub fn with_policy<Q:Fn(&VerifiedAgentToken)->bool>(self,policy:Q)->AgentIdentityResource<K,Q>{AgentIdentityResource{keys:self.keys,policy}}
    pub fn authorize(&self,request:&Request<Vec<u8>>,now:i64)->Decision{
        if ["signature-key","signature-input","signature"].iter().all(|h|!request.headers().contains_key(*h)){return Decision::AgentTokenRequired}
        let proof=match PreparedRequest::prepare(request,"sig",now,60){Ok(v)=>v,Err(e)=>return Decision::SignatureFailure(SignatureFailure::Proof(e))};
        let KeyMaterial::Jwt(compact)=proof.key() else{return Decision::AgentTokenRequired};
        let token=match AgentToken::parse(compact).and_then(|t|t.verify(&self.keys,now)){Ok(v)=>v,Err(e)=>return Decision::SignatureFailure(SignatureFailure::Token(e))};
        if token.claims().iat>now.saturating_add(60){return Decision::SignatureFailure(SignatureFailure::Proof(Error::ClockSkew))}
        if let Err(e)=proof.verify(&token.claims().cnf.jwk){return Decision::SignatureFailure(SignatureFailure::Proof(e))}
        if !(self.policy)(&token){return Decision::Forbidden}
        Decision::Granted(token)
    }
}
