//! Agent acceptance of a Go access-server R3 grant.
//!
//! Go `accessserver` issues `dwk` `aauth-access.json`, `iss` the access server,
//! `aud` the resource, and `ps` the person server. Go
//! `validateR3AuthTokenForResourceBinding` takes that `dwk` from the signed
//! token and requires `iss` to equal the Resource token's `aud`. A proposal
//! Resource token's `aud` is the class token's issuer
//! (`verifyR3ProposalRequirement`).

use std::collections::BTreeMap;

use aauth_rust_agent::{Agent, R3AgentError};
use aauth_rust_core::{
    AgentKeyResolver, AuthClaims, Confirmation, PersonClaims, ResourceClaims, TokenError,
    mint_auth_token, mint_person_token,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use aauth_rust_r3::{
    Grant, GrantedOperations, McpCodec, Operation, Parameter, Parameters, Proposal,
    ProposalOptions, Registry, mint_direct_auth_token, mint_per_call_auth_token,
    mint_proposal_resource_token, mint_resource_token, standard_registry, verify_resource_token,
};
use serde_json::json;

const NOW: i64 = 1_700_000_000;
const RESOURCE: &str = "https://resource.example";
const PS: &str = "https://ps.example";
const AS: &str = "https://as.example";
const OTHER_AS: &str = "https://other-as.example";
const SUBJECT: &str = "person-1";
const CLASS_URI: &str = "https://resource.example/r3/class-one";
const PROPOSAL_URI: &str = "https://resource.example/r3/proposal-one";
const CLASS: &[u8] = br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"},{"tool":"records.delete"}]}"#;
const PERSON_DOCUMENT: &str = "aauth-person.json";
const ACCESS_DOCUMENT: &str = "aauth-access.json";

type TestError = Box<dyn std::error::Error>;

struct Keys(Vec<(String, String, String, Jwk)>);

impl AgentKeyResolver for Keys {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        self.0
            .iter()
            .find(|(id, document, key_id, _)| id == issuer && document == dwk && key_id == kid)
            .map(|(.., jwk)| jwk.clone())
            .ok_or(TokenError::UnknownKey)
    }
}

struct World {
    agent: Agent,
    holder: Jwk,
    registry: Registry,
    keys: Keys,
    resource_key: SigningKey,
    person_key: SigningKey,
    access_key: SigningKey,
    person: String,
}

fn world() -> Result<World, TestError> {
    let agent_key = SigningKey::from_seed([2; 32]);
    let holder = agent_key.public_jwk();
    let person_key = SigningKey::from_seed([3; 32]);
    let resource_key = SigningKey::from_seed([4; 32]);
    let access_key = SigningKey::from_seed([7; 32]);
    let agent_token = Jws::sign(
        &json!({"typ": "aa-agent+jwt", "alg": "Ed25519", "kid": "ap"}),
        json!({
            "iss": "https://ap.example",
            "dwk": "aauth-agent.json",
            "sub": "aauth:Caller@ap.example",
            "jti": "agent-1",
            "iat": NOW,
            "exp": NOW + 3600,
            "ps": PS,
            "cnf": {"jwk": holder}
        })
        .to_string()
        .as_bytes(),
        &SigningKey::from_seed([1; 32]),
    )?;
    let person = mint_person_token(
        &person_key,
        "ps-1",
        &PersonClaims {
            iss: PS.into(),
            dwk: PERSON_DOCUMENT.into(),
            aud: RESOURCE.into(),
            sub: SUBJECT.into(),
            jti: "person-1".into(),
            iat: NOW,
            exp: NOW + 3600,
            cnf: Confirmation {
                jwk: holder.clone(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: BTreeMap::new(),
        },
    )?;
    let keys = Keys(vec![
        (
            PS.into(),
            PERSON_DOCUMENT.into(),
            "ps-1".into(),
            person_key.public_jwk(),
        ),
        (
            PS.into(),
            ACCESS_DOCUMENT.into(),
            "as-key".into(),
            access_key.public_jwk(),
        ),
        (
            AS.into(),
            ACCESS_DOCUMENT.into(),
            "as-key".into(),
            access_key.public_jwk(),
        ),
        (
            RESOURCE.into(),
            "aauth-resource.json".into(),
            "resource-1".into(),
            resource_key.public_jwk(),
        ),
    ]);
    Ok(World {
        agent: Agent::new(agent_key, agent_token)?,
        holder,
        registry: standard_registry()?,
        keys,
        resource_key,
        person_key,
        access_key,
        person,
    })
}

fn resource_token(world: &World, audience: &str, jti: &str) -> Result<String, TestError> {
    let (compact, _) = mint_resource_token(
        &world.registry,
        &world.resource_key,
        "resource-1",
        &ResourceClaims {
            iss: RESOURCE.into(),
            dwk: "aauth-resource.json".into(),
            aud: audience.into(),
            sub: SUBJECT.into(),
            jti: jti.into(),
            iat: NOW,
            exp: NOW + 300,
            ps: PS.into(),
            presented_jti: "person-1".into(),
            agent_jkt: world.holder.thumbprint()?,
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        CLASS_URI,
        CLASS,
    )?;
    Ok(compact)
}

fn class_grant(world: &World, issuer: &str, document: &str) -> Result<String, TestError> {
    let (key, kid) = if document == PERSON_DOCUMENT {
        (&world.person_key, "ps-1")
    } else {
        (&world.access_key, "as-key")
    };
    let (_, reference) = mint_resource_token(
        &world.registry,
        &world.resource_key,
        "resource-1",
        &resource_claims(world, issuer, "unused-resource")?,
        CLASS_URI,
        CLASS,
    )?;
    let parsed = world.registry.parse_document(CLASS)?;
    let vocabulary = McpCodec::vocabulary()?;
    let operation = Operation::new(&vocabulary, br#"{"tool":"records.read"}"#)?;
    let grant = Grant::new(&GrantedOperations::new(&vocabulary, &[operation])?, &parsed)?;
    Ok(mint_direct_auth_token(
        &world.registry,
        key,
        kid,
        &auth_claims(world, issuer, document, "class-grant", NOW + 600)?,
        &reference,
        CLASS,
        &grant,
    )?)
}

fn resource_claims(world: &World, audience: &str, jti: &str) -> Result<ResourceClaims, TestError> {
    Ok(ResourceClaims {
        iss: RESOURCE.into(),
        dwk: "aauth-resource.json".into(),
        aud: audience.into(),
        sub: SUBJECT.into(),
        jti: jti.into(),
        iat: NOW,
        exp: NOW + 300,
        ps: PS.into(),
        presented_jti: "person-1".into(),
        agent_jkt: world.holder.thumbprint()?,
        nbf: None,
        tenant: None,
        mission_s256: None,
        scope: None,
        account: None,
        login_hint: None,
        extra: BTreeMap::new(),
    })
}

fn auth_claims(
    world: &World,
    issuer: &str,
    document: &str,
    jti: &str,
    exp: i64,
) -> Result<AuthClaims, TestError> {
    Ok(AuthClaims {
        iss: issuer.into(),
        dwk: document.into(),
        aud: RESOURCE.into(),
        sub: SUBJECT.into(),
        jti: jti.into(),
        iat: NOW,
        exp,
        ps: PS.into(),
        cnf: Confirmation {
            jwk: world.holder.clone(),
        },
        nbf: None,
        tenant: None,
        mission_s256: None,
        scope: None,
        account: None,
        extra: BTreeMap::new(),
    })
}

fn is_context(result: Result<impl Sized, R3AgentError>) -> bool {
    matches!(result, Err(R3AgentError::Context))
}

#[test]
fn access_server_class_grant_uses_the_signed_access_document() -> Result<(), TestError> {
    let world = world()?;
    let registry = standard_registry()?;
    let federated = world.agent.verify_r3_resource_token(
        &resource_token(&world, AS, "resource-as")?,
        RESOURCE,
        PS,
        &world.person,
        None,
        &world.keys,
        NOW,
    )?;
    assert_eq!(federated.claims().aud, AS);
    let delivered = world.agent.verify_r3_auth_delivery(
        &class_grant(&world, AS, ACCESS_DOCUMENT)?,
        RESOURCE,
        &federated,
        &world.person,
        &registry,
        &world.keys,
        NOW,
    )?;
    assert_eq!(delivered.claims().dwk, ACCESS_DOCUMENT);
    assert_eq!(delivered.claims().iss, AS);
    assert_eq!(delivered.claims().ps, PS);

    let direct_resource = world.agent.verify_r3_resource_token(
        &resource_token(&world, PS, "resource-ps")?,
        RESOURCE,
        PS,
        &world.person,
        None,
        &world.keys,
        NOW,
    )?;
    assert!(is_context(world.agent.verify_r3_auth_delivery(
        &class_grant(&world, AS, ACCESS_DOCUMENT)?,
        RESOURCE,
        &direct_resource,
        &world.person,
        &registry,
        &world.keys,
        NOW,
    )));
    assert!(is_context(world.agent.verify_r3_auth_delivery(
        &class_grant(&world, PS, PERSON_DOCUMENT)?,
        RESOURCE,
        &federated,
        &world.person,
        &registry,
        &world.keys,
        NOW,
    )));
    Ok(())
}

#[test]
fn direct_person_server_grant_still_verifies() -> Result<(), TestError> {
    let world = world()?;
    let verified = world.agent.verify_r3_resource_token(
        &resource_token(&world, PS, "resource-ps")?,
        RESOURCE,
        PS,
        &world.person,
        None,
        &world.keys,
        NOW,
    )?;
    let delivered = world.agent.verify_r3_auth_delivery(
        &class_grant(&world, PS, PERSON_DOCUMENT)?,
        RESOURCE,
        &verified,
        &world.person,
        &world.registry,
        &world.keys,
        NOW,
    )?;
    assert_eq!(delivered.claims().dwk, PERSON_DOCUMENT);
    assert_eq!(delivered.claims().iss, PS);
    Ok(())
}

#[test]
fn access_server_per_call_grant_uses_the_class_document() -> Result<(), TestError> {
    let world = world()?;
    let registry = standard_registry()?;
    let parameters = Parameters::new(Vec::<(String, Parameter)>::new())?;
    let proposal = Proposal::new(
        &Operation::new(&McpCodec::vocabulary()?, br#"{"tool":"records.delete"}"#)?,
        &parameters,
        ProposalOptions {
            account: None,
            result: None,
            display: None,
        },
    )?;
    let exact = serde_json::to_vec(&proposal)?;
    let class = mint_auth_token(
        &world.access_key,
        "as-key",
        &auth_claims(&world, AS, ACCESS_DOCUMENT, "class-as", NOW + 3600)?,
    )?;
    let (proposal_token, reference) = mint_proposal_resource_token(
        &registry,
        &world.resource_key,
        "resource-1",
        &proposal_claims(&world, AS, "class-as")?,
        PROPOSAL_URI,
        &exact,
    )?;
    let verified = world.agent.verify_r3_proposal_challenge(
        &proposal_token,
        RESOURCE,
        PS,
        &class,
        &world.keys,
        NOW,
    )?;
    let per_call = mint_per_call_auth_token(
        &registry,
        &world.access_key,
        "as-key",
        &auth_claims(&world, AS, ACCESS_DOCUMENT, "per-call-as", NOW + 600)?,
        &reference,
        &exact,
    )?;
    let delivered = world.agent.verify_r3_per_call_delivery(
        &per_call,
        RESOURCE,
        &verified,
        &class,
        &registry,
        &world.keys,
        NOW,
    )?;
    assert_eq!(delivered.claims().dwk, ACCESS_DOCUMENT);
    assert_eq!(delivered.claims().iss, AS);

    let (person_audience, _) = mint_proposal_resource_token(
        &registry,
        &world.resource_key,
        "resource-1",
        &proposal_claims(&world, PS, "class-as")?,
        PROPOSAL_URI,
        &exact,
    )?;
    assert!(is_context(world.agent.verify_r3_proposal_challenge(
        &person_audience,
        RESOURCE,
        PS,
        &class,
        &world.keys,
        NOW,
    )));

    let person_role = mint_per_call_auth_token(
        &registry,
        &world.person_key,
        "ps-1",
        &auth_claims(&world, PS, PERSON_DOCUMENT, "per-call-ps", NOW + 600)?,
        &reference,
        &exact,
    )?;
    assert!(is_context(world.agent.verify_r3_per_call_delivery(
        &person_role,
        RESOURCE,
        &verified,
        &class,
        &registry,
        &world.keys,
        NOW,
    )));
    Ok(())
}

#[test]
fn shared_identifier_keeps_the_class_tokens_access_document() -> Result<(), TestError> {
    let world = world()?;
    let registry = standard_registry()?;
    let class = mint_auth_token(
        &world.access_key,
        "as-key",
        &auth_claims(&world, PS, ACCESS_DOCUMENT, "class-shared", NOW + 3600)?,
    )?;
    let parameters = Parameters::new(Vec::<(String, Parameter)>::new())?;
    let exact = serde_json::to_vec(&Proposal::new(
        &Operation::new(&McpCodec::vocabulary()?, br#"{"tool":"records.delete"}"#)?,
        &parameters,
        ProposalOptions {
            account: None,
            result: None,
            display: None,
        },
    )?)?;
    let (proposal_token, reference) = mint_proposal_resource_token(
        &registry,
        &world.resource_key,
        "resource-1",
        &proposal_claims(&world, PS, "class-shared")?,
        PROPOSAL_URI,
        &exact,
    )?;
    let verified = world.agent.verify_r3_proposal_challenge(
        &proposal_token,
        RESOURCE,
        PS,
        &class,
        &world.keys,
        NOW,
    )?;
    let access_grant = mint_per_call_auth_token(
        &registry,
        &world.access_key,
        "as-key",
        &auth_claims(&world, PS, ACCESS_DOCUMENT, "per-call-shared", NOW + 600)?,
        &reference,
        &exact,
    )?;
    let delivered = world.agent.verify_r3_per_call_delivery(
        &access_grant,
        RESOURCE,
        &verified,
        &class,
        &registry,
        &world.keys,
        NOW,
    )?;
    assert_eq!(delivered.claims().dwk, ACCESS_DOCUMENT);
    assert_eq!(delivered.claims().iss, PS);

    let person_grant = mint_per_call_auth_token(
        &registry,
        &world.person_key,
        "ps-1",
        &auth_claims(&world, PS, PERSON_DOCUMENT, "per-call-person", NOW + 600)?,
        &reference,
        &exact,
    )?;
    assert!(is_context(world.agent.verify_r3_per_call_delivery(
        &person_grant,
        RESOURCE,
        &verified,
        &class,
        &registry,
        &world.keys,
        NOW,
    )));
    Ok(())
}

#[test]
fn qa_d3_person_parent_and_class_issuer() -> Result<(), TestError> {
    let mut world = world()?;
    let other_key = SigningKey::from_seed([8; 32]);
    world.keys.0.push((
        OTHER_AS.into(),
        ACCESS_DOCUMENT.into(),
        "as-key".into(),
        other_key.public_jwk(),
    ));
    let class = class_grant(&world, AS, ACCESS_DOCUMENT)?;
    let resource = resource_token(&world, AS, "resource-as")?;
    assert!(matches!(
        world.agent.verify_r3_resource_token(
            &resource,
            RESOURCE,
            PS,
            &class,
            None,
            &world.keys,
            NOW,
        ),
        Err(R3AgentError::Token(_))
    ));
    let verified = world.agent.verify_r3_resource_token(
        &resource,
        RESOURCE,
        PS,
        &world.person,
        None,
        &world.keys,
        NOW,
    )?;
    assert!(matches!(
        world.agent.verify_r3_auth_delivery(
            &class,
            RESOURCE,
            &verified,
            &class,
            &world.registry,
            &world.keys,
            NOW,
        ),
        Err(R3AgentError::Token(_))
    ));
    world.agent.verify_r3_auth_delivery(
        &class,
        RESOURCE,
        &verified,
        &world.person,
        &world.registry,
        &world.keys,
        NOW,
    )?;

    let registry = standard_registry()?;
    let parameters = Parameters::new(Vec::<(String, Parameter)>::new())?;
    let exact = serde_json::to_vec(&Proposal::new(
        &Operation::new(&McpCodec::vocabulary()?, br#"{"tool":"records.delete"}"#)?,
        &parameters,
        ProposalOptions {
            account: None,
            result: None,
            display: None,
        },
    )?)?;
    let (proposal_token, reference) = mint_proposal_resource_token(
        &registry,
        &world.resource_key,
        "resource-1",
        &proposal_claims(&world, OTHER_AS, "class-grant")?,
        PROPOSAL_URI,
        &exact,
    )?;
    let proposal = verify_resource_token(&proposal_token, &world.keys, NOW)?;
    let per_call = mint_per_call_auth_token(
        &registry,
        &other_key,
        "as-key",
        &auth_claims(
            &world,
            OTHER_AS,
            ACCESS_DOCUMENT,
            "per-call-other",
            NOW + 600,
        )?,
        &reference,
        &exact,
    )?;
    assert!(is_context(world.agent.verify_r3_per_call_delivery(
        &per_call,
        RESOURCE,
        &proposal,
        &class,
        &registry,
        &world.keys,
        NOW,
    )));
    Ok(())
}

fn proposal_claims(
    world: &World,
    audience: &str,
    presented_jti: &str,
) -> Result<ResourceClaims, TestError> {
    let mut claims = resource_claims(world, audience, "proposal-resource")?;
    claims.presented_jti = presented_jti.into();
    Ok(claims)
}

#[test]
fn a_mission_resource_token_never_outlives_its_person_token() -> Result<(), TestError> {
    const MISSION: &str = "N1fWRFx_bLw1RcyTspTOoOuN1ct9hw7mEHZuGFMTmhw";
    let world = world()?;
    let person_exp = NOW + 600;
    let person = mint_person_token(
        &world.person_key,
        "ps-1",
        &PersonClaims {
            iss: PS.into(),
            dwk: PERSON_DOCUMENT.into(),
            aud: RESOURCE.into(),
            sub: SUBJECT.into(),
            jti: "person-1".into(),
            iat: NOW,
            exp: person_exp,
            cnf: Confirmation {
                jwk: world.holder.clone(),
            },
            nbf: None,
            tenant: None,
            mission_s256: Some(MISSION.into()),
            extra: BTreeMap::new(),
        },
    )?;
    let mission_resource_token = |exp: i64, mission: Option<&str>| -> Result<String, TestError> {
        let mut claims = resource_claims(&world, PS, "resource-mission")?;
        claims.exp = exp;
        claims.mission_s256 = mission.map(Into::into);
        Ok(mint_resource_token(
            &world.registry,
            &world.resource_key,
            "resource-1",
            &claims,
            CLASS_URI,
            CLASS,
        )?
        .0)
    };
    let verify = |compact: &str| {
        world
            .agent
            .verify_r3_resource_token(compact, RESOURCE, PS, &person, None, &world.keys, NOW)
    };
    let within = verify(&mission_resource_token(person_exp, Some(MISSION))?)?;
    assert_eq!(within.claims().mission_s256.as_deref(), Some(MISSION));
    assert!(is_context(verify(&mission_resource_token(
        person_exp + 1,
        Some(MISSION)
    )?)));
    // The mission itself must match the Person token.
    assert!(is_context(verify(&mission_resource_token(
        person_exp, None
    )?)));
    // A missionless Person token keeps the general rule: the Resource token
    // may outlive it, as long as it was issued inside its validity.
    let short = mint_person_token(
        &world.person_key,
        "ps-1",
        &PersonClaims {
            iss: PS.into(),
            dwk: PERSON_DOCUMENT.into(),
            aud: RESOURCE.into(),
            sub: SUBJECT.into(),
            jti: "person-1".into(),
            iat: NOW,
            exp: NOW + 200,
            cnf: Confirmation {
                jwk: world.holder.clone(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: BTreeMap::new(),
        },
    )?;
    world.agent.verify_r3_resource_token(
        &resource_token(&world, PS, "resource-missionless")?,
        RESOURCE,
        PS,
        &short,
        None,
        &world.keys,
        NOW,
    )?;
    Ok(())
}
