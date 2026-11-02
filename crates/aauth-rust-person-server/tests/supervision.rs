//! A Person Server that consults supervision servers decides nothing itself
//! for the agents routed to them (`draft-hardt-aauth-supervision`).
#[path = "../examples/supervised_agents/mod.rs"]
mod world;

use aauth_rust_agent::Agent;
use aauth_rust_core::continuation::{MemoryContinuations, PendingResponse, Requirement};
use aauth_rust_core::interaction::{
    InteractionOutcome, ResourceInteraction, completion_redirect, parse_interaction_query,
};
use aauth_rust_core::supervision::{Answer, Decision};
use aauth_rust_core::{
    ApprovedMission, AuthToken, PersonToken, ResourceClaims, mint_resource_token,
};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    FederationInput, InteractionRelay, InteractionRelayConfig, PolicyError, R3AuthorizationRequest,
    R3Decision, R3IssuerConfig, R3Policy, RelayChannel, RelayError, RelayUnavailable,
    ResourceInteractionCallback, ResourceInteractionConfig, ResourceInteractionError,
    SupervisionHostError, Unconsulted, Waiting,
};
use aauth_rust_r3::{
    FetchBody, FetchLimits, FetchResponse, FetchTransport, IssuanceError, IssuanceRecord,
    IssuanceStore, standard_registry,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use world::{CALENDAR, HOME, Keys, ORG, PS, START, Supervisor, World, body, hold, location, text};

/// What a supervision server observed under `name`, in order.
fn observed(supervisor: &Supervisor, name: &str) -> Vec<Value> {
    supervisor
        .observed
        .lock()
        .unwrap()
        .iter()
        .filter(|(seen, _)| seen == name)
        .map(|(_, event)| event.clone())
        .collect()
}

#[test]
fn the_four_use_cases_hold_together() {
    let tour = world::tour();
    assert_eq!(
        tour.host_decisions, 0,
        "host policy decided for a supervised agent"
    );
    assert_eq!(tour.allowed_without_the_person, 3);
    assert_eq!(tour.asked_the_person, 1);
    assert!(tour.reach_remembered);
    assert!(!tour.org_saw_the_personal_agent);
    assert!(tour.home_saw_the_personal_agent);
    assert!(tour.person_decided_while_asleep);
    assert_eq!(
        tour.delivered_on_waking,
        ["agent.bound", "person_token.issued", "decision.resolved"]
    );
    assert_eq!(tour.verified_signer, ORG);
    assert!(tour.tampering_detected);
}

#[test]
fn an_agent_nobody_supervises_is_decided_by_host_policy() {
    let world = World::new();
    let granted = world.auth_token(&world.mail, "calendar.write");
    assert_eq!(granted.status(), 200, "{}", text(&granted));
    assert_eq!(
        body(&world.permission(&world.mail, "SendEmail"))["permission"],
        "granted"
    );
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 2);
    assert!(world.org.seen.lock().unwrap().is_empty());
}

#[test]
fn a_denial_reaches_the_agent_with_its_reason_and_an_ask_can_be_refused() {
    let world = World::new();
    world.route(&world.mail, Some(ORG));
    assert_eq!(world.person_token(&world.mail, None).status(), 200);
    let denied = world.permission(&world.mail, "DeleteMailbox");
    assert_eq!(
        body(&denied),
        json!({ "permission": "denied", "reason": "Deleting a mailbox is never delegated." })
    );
    let asked = world.auth_token(&world.mail, "calendar.write");
    assert_eq!(asked.status(), 202, "{}", text(&asked));
    let held = hold(&asked);
    let Waiting::Person(ask) = &held.waiting else {
        panic!("{:?}", held.waiting);
    };
    assert_eq!(ask.recommendation, Some(Answer::Allow));
    // Polling before the person answers stays pending.
    assert_eq!(world.poll(&world.mail, &location(&asked)).status(), 202);
    world.person_answers(&held, Answer::Deny, None);
    let refused = world.poll(&world.mail, &location(&asked));
    assert_eq!(
        (refused.status().as_u16(), body(&refused)["error"].clone()),
        (403, json!("denied"))
    );
    assert_eq!(world.poll(&world.mail, &location(&asked)).status(), 410);
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let observed = world.org.observed.lock().unwrap();
    let (_, resolved) = observed
        .iter()
        .find(|(name, _)| name == "decision.resolved")
        .unwrap();
    assert_eq!(resolved["answer"], "deny");
    assert_eq!(resolved["recommendation"], "allow");
    assert_eq!(resolved["sdi"], json!(held.sdi));
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 0);
}

#[test]
fn an_allow_narrows_the_auth_token_to_its_scope_and_expiry() {
    let world = World::new();
    world.route(&world.travel, Some(HOME));
    world.connect_home();
    let granted = world.auth_token(&world.travel, "calendar.read calendar.write");
    assert_eq!(granted.status(), 200, "{}", text(&granted));
    let token =
        aauth_rust_core::AuthToken::parse(body(&granted)["auth_token"].as_str().unwrap()).unwrap();
    assert_eq!(
        token.unverified_claims().scope.as_deref(),
        Some("calendar.read")
    );
    assert_eq!(token.unverified_claims().exp, START + 900);
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 0);
}

#[test]
fn a_mission_is_refined_approved_updated_and_completed_under_supervision() {
    let world = World::new();
    world.route(&world.mail, Some(ORG));
    // The agent is bound by its first person token, which the server allows.
    assert_eq!(world.person_token(&world.mail, None).status(), 200);
    let approved = world.post(
        &world.mail,
        "/mission",
        json!({
            "description": "# Quarterly report\n\nCollect the figures.",
            "tools": [
                { "name": "WebSearch", "description": "Search the web" },
                { "name": "SendEmail", "description": "Send email" }
            ],
            "resources": [CALENDAR]
        }),
    );
    assert_eq!(approved.status(), 200, "{}", text(&approved));
    let s256 = body(&approved)["s256"].as_str().unwrap().to_owned();
    let mission =
        ApprovedMission::decode(&s256, body(&approved)["mission"].as_str().unwrap()).unwrap();
    assert!(
        mission
            .description()
            .ends_with("Keep work data inside the organization.")
    );
    let blob: serde_json::Value = serde_json::from_slice(mission.exact_json()).unwrap();
    assert_eq!(
        blob["approved_tools"],
        json!([{ "name": "WebSearch", "description": "Search the web" }])
    );
    assert_eq!(blob["approved_resources"], json!([CALENDAR]));

    let update = world.post(
        &world.mail,
        &format!("/mission/{s256}"),
        json!({ "action": "update", "description": "Figures arrive a day late." }),
    );
    assert_eq!(update.status(), 200, "{}", text(&update));
    let completion = world.post(
        &world.mail,
        &format!("/mission/{s256}"),
        json!({ "action": "completion", "summary": "Report sent." }),
    );
    assert_eq!(completion.status(), 202, "{}", text(&completion));
    let held = hold(&completion);
    assert!(matches!(held.waiting, Waiting::Person(_)));
    world.person_answers(&held, Answer::Allow, None);
    let done = world.poll(&world.mail, &location(&completion));
    assert_eq!(
        body(&done)["termination_reason"],
        "completed",
        "{}",
        text(&done)
    );
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let names = world.org.observed_names();
    let approved_at = names.iter().position(|n| n == "approved").unwrap();
    let terminated_at = names.iter().position(|n| n == "terminated").unwrap();
    assert!(approved_at < terminated_at, "{names:?}");
    // A completed mission refuses further acts at this server; nothing is put,
    // and its end is not reported again.
    let after = world.post(
        &world.mail,
        &format!("/mission/{s256}"),
        json!({ "action": "update", "description": "One more thing." }),
    );
    assert_eq!(body(&after)["error"], "mission_terminated");
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let ended = observed(&world.org, "terminated");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["reason"], "completed");
    assert_eq!(ended[0]["sdi"], json!(held.sdi));
}

#[test]
fn a_mission_that_expires_is_reported_terminated_once() {
    let world = World::new();
    world.route(&world.travel, Some(HOME));
    world.connect_home();
    assert_eq!(world.person_token(&world.travel, None).status(), 200);
    // START + 600.
    *world.mission_expiry.lock().unwrap() = Some("2027-01-15T08:10:00Z".into());
    let approved = world.post(
        &world.travel,
        "/mission",
        json!({ "description": "# Weekend away\n\nBook a hotel." }),
    );
    assert_eq!(approved.status(), 200, "{}", text(&approved));
    let s256 = body(&approved)["s256"].as_str().unwrap().to_owned();
    world.advance(600);
    for _ in 0..2 {
        let late = world.post(
            &world.travel,
            "/permission",
            json!({ "action": "BookHotel", "mission_s256": s256 }),
        );
        assert_eq!(
            (
                late.status().as_u16(),
                body(&late)["termination_reason"].clone()
            ),
            (403, json!("expired")),
            "{}",
            text(&late)
        );
    }
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let ended = observed(&world.home, "terminated");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["reason"], "expired");
}

/// The calendar revokes one of its resource tokens at the Person Server.
fn revoke_resource_token(world: &World, jti: &str, exp: i64) -> Response<Vec<u8>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{PS}/revoke"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({ "jti": jti, "exp": exp })).unwrap())
        .unwrap();
    sign_request(
        &mut request,
        &SigningKey::from_seed([5; 32]),
        KeyMaterial::JwksUri {
            id: CALENDAR.into(),
            dwk: "aauth-resource.json".into(),
            kid: "cal-1".into(),
        },
        world.time(),
    )
    .unwrap();
    world.ps.handle(&request)
}

#[test]
fn a_resource_token_its_resource_revokes_is_reported_once() {
    let world = World::extended(false, |ps| ps.with_revocation());
    world.route(&world.mail, Some(ORG));
    let granted = world.auth_token(&world.mail, "calendar.read");
    assert_eq!(granted.status(), 200, "{}", text(&granted));
    let jti = format!("rt-{START}-calendar.read");
    for _ in 0..2 {
        let revoked = revoke_resource_token(&world, &jti, START + 300);
        assert_eq!(revoked.status(), 200, "{}", text(&revoked));
    }
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let reported = observed(&world.org, "revocation.received");
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(reported[0]["token_type"], "resource_token");
    assert_eq!(reported[0]["iss"], CALENDAR);
    assert_eq!(reported[0]["jti"], json!(jti));
    assert_eq!(reported[0]["exp"], START + 300);
}

#[test]
fn a_question_for_the_agent_is_relayed_and_answered() {
    let world = World::new();
    world.route(&world.travel, Some(HOME));
    world.connect_home();
    assert_eq!(world.person_token(&world.travel, None).status(), 200);
    let asked = world.permission(&world.travel, "BookFlight");
    assert_eq!(asked.status(), 202, "{}", text(&asked));
    assert_eq!(
        asked.headers()["aauth-requirement"],
        "requirement=clarification"
    );
    assert_eq!(body(&asked)["clarification"], "Is the fare refundable?");
    let mut answer = http::Request::builder()
        .method("POST")
        .uri(location(&asked))
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&json!({
                "action": "clarification_response",
                "clarification_response": "Yes, fully refundable until 48 hours before departure."
            }))
            .unwrap(),
        )
        .unwrap();
    world.travel.sign(&mut answer, world.time()).unwrap();
    let relayed = world.ps.handle(&answer);
    assert_eq!(relayed.status(), 202, "{}", text(&relayed));
    // Only the agent that asked may poll.
    let other = world.poll(&world.mail, &location(&asked));
    assert_eq!(body(&other)["error"], "wrong_poller");
    let granted = world.poll(&world.travel, &location(&asked));
    assert_eq!(
        body(&granted)["permission"],
        "granted",
        "{}",
        text(&granted)
    );
    assert_eq!(world.poll(&world.travel, &location(&asked)).status(), 410);
}

#[test]
fn a_decision_the_server_reaches_later_is_polled_by_the_host() {
    let world = World::new();
    world.route(&world.travel, Some(HOME));
    world.connect_home();
    assert_eq!(world.person_token(&world.travel, None).status(), 200);
    world.defer_home.store(true, Ordering::SeqCst);
    let pending = world.permission(&world.travel, "PayInvoice");
    assert_eq!(pending.status(), 202, "{}", text(&pending));
    let held = hold(&pending);
    assert!(matches!(
        held.waiting,
        Waiting::Supervisor { retry_after: 5 }
    ));
    assert_eq!(
        world.ps.advance_supervision(&held.reference),
        Err(SupervisionHostError::NotReady)
    );
    // The person cannot answer for a server that is still deciding.
    assert_eq!(
        world.ps.resolve_supervision(
            &held.reference,
            aauth_rust_person_server::PersonAnswer::once(Answer::Allow)
        ),
        Err(SupervisionHostError::NotReady)
    );
    world.advance(5);
    let still = world.ps.advance_supervision(&held.reference).unwrap();
    assert!(matches!(still.waiting, Waiting::Supervisor { .. }));
    world
        .home
        .server
        .read()
        .unwrap()
        .decide_pending(
            world::PS,
            &held.sdi,
            aauth_rust_supervision_server::Verdict::Allow(Default::default()),
        )
        .unwrap();
    world.advance(5);
    let decided = world.ps.advance_supervision(&held.reference).unwrap();
    assert_eq!(decided.waiting, Waiting::Decided);
    let granted = world.poll(&world.travel, &location(&pending));
    assert_eq!(
        body(&granted)["permission"],
        "granted",
        "{}",
        text(&granted)
    );
    // The decision reached at the pending URL is signed for that poll.
    let record = world.ps.supervision_record(&held.sdi).unwrap().unwrap();
    let verified = record.verify(&Keys).unwrap();
    assert_eq!(verified.supervisor, HOME);
    assert!(matches!(verified.decision, Decision::Allow(_)));
}

#[test]
fn a_routing_change_replays_the_agents_state_before_the_next_act() {
    let world = World::new();
    world.route(&world.mail, Some(ORG));
    assert_eq!(world.person_token(&world.mail, None).status(), 200);
    let approved = world.post(
        &world.mail,
        "/mission",
        json!({ "description": "Plan the offsite." }),
    );
    let s256 = body(&approved)["s256"].as_str().unwrap().to_owned();
    world.connect_home();
    world.route(&world.mail, Some(HOME));
    let under_mission = world.post(
        &world.mail,
        "/permission",
        json!({ "action": "ReserveRoom", "mission_s256": s256 }),
    );
    assert_eq!(
        body(&under_mission)["permission"],
        "granted",
        "{}",
        text(&under_mission)
    );
    let names = world.home.observed_names();
    assert_eq!(
        &names[..3],
        ["agent.bound", "person_token.issued", "approved"],
        "{names:?}"
    );
    // Every later act and event goes to the new server and no other.
    let org_requests = world.org.seen.lock().unwrap().len();
    assert_eq!(world.permission(&world.mail, "ArchiveEmail").status(), 200);
    assert_eq!(world.org.seen.lock().unwrap().len(), org_requests);
}

#[test]
fn a_server_that_lost_its_records_is_reconnected_and_given_the_mission_again() {
    let world = World::new();
    world.route(&world.mail, Some(ORG));
    assert_eq!(world.person_token(&world.mail, None).status(), 200);
    let approved = world.post(
        &world.mail,
        "/mission",
        json!({ "description": "Plan the offsite." }),
    );
    let s256 = body(&approved)["s256"].as_str().unwrap().to_owned();
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    world.org.forget_everything();
    let under_mission = world.post(
        &world.mail,
        "/permission",
        json!({ "action": "ReserveRoom", "mission_s256": s256 }),
    );
    assert_eq!(
        body(&under_mission)["permission"],
        "granted",
        "{}",
        text(&under_mission)
    );
    let paths: Vec<String> = world
        .org
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(path, _)| path.clone())
        .collect();
    let tail = &paths[paths.len() - 5..];
    assert_eq!(
        tail,
        [
            "/decision".to_owned(),
            "/connect".into(),
            "/decision".into(),
            format!("/mission/{s256}"),
            "/decision".into(),
        ],
        "{paths:?}"
    );
}

#[test]
fn an_unanswered_ask_is_reported_abandoned_when_it_expires() {
    let world = World::new();
    world.route(&world.research, Some(ORG));
    let asked = world.permission(&world.research, "SendEmail");
    // An unbound agent names no person, so host policy decides it.
    assert_eq!(asked.status(), 200, "{}", text(&asked));
    assert_eq!(world.person_token(&world.research, None).status(), 200);
    let asked = world.permission(&world.research, "SendEmail");
    let held = hold(&asked);
    world.advance(601);
    assert_eq!(world.poll(&world.research, &location(&asked)).status(), 408);
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let observed = world.org.observed.lock().unwrap();
    let (_, resolved) = observed
        .iter()
        .rev()
        .find(|(name, _)| name == "decision.resolved")
        .unwrap();
    assert_eq!(resolved["answer"], "abandoned");
    assert_eq!(resolved["sdi"], json!(held.sdi));
}

#[test]
fn a_server_without_signed_decisions_is_not_consulted_by_default() {
    let world = World::new();
    world.route(&world.mail, Some(ORG));
    // Replace the organization's server by one that does not sign.
    {
        let mut server = world.org.server.write().unwrap();
        *server = aauth_rust_supervision_server::SupervisionServer::new(
            aauth_rust_supervision_server::Config::new(ORG),
            world::PersonServerKeys,
            Box::new(world::OrgPolicy {
                observed: world.org.observed.clone(),
            }) as Box<dyn aauth_rust_supervision_server::Policy>,
            aauth_rust_core::continuation::MemoryContinuations::new(1000),
            Box::new(|| world::START) as world::SupervisorClock,
        )
        .unwrap();
    }
    let response = world.person_token(&world.mail, None);
    let held = hold(&response);
    assert_eq!(held.waiting, Waiting::Unavailable(Unconsulted::Unsigned));
    assert!(world.org.seen.lock().unwrap().is_empty());
    world.person_answers(&held, Answer::Allow, None);
    let issued = world.poll(&world.mail, &location(&response));
    assert_eq!(issued.status(), 200, "{}", text(&issued));
    let record = world.ps.supervision_record(&held.sdi).unwrap().unwrap();
    assert_eq!(record.outcome.as_deref(), Some("person allow"));
    assert!(record.exchanges.is_empty());
}

#[test]
fn a_four_party_request_is_put_to_the_supervisor_before_the_access_server() {
    let world = World::federated();
    world.route(&world.mail, Some(ORG));
    let read = world.auth_token(&world.mail, "calendar.read");
    assert_eq!(read.status(), 200, "{}", text(&read));
    let token =
        aauth_rust_core::AuthToken::parse(body(&read)["auth_token"].as_str().unwrap()).unwrap();
    assert_eq!(token.unverified_claims().iss, world::AS);

    // The person allows an exception, then the Access Server defers.
    world.defer_access.store(true, Ordering::SeqCst);
    let write = world.auth_token(&world.mail, "calendar.write");
    assert_eq!(write.status(), 202, "{}", text(&write));
    let held = hold(&write);
    world.person_answers(&held, Answer::Allow, None);
    let waiting = world.poll(&world.mail, &location(&write));
    assert_eq!(waiting.status(), 202, "{}", text(&waiting));
    assert_eq!(
        location(&waiting),
        location(&write),
        "the agent keeps one pending URL"
    );
    let Waiting::AccessServer { reference } =
        world.ps.supervision_hold(&held.reference).unwrap().waiting
    else {
        panic!("the act waits for the Access Server");
    };
    world.defer_access.store(false, Ordering::SeqCst);
    let advanced = world
        .ps
        .advance_federation(&reference, aauth_rust_person_server::FederationInput::Poll)
        .unwrap();
    assert_eq!(advanced.status(), 200);
    let delivered = world.poll(&world.mail, &location(&write));
    assert_eq!(delivered.status(), 200, "{}", text(&delivered));
    let token = AuthToken::parse(body(&delivered)["auth_token"].as_str().unwrap()).unwrap();
    assert_eq!(world.poll(&world.mail, &location(&write)).status(), 410);
    // The token the Access Server issued after deferring is reported under the act.
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let issued = observed(&world.org, "auth_token.issued");
    let reported = issued
        .iter()
        .find(|event| event["sdi"] == json!(held.sdi))
        .unwrap_or_else(|| panic!("{issued:?}"));
    assert_eq!(reported["jti"], json!(token.unverified_claims().jti));
    assert_eq!(reported["issuer"], world::AS);

    // The person's own server narrows to calendar.read until START + 900. The
    // Person Server passes that to the Access Server, which issues within it.
    world.connect_home();
    world.route(&world.travel, Some(HOME));
    let fits = world.auth_token(&world.travel, "calendar.read calendar.write");
    assert_eq!(fits.status(), 200, "{}", text(&fits));
    let narrowed = AuthToken::parse(body(&fits)["auth_token"].as_str().unwrap()).unwrap();
    assert_eq!(
        narrowed.unverified_claims().scope.as_deref(),
        Some("calendar.read")
    );
    assert!(narrowed.unverified_claims().exp <= START + 900);
    // An Access Server that ignores the narrowing issues what the Resource
    // token asked for; the Person Server refuses that token.
    world.access_ignores_narrowing.store(true, Ordering::SeqCst);
    let wider = world.auth_token(&world.travel, "calendar.read calendar.write");
    assert_eq!(
        (wider.status().as_u16(), body(&wider)["error"].clone()),
        (403, json!("access_denied"))
    );
    // One issued after the Access Server deferred is refused at the agent's poll.
    world.defer_access.store(true, Ordering::SeqCst);
    let waiting = world.auth_token(&world.travel, "calendar.read calendar.write");
    assert_eq!(waiting.status(), 202, "{}", text(&waiting));
    world.defer_access.store(false, Ordering::SeqCst);
    world
        .ps
        .advance_federation(&location(&waiting), FederationInput::Poll)
        .unwrap();
    let refused = world.poll(&world.travel, &location(&waiting));
    assert_eq!(
        (refused.status().as_u16(), body(&refused)["error"].clone()),
        (403, json!("denied"))
    );
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 0);
}

const CLASS: &[u8] = br#"{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"events.read"},{"tool":"events.write"}]}"#;
const CLASS_URI: &str = "https://calendar.example/r3/calendar";

struct Document {
    bytes: Vec<u8>,
    offset: usize,
}
impl FetchBody for Document {
    fn read(&mut self, out: &mut [u8], _: Instant) -> std::io::Result<usize> {
        let size = out.len().min(self.bytes.len() - self.offset);
        out[..size].copy_from_slice(&self.bytes[self.offset..self.offset + size]);
        self.offset += size;
        Ok(size)
    }
}

/// The calendar serves its R3 document to the Person Server.
struct Calendar;
impl FetchTransport for Calendar {
    fn send(&self, request: Request<Vec<u8>>, _: Instant) -> std::io::Result<FetchResponse> {
        assert_eq!(request.uri().to_string(), CLASS_URI);
        Ok(Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Box::new(Document {
                bytes: CLASS.to_vec(),
                offset: 0,
            }) as Box<dyn FetchBody>)
            .unwrap())
    }
}

/// Host R3 consent, which must not decide for a supervised agent.
struct HostR3(Arc<AtomicUsize>);
impl R3Policy for HostR3 {
    fn authorize_document(
        &self,
        _: &R3AuthorizationRequest<'_>,
    ) -> Result<R3Decision, PolicyError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::Denied)
    }
}

struct AuditLog;
impl IssuanceStore for AuditLog {
    fn commit(&self, _: &IssuanceRecord) -> Result<(), IssuanceError> {
        Ok(())
    }
}

/// A person token, then an auth token for `scope` at the calendar, whose
/// challenge names its R3 document.
fn r3_auth_token(world: &World, agent: &aauth_rust_agent::Agent, scope: &str) -> Response<Vec<u8>> {
    let person = world.person_token(agent, None);
    assert_eq!(person.status(), 200, "{}", text(&person));
    let person_token = body(&person)["person_token"].as_str().unwrap().to_owned();
    let presented = PersonToken::parse(&person_token).unwrap();
    let p = presented.unverified_claims();
    let (resource_token, _) = aauth_rust_r3::mint_resource_token(
        &standard_registry().unwrap(),
        &SigningKey::from_seed([5; 32]),
        "cal-1",
        &ResourceClaims {
            iss: CALENDAR.into(),
            dwk: "aauth-resource.json".into(),
            aud: PS.into(),
            sub: p.sub.clone(),
            jti: format!("r3-{}-{scope}", world.time()),
            iat: world.time(),
            exp: world.time() + 300,
            ps: PS.into(),
            presented_jti: p.jti.clone(),
            agent_jkt: agent.public_jwk().thumbprint().unwrap(),
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: Some(scope.into()),
            account: None,
            login_hint: None,
            extra: Default::default(),
        },
        CLASS_URI,
        CLASS,
    )
    .unwrap();
    world.post(
        agent,
        "/token",
        json!({ "resource_token": resource_token, "presented_token": person_token }),
    )
}

#[test]
fn an_r3_request_is_an_auth_token_act_for_the_supervisor() {
    let host_r3 = Arc::new(AtomicUsize::new(0));
    let policy = host_r3.clone();
    let world = World::extended(false, move |ps| {
        ps.with_r3(R3IssuerConfig {
            registry: standard_registry().unwrap(),
            egress: Box::new(|_: &str, _: Instant| Ok(())),
            transport: Box::new(Calendar),
            limits: FetchLimits::default(),
            policy: Box::new(HostR3(policy)),
            audit: Arc::new(AuditLog),
        })
        .unwrap()
    });
    world.route(&world.mail, Some(ORG));
    // Standing policy allows reading: every operation of the document is granted.
    let granted = r3_auth_token(&world, &world.mail, "calendar.read");
    assert_eq!(granted.status(), 200, "{}", text(&granted));
    let token = AuthToken::parse(body(&granted)["auth_token"].as_str().unwrap()).unwrap();
    let claims = token.unverified_claims();
    assert_eq!(
        claims.extra["r3_granted"]["operations"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert!(!claims.extra.contains_key("r3_per_call"));
    // An exception goes to the person, with the document to show them.
    let asked = r3_auth_token(&world, &world.mail, "calendar.write");
    assert_eq!(asked.status(), 202, "{}", text(&asked));
    let held = hold(&asked);
    assert_eq!(held.r3_document.as_deref(), Some(CLASS));
    world.person_answers(&held, Answer::Allow, None);
    let issued = world.poll(&world.mail, &location(&asked));
    assert_eq!(issued.status(), 200, "{}", text(&issued));
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    assert!(
        observed(&world.org, "auth_token.issued")
            .iter()
            .any(|event| event["sdi"] == json!(held.sdi))
    );
    assert_eq!(host_r3.load(Ordering::SeqCst), 0);
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 0);
}

/// The person's channel: it has none for payments.
#[derive(Clone, Default)]
struct PersonChannel(Arc<Mutex<Vec<InteractionRelay>>>);
impl RelayChannel for PersonChannel {
    fn relay(&self, relay: &InteractionRelay) -> Result<(), RelayUnavailable> {
        if relay.kind == "payment" {
            return Err(RelayUnavailable);
        }
        self.0.lock().unwrap().push(relay.clone());
        Ok(())
    }
}

#[test]
fn a_relayed_interaction_reaches_the_person_and_the_supervisor_is_told() {
    let person = PersonChannel::default();
    let channel = person.clone();
    let world = World::extended(false, move |ps| {
        ps.with_interaction_relay(InteractionRelayConfig::new(
            channel,
            MemoryContinuations::new(100),
        ))
        .unwrap()
    });
    world.route(&world.mail, Some(ORG));
    assert_eq!(world.person_token(&world.mail, None).status(), 200);
    let accepted = world.post(
        &world.mail,
        "/interaction",
        json!({
            "type": "interaction", "url": "https://calendar.example/confirm",
            "code": "X7K2-M9P4", "description": "Confirm the booking.",
        }),
    );
    assert_eq!(accepted.status(), 202, "{}", text(&accepted));
    let relay = accepted
        .extensions()
        .get::<InteractionRelay>()
        .cloned()
        .unwrap();
    assert_eq!(*person.0.lock().unwrap(), vec![relay.clone()]);
    assert_eq!(
        location(&accepted),
        format!("{PS}/interaction/relay/{}", relay.reference)
    );
    assert_eq!(world.poll(&world.mail, &location(&accepted)).status(), 202);
    assert_eq!(
        world.poll(&world.research, &location(&accepted)).status(),
        410
    );
    world.ps.relay_engaged(&relay.reference).unwrap();
    // The same answer again converges; another one is refused.
    world.ps.relay_engaged(&relay.reference).unwrap();
    assert_eq!(
        world.ps.relay_finished(&relay.reference),
        Err(RelayError::Gone)
    );
    let engaged = world.poll(&world.mail, &location(&accepted));
    assert_eq!(
        (engaged.status().as_u16(), body(&engaged)),
        (200, json!({ "status": "interacting" }))
    );
    assert_eq!(world.poll(&world.mail, &location(&accepted)).status(), 410);
    assert_eq!(
        world.ps.relay_engaged(&relay.reference),
        Err(RelayError::Gone)
    );

    // Without a channel the agent directs the person itself.
    let payment = world.post(
        &world.mail,
        "/interaction",
        json!({ "type": "payment", "url": "https://calendar.example/pay", "code": "X7K2-M9P4" }),
    );
    assert_eq!(
        (payment.status().as_u16(), body(&payment)["error"].clone()),
        (424, json!("interaction_unavailable"))
    );
    // A relay the person never engages with ends at the agent's max_wait.
    let quiet = world.post(
        &world.mail,
        "/interaction",
        json!({
            "type": "interaction", "url": "https://calendar.example/confirm",
            "code": "X7K2-M9P4", "max_wait": 30,
        }),
    );
    assert_eq!(quiet.status(), 202, "{}", text(&quiet));
    world.advance(30);
    let ended = world.poll(&world.mail, &location(&quiet));
    assert_eq!(
        (ended.status().as_u16(), body(&ended)),
        (200, json!({ "status": "pending" }))
    );
    let answered = world.post(
        &world.mail,
        "/interaction",
        json!({ "type": "question", "question": "Window seat?" }),
    );
    assert_eq!(answered.status(), 200, "{}", text(&answered));

    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let requested = observed(&world.org, "interaction.requested");
    let kinds: Vec<&str> = requested
        .iter()
        .map(|event| event["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["interaction", "interaction", "question"]);
    assert_eq!(requested[0]["url"], "https://calendar.example/confirm");
    assert!(requested.iter().all(|event| event.get("code").is_none()));
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 0);
}

/// A world whose Person Server resolves resource-initiated interaction.
fn interaction_world() -> World {
    World::extended(false, |ps| {
        ps.with_resource_interaction(ResourceInteractionConfig::new(
            MemoryContinuations::new(64),
            &format!("{PS}/consent"),
            &format!("{PS}/resource-callback"),
            |url: &str| url.starts_with(CALENDAR),
        ))
        .unwrap()
    })
}

const CONNECT: &str = "https://calendar.example/connect";

/// `/token` for `scope` with a resource token whose `interaction` claim
/// names the calendar's own sign-in. Returns the answer and the code the
/// calendar expects back.
fn interaction_request(world: &World, agent: &Agent, scope: &str) -> (Response<Vec<u8>>, String) {
    let person = world.person_token(agent, None);
    assert_eq!(person.status(), 200, "{}", text(&person));
    let person = body(&person)["person_token"].as_str().unwrap().to_owned();
    let p = PersonToken::parse(&person).unwrap();
    let p = p.unverified_claims();
    let mut claims = ResourceClaims {
        iss: CALENDAR.into(),
        dwk: "aauth-resource.json".into(),
        aud: PS.into(),
        sub: p.sub.clone(),
        jti: format!("rt-{}-interaction", p.jti),
        iat: world.time(),
        exp: world.time() + 300,
        ps: PS.into(),
        presented_jti: p.jti.clone(),
        agent_jkt: agent.public_jwk().thumbprint().unwrap(),
        nbf: None,
        tenant: p.tenant.clone(),
        mission_s256: None,
        scope: Some(scope.into()),
        account: None,
        login_hint: None,
        extra: Default::default(),
    };
    let interaction = ResourceInteraction::open(CONNECT).unwrap();
    interaction.insert_into(&mut claims);
    let resource = mint_resource_token(&SigningKey::from_seed([5; 32]), "cal-1", &claims).unwrap();
    let answer = world.post(
        agent,
        "/token",
        json!({
            "resource_token": resource,
            "presented_token": person,
            "capabilities": ["interaction"],
            "justification": "Find a free afternoon.",
        }),
    );
    (answer, interaction.code().to_owned())
}

/// The interaction id and code of a `202` with `requirement=interaction`.
fn interaction_of(response: &Response<Vec<u8>>) -> (String, String) {
    assert_eq!(response.status(), 202, "{}", text(response));
    let parsed = PendingResponse::parse(PS, response).unwrap();
    let Requirement::Interaction { url, code } = parsed.requirement else {
        panic!("expected requirement=interaction: {}", text(response));
    };
    let id = url
        .strip_prefix(&format!("{PS}/consent/"))
        .expect("this server's own interaction page")
        .to_owned();
    (id, code)
}

/// The person passes the interstitial and completes the calendar's flow.
/// Returns the callback's outcome.
fn person_completes_the_resource_flow(
    world: &World,
    id: &str,
    code: &str,
    resource_code: &str,
) -> ResourceInteractionCallback {
    let shown = world.ps.resource_interaction(id).unwrap();
    assert!(shown.supervised, "the host shows no consent of its own");
    assert_eq!(shown.resource, CALENDAR);
    let redirect = world
        .ps
        .redirect_to_resource(id, &format!("code={code}"))
        .unwrap();
    assert_eq!(redirect.status(), 302);
    let target = location(&redirect);
    let arrived =
        parse_interaction_query(target.strip_prefix(&format!("{CONNECT}?")).unwrap()).unwrap();
    assert_eq!(arrived.code, resource_code);
    let callback = arrived.callback.unwrap();
    let back = location(&completion_redirect(&callback, InteractionOutcome::Completed).unwrap());
    let flow = back
        .strip_prefix(&format!("{PS}/resource-callback/"))
        .unwrap();
    world.ps.resource_interaction_callback(flow, None).unwrap()
}

#[test]
fn a_supervised_resource_interaction_is_decided_first_and_issued_within_the_allow() {
    let world = interaction_world();
    world.route(&world.travel, Some(HOME));
    world.connect_home();
    // The person's own server allows at once, narrowed to calendar.read until
    // START + 900. Only then is the person sent to the calendar.
    let (opened, resource_code) =
        interaction_request(&world, &world.travel, "calendar.read calendar.write");
    let pending = location(&opened);
    assert!(pending.starts_with(&format!("{PS}/token/interaction/")));
    let (id, code) = interaction_of(&opened);
    assert!(
        world
            .home
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|(path, _)| path.ends_with("/decision")),
        "the supervisor decided before the person was sent anywhere"
    );
    let ResourceInteractionCallback::Completed { redirect } =
        person_completes_the_resource_flow(&world, &id, &code, &resource_code)
    else {
        panic!("a supervised callback issues within the allow");
    };
    assert!(redirect.is_none());
    assert_eq!(
        world.ps.decide_resource_interaction(&id, true).unwrap_err(),
        ResourceInteractionError::InvalidCode
    );
    let granted = world.poll(&world.travel, &pending);
    assert_eq!(granted.status(), 200, "{}", text(&granted));
    let token = AuthToken::parse(body(&granted)["auth_token"].as_str().unwrap()).unwrap();
    assert_eq!(
        token.unverified_claims().scope.as_deref(),
        Some("calendar.read")
    );
    assert_eq!(token.unverified_claims().exp, START + 900);
    assert_eq!(world.poll(&world.travel, &pending).status(), 410);
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    let issued = observed(&world.home, "auth_token.issued");
    let reported = issued
        .iter()
        .find(|event| event["jti"] == json!(token.unverified_claims().jti))
        .unwrap_or_else(|| panic!("{issued:?}"));
    let sdi = reported["sdi"].as_str().unwrap();
    assert!(
        world.ps.supervision_record(sdi).unwrap().is_some(),
        "reported under the decision's sdi"
    );
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 0);
}

#[test]
fn a_held_resource_interaction_is_relayed_at_the_one_pending_url() {
    let world = interaction_world();
    world.route(&world.mail, Some(ORG));
    assert_eq!(world.person_token(&world.mail, None).status(), 200);

    // The organization asks the person. A deny ends the request; nobody is
    // sent to the calendar.
    let (asked, _) = interaction_request(&world, &world.mail, "calendar.write");
    assert_eq!(asked.status(), 202, "{}", text(&asked));
    let held = hold(&asked);
    assert!(location(&asked).starts_with(&format!("{PS}/pending/")));
    world.person_answers(&held, Answer::Deny, None);
    let refused = world.poll(&world.mail, &location(&asked));
    assert_eq!(
        (refused.status().as_u16(), body(&refused)["error"].clone()),
        (403, json!("denied"))
    );

    // The person allows. The agent's next poll of the same URL starts the
    // calendar's flow, and it polls that URL to the token.
    let (asked, resource_code) = interaction_request(&world, &world.mail, "calendar.write");
    let pending = location(&asked);
    let held = hold(&asked);
    world.person_answers(&held, Answer::Allow, None);
    let opened = world.poll(&world.mail, &pending);
    assert_eq!(location(&opened), pending);
    let (id, code) = interaction_of(&opened);
    let again = world.poll(&world.mail, &pending);
    assert_eq!(again.status(), 202, "{}", text(&again));
    assert_eq!(location(&again), pending);
    let ResourceInteractionCallback::Completed { .. } =
        person_completes_the_resource_flow(&world, &id, &code, &resource_code)
    else {
        panic!("a supervised callback issues within the allow");
    };
    let granted = world.poll(&world.mail, &pending);
    assert_eq!(granted.status(), 200, "{}", text(&granted));
    let token = AuthToken::parse(body(&granted)["auth_token"].as_str().unwrap()).unwrap();
    assert_eq!(
        token.unverified_claims().scope.as_deref(),
        Some("calendar.write")
    );
    assert_eq!(world.poll(&world.mail, &pending).status(), 410);
    assert_eq!(world.ps.deliver_supervision().unwrap(), 0);
    assert!(
        observed(&world.org, "auth_token.issued")
            .iter()
            .any(|event| event["sdi"] == json!(held.sdi)
                && event["jti"] == json!(token.unverified_claims().jti))
    );

    // A cancellation at that URL ends the calendar's flow too.
    let (asked, _) = interaction_request(&world, &world.mail, "calendar.write");
    let pending = location(&asked);
    world.person_answers(&hold(&asked), Answer::Allow, None);
    let (id, code) = interaction_of(&world.poll(&world.mail, &pending));
    let mut cancel = Request::builder()
        .method("DELETE")
        .uri(&pending)
        .body(Vec::new())
        .unwrap();
    world.mail.sign(&mut cancel, world.time()).unwrap();
    let cancelled = world.ps.handle(&cancel);
    assert_eq!(cancelled.status(), 200, "{}", text(&cancelled));
    assert_eq!(world.poll(&world.mail, &pending).status(), 410);
    assert_eq!(
        world
            .ps
            .redirect_to_resource(&id, &format!("code={code}"))
            .unwrap_err(),
        ResourceInteractionError::InvalidCode
    );
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 0);
}
