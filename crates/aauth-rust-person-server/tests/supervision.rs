//! A Person Server that consults supervision servers decides nothing itself
//! for the agents routed to them (`draft-hardt-aauth-supervision`).
#[path = "../examples/supervised_agents/mod.rs"]
mod world;

use aauth_rust_core::ApprovedMission;
use aauth_rust_core::supervision::{Answer, Decision};
use aauth_rust_person_server::{SupervisionHostError, Unconsulted, Waiting};
use serde_json::json;
use std::sync::atomic::Ordering;
use world::{CALENDAR, HOME, Keys, ORG, START, World, body, hold, location, text};

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
    // A completed mission refuses further acts at this server; nothing is put.
    let after = world.post(
        &world.mail,
        &format!("/mission/{s256}"),
        json!({ "action": "update", "description": "One more thing." }),
    );
    assert_eq!(body(&after)["error"], "mission_terminated");
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
    assert!(body(&delivered)["auth_token"].is_string());
    assert_eq!(world.poll(&world.mail, &location(&write)).status(), 410);

    // A narrowing the Access Server cannot be told about is refused, not widened.
    world.connect_home();
    world.route(&world.travel, Some(HOME));
    let narrowed = world.auth_token(&world.travel, "calendar.read calendar.write");
    assert_eq!(
        (narrowed.status().as_u16(), body(&narrowed)["error"].clone()),
        (403, json!("access_denied"))
    );
    assert_eq!(world.host_decisions.load(Ordering::SeqCst), 0);
}
