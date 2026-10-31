mod supervised_agents;
fn main() {
    let tour = supervised_agents::tour();
    assert_eq!(tour.host_decisions, 0);
    assert!(tour.reach_remembered && tour.person_decided_while_asleep);
    assert!(!tour.org_saw_the_personal_agent && tour.home_saw_the_personal_agent);
    assert!(tour.tampering_detected);
    println!(
        "standing policy allowed {} requests and asked the person {} time(s); \"always\" was remembered: {}",
        tour.allowed_without_the_person, tour.asked_the_person, tour.reach_remembered
    );
    println!(
        "the personal agent reached only the person's own server; while it slept the person decided, and on waking it received: {}",
        tour.delivered_on_waking.join(", ")
    );
    println!(
        "a stored decision verifies as signed by {}; with its body changed it does not",
        tour.verified_signer
    );
}
