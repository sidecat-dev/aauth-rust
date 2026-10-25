use super::*;
use crate::{MissionAudit, MissionEdit, MissionUpdateBytes};
use aauth_rust_core::ApprovedMission;
use aauth_rust_jose::strict_json;
use std::collections::BTreeMap;
use std::sync::Mutex;

pub(super) struct Gate {
    proposals: Mutex<BTreeMap<String, Proposal>>,
}

struct Proposal {
    owner_issuer: String,
    owner_subject: String,
    description: String,
    status: Status,
    /// The owner has already received the terminal poll (`200` or `403`).
    delivered: bool,
}

enum Status {
    Pending,
    /// One approval passed the pending check and has not finished the audit write.
    Approving,
    Approved {
        s256: String,
        encoded: String,
    },
    Denied,
}

enum Terminal {
    Approved(String, String),
    Denied,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            proposals: Mutex::new(BTreeMap::new()),
        }
    }
}

enum Route {
    Create,
    Approval(String),
    Poll(String),
    Document(String),
}

const MAX_TEXT: usize = 16_384;

fn direct_agent(agent: &aauth_rust_core::VerifiedAgentToken) -> Result<(), Failure> {
    if agent.claims().parent_agent.is_some() {
        Err(Failure::credential(aauth_rust_core::TokenError::InvalidJwt))
    } else {
        Ok(())
    }
}

impl<K: AgentKeyResolver, S: Store, P: Policy, C: Fn() -> i64, I: Fn() -> String>
    PersonServer<K, S, P, C, I>
{
    /// Enable mission proposal, approval, update, completion and owner audit.
    ///
    /// Metadata advertises `mission_endpoint` only after this call. An agent
    /// proposes with a signed `jwt` POST and receives `202` with `Location`.
    /// The approval POST must be signed as this server (`jwks_uri`,
    /// `aauth-person.json`, this server's kid). A missing or different signature
    /// leaves the proposal unchanged. The proposing agent polls `Location` once
    /// to receive `s256` and `mission`; a later poll is `410 gone`. A denied
    /// proposal's first poll is `403 access_denied` and the next is `410 gone`.
    /// The first approval claims the proposal before the audit write, so a
    /// second approval does not write another audit. Accepted documents are
    /// stored through [`crate::Store::write_mission_audit`]. Proposals stay in
    /// process memory.
    /// This does not install an issuance [`crate::MissionRecord`] and does not
    /// advertise `mission_control_endpoint`. A token with `parent_agent` is
    /// `401 invalid_jwt` and does not create or change a proposal.
    pub fn with_missions(mut self) -> Self {
        self.mission_http = Some(Gate::default());
        self
    }

    pub(super) fn route_mission(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Option<Response<Vec<u8>>>, Failure> {
        if self.mission_http.is_none() {
            return Ok(None);
        }
        let Some(route) = parse_route(request.uri().path()) else {
            return Ok(None);
        };
        let response = match (request.method().as_str(), route) {
            ("POST", Route::Create) => self.create_mission(request, now)?,
            ("POST", Route::Approval(id)) => self.approve_mission(request, now, &id)?,
            ("GET", Route::Poll(id)) => self.poll_mission(request, now, &id)?,
            ("POST", Route::Document(s256)) => self.mutate_mission(request, now, &s256)?,
            ("GET", Route::Document(s256)) => self.read_mission(request, now, &s256)?,
            _ => return Ok(None),
        };
        Ok(Some(response))
    }

    fn create_mission(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let agent = self.verify_request(request, now)?;
        direct_agent(&agent)?;
        let body = json_object(request)?;
        let description = required_text(&body, "description")?;
        let owner = agent.claims();
        if aauth_rust_core::validate_agent_identifier(&owner.sub).is_err() {
            return Err(Failure::parameter("invalid_request"));
        }
        let id = (self.ids)();
        if !path_token(&id) {
            return Err(Failure::internal());
        }
        self.insert_proposal(
            id.clone(),
            Proposal {
                owner_issuer: owner.iss.clone(),
                owner_subject: owner.sub.clone(),
                description,
                status: Status::Pending,
                delivered: false,
            },
        )?;
        Ok(proposal_pending(&self.proposal_location(&id)))
    }

    fn poll_mission(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        id: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let agent = self.verify_agent(request, now, false)?;
        direct_agent(&agent)?;
        let owner = agent.claims();
        let location = self.proposal_location(id);
        let mut proposals = self.proposals()?;
        let Some(proposal) = proposals.get_mut(id) else {
            return Err(mission_not_found());
        };
        if proposal.owner_issuer != owner.iss || proposal.owner_subject != owner.sub {
            return Err(mission_not_found());
        }
        if proposal.delivered {
            return Err(Failure::status(StatusCode::GONE, "gone"));
        }
        let terminal = match &proposal.status {
            Status::Pending | Status::Approving => None,
            Status::Approved { s256, encoded } => {
                Some(Terminal::Approved(s256.clone(), encoded.clone()))
            }
            Status::Denied => Some(Terminal::Denied),
        };
        let Some(terminal) = terminal else {
            return Ok(proposal_pending(&location));
        };
        proposal.delivered = true;
        match terminal {
            Terminal::Approved(s256, encoded) => Ok(json_response(
                StatusCode::OK,
                json!({ "s256": s256, "mission": encoded }),
            )),
            Terminal::Denied => Err(Failure::status(StatusCode::FORBIDDEN, "access_denied")),
        }
    }

    fn approve_mission(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        id: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        self.verify_approver(request, now)?;
        let decision = match json_object(request)?.get("decision") {
            Some(Value::String(value)) if value == "approve" || value == "deny" => value.clone(),
            _ => return Err(Failure::parameter("invalid_request")),
        };
        let (owner_subject, owner_issuer, description) = {
            let mut proposals = self.proposals()?;
            let Some(proposal) = proposals.get_mut(id) else {
                return Err(mission_not_found());
            };
            if !matches!(proposal.status, Status::Pending) {
                return Err(mission_not_found());
            }
            if decision == "deny" {
                proposal.status = Status::Denied;
                return Ok(json_response(
                    StatusCode::OK,
                    json!({ "decision": "denied" }),
                ));
            }
            proposal.status = Status::Approving;
            (
                proposal.owner_subject.clone(),
                proposal.owner_issuer.clone(),
                proposal.description.clone(),
            )
        };
        let written = (|| -> Result<(String, String), Failure> {
            let document = ApprovedMission::mint(&owner_subject, now, &description)
                .map_err(|_| Failure::internal())?;
            let audit = MissionAudit {
                person_server: self.config.issuer.clone(),
                owner_issuer,
                owner_subject,
                s256: document.s256().to_owned(),
                encoded: document.encoded().to_owned(),
                updates: Vec::new(),
                summary: None,
                termination_reason: None,
            };
            self.store.write_mission_audit(&audit).map_err(stored)?;
            Ok((document.s256().to_owned(), document.encoded().to_owned()))
        })();
        let (s256, encoded) = match written {
            Ok(document) => document,
            Err(error) => {
                self.release_approval_claim(id);
                return Err(error);
            }
        };
        let mut proposals = self.proposals()?;
        let Some(proposal) = proposals.get_mut(id) else {
            return Err(Failure::internal());
        };
        if !matches!(proposal.status, Status::Approving) {
            return Err(Failure::internal());
        }
        proposal.status = Status::Approved { s256, encoded };
        Ok(json_response(
            StatusCode::OK,
            json!({ "decision": "approved" }),
        ))
    }

    fn mutate_mission(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        s256: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let agent = self.verify_request(request, now)?;
        direct_agent(&agent)?;
        let body = json_object(request)?;
        let action = match body.get("action") {
            Some(Value::String(action)) => action.clone(),
            _ => return Err(Failure::parameter("invalid_request")),
        };
        let edit = match action.as_str() {
            "update" => MissionEdit::Update(update_bytes(
                "description",
                &required_text(&body, "description")?,
            )?),
            "completion" => {
                MissionEdit::Completion(update_bytes("summary", &required_text(&body, "summary")?)?)
            }
            _ => return Err(Failure::parameter("invalid_request")),
        };
        let owner = agent.claims();
        let audit = self
            .store
            .edit_mission_audit(&self.config.issuer, &owner.iss, &owner.sub, s256, edit)
            .map_err(edited)?;
        let response = if action == "completion" {
            json!({
                "mission_status": "terminated",
                "termination_reason": "completed"
            })
        } else {
            let digest = audit
                .updates
                .last()
                .map(|update| update.s256.clone())
                .ok_or_else(Failure::internal)?;
            json!({ "s256": digest })
        };
        Ok(json_response(StatusCode::OK, response))
    }

    fn read_mission(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
        s256: &str,
    ) -> Result<Response<Vec<u8>>, Failure> {
        let agent = self.verify_agent(request, now, false)?;
        direct_agent(&agent)?;
        let owner = agent.claims();
        let Some(audit) = self
            .store
            .read_mission_audit(&self.config.issuer, &owner.iss, &owner.sub, s256)
            .map_err(stored)?
        else {
            return Err(mission_not_found());
        };
        let updates = audit
            .updates
            .iter()
            .map(|update| json!({ "s256": update.s256, "encoded": update.encoded }))
            .collect::<Vec<_>>();
        let mut value = json!({
            "s256": audit.s256,
            "mission": audit.encoded,
            "updates": updates
        });
        if let Some(summary) = &audit.summary {
            value["summary"] = json!({ "s256": summary.s256, "encoded": summary.encoded });
        }
        if let Some(reason) = &audit.termination_reason {
            value["mission_status"] = json!("terminated");
            value["termination_reason"] = json!(reason);
        }
        Ok(json_response(StatusCode::OK, value))
    }

    pub(super) fn verify_approver(
        &self,
        request: &Request<Vec<u8>>,
        now: i64,
    ) -> Result<(), Failure> {
        let proof = PreparedRequest::prepare_with_schemes(request, "sig", now, 60, &["jwks_uri"])
            .map_err(|error| Failure::proof(error, request, now))?;
        let base = std::str::from_utf8(proof.signature_base())
            .map_err(|_| Failure::proof(ProofError::InvalidInput, request, now))?;
        if !base
            .lines()
            .any(|line| line.starts_with("\"content-digest\":"))
            || !base
                .lines()
                .any(|line| line.starts_with("\"content-type\":"))
        {
            return Err(Failure::proof(ProofError::InvalidInput, request, now));
        }
        let KeyMaterial::JwksUri { id, dwk, kid } = proof.key() else {
            return Err(Failure::proof(ProofError::UnsupportedScheme, request, now));
        };
        if id != &self.config.issuer || dwk != "aauth-person.json" || kid != &self.config.kid {
            return Err(Failure::proof(ProofError::InvalidKey, request, now));
        }
        let key = self
            .resolver()
            .key(id, dwk, kid)
            .map_err(Failure::credential)?;
        proof
            .verify(&key)
            .map_err(|error| Failure::proof(error, request, now))?;
        Ok(())
    }

    fn release_approval_claim(&self, id: &str) {
        let Ok(mut proposals) = self.proposals() else {
            return;
        };
        if let Some(proposal) = proposals.get_mut(id)
            && matches!(proposal.status, Status::Approving)
        {
            proposal.status = Status::Pending;
        }
    }

    fn proposals(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, Proposal>>, Failure> {
        self.mission_http
            .as_ref()
            .ok_or_else(Failure::internal)?
            .proposals
            .lock()
            .map_err(|_| Failure::internal())
    }

    fn insert_proposal(&self, id: String, proposal: Proposal) -> Result<(), Failure> {
        let mut proposals = self.proposals()?;
        if proposals.contains_key(&id) {
            return Err(Failure::internal());
        }
        proposals.insert(id, proposal);
        Ok(())
    }

    fn proposal_location(&self, id: &str) -> String {
        format!("{}/mission/proposal/{id}", self.config.issuer)
    }
}

fn parse_route(path: &str) -> Option<Route> {
    let rest = path.strip_prefix("/mission")?;
    if rest.is_empty() {
        return Some(Route::Create);
    }
    let rest = rest.strip_prefix('/')?;
    if let Some(id) = rest.strip_prefix("proposal/") {
        if let Some(id) = id.strip_suffix("/approval") {
            return path_token(id).then(|| Route::Approval(id.to_owned()));
        }
        return path_token(id).then(|| Route::Poll(id.to_owned()));
    }
    path_token(rest).then(|| Route::Document(rest.to_owned()))
}

fn proposal_pending(location: &str) -> Response<Vec<u8>> {
    let mut response = json_response(StatusCode::ACCEPTED, json!({ "status": "pending" }));
    if let Ok(location) = location.parse() {
        response.headers_mut().insert("location", location);
    }
    response
        .headers_mut()
        .insert("retry-after", "5".parse().expect("retry-after"));
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().expect("cache-control"));
    response
}

fn path_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn json_object(request: &Request<Vec<u8>>) -> Result<serde_json::Map<String, Value>, Failure> {
    let value = strict_json(request.body()).map_err(|_| Failure::parameter("invalid_request"))?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(Failure::parameter("invalid_request")),
    }
}

fn required_text(object: &serde_json::Map<String, Value>, name: &str) -> Result<String, Failure> {
    match object.get(name) {
        Some(Value::String(text)) if !text.is_empty() && text.len() <= MAX_TEXT => Ok(text.clone()),
        _ => Err(Failure::parameter("invalid_request")),
    }
}

fn update_bytes(field: &str, text: &str) -> Result<MissionUpdateBytes, Failure> {
    let mut object = serde_json::Map::new();
    object.insert(field.into(), Value::String(text.into()));
    let bytes = serde_json::to_vec(&Value::Object(object)).map_err(|_| Failure::internal())?;
    MissionUpdateBytes::from_exact(&bytes).map_err(stored)
}

fn mission_not_found() -> Failure {
    Failure::status(StatusCode::NOT_FOUND, "mission_not_found")
}

fn stored(error: StoreError) -> Failure {
    match error {
        StoreError::InvalidRecord => Failure::parameter("invalid_request"),
        _ => Failure::internal(),
    }
}

fn edited(error: crate::MissionAuditError) -> Failure {
    match error {
        crate::MissionAuditError::NotFound => mission_not_found(),
        crate::MissionAuditError::Terminated(reason) => Failure::mission_terminated(&reason),
        crate::MissionAuditError::Invalid => Failure::parameter("invalid_request"),
        crate::MissionAuditError::Unavailable => Failure::internal(),
    }
}
