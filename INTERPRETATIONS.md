# Selected mission interpretations

Source: Core70d67375deb0bb002af7da0711fc58f6e8926e7e, as recorded in
SPECIFICATIONS.md. These choices concern the bounded immediate PS/Resource path.

- ISO8601 mission timestamps use the RFC3339 profile, including offsets and
  fractions. Integer JWT expiry uses the floor of the mission timestamp, so a
  fractional expiry cannot extend authority; the reference store treats that
  conservative integer boundary as terminated. Exact timestamp bytes are retained.
- The approving PS is authenticated beside s256, never from legacy approver
  content. Unknown members preserve their original bytes and confer no authority.
  Duplicate JSON members at any depth are rejected as ambiguous input.
- A host-approved record includes a PS-private authenticated person ID as well
  as the full AP/Agent identity. Mission text, text assent or a token supplied
  by an unauthenticated host caller cannot establish Person approval. Installation
  is host administration; Policy still chooses the directed identity and grant.
- An unknown or wrong-owner reference at the Person token endpoint returns
  invalid_request; the selected endpoint error table supplies no distinct code
  there. This is deliberately separate from the unimplemented mission endpoint's
  mission_not_found. Both lookup misses use an owner-qualified key. Owned terminal
  missions return mission_terminated with mission_status terminated and an opaque
  termination_reason. The reason never permits reactivation. An empty reason is
  refused before the record changes; the draft does not define the empty string.
- Store::missions is optional and closed by default; mission checks and issuance
  retention must be atomic in the same store. Expiry/termination/revocation during
  policy or commit withholds credentials even if an internal issuance row was
  already retained. No rollback claim is made after an uncertain commit. Stores
  supporting administrative binding replacement must invalidate old approvals.
- A Resource challenge is not a grant and may outlive a Person credential/mission.
  Issuance/redemption still require current inputs. Person/Auth expiry remains
  bounded by the mission and verified parent credentials. Resource host policy
  owns operation/revision/payload enforcement and any current revocation channel.

AS, children, chaining, human review, creation and deferred mission control are
not implemented by this profile. This is no full R3/latest-edition qualification.
