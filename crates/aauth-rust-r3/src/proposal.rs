use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize, Serializer};

use crate::digest::digest;
use crate::document::Display;
use crate::error::Error;
use crate::jsonvalue::{
    Json, compact_json, decode_strict_object, expect_json_string, json_equal, parse_json, push_key,
    push_optional_string, push_string, raw_array_elements, refuse_deserialize, serialize_exact,
};
use crate::reference::Reference;
use crate::uri::VocabularyUri;
use crate::vocabulary::{Operation, Registry, SetUse, new_operation_value};

/// Per-call display: an ordinary display plus optional Markdown detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalDisplay {
    display: Display,
    detail: Option<String>,
}

impl ProposalDisplay {
    /// Copy `display` and `detail`. `None` omits `detail`; `Some("")` keeps it present and empty.
    ///
    /// # Errors
    /// Returns [`Error`] when `display` is invalid.
    pub fn new(display: &Display, detail: Option<&str>) -> Result<Self, Error> {
        let value = Self {
            display: display.clone(),
            detail: detail.map(str::to_owned),
        };
        value.validate()?;
        Ok(value)
    }

    /// Required consent-screen summary.
    pub fn summary(&self) -> &str {
        self.display.summary()
    }

    /// Side-effect description when the member is present.
    pub fn implications(&self) -> Option<&str> {
        self.display.implications()
    }

    /// Accessed-data description when the member is present.
    pub fn data_accessed(&self) -> Option<&str> {
        self.display.data_accessed()
    }

    /// Irreversible-action description when the member is present.
    pub fn irreversible(&self) -> Option<&str> {
        self.display.irreversible()
    }

    /// Markdown detail when the member is present, including a present empty string.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    fn validate(&self) -> Result<(), Error> {
        self.display.validate()
    }

    fn write_json(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        out.push(b'{');
        push_key(out, "summary");
        push_string(out, self.summary());
        push_optional_string(out, "implications", self.implications());
        push_optional_string(out, "data_accessed", self.data_accessed());
        push_optional_string(out, "irreversible", self.irreversible());
        push_optional_string(out, "detail", self.detail());
        out.push(b'}');
        Ok(())
    }
}

/// Exact-byte digest of a large or sensitive parameter, plus optional display metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterDigest {
    s256: String,
    excerpt: Option<String>,
    media_type: Option<String>,
}

impl ParameterDigest {
    /// Canonical unpadded base64url SHA-256.
    pub fn s256(&self) -> &str {
        &self.s256
    }

    /// Human-readable excerpt when the member is present, including a present empty string.
    pub fn excerpt(&self) -> Option<&str> {
        self.excerpt.as_deref()
    }

    /// Media type when the member is present, including a present empty string.
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }
}

/// The OPTIONAL proposal `result`: what the resource holds after it has
/// already run the operation and seeks approval to release the result.
///
/// Its members are resource-defined. They describe the result for the issuer
/// and Person Server; the result itself is not carried. Members are stored as
/// compact JSON with names sorted, and number spelling is preserved.
#[derive(Clone, Debug)]
pub struct ProposalResult {
    json: Vec<u8>,
}

impl ProposalResult {
    /// Strictly parse one JSON object. An empty object is a present result.
    ///
    /// # Errors
    /// Returns [`Error`] when `value` is not exactly one strict JSON object.
    pub fn new(value: &[u8]) -> Result<Self, Error> {
        let parsed =
            parse_json(value).map_err(|err| Error::wrap("r3: invalid proposal result", err))?;
        if !matches!(parsed, Json::Object(_)) {
            return Err(Error::new("r3: proposal result must be a JSON object"));
        }
        Ok(Self {
            json: compact_json(&parsed),
        })
    }

    /// Owned compact JSON object.
    pub fn json(&self) -> Vec<u8> {
        self.json.clone()
    }
}

#[derive(Clone)]
enum ParameterKind {
    Inline(Vec<u8>),
    Digest(ParameterDigest),
}

/// An owned inline JSON value, or a digest descriptor.
///
/// An object that contains `s256` is the digest shape and cannot be approved as inline JSON.
#[derive(Clone)]
pub struct Parameter {
    kind: ParameterKind,
}

impl Parameter {
    /// Strictly parse `value`, reject a top-level `s256` object, and store compact JSON.
    ///
    /// Object keys are sorted. Number spelling is preserved.
    ///
    /// # Errors
    /// Returns [`Error`] when `value` is not one JSON value or uses the digest shape.
    pub fn inline(value: &[u8]) -> Result<Self, Error> {
        let parsed =
            parse_json(value).map_err(|err| Error::wrap("r3: invalid inline parameter", err))?;
        if let Json::Object(members) = &parsed
            && members.iter().any(|(name, _)| name == "s256")
        {
            return Err(Error::new(
                "r3: inline parameter uses a reserved digest descriptor member",
            ));
        }
        Ok(Self {
            kind: ParameterKind::Inline(compact_json(&parsed)),
        })
    }

    /// Build a digest descriptor from a canonical hash and optional display metadata.
    ///
    /// `None` omits `excerpt` or `media_type`; `Some("")` keeps it present and empty.
    ///
    /// # Errors
    /// Returns [`Error`] when `s256` is not canonical SHA-256 or a non-empty `media_type`
    /// is not an RFC 9110 media type.
    pub fn from_digest(
        s256: impl Into<String>,
        excerpt: Option<&str>,
        media_type: Option<&str>,
    ) -> Result<Self, Error> {
        let digest = parameter_digest(
            s256.into(),
            excerpt.map(str::to_owned),
            media_type.map(str::to_owned),
        )?;
        Ok(Self {
            kind: ParameterKind::Digest(digest),
        })
    }

    /// Hash `exact` and build a digest descriptor.
    ///
    /// # Errors
    /// Returns [`Error`] when a non-empty `media_type` is not an RFC 9110 media type.
    pub fn from_exact_bytes(
        exact: &[u8],
        excerpt: Option<&str>,
        media_type: Option<&str>,
    ) -> Result<Self, Error> {
        Self::from_digest(digest(exact), excerpt, media_type)
    }

    /// Owned inline JSON when this parameter is inline.
    pub fn inline_json(&self) -> Option<Vec<u8>> {
        match &self.kind {
            ParameterKind::Inline(bytes) if self.validate().is_ok() => Some(bytes.clone()),
            _ => None,
        }
    }

    /// Digest descriptor when this parameter is a digest.
    pub fn parameter_digest(&self) -> Option<ParameterDigest> {
        match &self.kind {
            ParameterKind::Digest(digest) if self.validate().is_ok() => Some(digest.clone()),
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        match &self.kind {
            ParameterKind::Inline(bytes) => {
                if bytes.is_empty() {
                    return Err(Error::new("r3: inline parameter is empty"));
                }
                parse_json(bytes)?;
                Ok(())
            }
            ParameterKind::Digest(digest) => {
                parameter_digest(
                    digest.s256.clone(),
                    digest.excerpt.clone(),
                    digest.media_type.clone(),
                )?;
                Ok(())
            }
        }
    }

    fn matches_presented(&self, presented: &PresentedParameter) -> Result<bool, Error> {
        self.validate()?;
        match (&self.kind, presented) {
            (ParameterKind::Digest(digest), PresentedParameter::Exact(bytes)) => {
                Ok(crate::digest::digest(bytes) == digest.s256)
            }
            (ParameterKind::Inline(raw), PresentedParameter::Inline(bytes)) => {
                let want = parse_json(raw)?;
                let got = parse_json(bytes)
                    .map_err(|err| Error::wrap("r3: invalid presented inline parameter", err))?;
                Ok(json_equal(&want, &got))
            }
            _ => Ok(false),
        }
    }

    fn write_json(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        match &self.kind {
            ParameterKind::Inline(bytes) => out.extend_from_slice(bytes),
            ParameterKind::Digest(digest) => {
                out.push(b'{');
                push_key(out, "s256");
                push_string(out, &digest.s256);
                push_optional_string(out, "excerpt", digest.excerpt());
                push_optional_string(out, "media_type", digest.media_type());
                out.push(b'}');
            }
        }
        Ok(())
    }
}

/// Call-time parameter value. Inline JSON compares structurally. Digest bytes compare by hash.
#[derive(Clone)]
pub enum PresentedParameter {
    /// JSON compared by structure, including normalized numbers.
    Inline(Vec<u8>),
    /// Exact bytes compared with SHA-256.
    Exact(Vec<u8>),
}

impl PresentedParameter {
    /// Store `value` for structural comparison.
    ///
    /// # Errors
    /// Returns [`Error`] when `value` is not one JSON value.
    pub fn inline(value: &[u8]) -> Result<Self, Error> {
        parse_json(value)
            .map_err(|err| Error::wrap("r3: invalid presented inline parameter", err))?;
        Ok(Self::Inline(value.to_vec()))
    }

    /// Store an owned copy of the exact call bytes.
    pub fn exact_bytes(value: &[u8]) -> Self {
        Self::Exact(value.to_vec())
    }

    /// Owned call-time JSON when this value is compared structurally.
    pub fn inline_json(&self) -> Option<Vec<u8>> {
        match self {
            Self::Inline(bytes) if self.validate().is_ok() => Some(bytes.clone()),
            _ => None,
        }
    }

    /// Owned call-time bytes when this value is bound by a digest.
    pub fn exact_bytes_value(&self) -> Option<Vec<u8>> {
        match self {
            Self::Exact(bytes) => Some(bytes.clone()),
            Self::Inline(_) => None,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Inline(bytes) => {
                parse_json(bytes)?;
                Ok(())
            }
            Self::Exact(_) => Ok(()),
        }
    }
}

/// Copy-safe call parameters. An initialized empty set is valid.
///
/// [`Default`] is uninitialized and is rejected by [`Proposal::new`].
#[derive(Clone, Default)]
pub struct Parameters {
    values: Option<BTreeMap<String, Parameter>>,
}

impl Parameters {
    /// Copy every parameter. Names keep the caller's strings, including empty and padded names.
    ///
    /// # Errors
    /// Returns [`Error`] when a parameter is invalid or a name is repeated.
    pub fn new(entries: impl IntoIterator<Item = (String, Parameter)>) -> Result<Self, Error> {
        let mut values = BTreeMap::new();
        for (name, parameter) in entries {
            parameter
                .validate()
                .map_err(|err| Error::wrap(format!("r3: parameter \"{name}\""), err))?;
            if values.insert(name.clone(), parameter).is_some() {
                return Err(Error::new(format!("r3: duplicate parameter \"{name}\"")));
            }
        }
        Ok(Self {
            values: Some(values),
        })
    }

    /// Owned copy of one parameter.
    pub fn get(&self, name: &str) -> Option<Parameter> {
        self.values.as_ref()?.get(name).cloned()
    }

    /// Parameter names in lexical order.
    pub fn names(&self) -> Vec<String> {
        self.values
            .as_ref()
            .map(|values| values.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Require the same names and a match for each inline or digest value.
    ///
    /// A different name set returns `Ok(false)`. An invalid presented value returns [`Error`].
    ///
    /// # Errors
    /// Returns [`Error`] when these parameters are uninitialized or a presented value is invalid.
    pub fn matches(&self, presented: &BTreeMap<String, PresentedParameter>) -> Result<bool, Error> {
        let values = self.validate()?;
        for (name, value) in presented {
            value
                .validate()
                .map_err(|err| Error::wrap(format!("r3: presented parameter \"{name}\""), err))?;
        }
        if values.len() != presented.len() {
            return Ok(false);
        }
        for (name, parameter) in values {
            let Some(actual) = presented.get(name) else {
                return Ok(false);
            };
            if !parameter.matches_presented(actual)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validate(&self) -> Result<&BTreeMap<String, Parameter>, Error> {
        let Some(values) = &self.values else {
            return Err(Error::new("r3: parameters are uninitialized"));
        };
        for (name, parameter) in values {
            parameter
                .validate()
                .map_err(|err| Error::wrap(format!("r3: parameter \"{name}\""), err))?;
        }
        Ok(values)
    }

    fn write_json(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let values = self.validate()?;
        out.push(b'{');
        for (index, (name, parameter)) in values.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            push_string(out, name);
            out.push(b':');
            parameter.write_json(out)?;
        }
        out.push(b'}');
        Ok(())
    }
}

impl Serialize for Parameters {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        self.write_json(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serialize_exact(&bytes, serializer)
    }
}

/// Optional account, release-gating result, and per-call display copied into a [`Proposal`].
#[derive(Clone, Copy, Debug, Default)]
pub struct ProposalOptions<'a> {
    /// Account identifier. `Some("")` is present and empty. `None` omits the member.
    pub account: Option<&'a str>,
    /// Release-gating result. `None` omits the member: the call has not run
    /// and the approval is for execution.
    pub result: Option<&'a ProposalResult>,
    /// Per-call display. `None` omits the member.
    pub display: Option<&'a ProposalDisplay>,
}

/// A validated per-call proposal for exactly one operation.
#[derive(Clone)]
pub struct Proposal {
    operation: Operation,
    parameters: Parameters,
    result: Option<ProposalResult>,
    account: Option<String>,
    display: Option<ProposalDisplay>,
}

impl Proposal {
    /// Copy the operation, parameters, and optional account, result, and display.
    ///
    /// When `result` is present, the draft requires `display` to state that the
    /// operation has run and that release of its result is being approved. This
    /// crate does not judge display prose.
    ///
    /// # Errors
    /// Returns [`Error`] when the operation or parameters are uninitialized.
    pub fn new(
        operation: &Operation,
        parameters: &Parameters,
        options: ProposalOptions<'_>,
    ) -> Result<Self, Error> {
        operation.json()?;
        parameters.validate()?;
        if let Some(display) = options.display {
            display.validate()?;
        }
        Ok(Self {
            operation: operation.clone(),
            parameters: parameters.clone(),
            result: options.result.cloned(),
            account: options.account.map(str::to_owned),
            display: options.display.cloned(),
        })
    }

    /// Copy of the single operation.
    pub fn operation(&self) -> Operation {
        self.operation.clone()
    }

    /// Copy of the parameter set.
    pub fn parameters(&self) -> Parameters {
        self.parameters.clone()
    }

    /// Release-gating result when the member is present. Presence means the
    /// resource has already run the operation and seeks approval to release
    /// its result; absence means the approval is for execution.
    pub fn result(&self) -> Option<&ProposalResult> {
        self.result.as_ref()
    }

    /// Account value when the member is present.
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// Per-call display when the member is present.
    pub fn display(&self) -> Option<&ProposalDisplay> {
        self.display.as_ref()
    }

    fn to_json(&self) -> Result<Vec<u8>, Error> {
        let operation = self.operation.json()?;
        let mut out = Vec::new();
        out.push(b'{');
        push_key(&mut out, "vocabulary");
        push_string(&mut out, self.operation.vocabulary().as_str());
        out.push(b',');
        push_key(&mut out, "operations");
        out.push(b'[');
        out.extend_from_slice(&operation);
        out.push(b']');
        out.push(b',');
        push_key(&mut out, "parameters");
        self.parameters.write_json(&mut out)?;
        if let Some(result) = &self.result {
            out.push(b',');
            push_key(&mut out, "result");
            out.extend_from_slice(&result.json);
        }
        if let Some(account) = &self.account {
            out.push(b',');
            push_key(&mut out, "account");
            push_string(&mut out, account);
        }
        if let Some(display) = &self.display {
            out.push(b',');
            push_key(&mut out, "display");
            display.write_json(&mut out)?;
        }
        out.push(b'}');
        Ok(out)
    }
}

impl Serialize for Proposal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_json().map_err(serde::ser::Error::custom)?;
        serialize_exact(&bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for Proposal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        refuse_deserialize(
            deserializer,
            "r3: Proposal requires a vocabulary registry; use Registry::parse_proposal",
        )
    }
}

impl Registry {
    /// Parse a proposal. The source bytes are not retained.
    ///
    /// # Errors
    /// Returns [`Error`] when the JSON is not one registered operation with a parameter object.
    pub fn parse_proposal(&self, source: &[u8]) -> Result<Proposal, Error> {
        let mut vocabulary = None;
        let mut operations_raw = None;
        let mut parameters = None;
        let mut result = None;
        let mut account = None;
        let mut display = None;
        let seen = decode_strict_object(
            source,
            &[
                "vocabulary",
                "operations",
                "parameters",
                "result",
                "account",
                "display",
            ],
            |name, raw| {
                match name {
                    "vocabulary" => vocabulary = Some(expect_json_string(raw)?),
                    "operations" => operations_raw = Some(raw.to_vec()),
                    "parameters" => parameters = Some(parse_parameters(raw)?),
                    "result" => result = Some(ProposalResult::new(raw)?),
                    "account" => account = Some(expect_json_string(raw)?),
                    "display" => display = Some(parse_proposal_display(raw)?),
                    _ => return Err(Error::new(format!("unknown member \"{name}\""))),
                }
                Ok(())
            },
        )
        .map_err(|err| Error::wrap("r3: invalid proposal", err))?;
        for required in ["vocabulary", "operations", "parameters"] {
            if !seen.contains(required) {
                return Err(Error::new(format!("r3: proposal is missing {required}")));
            }
        }
        let vocabulary_text = vocabulary.unwrap_or_default();
        let uri = VocabularyUri::parse(&vocabulary_text).map_err(|_| {
            Error::new(format!(
                "r3: vocabulary \"{vocabulary_text}\" is not registered"
            ))
        })?;
        let Some(registered) = self.vocabulary(&uri) else {
            return Err(Error::new(format!(
                "r3: vocabulary \"{uri}\" is not registered"
            )));
        };
        let operations_raw =
            operations_raw.ok_or_else(|| Error::new("r3: proposal is missing operations"))?;
        let operations = raw_array_elements(&operations_raw)?;
        let value = new_operation_value(&registered, &operations, SetUse::Proposal)?;
        let Some(operation_json) = value.canonical_raw().first() else {
            return Err(Error::new(
                "r3: proposal must contain exactly one operation",
            ));
        };
        if value.canonical_raw().len() != 1 {
            return Err(Error::new(
                "r3: proposal must contain exactly one operation",
            ));
        }
        let operation = Operation::new(&registered, operation_json)?;
        let parameters =
            parameters.ok_or_else(|| Error::new("r3: proposal is missing parameters"))?;
        Proposal::new(
            &operation,
            &parameters,
            ProposalOptions {
                account: account.as_deref(),
                result: result.as_ref(),
                display: display.as_ref(),
            },
        )
    }

    /// Check `reference` against `exact_bytes`, then parse those bytes as a proposal.
    ///
    /// # Errors
    /// Returns [`Error`] when the reference is invalid, the digest differs, or the bytes
    /// are not a proposal.
    pub fn parse_referenced_proposal(
        &self,
        reference: &Reference,
        exact_bytes: &[u8],
    ) -> Result<Proposal, Error> {
        reference
            .validate()
            .map_err(|err| Error::wrap("r3: invalid proposal reference", err))?;
        if digest(exact_bytes) != reference.digest() {
            return Err(Error::new("r3: referenced proposal digest mismatch"));
        }
        self.parse_proposal(exact_bytes)
    }
}

/// Require the token account and the proposal account to have the same presence and value.
///
/// # Errors
/// Returns [`Error`] when one side has an account and the other does not, or the values differ.
pub fn validate_proposal_account(
    proposal: &Proposal,
    token_account: Option<&str>,
) -> Result<(), Error> {
    match (proposal.account(), token_account) {
        (Some(_), None) => Err(Error::new("proposal contains account but token does not")),
        (None, Some(_)) => Err(Error::new("token contains account but proposal does not")),
        (Some(proposal_account), Some(token_account)) if proposal_account != token_account => {
            Err(Error::new("token and proposal account values differ"))
        }
        _ => Ok(()),
    }
}

fn parse_parameters(data: &[u8]) -> Result<Parameters, Error> {
    let value = parse_json(data).map_err(|err| Error::wrap("r3: invalid parameters", err))?;
    let Json::Object(members) = value else {
        return Err(Error::new("r3: parameters must be a JSON object"));
    };
    let mut values = BTreeMap::new();
    for (name, semantic) in members {
        let encoded = compact_json(&semantic);
        let parameter = parse_parameter(&encoded)
            .map_err(|err| Error::wrap(format!("r3: parameter \"{name}\""), err))?;
        values.insert(name, parameter);
    }
    Ok(Parameters {
        values: Some(values),
    })
}

fn parse_parameter(data: &[u8]) -> Result<Parameter, Error> {
    let value = parse_json(data)?;
    if let Json::Object(members) = &value
        && members.iter().any(|(name, _)| name == "s256")
    {
        return digest_parameter(members);
    }
    Parameter::inline(&compact_json(&value))
}

fn digest_parameter(members: &[(String, Json)]) -> Result<Parameter, Error> {
    for (name, _) in members {
        if name != "s256" && name != "excerpt" && name != "media_type" {
            return Err(Error::new(format!(
                "r3: digest parameter has unknown member \"{name}\""
            )));
        }
    }
    let Some((_, s256_value)) = members.iter().find(|(name, _)| name == "s256") else {
        return Err(Error::new("r3: digest parameter is missing s256"));
    };
    let Json::String(s256) = s256_value else {
        return Err(Error::new("r3: digest parameter s256 must be a string"));
    };
    let excerpt = optional_digest_string(members, "excerpt")?;
    let media_type = optional_digest_string(members, "media_type")?;
    Parameter::from_digest(s256.clone(), excerpt, media_type)
}

fn optional_digest_string<'a>(
    members: &'a [(String, Json)],
    name: &str,
) -> Result<Option<&'a str>, Error> {
    let Some((_, value)) = members.iter().find(|(key, _)| key == name) else {
        return Ok(None);
    };
    match value {
        Json::String(text) => Ok(Some(text.as_str())),
        _ => Err(Error::new(format!(
            "r3: digest parameter {name} must be a string"
        ))),
    }
}

fn parameter_digest(
    s256: String,
    excerpt: Option<String>,
    media_type: Option<String>,
) -> Result<ParameterDigest, Error> {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(s256.as_bytes()) else {
        return Err(Error::new(
            "r3: parameter digest s256 must be canonical unpadded base64url SHA-256",
        ));
    };
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != s256 {
        return Err(Error::new(
            "r3: parameter digest s256 must be canonical unpadded base64url SHA-256",
        ));
    }
    if let Some(media_type) = &media_type {
        if media_type != media_type.trim() {
            return Err(Error::new(
                "r3: parameter digest media_type must be valid trimmed UTF-8",
            ));
        }
        // A present empty value names no media type. It is kept, not refused;
        // Go also accepts it.
        if !media_type.is_empty() && !is_media_type(media_type.as_bytes()) {
            return Err(Error::wrap(
                "r3: invalid parameter digest media_type",
                Error::new("invalid media type"),
            ));
        }
    }
    Ok(ParameterDigest {
        s256,
        excerpt,
        media_type,
    })
}

/// RFC 9110 section 8.3.1 `media-type`:
///
/// ```text
/// media-type = type "/" subtype parameters
/// parameters = *( OWS ";" OWS [ parameter ] )
/// parameter  = token "=" ( token / quoted-string )
/// ```
///
/// A quoted value may be empty and may hold `;` or a quoted-pair. A
/// parameter name may not repeat, ignoring ASCII case (RFC 6838 section 4.3).
///
/// The `mime` crate does not fit: it does not handle a quoted-pair or an
/// empty quoted string.
fn is_media_type(bytes: &[u8]) -> bool {
    let type_end = token_end(bytes, 0);
    if type_end == 0 || bytes.get(type_end) != Some(&b'/') {
        return false;
    }
    let mut index = token_end(bytes, type_end + 1);
    if index == type_end + 1 {
        return false;
    }
    let mut names = BTreeSet::new();
    loop {
        let separator = skip_ows(bytes, index);
        match bytes.get(separator) {
            None if separator == index => return true,
            Some(b';') => index = skip_ows(bytes, separator + 1),
            _ => return false,
        }
        let name_end = token_end(bytes, index);
        if name_end == index {
            continue;
        }
        if bytes.get(name_end) != Some(&b'=') {
            return false;
        }
        let value_start = name_end + 1;
        let value_end = if bytes.get(value_start) == Some(&b'"') {
            match quoted_string_end(bytes, value_start) {
                Some(end) => end,
                None => return false,
            }
        } else {
            token_end(bytes, value_start)
        };
        if value_end == value_start || !names.insert(bytes[index..name_end].to_ascii_lowercase()) {
            return false;
        }
        index = value_end;
    }
}

/// RFC 9110 `tchar`.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// End of the run of `tchar` that starts at `start`.
fn token_end(bytes: &[u8], start: usize) -> usize {
    start
        + bytes
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(|byte| is_tchar(**byte))
            .count()
}

/// End of the run of `SP` / `HTAB` that starts at `start`.
fn skip_ows(bytes: &[u8], start: usize) -> usize {
    start
        + bytes
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count()
}

/// Index just past the RFC 9110 `quoted-string` whose opening quote is at `start`.
///
/// `qdtext` is `HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text`, and a
/// `quoted-pair` is `\` before `HTAB / SP / VCHAR / obs-text`.
fn quoted_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    loop {
        match *bytes.get(index)? {
            b'"' => return Some(index + 1),
            b'\\' => {
                let escaped = *bytes.get(index + 1)?;
                if !matches!(escaped, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff) {
                    return None;
                }
                index += 2;
            }
            b'\t' | b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => index += 1,
            _ => return None,
        }
    }
}

fn parse_proposal_display(data: &[u8]) -> Result<ProposalDisplay, Error> {
    let mut summary = None;
    let mut implications = None;
    let mut data_accessed = None;
    let mut irreversible = None;
    let mut detail = None;
    let seen = decode_strict_object(
        data,
        &[
            "summary",
            "implications",
            "data_accessed",
            "irreversible",
            "detail",
        ],
        |name, raw| {
            let text = expect_json_string(raw)?;
            match name {
                "summary" => summary = Some(text),
                "implications" => implications = Some(text),
                "data_accessed" => data_accessed = Some(text),
                "irreversible" => irreversible = Some(text),
                "detail" => detail = Some(text),
                _ => return Err(Error::new(format!("unknown member \"{name}\""))),
            }
            Ok(())
        },
    )
    .map_err(|err| Error::wrap("r3: invalid proposal display", err))?;
    if !seen.contains("summary") {
        return Err(Error::new("r3: proposal display is missing summary"));
    }
    let display = Display::new(
        summary.unwrap_or_default(),
        implications.as_deref(),
        data_accessed.as_deref(),
        irreversible.as_deref(),
    )?;
    ProposalDisplay::new(&display, detail.as_deref())
}
