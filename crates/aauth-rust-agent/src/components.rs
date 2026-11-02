//! Covered components a Resource requires beyond the base set, learned from
//! its metadata or from an `invalid_input` refusal
//! (`draft-hardt-oauth-aauth-protocol`, Covered Components, Metadata Documents
//! and Resource Metadata; `draft-hardt-httpbis-signature-key`, invalid_input).
//! The host fetches the metadata and sends the requests; this module reads
//! what they returned.
use crate::Agent;
use aauth_rust_signature_key::parse_signature_error;
use http::{HeaderMap, Request};
use serde_json::Value;
use sfv::{BareItem, Dictionary, ListEntry, Parser};

/// Largest metadata document or combined header field read here.
const LIMIT: usize = 65536;

/// A metadata document or refusal that does not say what to sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureComponentsError {
    /// The document is over 64 KiB or not a strict JSON object, or its
    /// `additional_signature_components` is not an array of strings.
    #[error(
        "Resource metadata must be a JSON object of at most 64 KiB whose additional_signature_components is an array of strings"
    )]
    MalformedMetadata,
    /// The document has no string `issuer` (`issuer_missing`).
    #[error("Resource metadata has no issuer string: do not use the document")]
    IssuerMissing,
    /// `issuer` is not, byte for byte, the Resource the document was fetched
    /// for (`issuer_mismatch`).
    #[error(
        "Resource metadata issuer is not the Resource it was fetched from: compare the exact strings, and do not use the document"
    )]
    IssuerMismatch,
    /// The headers carry no `Signature-Error` with `error=invalid_input` and
    /// a non-empty `required_input` list of plain component names.
    #[error(
        "not an invalid_input refusal with a required_input list of component names: nothing to sign differently"
    )]
    NoRequiredInput,
    /// The request passed as refused carries no `sig` signature.
    #[error("the refused request has no sig signature: pass the request as it was signed and sent")]
    Unsigned,
    /// The refused request already covered every listed component, so
    /// signing again would be refused again.
    #[error(
        "the refused request already covered every required component: signing it again will not help"
    )]
    AlreadyCovered,
}

impl Agent {
    /// Cover what a Resource's metadata document requires, on every request
    /// the returned Agent signs.
    ///
    /// `resource` is the Resource identifier the host fetched
    /// `{resource}/.well-known/aauth-resource.json` from, and `metadata` is
    /// the body it got back. The document's `issuer` must equal `resource`
    /// byte for byte. Its `additional_signature_components`, or none when the
    /// member is absent, replace any earlier list, as with
    /// [`Self::with_additional_signature_components`]; use the returned Agent
    /// for that Resource only. Other members are not read.
    ///
    /// # Errors
    /// [`SignatureComponentsError::IssuerMissing`] or
    /// [`SignatureComponentsError::IssuerMismatch`] for the issuer check, and
    /// [`SignatureComponentsError::MalformedMetadata`] for any other document
    /// this method cannot read.
    pub fn with_resource_metadata(
        &self,
        resource: &str,
        metadata: &[u8],
    ) -> Result<Self, SignatureComponentsError> {
        if metadata.len() > LIMIT {
            return Err(SignatureComponentsError::MalformedMetadata);
        }
        let Ok(Value::Object(document)) = aauth_rust_jose::strict_json(metadata) else {
            return Err(SignatureComponentsError::MalformedMetadata);
        };
        let issuer = document
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or(SignatureComponentsError::IssuerMissing)?;
        if issuer != resource {
            return Err(SignatureComponentsError::IssuerMismatch);
        }
        let components = match document.get("additional_signature_components") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or(SignatureComponentsError::MalformedMetadata)?,
            Some(_) => return Err(SignatureComponentsError::MalformedMetadata),
        };
        Ok(self.with_additional_signature_components(components))
    }

    /// Also cover what an `invalid_input` refusal says the server requires.
    ///
    /// `refused` is the request as it was signed and sent, and `refusal` the
    /// headers of the `401` that answered it. Each component in the
    /// `Signature-Error` member `required_input` that the refused signature
    /// did not cover is added to this Agent's list, after any already there.
    /// Sign the request again with the returned Agent. Components the
    /// signature covered are not added: `content-type`, `authorization` and
    /// `@query` stay covered only when the request has them.
    ///
    /// # Errors
    /// [`SignatureComponentsError::NoRequiredInput`] unless the refusal is
    /// `invalid_input` with a non-empty list of plain component names,
    /// [`SignatureComponentsError::Unsigned`] for a request without a `sig`
    /// signature, and [`SignatureComponentsError::AlreadyCovered`] when no
    /// listed component was missing.
    pub fn with_required_input<B>(
        &self,
        refused: &Request<B>,
        refusal: &HeaderMap,
    ) -> Result<Self, SignatureComponentsError> {
        let required = required_input(refusal)?;
        let covered = covered(refused.headers())?;
        let mut components = self.components.clone();
        let mut added = false;
        for component in required {
            if !covered.contains(&component) {
                added = true;
                if !components.contains(&component) {
                    components.push(component);
                }
            }
        }
        if !added {
            return Err(SignatureComponentsError::AlreadyCovered);
        }
        Ok(self.with_additional_signature_components(components))
    }
}

/// All lines of `name` as one field value, or `None` when absent, not ASCII,
/// or over [`LIMIT`].
fn combined(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut field = String::new();
    for (index, value) in headers.get_all(name).iter().enumerate() {
        if index > 0 {
            field.push_str(", ");
        }
        field.push_str(value.to_str().ok()?);
        if field.len() > LIMIT {
            return None;
        }
    }
    (!field.is_empty()).then_some(field)
}

/// The plain strings of an inner list, or `None` if any item is not one.
fn strings(entry: Option<&ListEntry>) -> Option<Vec<String>> {
    let Some(ListEntry::InnerList(list)) = entry else {
        return None;
    };
    list.items
        .iter()
        .map(|item| match &item.bare_item {
            BareItem::String(name) if item.params.is_empty() => Some(name.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

fn required_input(refusal: &HeaderMap) -> Result<Vec<String>, SignatureComponentsError> {
    let missing = SignatureComponentsError::NoRequiredInput;
    let field = combined(refusal, "signature-error").ok_or(missing)?;
    parse_signature_error(&field)
        .ok()
        .and_then(|error| error.required_input)
        .filter(|required| !required.is_empty())
        .ok_or(missing)
}

fn covered(headers: &HeaderMap) -> Result<Vec<String>, SignatureComponentsError> {
    let unsigned = SignatureComponentsError::Unsigned;
    let field = combined(headers, "signature-input").ok_or(unsigned)?;
    let dictionary: Dictionary = Parser::new(&field).parse().map_err(|_| unsigned)?;
    strings(dictionary.get("sig")).ok_or(unsigned)
}
