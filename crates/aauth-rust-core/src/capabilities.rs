//! `AAuth-Capabilities` request header (`draft-hardt-oauth-aauth-protocol`,
//! AAuth-Capabilities Request Header).
//!
//! An agent declares the requirements it can handle so a resource knows which
//! ones it may raise. The field is a Structured Field List of Tokens.
//! Unrecognized values and all parameters are ignored. An absent field, or
//! one that does not parse as a List of Tokens, declares nothing: a recipient
//! never assumes a capability the agent did not state.

use std::collections::BTreeSet;

use http::{HeaderMap, HeaderValue};
use sfv::{BareItem, List, ListEntry, Parser};

use crate::continuation::Requirement;

const MAX_FIELD_BYTES: usize = 8192;

/// A capability value this library recognizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// `interaction`: the agent can get a user to a URL, directly or through its PS.
    Interaction,
    /// `clarification`: the agent can answer clarification questions.
    Clarification,
    /// `payment`: the agent can handle `402` payment flows, directly or through its PS.
    Payment,
    /// `budget`: the agent reads budget claims and the `AAuth-Budget` header
    /// (`draft-hardt-aauth-budgets`, Capability Negotiation).
    Budget,
}

impl Capability {
    /// The registered token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interaction => "interaction",
            Self::Clarification => "clarification",
            Self::Payment => "payment",
            Self::Budget => "budget",
        }
    }

    /// The recognized capability named by `token`, or `None` for any other value.
    pub fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "interaction" => Self::Interaction,
            "clarification" => Self::Clarification,
            "payment" => Self::Payment,
            "budget" => Self::Budget,
            _ => return None,
        })
    }
}

/// The capabilities one request declared.
///
/// [`Capabilities::from_headers`] reads a request. An agent builds its own
/// declaration with [`Capabilities::with`] and [`Capabilities::union`] and
/// writes it with [`Capabilities::header_value`].
///
/// ```
/// use aauth_rust_core::capabilities::{Capabilities, Capability};
/// let mut headers = http::HeaderMap::new();
/// assert!(Capabilities::from_headers(&headers).is_empty());
/// headers.insert("aauth-capabilities", "interaction;v=2, telepathy".parse()?);
/// let declared = Capabilities::from_headers(&headers);
/// assert!(declared.contains(Capability::Interaction));
/// assert!(!declared.contains(Capability::Payment));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    declared: BTreeSet<Capability>,
}

impl Capabilities {
    /// Nothing declared.
    pub fn none() -> Self {
        Self::default()
    }

    /// Read every `AAuth-Capabilities` field line of a request.
    ///
    /// Several field lines are one combined List. An absent field declares
    /// nothing. A field that is not a List of Tokens, or is larger than 8 KiB,
    /// is treated as absent rather than refused. Unrecognized tokens and every
    /// parameter are ignored.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut lines = Vec::new();
        for value in headers.get_all("aauth-capabilities") {
            let Ok(line) = value.to_str() else {
                return Self::none();
            };
            lines.push(line);
        }
        if lines.is_empty() {
            return Self::none();
        }
        let field = lines.join(", ");
        if field.len() > MAX_FIELD_BYTES {
            return Self::none();
        }
        Self::parse(&field).unwrap_or_default()
    }

    fn parse(field: &str) -> Option<Self> {
        let list = Parser::new(field).parse::<List>().ok()?;
        let mut declared = BTreeSet::new();
        for entry in &list {
            let ListEntry::Item(item) = entry else {
                return None;
            };
            let BareItem::Token(token) = &item.bare_item else {
                return None;
            };
            if let Some(capability) = Capability::from_token(token.as_str()) {
                declared.insert(capability);
            }
        }
        Some(Self { declared })
    }

    /// Add one capability.
    pub fn with(mut self, capability: Capability) -> Self {
        self.declared.insert(capability);
        self
    }

    /// Both sets together, as an agent unions its own capabilities with the
    /// ones its PS returned at mission approval.
    pub fn union(&self, other: &Self) -> Self {
        Self {
            declared: self.declared.union(&other.declared).copied().collect(),
        }
    }

    /// Whether `capability` was declared.
    pub fn contains(&self, capability: Capability) -> bool {
        self.declared.contains(&capability)
    }

    /// Whether nothing was declared.
    pub fn is_empty(&self) -> bool {
        self.declared.is_empty()
    }

    /// Declared capabilities in a stable order.
    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.declared.iter().copied()
    }

    /// Whether a recipient may raise `requirement` to this caller.
    ///
    /// `interaction` needs the `interaction` capability, `clarification`
    /// needs `clarification`, and a payment requirement needs `payment`. The
    /// other requirements ask nothing of the agent beyond polling.
    pub fn allows(&self, requirement: &Requirement) -> bool {
        match requirement {
            Requirement::Interaction { .. } => self.contains(Capability::Interaction),
            Requirement::Clarification { .. } => self.contains(Capability::Clarification),
            Requirement::Payment { .. } => self.contains(Capability::Payment),
            Requirement::Waiting
            | Requirement::Claims(_)
            | Requirement::Approval
            | Requirement::AuthToken { .. } => true,
        }
    }

    /// Write this declaration on a request to a resource, replacing any
    /// `AAuth-Capabilities` field, or removing it when nothing is declared.
    /// Agents should send it on signed requests to resources. A request to a
    /// Person Server endpoint carries the `capabilities` parameter instead.
    pub fn insert_into(&self, headers: &mut HeaderMap) {
        match self.header_value() {
            Some(value) => {
                headers.insert("aauth-capabilities", value);
            }
            None => {
                headers.remove("aauth-capabilities");
            }
        }
    }

    /// The `AAuth-Capabilities` value an agent sends, or `None` when nothing
    /// is declared: the field is then omitted.
    pub fn header_value(&self) -> Option<HeaderValue> {
        if self.declared.is_empty() {
            return None;
        }
        let tokens: Vec<&str> = self.iter().map(Capability::as_str).collect();
        HeaderValue::from_str(&tokens.join(", ")).ok()
    }
}
