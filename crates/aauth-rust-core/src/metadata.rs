//! Display members shared by every metadata document
//! (`draft-hardt-oauth-aauth-protocol`, Metadata Documents).
//!
//! `aauth-agent.json`, `aauth-person.json`, `aauth-resource.json` and
//! `aauth-access.json` define `name`, `description`, `logo_uri`,
//! `logo_dark_uri`, `documentation_uri`, `tos_uri` and `policy_uri`
//! identically. All are optional. Each URL must use `https`.

use aauth_rust_jose::strict_json;
use serde_json::Value;

const MAX_NAME_BYTES: usize = 256;
const MAX_DESCRIPTION_BYTES: usize = 16_384;
const MAX_URI_BYTES: usize = 2048;

/// Members that carry a URL. Each must use `https`.
pub const DISPLAY_URI_MEMBERS: [&str; 5] = [
    "logo_uri",
    "logo_dark_uri",
    "documentation_uri",
    "tos_uri",
    "policy_uri",
];

/// A display member is malformed.
///
/// The value names the member: an empty, overlong or control-character
/// `name` or `description`, a URL that is not an absolute `https` URL with a
/// host and no userinfo, or a member that is not a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid metadata member {0}: name and description are nonempty text, and each URL is an absolute https URL with a host and no userinfo"
)]
pub struct DisplayError(pub &'static str);

/// Optional display members for one server's metadata document.
///
/// Every role that publishes metadata accepts one of these and writes its
/// members beside the protocol fields. `description` is Markdown: a reader
/// sanitizes it before rendering. Build it with the `with_` methods, which
/// check each value as it is set:
///
/// ```
/// use aauth_rust_core::MetadataDisplay;
/// let display = MetadataDisplay::new()
///     .with_name("Example Calendar")?
///     .with_logo_uri("https://calendar.example/logo.png")?
///     .with_tos_uri("https://calendar.example/terms")?;
/// assert_eq!(display.logo_uri(), Some("https://calendar.example/logo.png"));
/// assert!(MetadataDisplay::new().with_policy_uri("http://calendar.example/privacy").is_err());
/// # Ok::<(), aauth_rust_core::DisplayError>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataDisplay {
    name: Option<String>,
    description: Option<String>,
    logo_uri: Option<String>,
    logo_dark_uri: Option<String>,
    documentation_uri: Option<String>,
    tos_uri: Option<String>,
    policy_uri: Option<String>,
}

impl MetadataDisplay {
    /// No display members.
    pub fn new() -> Self {
        Self::default()
    }

    /// Human-readable display name, at most 256 bytes without control characters.
    ///
    /// # Errors
    /// [`DisplayError`] naming `name` for an empty, overlong or control-character value.
    pub fn with_name(mut self, name: &str) -> Result<Self, DisplayError> {
        check_text("name", name, MAX_NAME_BYTES, false)?;
        self.name = Some(name.to_owned());
        Ok(self)
    }

    /// Markdown description for consent screens and dashboards, at most 16384
    /// bytes. Line breaks and tabs are allowed; other control characters are not.
    ///
    /// # Errors
    /// [`DisplayError`] naming `description` for an empty, overlong or
    /// control-character value.
    pub fn with_description(mut self, markdown: &str) -> Result<Self, DisplayError> {
        check_text("description", markdown, MAX_DESCRIPTION_BYTES, true)?;
        self.description = Some(markdown.to_owned());
        Ok(self)
    }

    /// Logo URL.
    ///
    /// # Errors
    /// [`DisplayError`] naming `logo_uri` unless `uri` is an absolute `https` URL.
    pub fn with_logo_uri(mut self, uri: &str) -> Result<Self, DisplayError> {
        self.logo_uri = Some(https_member("logo_uri", uri)?);
        Ok(self)
    }

    /// Logo URL for dark backgrounds.
    ///
    /// # Errors
    /// [`DisplayError`] naming `logo_dark_uri` unless `uri` is an absolute `https` URL.
    pub fn with_logo_dark_uri(mut self, uri: &str) -> Result<Self, DisplayError> {
        self.logo_dark_uri = Some(https_member("logo_dark_uri", uri)?);
        Ok(self)
    }

    /// Developer documentation URL.
    ///
    /// # Errors
    /// [`DisplayError`] naming `documentation_uri` unless `uri` is an absolute `https` URL.
    pub fn with_documentation_uri(mut self, uri: &str) -> Result<Self, DisplayError> {
        self.documentation_uri = Some(https_member("documentation_uri", uri)?);
        Ok(self)
    }

    /// Terms of service URL.
    ///
    /// # Errors
    /// [`DisplayError`] naming `tos_uri` unless `uri` is an absolute `https` URL.
    pub fn with_tos_uri(mut self, uri: &str) -> Result<Self, DisplayError> {
        self.tos_uri = Some(https_member("tos_uri", uri)?);
        Ok(self)
    }

    /// Privacy policy URL.
    ///
    /// # Errors
    /// [`DisplayError`] naming `policy_uri` unless `uri` is an absolute `https` URL.
    pub fn with_policy_uri(mut self, uri: &str) -> Result<Self, DisplayError> {
        self.policy_uri = Some(https_member("policy_uri", uri)?);
        Ok(self)
    }

    /// `name`, when set.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    /// `description`, when set. Markdown; sanitize before rendering.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
    /// `logo_uri`, when set.
    pub fn logo_uri(&self) -> Option<&str> {
        self.logo_uri.as_deref()
    }
    /// `logo_dark_uri`, when set.
    pub fn logo_dark_uri(&self) -> Option<&str> {
        self.logo_dark_uri.as_deref()
    }
    /// `documentation_uri`, when set.
    pub fn documentation_uri(&self) -> Option<&str> {
        self.documentation_uri.as_deref()
    }
    /// `tos_uri`, when set.
    pub fn tos_uri(&self) -> Option<&str> {
        self.tos_uri.as_deref()
    }
    /// `policy_uri`, when set.
    pub fn policy_uri(&self) -> Option<&str> {
        self.policy_uri.as_deref()
    }

    /// Member names and values that are set, in the draft's table order.
    /// A role writes exactly these beside its protocol fields.
    pub fn members(&self) -> Vec<(&'static str, &str)> {
        [
            ("name", &self.name),
            ("description", &self.description),
            ("logo_uri", &self.logo_uri),
            ("logo_dark_uri", &self.logo_dark_uri),
            ("documentation_uri", &self.documentation_uri),
            ("tos_uri", &self.tos_uri),
            ("policy_uri", &self.policy_uri),
        ]
        .into_iter()
        .filter_map(|(member, value)| value.as_deref().map(|value| (member, value)))
        .collect()
    }

    /// Read the display members of a fetched metadata document.
    ///
    /// Absent members stay unset and other members are ignored. This does not
    /// check `issuer`; use the discovery functions for that.
    ///
    /// # Errors
    /// [`DisplayError`] naming `metadata` when the bytes are not one JSON
    /// object, or naming the member that is not a string or fails its check.
    pub fn from_metadata(bytes: &[u8]) -> Result<Self, DisplayError> {
        if bytes.len() > 65_536 {
            return Err(DisplayError("metadata"));
        }
        let metadata = strict_json(bytes).map_err(|_| DisplayError("metadata"))?;
        let Value::Object(members) = &metadata else {
            return Err(DisplayError("metadata"));
        };
        let text = |member: &'static str| -> Result<Option<&str>, DisplayError> {
            match members.get(member) {
                None => Ok(None),
                Some(Value::String(value)) => Ok(Some(value.as_str())),
                Some(_) => Err(DisplayError(member)),
            }
        };
        let mut display = Self::new();
        if let Some(name) = text("name")? {
            display = display.with_name(name)?;
        }
        if let Some(description) = text("description")? {
            display = display.with_description(description)?;
        }
        if let Some(uri) = text("logo_uri")? {
            display = display.with_logo_uri(uri)?;
        }
        if let Some(uri) = text("logo_dark_uri")? {
            display = display.with_logo_dark_uri(uri)?;
        }
        if let Some(uri) = text("documentation_uri")? {
            display = display.with_documentation_uri(uri)?;
        }
        if let Some(uri) = text("tos_uri")? {
            display = display.with_tos_uri(uri)?;
        }
        if let Some(uri) = text("policy_uri")? {
            display = display.with_policy_uri(uri)?;
        }
        Ok(display)
    }
}

/// Check every display URL member present in a parsed metadata object.
pub(crate) fn check_display_uris(metadata: &Value) -> Result<(), DisplayError> {
    for member in DISPLAY_URI_MEMBERS {
        match metadata.get(member) {
            None => {}
            Some(Value::String(uri)) => {
                https_member(member, uri)?;
            }
            Some(_) => return Err(DisplayError(member)),
        }
    }
    Ok(())
}

fn check_text(
    member: &'static str,
    value: &str,
    limit: usize,
    multiline: bool,
) -> Result<(), DisplayError> {
    let control = |c: char| c.is_control() && !(multiline && matches!(c, '\n' | '\r' | '\t'));
    if value.trim().is_empty() || value.len() > limit || value.chars().any(control) {
        return Err(DisplayError(member));
    }
    Ok(())
}

/// An absolute `https` URL with a host and no userinfo. A fragment is allowed.
fn https_member(member: &'static str, uri: &str) -> Result<String, DisplayError> {
    let invalid = DisplayError(member);
    if uri.len() > MAX_URI_BYTES
        || uri
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || !c.is_ascii())
    {
        return Err(invalid);
    }
    let before_fragment = uri.split('#').next().unwrap_or_default();
    let parsed: http::Uri = before_fragment.parse().map_err(|_| invalid)?;
    let authority = parsed.authority().ok_or(invalid)?;
    if parsed.scheme_str() != Some("https")
        || authority.host().is_empty()
        || authority.as_str().contains('@')
    {
        return Err(invalid);
    }
    Ok(uri.to_owned())
}
