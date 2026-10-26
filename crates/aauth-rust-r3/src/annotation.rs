use std::borrow::Cow;
use std::fmt;

use crate::error::Error;
use crate::uri;

/// Where a vocabulary would publish access-mode and budget hints.
///
/// The value names a location and an encoding. It does not parse, apply, or
/// enforce an annotation. Standard mechanisms use the constants. A third-party
/// mechanism uses an absolute URI without a fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnotationEncoding(Cow<'static, str>);

impl AnnotationEncoding {
    /// The vocabulary defines no annotation mechanism.
    pub const UNAVAILABLE: Self = Self(Cow::Borrowed("unavailable"));

    /// MCP `_meta` carries the hints.
    pub const MCP_META: Self = Self(Cow::Borrowed("mcp-meta"));

    /// A specification extension carries the hints.
    pub const SPECIFICATION_EXTENSION: Self = Self(Cow::Borrowed("specification-extension"));

    /// OData metadata carries the hints.
    pub const ODATA_METADATA: Self = Self(Cow::Borrowed("odata-metadata"));

    /// Hold wire text. [`crate::Vocabulary::new`] validates it.
    pub fn from_wire(text: impl Into<String>) -> Self {
        let text = text.into();
        match text.as_str() {
            "unavailable" => Self::UNAVAILABLE,
            "mcp-meta" => Self::MCP_META,
            "specification-extension" => Self::SPECIFICATION_EXTENSION,
            "odata-metadata" => Self::ODATA_METADATA,
            _ => Self(Cow::Owned(text)),
        }
    }

    /// Wire spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        match self.as_str() {
            "unavailable" | "mcp-meta" | "specification-extension" | "odata-metadata" => Ok(()),
            other => uri::validate(other).map_err(|err| {
                Error::wrap(
                    "r3: custom annotation encoding must be an absolute URI",
                    err,
                )
            }),
        }
    }
}

impl fmt::Display for AnnotationEncoding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
