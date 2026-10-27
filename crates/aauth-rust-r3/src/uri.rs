use std::fmt;

use crate::error::Error;

/// Absolute URI of one R3 operation vocabulary, with no fragment.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VocabularyUri(String);

impl VocabularyUri {
    /// Accept a non-empty trimmed absolute URI that has no fragment.
    ///
    /// # Errors
    /// Returns [`Error`] when `text` is empty, padded, relative, or contains a fragment.
    pub fn parse(text: &str) -> Result<Self, Error> {
        validate(text)?;
        Ok(Self(text.to_owned()))
    }

    /// The URI text, unchanged from registration.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn uninitialized() -> Self {
        Self(String::new())
    }

    /// A built-in URI. [`crate::Vocabulary::new`] still validates it.
    pub(crate) fn from_static(text: &'static str) -> Self {
        Self(text.to_owned())
    }
}

impl fmt::Display for VocabularyUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub(crate) fn validate(text: &str) -> Result<(), Error> {
    if text.is_empty() || text != text.trim() {
        return Err(Error::new(
            "r3: vocabulary URI must be non-empty, trimmed UTF-8",
        ));
    }
    if text
        .chars()
        .any(|c| c.is_whitespace() || c.is_ascii_control() || c == '#')
        || !has_scheme(text)
    {
        return Err(Error::new(format!(
            "r3: vocabulary URI \"{text}\" must be an absolute URI without a fragment"
        )));
    }
    Ok(())
}

fn has_scheme(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}
