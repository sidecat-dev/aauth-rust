use serde::{Deserialize, Serialize, Serializer};

use crate::digest::digest;
use crate::error::Error;
use crate::jsonvalue::{
    decode_strict_object, expect_json_string, push_key, push_optional_string, push_string,
    raw_array_elements, refuse_deserialize, serialize_exact,
};
use crate::reference::Reference;
use crate::uri::VocabularyUri;
use crate::vocabulary::{OperationSet, Registry, SetUse, new_parsed};

/// Human-readable consequences of granting a document's operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Display {
    summary: String,
    implications: Option<String>,
    data_accessed: Option<String>,
    irreversible: Option<String>,
}

impl Display {
    /// Build a display. For the last three members, `None` omits the member and
    /// `Some("")` keeps it present and empty.
    ///
    /// # Errors
    /// Returns [`Error`] when `summary` is blank after trimming.
    pub fn new(
        summary: impl Into<String>,
        implications: Option<&str>,
        data_accessed: Option<&str>,
        irreversible: Option<&str>,
    ) -> Result<Self, Error> {
        let display = Self {
            summary: summary.into(),
            implications: implications.map(str::to_owned),
            data_accessed: data_accessed.map(str::to_owned),
            irreversible: irreversible.map(str::to_owned),
        };
        display.validate()?;
        Ok(display)
    }

    /// Required consent-screen summary.
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Side-effect description when the member is present, including a present empty string.
    pub fn implications(&self) -> Option<&str> {
        self.implications.as_deref()
    }

    /// Accessed-data description when the member is present, including a present empty string.
    pub fn data_accessed(&self) -> Option<&str> {
        self.data_accessed.as_deref()
    }

    /// Irreversible-action description when the member is present, including a present empty
    /// string.
    pub fn irreversible(&self) -> Option<&str> {
        self.irreversible.as_deref()
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.summary.trim().is_empty() {
            return Err(Error::new("r3: display summary is required"));
        }
        Ok(())
    }

    pub(crate) fn write_json(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        out.push(b'{');
        push_key(out, "summary");
        push_string(out, &self.summary);
        push_optional_string(out, "implications", self.implications());
        push_optional_string(out, "data_accessed", self.data_accessed());
        push_optional_string(out, "irreversible", self.irreversible());
        out.push(b'}');
        Ok(())
    }
}

impl Serialize for Display {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        self.write_json(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serialize_exact(&bytes, serializer)
    }
}

/// Optional account and display copied into a [`Document`].
///
/// `account: Some("")` keeps an empty account on the wire. `None` omits it.
#[derive(Clone, Copy, Debug, Default)]
pub struct DocumentOptions<'a> {
    /// Account identifier from the authorization request.
    pub account: Option<&'a str>,
    /// Consent display. `None` omits the member.
    pub display: Option<&'a Display>,
}

/// A validated vocabulary-neutral R3 document.
///
/// The document does not retain the source bytes it was parsed from. [`Default`]
/// is not a valid document.
#[derive(Clone, Default)]
pub struct Document {
    operation_set: OperationSet,
    account: Option<String>,
    display: Option<Display>,
}

impl Document {
    /// Copy `operation_set` and the optional account and display.
    ///
    /// # Errors
    /// Returns [`Error`] when the operation set is uninitialized or the display is invalid.
    pub fn new(operation_set: &OperationSet, options: DocumentOptions<'_>) -> Result<Self, Error> {
        operation_set
            .json_operations()
            .map_err(|err| Error::wrap("r3: invalid document operation set", err))?;
        if let Some(display) = options.display {
            display.validate()?;
        }
        Ok(Self {
            operation_set: operation_set.clone(),
            account: options.account.map(str::to_owned),
            display: options.display.cloned(),
        })
    }

    /// Copy of the document's operation set.
    pub fn operation_set(&self) -> OperationSet {
        self.operation_set.clone()
    }

    /// Account value when the member is present, including a present empty string.
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// Display value when the member is present.
    pub fn display(&self) -> Option<&Display> {
        self.display.as_ref()
    }

    fn to_json(&self) -> Result<Vec<u8>, Error> {
        let operations = self
            .operation_set
            .json_operations()
            .map_err(|err| Error::wrap("r3: invalid document operation set", err))?;
        if let Some(display) = &self.display {
            display.validate()?;
        }
        let mut out = Vec::new();
        out.push(b'{');
        push_key(&mut out, "vocabulary");
        push_string(&mut out, self.operation_set.vocabulary().as_str());
        out.push(b',');
        push_key(&mut out, "operations");
        out.push(b'[');
        for (index, operation) in operations.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend_from_slice(operation);
        }
        out.push(b']');
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

impl Serialize for Document {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_json().map_err(serde::ser::Error::custom)?;
        serialize_exact(&bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        refuse_deserialize(
            deserializer,
            "r3: Document requires a vocabulary registry; use Registry::parse_document",
        )
    }
}

impl Registry {
    /// Parse a document. The source bytes are not retained.
    ///
    /// # Errors
    /// Returns [`Error`] when the JSON is not a strict document or its vocabulary
    /// is not allowlisted.
    pub fn parse_document(&self, source: &[u8]) -> Result<Document, Error> {
        let mut vocabulary = None;
        let mut operations_raw = None;
        let mut account = None;
        let mut display = None;
        let seen = decode_strict_object(
            source,
            &["vocabulary", "operations", "account", "display"],
            |name, raw| {
                match name {
                    "vocabulary" => vocabulary = Some(expect_json_string(raw)?),
                    "operations" => operations_raw = Some(raw.to_vec()),
                    "account" => account = Some(expect_json_string(raw)?),
                    "display" => display = Some(parse_display(raw)?),
                    _ => {
                        return Err(Error::new(format!("unknown member \"{name}\"")));
                    }
                }
                Ok(())
            },
        )
        .map_err(|err| Error::wrap("r3: invalid document", err))?;
        if !seen.contains("vocabulary") {
            return Err(Error::new("r3: document is missing vocabulary"));
        }
        if !seen.contains("operations") {
            return Err(Error::new("r3: document is missing operations"));
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
            operations_raw.ok_or_else(|| Error::new("r3: document is missing operations"))?;
        let operations = raw_array_elements(&operations_raw)?;
        let operation_set = new_parsed(registered, operations, SetUse::Document)?;
        Document::new(
            &operation_set,
            DocumentOptions {
                account: account.as_deref(),
                display: display.as_ref(),
            },
        )
    }

    /// Check `reference` against `exact_bytes`, then parse those bytes.
    ///
    /// # Errors
    /// Returns [`Error`] when the reference is invalid, the digest differs, or
    /// the bytes are not a document.
    pub fn parse_referenced_document(
        &self,
        reference: &Reference,
        exact_bytes: &[u8],
    ) -> Result<Document, Error> {
        reference
            .validate()
            .map_err(|err| Error::wrap("r3: invalid reference", err))?;
        if digest(exact_bytes) != reference.digest() {
            return Err(Error::new("r3: referenced document digest mismatch"));
        }
        self.parse_document(exact_bytes)
    }
}

/// Require the token account and the document account to have the same presence and value.
///
/// # Errors
/// Returns [`Error`] when one side has an account and the other does not, or the values differ.
pub fn validate_document_account(
    document: &Document,
    token_account: Option<&str>,
) -> Result<(), Error> {
    match (document.account(), token_account) {
        (Some(_), None) => Err(Error::new("document contains account but token does not")),
        (None, Some(_)) => Err(Error::new("token contains account but document does not")),
        (Some(document_account), Some(token_account)) if document_account != token_account => {
            Err(Error::new("token and document account values differ"))
        }
        _ => Ok(()),
    }
}

fn parse_display(data: &[u8]) -> Result<Display, Error> {
    let mut summary = None;
    let mut implications = None;
    let mut data_accessed = None;
    let mut irreversible = None;
    let seen = decode_strict_object(
        data,
        &["summary", "implications", "data_accessed", "irreversible"],
        |name, raw| {
            let text = expect_json_string(raw)?;
            match name {
                "summary" => summary = Some(text),
                "implications" => implications = Some(text),
                "data_accessed" => data_accessed = Some(text),
                "irreversible" => irreversible = Some(text),
                _ => return Err(Error::new(format!("unknown member \"{name}\""))),
            }
            Ok(())
        },
    )
    .map_err(|err| Error::wrap("r3: invalid display", err))?;
    if !seen.contains("summary") {
        return Err(Error::new("r3: display is missing summary"));
    }
    Display::new(
        summary.unwrap_or_default(),
        implications.as_deref(),
        data_accessed.as_deref(),
        irreversible.as_deref(),
    )
}
