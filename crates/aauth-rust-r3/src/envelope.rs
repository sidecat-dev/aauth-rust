use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::fmt;

use crate::error::Error;
use crate::uri::VocabularyUri;

/// Strict `vocabulary` / `operations` envelope.
///
/// Duplicate members and unknown members are refused. Operation elements stay
/// the bytes the sender wrote; this parser does not reserialize them.
pub(crate) fn parse_operation_envelope(
    source: &[u8],
) -> Result<(VocabularyUri, Vec<Vec<u8>>), Error> {
    let parts = serde_json::from_slice::<EnvelopeParts>(source)
        .map_err(|err| Error::new(format!("r3: invalid operation set: {err}")))?;
    let uri_text = parts
        .vocabulary
        .ok_or_else(|| Error::new("r3: operation set is missing vocabulary"))?;
    let operations = parts
        .operations
        .ok_or_else(|| Error::new("r3: operation set is missing operations"))?;
    Ok((VocabularyUri::parse(&uri_text)?, operations))
}

pub(crate) fn serialize_envelope<S: serde::Serializer>(
    uri: &str,
    operations: &[Vec<u8>],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let raw_operations = raw_values(operations).map_err(serde::ser::Error::custom)?;
    EnvelopeRef {
        vocabulary: uri,
        operations: &raw_operations,
    }
    .serialize(serializer)
}

fn raw_values(operations: &[Vec<u8>]) -> Result<Vec<Box<RawValue>>, Error> {
    operations
        .iter()
        .map(|operation| {
            let text = std::str::from_utf8(operation)
                .map_err(|_| Error::new("r3: operation is not valid UTF-8"))?;
            RawValue::from_string(text.to_owned())
                .map_err(|_| Error::new("r3: operation is not a JSON value"))
        })
        .collect()
}

#[derive(Serialize)]
struct EnvelopeRef<'a> {
    vocabulary: &'a str,
    operations: &'a [Box<RawValue>],
}

struct EnvelopeParts {
    vocabulary: Option<String>,
    operations: Option<Vec<Vec<u8>>>,
}

impl<'de> Deserialize<'de> for EnvelopeParts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(EnvelopeVisitor)
    }
}

struct EnvelopeVisitor;

impl<'de> Visitor<'de> for EnvelopeVisitor {
    type Value = EnvelopeParts;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an R3 vocabulary and operations object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut vocabulary = None;
        let mut operations = None;
        while let Some(key) = access.next_key::<String>()? {
            match key.as_str() {
                "vocabulary" if vocabulary.is_some() => {
                    let _ignored: serde_json::Value = access.next_value()?;
                    return Err(de::Error::custom("duplicate member \"vocabulary\""));
                }
                "operations" if operations.is_some() => {
                    let _ignored: serde_json::Value = access.next_value()?;
                    return Err(de::Error::custom("duplicate member \"operations\""));
                }
                "vocabulary" => vocabulary = Some(access.next_value()?),
                "operations" => {
                    let values: Vec<Box<RawValue>> = access.next_value()?;
                    operations = Some(
                        values
                            .into_iter()
                            .map(|value| value.get().as_bytes().to_vec())
                            .collect(),
                    );
                }
                other => {
                    let _ignored: serde_json::Value = access.next_value()?;
                    return Err(de::Error::custom(format!("unknown member \"{other}\"")));
                }
            }
        }
        Ok(EnvelopeParts {
            vocabulary,
            operations,
        })
    }
}
