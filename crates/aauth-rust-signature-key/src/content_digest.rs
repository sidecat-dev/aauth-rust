//! The bounded SHA-256 subset of RFC9530 Content-Digest.
use super::{Error, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::Request;
use sfv::{BareItem, Dictionary, ListEntry, Parser};
use sha2::{Digest, Sha256};

pub(crate) fn needed(req: &Request<Vec<u8>>) -> bool {
    !req.body().is_empty() || req.headers().contains_key("content-digest")
}
pub(crate) fn field(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}
pub(crate) fn verify(req: &Request<Vec<u8>>) -> Result<(), Error> {
    let field = header(req, "content-digest").map_err(|_| Error::InvalidDigest)?;
    let parsed: Dictionary = Parser::new(&field)
        .parse()
        .map_err(|_| Error::InvalidDigest)?;
    if parsed.len() != 1 {
        return Err(Error::InvalidDigest);
    }
    let Some(ListEntry::Item(item)) = parsed.get("sha-256") else {
        return Err(Error::InvalidDigest);
    };
    let BareItem::ByteSequence(expected) = &item.bare_item else {
        return Err(Error::InvalidDigest);
    };
    if !item.params.is_empty() || expected.as_slice() != Sha256::digest(req.body()).as_slice() {
        return Err(Error::InvalidDigest);
    }
    Ok(())
}
