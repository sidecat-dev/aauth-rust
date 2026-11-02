//! One pseudonym key for one server.
//!
//! The correlator is the JWK thumbprint of an Ed25519 or ES256 key. For
//! `jkt-jwt` the caller passes the enclave key. The ephemeral confirmation key rotates and is not
//! the correlator. Identity schemes are not bound here.
use std::collections::BTreeMap;

use aauth_rust_jose::Jwk;

use super::Error;

/// Servers a pseudonym key has already been used for.
#[derive(Clone, Debug, Default)]
pub struct ServerKeyBinding {
    servers: BTreeMap<String, String>,
}

impl ServerKeyBinding {
    /// No key has been admitted yet.
    pub fn open() -> Self {
        Self {
            servers: BTreeMap::new(),
        }
    }

    /// Admit `key` for `server`.
    ///
    /// `server` is an absolute HTTPS URL. The path and query are ignored.
    /// Host case and an explicit port 443 do not make a different server.
    /// Any other port does. The first authority a thumbprint is admitted for
    /// is the only one it may sign. The same server may use another key.
    ///
    /// # Errors
    /// `invalid_uri` when `server` is not HTTPS. `invalid_key` when `key` is
    /// not an Ed25519 or ES256 key, or its thumbprint was already admitted
    /// for a different authority.
    pub fn admit(&mut self, server: &str, key: &Jwk) -> Result<(), Error> {
        let server = server_id(server)?;
        // Thumbprints exist for every request-key algorithm; this binding
        // keeps the pseudonym keys of `jkt-jwt`, Ed25519 and ES256.
        if !aauth_rust_jose::JWS_ALGORITHMS.contains(&key.alg.as_str()) {
            return Err(Error::InvalidKey);
        }
        let thumbprint = key.thumbprint().map_err(|_| Error::InvalidKey)?;
        match self.servers.get(&thumbprint) {
            Some(bound) if bound != &server => Err(Error::InvalidKey),
            Some(_) => Ok(()),
            None => {
                self.servers.insert(thumbprint, server);
                Ok(())
            }
        }
    }
}

fn server_id(server: &str) -> Result<String, Error> {
    if server.contains('#') || server.contains('@') || server.contains(' ') {
        return Err(Error::InvalidUri);
    }
    let uri: http::Uri = server.parse().map_err(|_| Error::InvalidUri)?;
    super::canonical_authority(&uri)
}
