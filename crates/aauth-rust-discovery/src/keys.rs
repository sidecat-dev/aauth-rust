//! A key resolver that discovers trusted signers' keys over the admitted client.
use crate::client::{DiscoveryClient, DiscoveryError, document_name};
use aauth_rust_core::{
    AgentKeyResolver, TokenError, TrustedIssuerKeys, metadata_jwks_uri, validate_server_identifier,
};
use aauth_rust_jose::{Jwk, Jws, strict_json};
use aauth_rust_signature_key::{
    CachedDocument, DiscoveryFetch, Error as ProofError, IssuerKeyResolver, JwksResolver, KeyCache,
    KeyCacheAnswer, KeyCacheStore, KeyMaterial, PreparedRequest, SelfJwtAssertion,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Issuers, roles and JWKS URLs [`KeyResolver::new`] caches keys for at once.
pub const DEFAULT_CAPACITY: usize = 1024;
/// A key set fetched this long ago is no longer used, even after a failed refresh.
const MAX_RETENTION: u64 = 86_400;
/// Most keys read from one JWKS, as the issuer snapshots allow.
const MAX_KEYS: usize = 128;

type Trust = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;
type JwksTrust = Box<dyn Fn(&str) -> bool + Send + Sync>;
type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Resolves the keys of the signers the host trusts, by discovery.
///
/// For a trusted issuer and role (`iss`, `dwk`) it fetches
/// `{iss}/.well-known/{dwk}` through the [`DiscoveryClient`], requires the
/// document's `issuer` to be `iss`, fetches its `jwks_uri` (on the same host
/// unless the client's limits allow otherwise), and selects `kid`. This
/// serves tokens and `jwks_uri` signatures ([`AgentKeyResolver`]) and
/// `self-jwt` signatures ([`IssuerKeyResolver`], [`Self::verify_self_jwt`]).
/// For a trusted direct `jwks` URL it fetches that URL, as presented, and
/// selects `kid` ([`JwksResolver`]).
///
/// Key sets are cached under the Signature-Key rules in `KeyCache`: the JWKS
/// response's `Cache-Control`, `Expires` and `Age` set freshness, at most 24
/// hours; one issuer and role, or one JWKS URL, is fetched at most once a
/// minute, a failed fetch included; at most [`DEFAULT_CAPACITY`] are held.
/// An unknown `kid` in a fresh set refetches it once the minute has passed.
/// When a signature fails under a cached key, `refreshed_key` refetches the
/// set once, under the same minute (protocol line 2286; Signature-Key line
/// 1218). When a refetch fails, a key set fetched less than 24 hours ago
/// still answers.
///
/// Discovery is not trust. A new resolver trusts nothing: every lookup is
/// refused, before any network access, until the host names the issuers and
/// roles it accepts with [`Self::trust`] or [`Self::trust_when`], and the
/// JWKS URLs with [`Self::trust_jwks`] or [`Self::trust_jwks_when`].
///
/// Lookups block the calling thread while they fetch. Concurrent lookups of
/// one issuer and role, or one URL, wait for a single fetch.
pub struct KeyResolver {
    client: DiscoveryClient,
    trusted: Vec<(String, String)>,
    trust_when: Option<Trust>,
    trusted_jwks: Vec<String>,
    trust_jwks_when: Option<JwksTrust>,
    clock: Clock,
    state: Mutex<State>,
    fetched: Condvar,
}

struct State {
    cache: KeyCache,
    capacity: usize,
    sets: BTreeMap<String, KeySet>,
    in_flight: BTreeSet<String>,
}

/// Where a key set comes from.
#[derive(Clone, Copy)]
enum Source<'a> {
    /// `{issuer}/.well-known/{dwk}`, then its `jwks_uri`.
    Issuer { issuer: &'a str, dwk: &'a str },
    /// A direct `jwks` URL, compared as presented.
    Jwks { url: &'a str },
}

impl<'a> Source<'a> {
    fn name(&self) -> String {
        match self {
            Self::Issuer { issuer, dwk } => format!("{issuer}\n{dwk}"),
            Self::Jwks { url } => format!("jwks\n{url}"),
        }
    }
    fn target(self) -> CachedDocument<'a> {
        match self {
            Self::Issuer { issuer, dwk } => CachedDocument::JwksUriIssuer { issuer, dwk },
            Self::Jwks { url } => CachedDocument::JwksUrl(url),
        }
    }
    fn url(&self) -> String {
        match self {
            Self::Issuer { issuer, dwk } => format!("{issuer}/.well-known/{dwk}"),
            Self::Jwks { url } => (*url).to_owned(),
        }
    }
    fn document_error(&self, error: TokenError) -> DiscoveryError {
        DiscoveryError::Document {
            url: match self {
                Self::Issuer { issuer, .. } => (*issuer).to_owned(),
                Self::Jwks { url } => (*url).to_owned(),
            },
            error,
        }
    }
}

enum Held {
    /// An issuer's checked snapshot and the metadata it came from.
    Issuer {
        keys: TrustedIssuerKeys,
        metadata: Vec<u8>,
    },
    /// The keys of a direct JWKS.
    Jwks(Vec<Value>),
}

struct KeySet {
    held: Held,
    fetched_at: u64,
}

/// A key and, for an issuer, the metadata document it was found through.
struct Found {
    key: Jwk,
    metadata: Option<Vec<u8>>,
}

impl KeySet {
    fn select(&self, source: Source<'_>, kid: &str) -> Result<Found, DiscoveryError> {
        match (&self.held, source) {
            (Held::Issuer { keys, metadata }, Source::Issuer { issuer, dwk }) => keys
                .key(issuer, dwk, kid)
                .map(|key| Found {
                    key,
                    metadata: Some(metadata.clone()),
                })
                .map_err(|error| source.document_error(error)),
            (Held::Jwks(keys), Source::Jwks { .. }) => select_jwk(keys, kid)
                .map(|key| Found {
                    key,
                    metadata: None,
                })
                .map_err(|error| source.document_error(error)),
            _ => Err(source.document_error(TokenError::InvalidDiscoveryDocument)),
        }
    }
}

impl fmt::Debug for KeyResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyResolver")
            .field("client", &self.client)
            .field("trusted", &self.trusted)
            .field("trust_when", &self.trust_when.is_some())
            .field("trusted_jwks", &self.trusted_jwks)
            .field("trust_jwks_when", &self.trust_jwks_when.is_some())
            .finish_non_exhaustive()
    }
}

impl KeyResolver {
    /// A resolver over `client` that trusts no issuer or JWKS URL yet.
    pub fn new(client: DiscoveryClient) -> Self {
        Self {
            client,
            trusted: Vec::new(),
            trust_when: None,
            trusted_jwks: Vec::new(),
            trust_jwks_when: None,
            clock: Box::new(system_now),
            state: Mutex::new(State {
                cache: KeyCache::open(DEFAULT_CAPACITY).expect("nonzero capacity"),
                capacity: DEFAULT_CAPACITY,
                sets: BTreeMap::new(),
                in_flight: BTreeSet::new(),
            }),
            fetched: Condvar::new(),
        }
    }
    /// Trust `issuer` in the role whose metadata document is `dwk`, such as
    /// `aauth-agent.json` for an Agent Provider.
    pub fn trust(mut self, issuer: &str, dwk: &str) -> Self {
        self.trusted.push((issuer.to_owned(), dwk.to_owned()));
        self
    }
    /// Also trust every issuer and role `trusted` accepts.
    ///
    /// For a verifier that admits issuers it has no list of, such as a
    /// revocation endpoint open to any Agent Provider. Each issuer it admits
    /// can make this resolver fetch, within the client's egress admission.
    pub fn trust_when(
        mut self,
        trusted: impl Fn(&str, &str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.trust_when = Some(Box::new(trusted));
        self
    }
    /// Trust the signer identified by the direct `jwks` URL `url`, byte for
    /// byte as a `jwks` member presents it (Signature-Key, jwks scheme).
    pub fn trust_jwks(mut self, url: &str) -> Self {
        self.trusted_jwks.push(url.to_owned());
        self
    }
    /// Also trust every direct `jwks` URL `trusted` accepts. Each URL it
    /// admits can make this resolver fetch it, within the client's egress
    /// admission.
    pub fn trust_jwks_when(
        mut self,
        trusted: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.trust_jwks_when = Some(Box::new(trusted));
        self
    }
    /// Read the current time, Unix seconds, from `clock` instead of the system.
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }
    /// Hold keys for at most `capacity` issuers, roles and JWKS URLs.
    ///
    /// # Errors
    /// [`DiscoveryError::Configuration`] when `capacity` is zero.
    pub fn with_capacity(self, capacity: usize) -> Result<Self, DiscoveryError> {
        let cache = KeyCache::open(capacity)
            .map_err(|_| DiscoveryError::Configuration("capacity must be nonzero".into()))?;
        {
            let mut state = lock(&self.state);
            state.cache = cache;
            state.capacity = capacity;
            state.sets.clear();
        }
        Ok(self)
    }

    /// Whether the host trusts `issuer` in the role `dwk`.
    pub fn trusts(&self, issuer: &str, dwk: &str) -> bool {
        self.trusted
            .iter()
            .any(|(trusted, role)| trusted == issuer && role == dwk)
            || self
                .trust_when
                .as_ref()
                .is_some_and(|trusted| trusted(issuer, dwk))
    }

    /// Whether the host trusts the direct `jwks` URL `url`.
    pub fn trusts_jwks(&self, url: &str) -> bool {
        self.trusted_jwks.iter().any(|trusted| trusted == url)
            || self
                .trust_jwks_when
                .as_ref()
                .is_some_and(|trusted| trusted(url))
    }

    /// Resolve `kid` for a trusted issuer and role, with the reason when it fails.
    ///
    /// [`AgentKeyResolver::key`] is this, with the error mapped by
    /// [`DiscoveryError::token_error`].
    ///
    /// # Errors
    /// [`DiscoveryError::Untrusted`] before any fetch; `unknown_key`,
    /// `issuer_missing`, `issuer_mismatch` and the other document checks as
    /// [`DiscoveryError::Document`]; fetch failures as the client reports them.
    pub fn resolve(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, DiscoveryError> {
        self.issuer_source(issuer, dwk)
            .and_then(|source| self.lookup(source, kid, false))
            .map(|found| found.expect("a lookup without refresh always answers").key)
    }

    /// Fetch the key set of a trusted issuer and role again, because a
    /// signature failed under the key [`Self::resolve`] answered, and select
    /// `kid` from it. `None` when it was fetched within the last minute, or
    /// the fetch failed: the failure then stands.
    ///
    /// [`AgentKeyResolver::refreshed_key`] is this, with the error mapped by
    /// [`DiscoveryError::token_error`].
    ///
    /// # Errors
    /// As for [`Self::resolve`]; `unknown_key` when the fresh set no longer
    /// has `kid`.
    pub fn refresh(
        &self,
        issuer: &str,
        dwk: &str,
        kid: &str,
    ) -> Result<Option<Jwk>, DiscoveryError> {
        self.issuer_source(issuer, dwk)
            .and_then(|source| self.lookup(source, kid, true))
            .map(|found| found.map(|found| found.key))
    }

    /// Resolve `kid` in the direct JWKS at `url`, trusted with
    /// [`Self::trust_jwks`]. The URL is fetched as presented, through the
    /// client's admission. [`JwksResolver::key`] is this, with the error
    /// mapped by [`DiscoveryError::signature_error`].
    ///
    /// # Errors
    /// [`DiscoveryError::UntrustedJwks`] before any fetch; `unknown_key` and
    /// the other key checks as [`DiscoveryError::Document`]; fetch failures
    /// as the client reports them.
    pub fn resolve_jwks(&self, url: &str, kid: &str) -> Result<Jwk, DiscoveryError> {
        self.jwks_source(url)
            .and_then(|source| self.lookup(source, kid, false))
            .map(|found| found.expect("a lookup without refresh always answers").key)
    }

    /// Verify a request whose selected member is `self-jwt`: resolve the
    /// issuer's metadata and key, then verify the assertion and the HTTP
    /// signature with [`PreparedRequest::verify_self_jwt`], refreshing the
    /// key once if the assertion's signature fails. `expected_typ` is the
    /// deployment's JWT `typ`. The issuer and role the assertion names must
    /// be trusted with [`Self::trust`].
    ///
    /// # Errors
    /// `invalid_key` when the member is not `self-jwt` or its issuer and role
    /// are not trusted, `invalid_jwt` when the assertion names no `iss`,
    /// `dwk` or `kid`, and otherwise the errors of
    /// [`PreparedRequest::verify_self_jwt`].
    pub fn verify_self_jwt(
        &self,
        proof: &PreparedRequest,
        now: i64,
        expected_typ: &str,
    ) -> Result<SelfJwtAssertion, ProofError> {
        let KeyMaterial::SelfJwt { jwt } = proof.key() else {
            return Err(ProofError::InvalidKey);
        };
        // The names only find the issuer's documents; verification checks them.
        let (issuer, dwk, kid) = unverified_names(jwt)?;
        let found = self
            .issuer_source(&issuer, &dwk)
            .and_then(|source| self.lookup(source, &kid, false))
            .map_err(|error| error.signature_error())?
            .expect("a lookup without refresh always answers");
        let metadata = found.metadata.ok_or(ProofError::InvalidKey)?;
        proof.verify_self_jwt(&metadata, self, now, expected_typ)
    }

    fn issuer_source<'a>(
        &self,
        issuer: &'a str,
        dwk: &'a str,
    ) -> Result<Source<'a>, DiscoveryError> {
        if !self.trusts(issuer, dwk) {
            return Err(DiscoveryError::Untrusted {
                issuer: issuer.to_owned(),
                dwk: dwk.to_owned(),
            });
        }
        let source = Source::Issuer { issuer, dwk };
        validate_server_identifier(issuer).map_err(|error| source.document_error(error))?;
        if !document_name(dwk) {
            return Err(source.document_error(TokenError::InvalidDiscoveryDocument));
        }
        Ok(source)
    }

    fn jwks_source<'a>(&self, url: &'a str) -> Result<Source<'a>, DiscoveryError> {
        if !self.trusts_jwks(url) {
            return Err(DiscoveryError::UntrustedJwks {
                url: url.to_owned(),
            });
        }
        Ok(Source::Jwks { url })
    }

    /// The key `kid` from `source`'s set, fetching under the cache rules.
    ///
    /// With `refresh`, the set is fetched again whatever its freshness, once
    /// the minute has passed, and `None` is the answer inside the minute or
    /// when the fetch fails. Without it the answer is always `Some`.
    fn lookup(
        &self,
        source: Source<'_>,
        kid: &str,
        refresh: bool,
    ) -> Result<Option<Found>, DiscoveryError> {
        let name = source.name();
        let target = source.target();
        let invalid = |_| source.document_error(TokenError::InvalidServerIdentifier);
        let mut state = lock(&self.state);
        let mut refreshing = refresh;
        loop {
            if state.in_flight.contains(&name) {
                state = self.wait(state, &name)?;
                if refresh {
                    // Another lookup fetched the set meanwhile: use it.
                    return match state.sets.get(&name) {
                        Some(set) => set.select(source, kid).map(Some),
                        None => Ok(None),
                    };
                }
                continue;
            }
            let now = self.now();
            let answer = if refreshing {
                state.cache.refresh(target, now)
            } else {
                state.cache.lookup(target, now)
            }
            .map_err(invalid)?;
            match answer {
                KeyCacheAnswer::Fresh { .. } => {
                    match state.sets.get(&name).map(|set| set.select(source, kid)) {
                        Some(Err(DiscoveryError::Document {
                            error: TokenError::UnknownKey,
                            ..
                        }))
                        | None => refreshing = true,
                        Some(found) => return found.map(Some),
                    }
                }
                // Inside the refetch floor: a refresh changes nothing; a
                // lookup answers from the set fetched last, if one is held
                // and young enough.
                KeyCacheAnswer::Wait { .. } if refresh => return Ok(None),
                KeyCacheAnswer::Wait { .. } => {
                    return match state.sets.get(&name) {
                        Some(set) if now < set.fetched_at.saturating_add(MAX_RETENTION) => {
                            set.select(source, kid).map(Some)
                        }
                        _ => Err(DiscoveryError::Unavailable {
                            url: source.url(),
                            detail: "fetched less than a minute ago without a reusable key set"
                                .into(),
                        }),
                    };
                }
                KeyCacheAnswer::Full => {
                    return Err(DiscoveryError::Unavailable {
                        url: source.url(),
                        detail: "the key cache is full".into(),
                    });
                }
                KeyCacheAnswer::Fetch => break,
            }
        }
        state.in_flight.insert(name.clone());
        drop(state);
        let fetching = InFlight {
            resolver: self,
            name: &name,
        };
        let fetched = match source {
            Source::Issuer { issuer, dwk } => self.fetch_issuer(issuer, dwk),
            Source::Jwks { url } => self.fetch_jwks(url),
        };
        let mut state = fetching.finish();
        let now = self.now();
        match fetched {
            Ok((held, jwks)) => {
                let stored =
                    match state
                        .cache
                        .store_response(target, jwks.body(), jwks.cache_headers(), now)
                    {
                        Ok(stored) => stored,
                        // A cache header this cache cannot read: use the set for
                        // this lookup only, and count the fetch toward the floor.
                        Err(_) => state
                            .cache
                            .store(target, jwks.body(), Some("no-store"), now)
                            .unwrap_or(KeyCacheStore::Full),
                    };
                let set = KeySet {
                    held,
                    fetched_at: now,
                };
                let found = set.select(source, kid);
                if matches!(stored, KeyCacheStore::Stored { fresh: true, .. }) {
                    state.keep(name, set, now);
                } else {
                    state.sets.remove(&name);
                }
                found.map(Some)
            }
            Err(error) => {
                let _ = state.cache.record_failure(target, now);
                if refresh {
                    return Ok(None);
                }
                match state.sets.get(&name) {
                    Some(set) if now < set.fetched_at.saturating_add(MAX_RETENTION) => {
                        set.select(source, kid).map(Some).map_err(|_| error)
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// Metadata, then its `jwks_uri`, then the checked snapshot.
    fn fetch_issuer(
        &self,
        issuer: &str,
        dwk: &str,
    ) -> Result<(Held, crate::Fetched), DiscoveryError> {
        let metadata = self.client.fetch_metadata(issuer, dwk)?;
        let metadata_url = format!("{issuer}/.well-known/{dwk}");
        let jwks_uri = metadata_jwks_uri(issuer, metadata.bytes()).map_err(|error| {
            DiscoveryError::Document {
                url: metadata_url.clone(),
                error,
            }
        })?;
        let jwks = self.client.get(DiscoveryFetch::JwksFromMetadata {
            metadata_url: &metadata_url,
            jwks_url: &jwks_uri,
        })?;
        let keys = TrustedIssuerKeys::from_documents(issuer, dwk, metadata.bytes(), jwks.body())
            .map_err(|error| DiscoveryError::Document {
                url: jwks_uri.clone(),
                error,
            })?;
        Ok((
            Held::Issuer {
                keys,
                metadata: metadata.bytes().to_vec(),
            },
            jwks,
        ))
    }

    /// The direct JWKS at `url`, as presented.
    fn fetch_jwks(&self, url: &str) -> Result<(Held, crate::Fetched), DiscoveryError> {
        let jwks = self.client.get(DiscoveryFetch::Jwks { url })?;
        let invalid = || DiscoveryError::Document {
            url: url.to_owned(),
            error: TokenError::InvalidKey,
        };
        let document = strict_json(jwks.body()).map_err(|_| invalid())?;
        let keys = document
            .get("keys")
            .and_then(Value::as_array)
            .filter(|keys| keys.len() <= MAX_KEYS)
            .ok_or_else(invalid)?
            .clone();
        Ok((Held::Jwks(keys), jwks))
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        name: &str,
    ) -> Result<MutexGuard<'a, State>, DiscoveryError> {
        // A fetch is two exchanges, each bounded by the client timeout.
        let patience = self.client.limits().timeout * 3;
        let (state, waited) = self
            .fetched
            .wait_timeout_while(state, patience, |state| state.in_flight.contains(name))
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if waited.timed_out() {
            return Err(DiscoveryError::Unavailable {
                url: name.replace('\n', "/.well-known/"),
                detail: "another lookup of this issuer is still fetching".into(),
            });
        }
        Ok(state)
    }

    fn now(&self) -> u64 {
        u64::try_from((self.clock)()).unwrap_or(0)
    }
}

impl State {
    /// Keep `set`, holding at most `capacity` sets: expired ones go first,
    /// then the oldest.
    fn keep(&mut self, name: String, set: KeySet, now: u64) {
        self.sets
            .retain(|_, held| now < held.fetched_at.saturating_add(MAX_RETENTION));
        if !self.sets.contains_key(&name) && self.sets.len() >= self.capacity {
            let oldest = self
                .sets
                .iter()
                .min_by_key(|(_, held)| held.fetched_at)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                self.sets.remove(&oldest);
            }
        }
        self.sets.insert(name, set);
    }
}

/// Clears the in-flight mark and wakes waiters, also if the fetch unwinds.
struct InFlight<'r, 'n> {
    resolver: &'r KeyResolver,
    name: &'n str,
}

impl<'r> InFlight<'r, '_> {
    fn finish(self) -> MutexGuard<'r, State> {
        let resolver = self.resolver;
        let mut state = lock(&resolver.state);
        state.in_flight.remove(self.name);
        resolver.fetched.notify_all();
        std::mem::forget(self);
        state
    }
}

impl Drop for InFlight<'_, '_> {
    fn drop(&mut self) {
        lock(&self.resolver.state).in_flight.remove(self.name);
        self.resolver.fetched.notify_all();
    }
}

impl AgentKeyResolver for KeyResolver {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, TokenError> {
        self.resolve(issuer, dwk, kid)
            .map_err(|error| error.token_error())
    }
    fn refreshed_key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Option<Jwk>, TokenError> {
        self.refresh(issuer, dwk, kid)
            .map_err(|error| error.token_error())
    }
}

impl IssuerKeyResolver for KeyResolver {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Jwk, ProofError> {
        self.resolve(issuer, dwk, kid)
            .map_err(|error| error.signature_error())
    }
    fn refreshed_key(&self, issuer: &str, dwk: &str, kid: &str) -> Result<Option<Jwk>, ProofError> {
        self.refresh(issuer, dwk, kid)
            .map_err(|error| error.signature_error())
    }
}

impl JwksResolver for KeyResolver {
    fn key(&self, url: &str, kid: &str) -> Result<Jwk, ProofError> {
        self.resolve_jwks(url, kid)
            .map_err(|error| error.signature_error())
    }
    fn refreshed_key(&self, url: &str, kid: &str) -> Result<Option<Jwk>, ProofError> {
        self.jwks_source(url)
            .and_then(|source| self.lookup(source, kid, true))
            .map(|found| found.map(|found| found.key))
            .map_err(|error| error.signature_error())
    }
}

/// The one key with `kid` in a direct JWKS, in the token profile.
fn select_jwk(keys: &[Value], kid: &str) -> Result<Jwk, TokenError> {
    if kid.is_empty() {
        return Err(TokenError::InvalidKeyId);
    }
    let mut matches = keys
        .iter()
        .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid));
    let value = matches.next().ok_or(TokenError::UnknownKey)?;
    if matches.next().is_some() {
        return Err(TokenError::InvalidKey);
    }
    let key: Jwk = serde_json::from_value(value.clone()).map_err(|_| TokenError::InvalidKey)?;
    if !aauth_rust_jose::JWS_ALGORITHMS.contains(&key.alg.as_str()) {
        return Err(TokenError::UnsupportedAlgorithm);
    }
    key.validate().map_err(|_| TokenError::InvalidKey)?;
    Ok(key)
}

/// `iss`, `dwk` and header `kid` of a `self-jwt` assertion, unverified.
fn unverified_names(jwt: &str) -> Result<(String, String, String), ProofError> {
    let parsed = Jws::parse(jwt).map_err(|_| ProofError::InvalidJwt)?;
    let payload = strict_json(parsed.payload()).map_err(|_| ProofError::InvalidJwt)?;
    let text = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
            .ok_or(ProofError::InvalidJwt)
    };
    Ok((
        text(payload.get("iss"))?,
        text(payload.get("dwk"))?,
        text(parsed.header().get("kid"))?,
    ))
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
