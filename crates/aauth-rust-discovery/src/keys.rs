//! A key resolver that discovers trusted issuers' keys over the admitted client.
use crate::client::{DiscoveryClient, DiscoveryError, document_name};
use aauth_rust_core::{
    AgentKeyResolver, TokenError, TrustedIssuerKeys, metadata_jwks_uri, validate_server_identifier,
};
use aauth_rust_jose::Jwk;
use aauth_rust_signature_key::{
    CachedDocument, DiscoveryFetch, KeyCache, KeyCacheAnswer, KeyCacheStore,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Issuers and roles [`KeyResolver::new`] caches keys for at once.
pub const DEFAULT_CAPACITY: usize = 1024;
/// A key set fetched this long ago is no longer used, even after a failed refresh.
const MAX_RETENTION: u64 = 86_400;

type Trust = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;
type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Resolves (`iss`, `dwk`, `kid`) for the issuers the host trusts, by discovery.
///
/// For a trusted issuer it fetches `{iss}/.well-known/{dwk}` through the
/// [`DiscoveryClient`], requires the document's `issuer` to be `iss`, fetches
/// its `jwks_uri` (on the same host unless the client's limits allow
/// otherwise), and selects `kid`. Key sets are cached under the
/// Signature-Key rules in `KeyCache`: the JWKS response's `Cache-Control`,
/// `Expires` and `Age` set freshness, at most 24 hours; one issuer and role
/// is fetched at most once a minute, a failed fetch included; at most
/// [`DEFAULT_CAPACITY`] issuers and roles are held. An unknown `kid` in a
/// fresh set refetches it once the minute has passed. When a refetch fails,
/// a key set fetched less than 24 hours ago still answers.
///
/// Discovery is not trust. A new resolver trusts nothing: every lookup is
/// `UntrustedIssuer`, before any network access, until the host names the
/// issuers and roles it accepts with [`Self::trust`] or [`Self::trust_when`].
///
/// [`AgentKeyResolver::key`] blocks the calling thread while it fetches.
/// Concurrent lookups of one issuer and role wait for a single fetch.
pub struct KeyResolver {
    client: DiscoveryClient,
    trusted: Vec<(String, String)>,
    trust_when: Option<Trust>,
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

struct KeySet {
    keys: TrustedIssuerKeys,
    fetched_at: u64,
}

impl fmt::Debug for KeyResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyResolver")
            .field("client", &self.client)
            .field("trusted", &self.trusted)
            .field("trust_when", &self.trust_when.is_some())
            .finish_non_exhaustive()
    }
}

impl KeyResolver {
    /// A resolver over `client` that trusts no issuer yet.
    pub fn new(client: DiscoveryClient) -> Self {
        Self {
            client,
            trusted: Vec::new(),
            trust_when: None,
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
    /// Read the current time, Unix seconds, from `clock` instead of the system.
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }
    /// Hold keys for at most `capacity` issuers and roles.
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
        if !self.trusts(issuer, dwk) {
            return Err(DiscoveryError::Untrusted {
                issuer: issuer.to_owned(),
                dwk: dwk.to_owned(),
            });
        }
        let invalid = |error| DiscoveryError::Document {
            url: issuer.to_owned(),
            error,
        };
        validate_server_identifier(issuer).map_err(invalid)?;
        if !document_name(dwk) {
            return Err(invalid(TokenError::InvalidDiscoveryDocument));
        }
        let name = format!("{issuer}\n{dwk}");
        let target = CachedDocument::JwksUriIssuer { issuer, dwk };
        let select = |set: &KeySet| {
            set.keys
                .key(issuer, dwk, kid)
                .map_err(|error| DiscoveryError::Document {
                    url: issuer.to_owned(),
                    error,
                })
        };
        let mut state = lock(&self.state);
        let mut refreshing = false;
        loop {
            if state.in_flight.contains(&name) {
                state = self.wait(state, &name)?;
                continue;
            }
            let now = self.now();
            let answer = if refreshing {
                state.cache.refresh(target, now)
            } else {
                state.cache.lookup(target, now)
            }
            .map_err(|_| invalid(TokenError::InvalidServerIdentifier))?;
            match answer {
                KeyCacheAnswer::Fresh { .. } => match state.sets.get(&name).map(select) {
                    Some(Err(DiscoveryError::Document {
                        error: TokenError::UnknownKey,
                        ..
                    }))
                    | None => refreshing = true,
                    Some(found) => return found,
                },
                // Inside the refetch floor: answer from the set fetched last,
                // if one is held and young enough.
                KeyCacheAnswer::Wait { .. } => {
                    return match state.sets.get(&name) {
                        Some(set) if now < set.fetched_at.saturating_add(MAX_RETENTION) => {
                            select(set)
                        }
                        _ => Err(DiscoveryError::Unavailable {
                            url: format!("{issuer}/.well-known/{dwk}"),
                            detail: "fetched less than a minute ago without a reusable key set"
                                .into(),
                        }),
                    };
                }
                KeyCacheAnswer::Full => {
                    return Err(DiscoveryError::Unavailable {
                        url: format!("{issuer}/.well-known/{dwk}"),
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
        let fetched = self.fetch(issuer, dwk);
        let mut state = fetching.finish();
        let now = self.now();
        match fetched {
            Ok((keys, jwks)) => {
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
                    keys,
                    fetched_at: now,
                };
                let found = select(&set);
                if matches!(stored, KeyCacheStore::Stored { fresh: true, .. }) {
                    state.keep(name, set, now);
                } else {
                    state.sets.remove(&name);
                }
                found
            }
            Err(error) => {
                let _ = state.cache.record_failure(target, now);
                match state.sets.get(&name) {
                    Some(set) if now < set.fetched_at.saturating_add(MAX_RETENTION) => {
                        select(set).map_err(|_| error)
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// Metadata, then its `jwks_uri`, then the checked snapshot.
    fn fetch(
        &self,
        issuer: &str,
        dwk: &str,
    ) -> Result<(TrustedIssuerKeys, crate::Fetched), DiscoveryError> {
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
        Ok((keys, jwks))
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
