//! Bounded cache of JWKS documents the host has already fetched.
//!
//! This type does not open a connection. `store` records a fetch the host
//! already made and cannot retract it; call `lookup` before fetching. A
//! `jwks_uri` entry is keyed by issuer and `dwk`. Freshness is at most 86400
//! seconds, then reduced by `Age`. A quoted `max-age` or `s-maxage` delta is
//! accepted. `Expires` applies when `Cache-Control` sets no lifetime. The same
//! issuer and `dwk`, or the same URL, is not fetched again until sixty seconds
//! have passed.
use std::collections::BTreeMap;

use super::Error;

/// Minimum seconds between fetches of one issuer and `dwk`, or one JWKS URL.
pub const MIN_REFETCH_INTERVAL: u64 = 60;
/// Longest freshness this cache will honor, in seconds.
const MAX_KEY_TTL: u64 = 86_400;
/// Freshness used when `Cache-Control` names neither `s-maxage` nor `max-age`.
pub const DEFAULT_KEY_TTL: u64 = 300;
/// Largest JWKS document this cache will retain.
const MAX_DOCUMENT: usize = 65536;

/// What the cache will answer for one target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachedDocument<'a> {
    /// `jwks_uri` issuer and role document. The refetch floor is per issuer
    /// and `dwk`, not per `kid`.
    JwksUriIssuer {
        /// Canonical HTTPS issuer.
        issuer: &'a str,
        /// Role document name that distinguishes issuers sharing an origin.
        dwk: &'a str,
    },
    /// Direct `jwks` URL, compared as presented.
    JwksUrl(&'a str),
}

/// Header field values from a JWKS response the host already fetched.
#[derive(Clone, Copy, Debug, Default)]
pub struct FetchedHeaders<'a> {
    /// `Cache-Control` field value.
    pub cache_control: Option<&'a str>,
    /// `Age` field value, in seconds.
    pub age: Option<&'a str>,
    /// `Expires` field value, IMF-fixdate.
    pub expires: Option<&'a str>,
    /// `Date` field value, IMF-fixdate.
    pub date: Option<&'a str>,
}

/// Whether the host may use a stored document or must fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyCacheAnswer {
    /// The stored document is still fresh.
    Fresh {
        /// Document bytes from the last accepted store.
        body: Vec<u8>,
        /// First second at which this document is stale.
        expires_at: u64,
    },
    /// No fresh document is held, and the one-minute floor allows a fetch.
    Fetch,
    /// A fetch of this target was recorded inside the last minute.
    Wait {
        /// First second at which another fetch is allowed.
        until: u64,
    },
    /// A new target would exceed the bound. Targets still inside freshness
    /// or the refetch floor count.
    Full,
}

/// Result of recording a document the host fetched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCacheStore {
    /// The document was recorded.
    Stored {
        /// First second at which the document is stale.
        expires_at: u64,
        /// `false` when `no-store` or `no-cache` kept the document from being reused.
        fresh: bool,
    },
    /// The previous fetch of this target is still inside the one-minute floor.
    Wait {
        /// First second at which another fetch is allowed.
        until: u64,
    },
    /// Recording a new target would exceed the bound.
    Full,
}

#[derive(Clone, Debug)]
struct Entry {
    body: Vec<u8>,
    last_fetch: u64,
    expires_at: u64,
}

/// Verifier-side JWKS cache with an explicit entry bound.
#[derive(Debug)]
pub struct KeyCache {
    max_entries: usize,
    entries: BTreeMap<String, Entry>,
}

impl KeyCache {
    /// Open a cache that holds at most `max_entries` targets.
    ///
    /// # Errors
    /// `invalid_input` when `max_entries` is zero.
    pub fn open(max_entries: usize) -> Result<Self, Error> {
        if max_entries == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            max_entries,
            entries: BTreeMap::new(),
        })
    }

    /// Fresh document, permission to fetch, a wait, or a full cache.
    ///
    /// Entries that are stale and past the refetch floor are dropped before
    /// the bound is applied.
    ///
    /// # Errors
    /// `invalid_key` when `target` is not an HTTPS URL without userinfo or a fragment.
    pub fn lookup(
        &mut self,
        target: CachedDocument<'_>,
        now: u64,
    ) -> Result<KeyCacheAnswer, Error> {
        let key = cache_key(target)?;
        self.reclaim(now);
        if let Some(entry) = self.entries.get(&key) {
            return Ok(answer(entry, now));
        }
        if self.entries.len() >= self.max_entries {
            return Ok(KeyCacheAnswer::Full);
        }
        Ok(KeyCacheAnswer::Fetch)
    }

    /// Record `body` for `target` using `cache_control` at `now`.
    ///
    /// The host has already fetched `body`. This method cannot stop that
    /// request. A fetch inside the one-minute floor is refused and the stored
    /// document is left unchanged. `no-store` and `no-cache` record the fetch
    /// time without making the body reusable. Freshness is capped at 86400
    /// seconds. `Age`, `Expires`, and `Date` are absent; pass them to
    /// [`Self::store_response`].
    ///
    /// # Errors
    /// `invalid_key` for a target that is not HTTPS. `invalid_input` for a
    /// document larger than 65536 bytes or a `Cache-Control` value this cache
    /// cannot read.
    pub fn store(
        &mut self,
        target: CachedDocument<'_>,
        body: &[u8],
        cache_control: Option<&str>,
        now: u64,
    ) -> Result<KeyCacheStore, Error> {
        self.store_response(
            target,
            body,
            FetchedHeaders {
                cache_control,
                ..FetchedHeaders::default()
            },
            now,
        )
    }

    /// Record a fetch with `Age`, `Expires`, and `Date` header values.
    ///
    /// `s-maxage` wins over `max-age`. Either delta may be a quoted integer.
    /// `Age` is subtracted after the 86400-second cap. When `Cache-Control`
    /// sets no lifetime, an IMF-fixdate `Expires` is used: `Expires` minus
    /// `Date`, or minus `now` when `Date` is absent. This method cannot
    /// retract a fetch the host already made.
    ///
    /// # Errors
    /// `invalid_key` for a target that is not HTTPS. `invalid_input` for a
    /// document larger than 65536 bytes, an unreadable `Cache-Control` delta,
    /// a non-numeric `Age`, or an `Expires` or `Date` that is not IMF-fixdate.
    pub fn store_response(
        &mut self,
        target: CachedDocument<'_>,
        body: &[u8],
        headers: FetchedHeaders<'_>,
        now: u64,
    ) -> Result<KeyCacheStore, Error> {
        let key = cache_key(target)?;
        if body.len() > MAX_DOCUMENT {
            return Err(Error::InvalidInput);
        }
        let freshness = freshness(
            headers.cache_control,
            headers.age,
            headers.expires,
            headers.date,
            now,
        )?;
        self.reclaim(now);
        if let Some(entry) = self.entries.get(&key)
            && now < entry.last_fetch.saturating_add(MIN_REFETCH_INTERVAL)
        {
            return Ok(KeyCacheStore::Wait {
                until: entry.last_fetch.saturating_add(MIN_REFETCH_INTERVAL),
            });
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            return Ok(KeyCacheStore::Full);
        }
        let (stored_body, expires_at, fresh) = match freshness {
            Freshness::Reusable(ttl) => {
                let expires_at = now.saturating_add(ttl);
                (body.to_vec(), expires_at, now < expires_at)
            }
            Freshness::NotReusable => (Vec::new(), now, false),
        };
        self.entries.insert(
            key,
            Entry {
                body: stored_body,
                last_fetch: now,
                expires_at,
            },
        );
        Ok(KeyCacheStore::Stored { expires_at, fresh })
    }

    fn reclaim(&mut self, now: u64) {
        self.entries.retain(|_, entry| {
            now < entry.expires_at || now < entry.last_fetch.saturating_add(MIN_REFETCH_INTERVAL)
        });
    }
}

fn answer(entry: &Entry, now: u64) -> KeyCacheAnswer {
    if now < entry.expires_at {
        return KeyCacheAnswer::Fresh {
            body: entry.body.clone(),
            expires_at: entry.expires_at,
        };
    }
    let until = entry.last_fetch.saturating_add(MIN_REFETCH_INTERVAL);
    if now < until {
        return KeyCacheAnswer::Wait { until };
    }
    KeyCacheAnswer::Fetch
}

fn cache_key(target: CachedDocument<'_>) -> Result<String, Error> {
    match target {
        CachedDocument::JwksUriIssuer { issuer, dwk } => {
            https_target(issuer)?;
            if dwk.is_empty() || dwk.contains('\n') || dwk.contains(' ') {
                return Err(Error::InvalidKey);
            }
            Ok(format!("uri\n{issuer}\n{dwk}"))
        }
        CachedDocument::JwksUrl(url) => {
            https_target(url)?;
            Ok(format!("jwks\n{url}"))
        }
    }
}

fn https_target(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.contains('#') || value.contains('@') || value.contains(' ') {
        return Err(Error::InvalidKey);
    }
    if !value.starts_with("https://") {
        return Err(Error::InvalidKey);
    }
    let uri: http::Uri = value.parse().map_err(|_| Error::InvalidKey)?;
    super::canonical_authority(&uri).map_err(|_| Error::InvalidKey)?;
    Ok(())
}

enum Freshness {
    Reusable(u64),
    NotReusable,
}

fn freshness(
    cache_control: Option<&str>,
    age: Option<&str>,
    expires: Option<&str>,
    date: Option<&str>,
    now: u64,
) -> Result<Freshness, Error> {
    let age = match age {
        Some(value) => delta_seconds(value)?,
        None => 0,
    };
    let expires_at = match expires {
        Some(value) => Some(http_date(value)?),
        None => None,
    };
    let date_at = match date {
        Some(value) => Some(http_date(value)?),
        None => None,
    };
    let mut no_store = false;
    let mut no_cache = false;
    let mut max_age = None;
    let mut shared_age = None;
    if let Some(header) = cache_control {
        for directive in header.split(',') {
            let directive = directive.trim();
            if directive.is_empty() {
                continue;
            }
            let (name, value) = directive
                .split_once('=')
                .map(|(name, value)| (name.trim(), Some(value.trim())))
                .unwrap_or((directive, None));
            match name.to_ascii_lowercase().as_str() {
                "no-store" if value.is_none() => no_store = true,
                "no-cache" if value.is_none() => no_cache = true,
                "max-age" => max_age = Some(delta(value)?),
                "s-maxage" => shared_age = Some(delta(value)?),
                _ => {}
            }
        }
    }
    if no_store || no_cache {
        return Ok(Freshness::NotReusable);
    }
    let lifetime = if let Some(ttl) = shared_age.or(max_age) {
        ttl
    } else if let Some(exp) = expires_at {
        exp.saturating_sub(date_at.unwrap_or(now))
    } else {
        DEFAULT_KEY_TTL
    };
    Ok(Freshness::Reusable(
        lifetime.min(MAX_KEY_TTL).saturating_sub(age),
    ))
}

fn delta(value: Option<&str>) -> Result<u64, Error> {
    delta_seconds(value.ok_or(Error::InvalidInput)?)
}

fn delta_seconds(value: &str) -> Result<u64, Error> {
    let value = value.trim();
    let value = if let Some(inner) = value.strip_prefix('"') {
        inner.strip_suffix('"').ok_or(Error::InvalidInput)?
    } else {
        value
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidInput);
    }
    value.parse::<u64>().map_err(|_| Error::InvalidInput)
}

fn http_date(value: &str) -> Result<u64, Error> {
    let parts: Vec<&str> = value.trim().split(' ').collect();
    if parts.len() != 6 || parts[5] != "GMT" || parts[1].len() != 2 || parts[3].len() != 4 {
        return Err(Error::InvalidInput);
    }
    let day: u32 = parts[1].parse().map_err(|_| Error::InvalidInput)?;
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return Err(Error::InvalidInput),
    };
    let year: i32 = parts[3].parse().map_err(|_| Error::InvalidInput)?;
    if year < 1970 || day == 0 || day > month_len(year, month)? {
        return Err(Error::InvalidInput);
    }
    let clock: Vec<&str> = parts[4].split(':').collect();
    if clock.len() != 3 || clock.iter().any(|part| part.len() != 2) {
        return Err(Error::InvalidInput);
    }
    let hour: u64 = clock[0].parse().map_err(|_| Error::InvalidInput)?;
    let minute: u64 = clock[1].parse().map_err(|_| Error::InvalidInput)?;
    let second: u64 = clock[2].parse().map_err(|_| Error::InvalidInput)?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err(Error::InvalidInput);
    }
    let days = days_from_civil(year, month, day);
    let weekday = (days + 4).rem_euclid(7) as usize;
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    if parts[0] != format!("{},", WEEKDAYS[weekday]) {
        return Err(Error::InvalidInput);
    }
    let unix = days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64;
    u64::try_from(unix).map_err(|_| Error::InvalidInput)
}

fn month_len(year: i32, month: u32) -> Result<u32, Error> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    Ok(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(Error::InvalidInput),
    })
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = (year - era * 400) as u64;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year as u64;
    era * 146_097 + i64::try_from(day_of_era).unwrap_or(0) - 719_468
}
