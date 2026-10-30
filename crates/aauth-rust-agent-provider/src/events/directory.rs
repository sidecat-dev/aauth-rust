//! Directory [`EventStore`](super::EventStore).
//!
//! Each subscription is one JSON file holding its record, its use count and
//! the events it accepted. Each accepted event is one file holding its exact
//! token and body bytes. Every write goes to a temporary file, which is
//! synchronized and renamed, and then the directory is synchronized. Only
//! after that does the store report success.
//!
//! Accepting an event writes the event file first and the subscription file
//! second. The subscription file's rename is the commit point: an event file
//! no subscription lists was never accepted, and a later delivery of the same
//! event replaces it. A torn or unreadable subscription file makes that
//! subscription unavailable rather than guessing its use count. This is a
//! process exit and an interrupted write. It is not power loss on storage
//! that does not honor `fsync`. One store value owns its directory; separate
//! processes must not open the same directory.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use aauth_rust_core::events::body_s256;
use serde_json::{Value, json};

use super::{EventStore, EventStoreError, Recorded, RecordedEvent, Subscription};

/// Subscriptions and accepted events, one directory, one file each.
pub struct DirectoryEventStore {
    directory: PathBuf,
    serial: Mutex<()>,
    interrupt: AtomicBool,
}

/// One event a subscription accepted, in acceptance order.
struct Accepted {
    resource: String,
    jti: String,
    acknowledged: bool,
}

/// The subscription file's content.
struct State {
    subscription: Subscription,
    uses: u64,
    accepted: Vec<Accepted>,
}

impl DirectoryEventStore {
    /// Open or create `directory`. Records already there stay in force.
    ///
    /// # Errors
    /// Returns the filesystem error when the directory cannot be created.
    pub fn open(directory: impl Into<PathBuf>) -> io::Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            serial: Mutex::new(()),
            interrupt: AtomicBool::new(false),
        })
    }

    /// Fail the next subscription-file write before its rename. When it is
    /// the commit of an accepted event, that event's file is already written
    /// and stays unlisted. This is a host test hook and is not written down.
    pub fn interrupt_next_write(&self) {
        self.interrupt.store(true, Ordering::SeqCst);
    }

    fn subscription_path(&self, eid: &str) -> PathBuf {
        self.directory.join(format!("s-{}.json", file_key(&[eid])))
    }

    fn event_path(&self, resource: &str, jti: &str) -> PathBuf {
        self.directory
            .join(format!("e-{}.event", file_key(&[resource, jti])))
    }

    fn read_state(&self, eid: &str) -> Result<Option<State>, EventStoreError> {
        let bytes = match fs::read(self.subscription_path(eid)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(EventStoreError::Unavailable),
        };
        let state = decode_state(&bytes)?;
        if state.subscription.eid != eid {
            return Err(EventStoreError::Unavailable);
        }
        Ok(Some(state))
    }

    fn read_event(
        &self,
        resource: &str,
        jti: &str,
    ) -> Result<Option<RecordedEvent>, EventStoreError> {
        let bytes = match fs::read(self.event_path(resource, jti)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(EventStoreError::Unavailable),
        };
        let event = decode_event(&bytes)?;
        if event.resource != resource || event.jti != jti {
            return Err(EventStoreError::Unavailable);
        }
        Ok(Some(event))
    }

    fn commit(&self, state: &State) -> Result<(), EventStoreError> {
        replace(
            &self.subscription_path(&state.subscription.eid),
            &encode_state(state),
            Some(&self.interrupt),
        )
        .map_err(|_| EventStoreError::Unavailable)
    }

    /// Whether an event file is one its subscription accepted, rather than
    /// the remains of an interrupted acceptance.
    fn listed(&self, event: &RecordedEvent, current: &State) -> Result<bool, EventStoreError> {
        let lists = |state: &State| {
            state
                .accepted
                .iter()
                .any(|entry| entry.resource == event.resource && entry.jti == event.jti)
        };
        if event.eid == current.subscription.eid {
            return Ok(lists(current));
        }
        Ok(self
            .read_state(&event.eid)?
            .is_some_and(|state| lists(&state)))
    }
}

impl EventStore for DirectoryEventStore {
    fn create(&self, subscription: &Subscription) -> Result<(), EventStoreError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let state = State {
            subscription: subscription.clone(),
            uses: 0,
            accepted: Vec::new(),
        };
        match write_new(
            &self.subscription_path(&subscription.eid),
            &encode_state(&state),
            &self.interrupt,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(EventStoreError::Conflict),
            Err(_) => Err(EventStoreError::Unavailable),
        }
    }

    fn subscription(&self, eid: &str) -> Result<Option<(Subscription, u64)>, EventStoreError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        Ok(self
            .read_state(eid)?
            .map(|state| (state.subscription, state.uses)))
    }

    fn record(&self, event: &RecordedEvent) -> Result<Recorded, EventStoreError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let mut state = self
            .read_state(&event.eid)?
            .ok_or(EventStoreError::NotFound)?;
        if let Some(existing) = self.read_event(&event.resource, &event.jti)?
            && self.listed(&existing, &state)?
        {
            return Ok(Recorded::Duplicate { uses: state.uses });
        }
        if state
            .subscription
            .max_uses
            .is_some_and(|max| state.uses >= max)
        {
            return Err(EventStoreError::Exhausted);
        }
        replace(
            &self.event_path(&event.resource, &event.jti),
            &encode_event(event),
            None,
        )
        .map_err(|_| EventStoreError::Unavailable)?;
        state.uses += 1;
        state.accepted.push(Accepted {
            resource: event.resource.clone(),
            jti: event.jti.clone(),
            acknowledged: false,
        });
        self.commit(&state)?;
        Ok(Recorded::Accepted { uses: state.uses })
    }

    fn pending(&self, agent: &str) -> Result<Vec<RecordedEvent>, EventStoreError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let mut pending = Vec::new();
        let entries = fs::read_dir(&self.directory).map_err(|_| EventStoreError::Unavailable)?;
        for entry in entries {
            let name = entry.map_err(|_| EventStoreError::Unavailable)?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("s-") || !name.ends_with(".json") {
                continue;
            }
            let bytes =
                fs::read(self.directory.join(name)).map_err(|_| EventStoreError::Unavailable)?;
            let state = decode_state(&bytes)?;
            if state.subscription.agent != agent {
                continue;
            }
            for (position, entry) in state.accepted.iter().enumerate() {
                if entry.acknowledged {
                    continue;
                }
                let event = self
                    .read_event(&entry.resource, &entry.jti)?
                    .ok_or(EventStoreError::Unavailable)?;
                pending.push((
                    event.received_at,
                    state.subscription.eid.clone(),
                    position,
                    event,
                ));
            }
        }
        pending.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        Ok(pending.into_iter().map(|(_, _, _, event)| event).collect())
    }

    fn acknowledge(&self, agent: &str, resource: &str, jti: &str) -> Result<(), EventStoreError> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let Some(event) = self.read_event(resource, jti)? else {
            return Ok(());
        };
        if event.agent != agent {
            return Ok(());
        }
        let Some(mut state) = self.read_state(&event.eid)? else {
            return Ok(());
        };
        let Some(entry) = state
            .accepted
            .iter_mut()
            .find(|entry| entry.resource == resource && entry.jti == jti && !entry.acknowledged)
        else {
            return Ok(());
        };
        entry.acknowledged = true;
        self.commit(&state)
    }
}

/// Unpadded base64url SHA-256 over length-prefixed parts, as a file name.
fn file_key(parts: &[&str]) -> String {
    let mut input = Vec::new();
    for part in parts {
        input.extend_from_slice(&(part.len() as u64).to_be_bytes());
        input.extend_from_slice(part.as_bytes());
    }
    body_s256(&input)
}

fn encode_state(state: &State) -> Vec<u8> {
    let subscription = &state.subscription;
    let accepted: Vec<Value> = state
        .accepted
        .iter()
        .map(|entry| {
            json!({
                "resource": entry.resource,
                "jti": entry.jti,
                "acknowledged": entry.acknowledged,
            })
        })
        .collect();
    json!({
        "eid": subscription.eid,
        "agent": subscription.agent,
        "resource": subscription.resource,
        "max_uses": subscription.max_uses,
        "token_jti": subscription.token_jti,
        "token_expires_at": subscription.token_expires_at,
        "expires_at": subscription.expires_at,
        "uses": state.uses,
        "accepted": accepted,
    })
    .to_string()
    .into_bytes()
}

fn decode_state(bytes: &[u8]) -> Result<State, EventStoreError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| EventStoreError::Unavailable)?;
    let mut accepted = Vec::new();
    for entry in value
        .get("accepted")
        .and_then(Value::as_array)
        .ok_or(EventStoreError::Unavailable)?
    {
        accepted.push(Accepted {
            resource: text(entry, "resource")?,
            jti: text(entry, "jti")?,
            acknowledged: entry
                .get("acknowledged")
                .and_then(Value::as_bool)
                .ok_or(EventStoreError::Unavailable)?,
        });
    }
    let uses = value
        .get("uses")
        .and_then(Value::as_u64)
        .ok_or(EventStoreError::Unavailable)?;
    // The count is the number of accepted events; a disagreement means the
    // file is not one this store wrote.
    if uses != accepted.len() as u64 {
        return Err(EventStoreError::Unavailable);
    }
    Ok(State {
        subscription: Subscription {
            eid: text(&value, "eid")?,
            agent: text(&value, "agent")?,
            resource: text(&value, "resource")?,
            max_uses: optional(&value, "max_uses", Value::as_u64)?,
            token_jti: text(&value, "token_jti")?,
            token_expires_at: integer(&value, "token_expires_at")?,
            expires_at: optional(&value, "expires_at", Value::as_i64)?,
        },
        uses,
        accepted,
    })
}

/// A JSON header line, then the exact body bytes.
fn encode_event(event: &RecordedEvent) -> Vec<u8> {
    let mut bytes = json!({
        "eid": event.eid,
        "agent": event.agent,
        "resource": event.resource,
        "jti": event.jti,
        "expires_at": event.expires_at,
        "event_token": event.event_token,
        "content_type": event.content_type,
        "received_at": event.received_at,
        "body_length": event.body.len(),
    })
    .to_string()
    .into_bytes();
    bytes.push(b'\n');
    bytes.extend_from_slice(&event.body);
    bytes
}

fn decode_event(bytes: &[u8]) -> Result<RecordedEvent, EventStoreError> {
    let split = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(EventStoreError::Unavailable)?;
    let header: Value =
        serde_json::from_slice(&bytes[..split]).map_err(|_| EventStoreError::Unavailable)?;
    let body = &bytes[split + 1..];
    if header.get("body_length").and_then(Value::as_u64) != Some(body.len() as u64) {
        return Err(EventStoreError::Unavailable);
    }
    Ok(RecordedEvent {
        eid: text(&header, "eid")?,
        agent: text(&header, "agent")?,
        resource: text(&header, "resource")?,
        jti: text(&header, "jti")?,
        expires_at: integer(&header, "expires_at")?,
        event_token: text(&header, "event_token")?,
        body: body.to_vec(),
        content_type: optional(&header, "content_type", |value| {
            value.as_str().map(str::to_owned)
        })?,
        received_at: integer(&header, "received_at")?,
    })
}

fn text(value: &Value, name: &str) -> Result<String, EventStoreError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(EventStoreError::Unavailable)
}

fn integer(value: &Value, name: &str) -> Result<i64, EventStoreError> {
    value
        .get(name)
        .and_then(Value::as_i64)
        .ok_or(EventStoreError::Unavailable)
}

/// A member that is `null` or absent is `None`; any other value must read.
fn optional<T>(
    value: &Value,
    name: &str,
    read: impl Fn(&Value) -> Option<T>,
) -> Result<Option<T>, EventStoreError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(member) => read(member).map(Some).ok_or(EventStoreError::Unavailable),
    }
}

fn write_new(path: &Path, bytes: &[u8], interrupt: &AtomicBool) -> io::Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    let pending = path.with_extension("tmp");
    let _ = fs::remove_file(&pending);
    let mut file = match File::options().write(true).create_new(true).open(&pending) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error),
    };
    if take_interrupt(bytes, &mut file, interrupt)? {
        return Err(io::Error::other("interrupted write"));
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    match fs::rename(&pending, path) {
        Ok(()) => {
            sync_parent(path)?;
            Ok(true)
        }
        Err(_error) if path.exists() => Ok(false),
        Err(error) => Err(error),
    }
}

fn replace(path: &Path, bytes: &[u8], interrupt: Option<&AtomicBool>) -> io::Result<()> {
    let pending = path.with_extension("tmp");
    {
        let mut file = File::create(&pending)?;
        if let Some(interrupt) = interrupt
            && take_interrupt(bytes, &mut file, interrupt)?
        {
            return Err(io::Error::other("interrupted write"));
        }
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&pending, path)?;
    sync_parent(path)
}

fn take_interrupt(bytes: &[u8], file: &mut File, interrupt: &AtomicBool) -> io::Result<bool> {
    if interrupt.swap(false, Ordering::SeqCst) {
        let torn = if bytes.is_empty() { bytes } else { &bytes[..1] };
        file.write_all(torn)?;
        file.sync_all()?;
        return Ok(true);
    }
    Ok(false)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        sync_dir(parent)?;
    }
    Ok(())
}

fn sync_dir(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(directory)?.sync_all()?;
    }
    let _ = directory;
    Ok(())
}
