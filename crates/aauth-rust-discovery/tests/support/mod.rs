//! Loopback HTTPS sites for the journeys: a self-signed certificate per name,
//! a thread per connection, and a resolver that sends each name to its listener.
#![allow(dead_code, reason = "each test file uses part of the harness")]
use aauth_rust_discovery::DiscoveryClient;
use http::{Request, Response};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type Handler = Arc<dyn Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync>;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Names served on loopback, each with its own certificate.
pub struct Net {
    certificates: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
    table: Arc<RwLock<BTreeMap<String, SocketAddr>>>,
    sites: Vec<Site>,
    log: Arc<Mutex<Vec<String>>>,
}

impl Net {
    pub fn new(names: &[&str]) -> Self {
        let certificates = names
            .iter()
            .map(|name| {
                let certified = rcgen::generate_simple_self_signed(vec![(*name).into()]).unwrap();
                (
                    (*name).to_owned(),
                    (
                        certified.cert.der().to_vec(),
                        certified.key_pair.serialize_der(),
                    ),
                )
            })
            .collect();
        Self {
            certificates,
            table: Arc::default(),
            sites: Vec::new(),
            log: Arc::default(),
        }
    }

    /// A client that trusts these certificates, resolves these names to
    /// loopback, and admits loopback explicitly.
    pub fn client(&self) -> DiscoveryClient {
        self.builder().allow_restricted_addresses().build().unwrap()
    }

    /// The same, without admitting loopback.
    pub fn strict_client(&self) -> DiscoveryClient {
        self.builder().build().unwrap()
    }

    fn builder(&self) -> aauth_rust_discovery::DiscoveryClientBuilder {
        let table = self.table.clone();
        DiscoveryClient::builder()
            .root_certificates(self.certificates.values().map(|(der, _)| der.clone()))
            .resolver(move |host: &str, _port: u16| {
                table
                    .read()
                    .unwrap()
                    .get(host)
                    .map(|address| vec![*address])
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown test name"))
            })
    }

    /// Serve `name` with `handler`. Every request is logged as `METHOD name/path`.
    pub fn serve(
        &mut self,
        name: &str,
        handler: impl Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync + 'static,
    ) {
        let (der, key) = self.certificates[name].clone();
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(der)],
                    PrivatePkcs8KeyDer::from(key).into(),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        self.table.write().unwrap().insert(name.to_owned(), address);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let handler: Handler = Arc::new(handler);
        let host = name.to_owned();
        let log = self.log.clone();
        let worker = thread::spawn(move || {
            for tcp in listener.incoming() {
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                let Ok(tcp) = tcp else { continue };
                let (config, handler, host, log) =
                    (config.clone(), handler.clone(), host.clone(), log.clone());
                thread::spawn(move || {
                    let _ = connection(tcp, config, &host, &handler, &log);
                });
            }
        });
        self.sites.push(Site {
            address,
            stop,
            worker: Some(worker),
        });
    }

    /// Requests served so far, as `METHOD name/path`.
    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// How many logged requests start with `prefix`.
    pub fn count(&self, prefix: &str) -> usize {
        self.log()
            .iter()
            .filter(|line| line.starts_with(prefix))
            .count()
    }
}

struct Site {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(1));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn connection(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    host: &str,
    handler: &Handler,
    log: &Mutex<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))?;
    let mut stream = StreamOwned::new(ServerConnection::new(config)?, tcp);
    let mut bytes = Vec::new();
    let end = loop {
        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let mut chunk = [0; 4096];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let mut fields = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut fields);
    parsed.parse(&bytes[..end])?;
    let hosts: Vec<_> = parsed
        .headers
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("host"))
        .collect();
    if hosts.len() != 1 || hosts[0].value != host.as_bytes() {
        return Err("unexpected Host".into());
    }
    let length: usize = parsed
        .headers
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case("content-length"))
        .map(|field| std::str::from_utf8(field.value).unwrap().parse().unwrap())
        .unwrap_or(0);
    let mut body = bytes[end..].to_vec();
    while body.len() < length {
        let mut chunk = [0; 4096];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("truncated request".into());
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let method = parsed.method.unwrap().to_owned();
    let path = parsed.path.unwrap().to_owned();
    log.lock().unwrap().push(format!("{method} {host}{path}"));
    let mut builder = Request::builder()
        .method(method.as_str())
        .uri(format!("https://{host}{path}"));
    for field in parsed.headers.iter() {
        builder = builder.header(field.name, field.value);
    }
    let response = handler(builder.body(body)?);
    let chunked = response
        .headers()
        .get("transfer-encoding")
        .is_some_and(|value| value == "chunked");
    let mut out = format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\n",
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("Status")
    )
    .into_bytes();
    for (name, value) in response.headers() {
        out.extend_from_slice(format!("{name}: ").as_bytes());
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if chunked {
        out.extend_from_slice(b"\r\n");
        for piece in response.body().chunks(700) {
            out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
            out.extend_from_slice(piece);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
    } else {
        out.extend_from_slice(
            format!("Content-Length: {}\r\n\r\n", response.body().len()).as_bytes(),
        );
        out.extend_from_slice(response.body());
    }
    stream.write_all(&out)?;
    stream.conn.send_close_notify();
    stream.flush()?;
    Ok(())
}

/// A JSON response.
pub fn json(status: u16, bytes: impl Into<Vec<u8>>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(bytes.into())
        .unwrap()
}

/// An empty response with one header.
pub fn status_with(status: u16, name: &str, value: &str) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(name, value)
        .body(Vec::new())
        .unwrap()
}
