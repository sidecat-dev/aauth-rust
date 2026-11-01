//! One bounded HTTP/1.1 exchange per connection: a request, its response, then close.
use http::header::{HeaderName, HeaderValue};
use http::{Request, Response};
use std::io::{self, Read, Write};

/// Largest response status line and header block read.
const MAX_HEAD: usize = 32 * 1024;
/// Most response header fields parsed.
const MAX_HEADERS: usize = 100;
/// Longest chunk-size line, extensions included.
const MAX_CHUNK_LINE: usize = 1024;

/// Fields the codec writes itself or that do not belong on a one-shot request.
const HOP_BY_HOP: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "te",
    "upgrade",
    "keep-alive",
    "proxy-connection",
];

#[derive(Debug)]
pub(crate) enum WireError {
    /// The body is larger than the limit.
    TooLarge,
    /// The deadline passed.
    Timeout,
    /// A read or write failed, including TLS.
    Io(io::Error),
    /// The response is not HTTP/1.1 this codec reads.
    Malformed(&'static str),
}

impl From<io::Error> for WireError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::Timeout,
            _ => Self::Io(error),
        }
    }
}

/// Write `request` with `Host: host`, `Content-Length` when there is a body
/// or the method carries one, and `Connection: close`.
pub(crate) fn write_request(
    stream: &mut impl Write,
    request: &Request<Vec<u8>>,
    host: &str,
) -> Result<(), WireError> {
    let target = request
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .filter(|path| path.starts_with('/'))
        .unwrap_or("/");
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(request.method().as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(target.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    head.extend_from_slice(host.as_bytes());
    head.extend_from_slice(b"\r\n");
    for (name, value) in request.headers() {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    let method_has_body = matches!(request.method().as_str(), "POST" | "PUT" | "PATCH");
    if method_has_body || !request.body().is_empty() {
        head.extend_from_slice(format!("Content-Length: {}\r\n", request.body().len()).as_bytes());
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    stream.write_all(&head)?;
    stream.write_all(request.body())?;
    stream.flush()?;
    Ok(())
}

/// Read one response whose body is at most `limit` bytes.
///
/// The body is framed by `Content-Length`, `Transfer-Encoding: chunked`, or
/// the end of the connection. Informational `1xx` responses are skipped. A
/// message carrying both framings is refused.
pub(crate) fn read_response(
    stream: &mut impl Read,
    limit: usize,
) -> Result<Response<Vec<u8>>, WireError> {
    let mut reader = Buffered {
        stream,
        pending: Vec::with_capacity(4096),
    };
    loop {
        let end = reader.head_end()?;
        let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Response::new(&mut fields);
        match parsed.parse(&reader.pending[..end]) {
            Ok(httparse::Status::Complete(_)) => {}
            _ => return Err(WireError::Malformed("unreadable response head")),
        }
        let status = parsed
            .code
            .ok_or(WireError::Malformed("response has no status"))?;
        let mut builder = Response::builder().status(status);
        for field in parsed.headers.iter() {
            let name = HeaderName::from_bytes(field.name.as_bytes())
                .map_err(|_| WireError::Malformed("invalid header name"))?;
            let value = HeaderValue::from_bytes(field.value)
                .map_err(|_| WireError::Malformed("invalid header value"))?;
            builder = builder.header(name, value);
        }
        let head = builder
            .body(Vec::<u8>::new())
            .map_err(|_| WireError::Malformed("invalid response head"))?;
        reader.pending.drain(..end);
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        let body = if status == 204 || status == 304 || status == 101 {
            Vec::new()
        } else {
            reader.body(head.headers(), limit)?
        };
        let (parts, _) = head.into_parts();
        return Ok(Response::from_parts(parts, body));
    }
}

struct Buffered<'a, S> {
    stream: &'a mut S,
    pending: Vec<u8>,
}

impl<S: Read> Buffered<'_, S> {
    /// Read more bytes. `false` at a clean end of stream.
    fn fill(&mut self) -> Result<bool, WireError> {
        let mut chunk = [0u8; 8192];
        let read = self.stream.read(&mut chunk)?;
        self.pending.extend_from_slice(&chunk[..read]);
        Ok(read > 0)
    }

    fn head_end(&mut self) -> Result<usize, WireError> {
        loop {
            if let Some(at) = find(&self.pending, b"\r\n\r\n") {
                return Ok(at + 4);
            }
            if self.pending.len() > MAX_HEAD {
                return Err(WireError::Malformed("response head is too large"));
            }
            if !self.fill()? {
                return Err(WireError::Malformed("connection closed before a response"));
            }
        }
    }

    fn body(&mut self, headers: &http::HeaderMap, limit: usize) -> Result<Vec<u8>, WireError> {
        let chunked = chunked(headers)?;
        let length = content_length(headers)?;
        if chunked && length.is_some() {
            return Err(WireError::Malformed(
                "response has both Transfer-Encoding and Content-Length",
            ));
        }
        if chunked {
            return self.chunked(limit);
        }
        if let Some(length) = length {
            if length > limit {
                return Err(WireError::TooLarge);
            }
            while self.pending.len() < length {
                if !self.fill()? {
                    return Err(WireError::Malformed("truncated response body"));
                }
            }
            return Ok(self.pending[..length].to_vec());
        }
        loop {
            if self.pending.len() > limit {
                return Err(WireError::TooLarge);
            }
            if !self.fill()? {
                return Ok(std::mem::take(&mut self.pending));
            }
        }
    }

    fn chunked(&mut self, limit: usize) -> Result<Vec<u8>, WireError> {
        let mut body = Vec::new();
        loop {
            let (consumed, size) = loop {
                match httparse::parse_chunk_size(&self.pending) {
                    Ok(httparse::Status::Complete(found)) => break found,
                    Ok(httparse::Status::Partial) => {
                        if self.pending.len() > MAX_CHUNK_LINE {
                            return Err(WireError::Malformed("chunk size line is too long"));
                        }
                        if !self.fill()? {
                            return Err(WireError::Malformed("truncated chunked body"));
                        }
                    }
                    Err(_) => return Err(WireError::Malformed("invalid chunk size")),
                }
            };
            self.pending.drain(..consumed);
            let size = usize::try_from(size).map_err(|_| WireError::TooLarge)?;
            if size == 0 {
                return self.trailers().map(|()| body);
            }
            if body.len().saturating_add(size) > limit {
                return Err(WireError::TooLarge);
            }
            while self.pending.len() < size + 2 {
                if !self.fill()? {
                    return Err(WireError::Malformed("truncated chunked body"));
                }
            }
            if &self.pending[size..size + 2] != b"\r\n" {
                return Err(WireError::Malformed("chunk is not followed by CRLF"));
            }
            body.extend_from_slice(&self.pending[..size]);
            self.pending.drain(..size + 2);
        }
    }

    /// Skip trailer fields up to the empty line that ends the message.
    fn trailers(&mut self) -> Result<(), WireError> {
        let mut read = 0;
        loop {
            if let Some(at) = find(&self.pending, b"\r\n") {
                let empty = at == 0;
                self.pending.drain(..at + 2);
                read += at + 2;
                if empty {
                    return Ok(());
                }
                continue;
            }
            if read + self.pending.len() > MAX_HEAD {
                return Err(WireError::Malformed("trailer section is too large"));
            }
            if !self.fill()? {
                return Err(WireError::Malformed("truncated chunked body"));
            }
        }
    }
}

/// `true` for a chunked body, `false` without `Transfer-Encoding`.
fn chunked(headers: &http::HeaderMap) -> Result<bool, WireError> {
    let mut codings = Vec::new();
    for value in headers.get_all("transfer-encoding") {
        let value = value
            .to_str()
            .map_err(|_| WireError::Malformed("invalid Transfer-Encoding"))?;
        codings.extend(
            value
                .split(',')
                .map(|coding| coding.trim().to_ascii_lowercase()),
        );
    }
    codings.retain(|coding| !coding.is_empty());
    match codings.as_slice() {
        [] => Ok(false),
        [only] if only == "chunked" => Ok(true),
        _ => Err(WireError::Malformed("unsupported Transfer-Encoding")),
    }
}

fn content_length(headers: &http::HeaderMap) -> Result<Option<usize>, WireError> {
    let mut length = None;
    for value in headers.get_all("content-length") {
        let value = value
            .to_str()
            .map_err(|_| WireError::Malformed("invalid Content-Length"))?;
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() || !item.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(WireError::Malformed("invalid Content-Length"));
            }
            let parsed: usize = item.parse().map_err(|_| WireError::TooLarge)?;
            if length.is_some_and(|seen| seen != parsed) {
                return Err(WireError::Malformed("conflicting Content-Length"));
            }
            length = Some(parsed);
        }
    }
    Ok(length)
}

fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{WireError, read_response};

    fn read(wire: &[u8], limit: usize) -> Result<http::Response<Vec<u8>>, WireError> {
        read_response(&mut &wire[..], limit)
    }

    #[test]
    fn bodies_are_framed_by_length_chunks_or_close_and_bounded() {
        let length = read(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra", 16).unwrap();
        assert_eq!(length.body(), b"{}");
        let chunked = read(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\n{\"a\r\n4\r\n\":1}\r\n0\r\nTrailer: t\r\n\r\n",
            16,
        )
        .unwrap();
        assert_eq!(chunked.body(), br#"{"a":1}"#);
        let closed = read(b"HTTP/1.1 200 OK\r\n\r\n[1,2]", 16).unwrap();
        assert_eq!(closed.body(), b"[1,2]");
        for oversized in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n11\r\n"[..],
            &b"HTTP/1.1 200 OK\r\n\r\n01234567890123456"[..],
        ] {
            assert!(matches!(read(oversized, 16), Err(WireError::TooLarge)));
        }
        for malformed in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}"[..],
        ] {
            assert!(matches!(read(malformed, 16), Err(WireError::Malformed(_))));
        }
    }
}
