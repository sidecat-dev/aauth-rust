use std::collections::BTreeMap;

/// Opaque details from one valid Payment HTTP authentication challenge.
/// Parsing does not admit a payment method or authorize settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentChallenge {
    /// Nonempty bill identifier supplied by the payment challenge.
    pub id: String,
    /// Optional payment method; the host owns admission and execution.
    pub method: Option<String>,
    /// Optional amount string; no arithmetic or currency conversion is applied.
    pub amount: Option<String>,
    /// Optional currency string supplied by the remote policy.
    pub currency: Option<String>,
}

/// Malformed, missing or ambiguous Payment HTTP authentication challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid or ambiguous Payment authentication challenge")]
pub struct PaymentChallengeError;

pub(super) fn parse(authenticate: &str) -> Result<PaymentChallenge, PaymentChallengeError> {
    if authenticate.is_empty() || authenticate.len() > 65536 {
        return Err(PaymentChallengeError);
    }
    let mut parser = AuthParser {
        input: authenticate.as_bytes(),
        position: 0,
    };
    let mut payment = None;
    loop {
        parser.list_separators();
        if parser.peek().is_none() {
            break;
        }
        let is_payment = parser.token()?.eq_ignore_ascii_case("Payment");
        let mut params = BTreeMap::new();
        let after_scheme = parser.position;
        parser.whitespace();
        if !matches!(parser.peek(), None | Some(b',')) {
            parser.position = after_scheme;
            // RFC 9110 section 11.3 requires SP between scheme and credentials.
            if !parser.take(b' ') {
                return Err(PaymentChallengeError);
            }
            parser.whitespace();
            if !matches!(parser.peek(), None | Some(b',')) && !parser.token68() {
                params = parser.parameters()?;
            }
        }
        if is_payment {
            if payment.is_some() {
                return Err(PaymentChallengeError);
            }
            payment = Some(PaymentChallenge {
                id: params
                    .remove("id")
                    .filter(|id| !id.is_empty())
                    .ok_or(PaymentChallengeError)?,
                method: params.remove("method"),
                amount: params.remove("amount"),
                currency: params.remove("currency"),
            });
        }
        parser.whitespace();
        if !matches!(parser.peek(), None | Some(b',')) {
            return Err(PaymentChallengeError);
        }
    }
    payment.ok_or(PaymentChallengeError)
}

struct AuthParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl AuthParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.position += 1;
        }
    }

    fn list_separators(&mut self) {
        self.whitespace();
        // RFC 9110 section 5.6.1 permits recipients to ignore empty list items.
        while self.take(b',') {
            self.whitespace();
        }
    }

    fn token(&mut self) -> Result<&str, PaymentChallengeError> {
        let start = self.position;
        while self.peek().is_some_and(is_token) {
            self.position += 1;
        }
        if self.position == start {
            return Err(PaymentChallengeError);
        }
        std::str::from_utf8(&self.input[start..self.position]).map_err(|_| PaymentChallengeError)
    }

    fn token68(&mut self) -> bool {
        let start = self.position;
        while self.peek().is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        }) {
            self.position += 1;
        }
        let nonempty = self.position > start;
        while self.take(b'=') {}
        self.whitespace();
        if nonempty && matches!(self.peek(), None | Some(b',')) {
            true
        } else {
            self.position = start;
            false
        }
    }

    fn parameters(&mut self) -> Result<BTreeMap<String, String>, PaymentChallengeError> {
        let mut params = BTreeMap::new();
        loop {
            let name = self.token()?.to_ascii_lowercase();
            self.whitespace();
            if !self.take(b'=') {
                return Err(PaymentChallengeError);
            }
            self.whitespace();
            let value = if self.take(b'"') {
                self.quoted_string()?
            } else {
                self.token()?.to_owned()
            };
            if params.insert(name, value).is_some() {
                return Err(PaymentChallengeError);
            }
            self.whitespace();
            if self.peek() != Some(b',') {
                break;
            }
            let separator = self.position;
            self.list_separators();
            if self.peek().is_none() {
                break;
            }
            let next = self.position;
            self.token()?;
            self.whitespace();
            if self.peek() == Some(b'=') {
                self.position = next;
            } else {
                self.position = separator;
                break;
            }
        }
        Ok(params)
    }

    fn quoted_string(&mut self) -> Result<String, PaymentChallengeError> {
        let mut value = Vec::new();
        loop {
            let byte = self.peek().ok_or(PaymentChallengeError)?;
            self.position += 1;
            match byte {
                b'"' => return String::from_utf8(value).map_err(|_| PaymentChallengeError),
                b'\\' => {
                    let escaped = self.peek().ok_or(PaymentChallengeError)?;
                    if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                        return Err(PaymentChallengeError);
                    }
                    value.push(escaped);
                    self.position += 1;
                }
                b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => {
                    value.push(byte);
                }
                _ => return Err(PaymentChallengeError),
            }
        }
    }
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
