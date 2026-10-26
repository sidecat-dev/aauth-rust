use std::fmt;

/// An R3 grammar or set-algebra failure.
#[derive(Debug)]
pub struct Error {
    message: String,
    source: Option<Box<Error>>,
}

impl Error {
    /// Build an error that has no underlying cause.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Build an error whose display text includes `source`.
    pub fn wrap(message: impl Into<String>, source: Self) -> Self {
        let message = format!("{}: {source}", message.into());
        Self {
            message,
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|err| err.as_ref() as &(dyn std::error::Error + 'static))
    }
}
