use std::error;
use std::fmt;
use std::io;

/// All crate errors are wrapped in this custom error type
#[derive(Debug)]
pub struct Error {
    original: Option<Box<dyn error::Error>>,
    msg: String,
}

impl Error {
    pub(crate) fn new<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            original: None,
            msg: msg.into(),
        }
    }

    pub(crate) fn with_source<S, E>(msg: S, source: E) -> Self
    where
        S: Into<String>,
        E: error::Error + 'static,
    {
        Self {
            original: Some(Box::new(source)),
            msg: msg.into(),
        }
    }

    pub(crate) fn bail<T, S>(msg: S) -> Result<T, Self>
    where
        S: Into<String>,
    {
        Err(Error::new(msg))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        let msg = error.to_string();
        Self {
            original: Some(Box::new(error)),
            msg,
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.original.as_ref().map(|o| o.as_ref())
    }
}
