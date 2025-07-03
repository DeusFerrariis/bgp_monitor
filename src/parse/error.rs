use bytes::{BufMut, Bytes, BytesMut};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ErrorKind {
    BadMessageLength,
    MalformedAttributeList,
    AttributeLengthErr,
    InvalidOrigin,
    MalformedAsPath,
    OptionalAttributeError,
    InvalidNetworkField,
    Other,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Error {
    pub kind: ErrorKind,
    pub data: Option<Bytes>,
}

impl ErrorKind {
    pub fn with_bytes(&self, bytes: Bytes) -> Error {
        let data = match self {
            ErrorKind::AttributeLengthErr => Some(bytes),
            ErrorKind::MalformedAsPath => Some(bytes),
            ErrorKind::InvalidOrigin => Some(bytes),
            ErrorKind::OptionalAttributeError => Some(bytes),
            _ => None,
        };

        Error {
            kind: self.clone(),
            data,
        }
    }

    pub fn as_err(&self) -> Error {
        Error {
            kind: self.clone(),
            data: None,
        }
    }
}
