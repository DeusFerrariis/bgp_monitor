use bytes::{Buf, BufMut, Bytes, BytesMut};
// Added Buf and BufMut
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeaderParseError {
    #[error("Input length {0} is shorter than {1}")]
    InputLengthOutOfRange(usize, usize),
    #[error("BGP marker field is malformed, expected all ones")]
    MalformedMarkerField,
    #[error("BGP length field out of range {min:?} - {max:?}. Got {actual:?}")]
    LengthFieldOutOfRange {
        min: usize,
        max: usize,
        actual: usize,
    },
}

#[derive(Error, Debug)]
pub enum BgpHeaderError {
    #[error("BGP length field out of range {min:?} - {max:?}. Got {actual:?}")]
    LengthFieldOutOfRange {
        min: usize,
        max: usize,
        actual: usize,
    },
}

#[repr(u8)]
#[derive(PartialEq, Eq, Debug)]
pub enum BgpMessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    // Represents unknown or future message types
    Unknown(u8),
}

#[derive(PartialEq, Eq, Debug)]
pub struct BgpHeader {
    pub marker: [u8; 16],
    pub length: u16,
    pub message_type: BgpMessageType,
}

impl From<u8> for BgpMessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => BgpMessageType::Open,
            2 => BgpMessageType::Update,
            3 => BgpMessageType::Notification,
            4 => BgpMessageType::Keepalive,
            _ => BgpMessageType::Unknown(value),
        }
    }
}

impl From<&BgpMessageType> for u8 {
    fn from(msg_type: &BgpMessageType) -> Self {
        match msg_type {
            &BgpMessageType::Open => 1,
            &BgpMessageType::Update => 2,
            &BgpMessageType::Notification => 3,
            &BgpMessageType::Keepalive => 4,
            &BgpMessageType::Unknown(value) => value,
        }
    }
}

impl BgpHeader {
    pub const MIN_LEN: u16 = 19;
    pub const MAX_LEN: u16 = 4096;
    pub const MARKER_VALUE: [u8; 16] = [0xFF; 16];

    pub fn new(length: u16, message_type: BgpMessageType) -> Result<Self, BgpHeaderError> {
        if length < Self::MIN_LEN || length > Self::MAX_LEN {
            return Err(BgpHeaderError::LengthFieldOutOfRange {
                min: Self::MIN_LEN as usize,
                max: Self::MAX_LEN as usize,
                actual: length as usize,
            });
        }

        Ok(BgpHeader {
            marker: Self::MARKER_VALUE,
            length,
            message_type,
        })
    }

    /// Parses BgpHeader from byte slice
    pub fn try_from_bytes(input: &mut Bytes) -> Result<Self, HeaderParseError> {
        if input.len() < Self::MIN_LEN as usize {
            return Err(HeaderParseError::InputLengthOutOfRange(
                Self::MIN_LEN as usize,
                input.len(),
            ));
        }

        // Validate marker
        let mut marker = [0u8; 16];
        let bytes = input.copy_to_bytes(16);
        marker.copy_from_slice(&bytes[..]);

        if marker != Self::MARKER_VALUE {
            return Err(HeaderParseError::MalformedMarkerField);
        }

        // Get length of message (big endian ordering)
        let length = input.get_u16();
        if length < Self::MIN_LEN || length > Self::MAX_LEN {
            return Err(HeaderParseError::LengthFieldOutOfRange {
                min: Self::MIN_LEN as usize,
                max: Self::MAX_LEN as usize,
                actual: length as usize,
            });
        }

        let message_type: BgpMessageType = input.get_u8().into();

        Ok(BgpHeader {
            marker,
            length,
            message_type,
        })
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(Self::MIN_LEN as usize);

        buffer.put_slice(&self.marker);
        buffer.put_u16(self.length);
        buffer.put_u8((&self.message_type).into());

        buffer.freeze()
    }
}
