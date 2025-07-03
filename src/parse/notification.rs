use bytes::{Buf, Bytes};

pub struct NotificationMessage {
    error_codes: NotificationErrorCode,
    data: Vec<u8>,
}

pub enum NotificationErrorCode {
    Header(HeaderSubErr),
    OpenMessage(OpenMessageSubErr),
    UpdateMessage(UpdateMessageSubErr),
    HoldTimeExpired,
    FiniteStateMachine,
    Cease,
    Unknown(u8, u8),
}

#[repr(u8)]
pub enum HeaderSubErr {
    ConnectionNotSyncronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
}

#[repr(u8)]
pub enum OpenMessageSubErr {
    UnsupportedVersionNumber = 1,
    BadPeerAS = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    AuthenticationFailure = 5,
    UnacceptableHoldTime = 6,
}

#[repr(u8)]
pub enum UpdateMessageSubErr {
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    ASRoutingLoop = 7,
    InvalidNextHopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedAsPath = 11,
}

impl NotificationMessage {
    const MIN_LEN: usize = 21;

    fn try_decode(data: &mut Bytes) -> Result<Self, String> {
        if data.len() < Self::MIN_LEN {
            return Err("Insufficient data for notification message".to_string());
        }

        let err_code = data.get_u8();
        let err_sub_code = data.get_u8();

        let notification_err_code = match err_code {
            1 => NotificationErrorCode::Header(HeaderSubErr::try_from(err_sub_code)?),
            2 => NotificationErrorCode::OpenMessage(OpenMessageSubErr::try_from(err_sub_code)?),
            3 => NotificationErrorCode::UpdateMessage(UpdateMessageSubErr::try_from(err_sub_code)?),
            4 => NotificationErrorCode::HoldTimeExpired,
            5 => NotificationErrorCode::FiniteStateMachine,
            6 => NotificationErrorCode::Cease,
            _ => NotificationErrorCode::Unknown(err_code, err_sub_code),
        };

        todo!()
    }
}

impl TryFrom<u8> for HeaderSubErr {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::ConnectionNotSyncronized),
            2 => Ok(Self::BadMessageLength),
            3 => Ok(Self::BadMessageType),
            _ => Err(format!("Unknown header sub error code {}", value)),
        }
    }
}

impl TryFrom<u8> for OpenMessageSubErr {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UnsupportedVersionNumber),
            2 => Ok(Self::BadPeerAS),
            3 => Ok(Self::BadBgpIdentifier),
            4 => Ok(Self::UnsupportedOptionalParameter),
            5 => Ok(Self::AuthenticationFailure),
            6 => Ok(Self::UnacceptableHoldTime),
            _ => Err(format!("Unknown OPEN message error code {}", value)),
        }
    }
}

impl TryFrom<u8> for UpdateMessageSubErr {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::MalformedAttributeList),
            2 => Ok(Self::UnrecognizedWellKnownAttribute),
            3 => Ok(Self::MissingWellKnownAttribute),
            4 => Ok(Self::AttributeFlagsError),
            5 => Ok(Self::AttributeLengthError),
            6 => Ok(Self::InvalidOriginAttribute),
            7 => Ok(Self::ASRoutingLoop),
            8 => Ok(Self::InvalidNextHopAttribute),
            9 => Ok(Self::OptionalAttributeError),
            10 => Ok(Self::InvalidNetworkField),
            11 => Ok(Self::MalformedAsPath),
            _ => Err(format!("Unknown UPDATE message error code: {}", value)),
        }
    }
}
