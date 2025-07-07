use super::error::{Error as BgpError, ErrorKind};
use std::{env::VarError, net::Ipv4Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, PartialEq)]
pub struct PathAttribute {
    pub flags: PathAttributeFlags,
    pub type_code: AttributeType,
    pub value: AttributeValue,
}

#[derive(Debug, PartialEq)]
pub struct PathAttributeFlags {
    pub optional: bool,
    pub transitive: bool,
    pub partial: bool,
    pub extended_length: bool,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum AttributeType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExitDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Communities = 8,
    Unknown(u8),
}

#[derive(Debug, PartialEq)]
pub enum AttributeValue {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(NextHop),
    MultiExitDisc(MultiExitDisc),
    LocalPref(LocalPref),
    AtomicAggregate, // This attribute has no value
    Aggregator(Aggregator),
    Communities(Communities),
    Unknown(Bytes),
}

// --- Attribute Value Structs ---

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum OriginType {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

#[derive(Debug, PartialEq)]
pub struct Origin {
    pub origin_type: OriginType,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

#[derive(Debug, PartialEq)]
pub struct AsPathSegment {
    pub segment_type: AsPathSegmentType,
    pub asns: Vec<u32>,
}

#[derive(Debug, PartialEq)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

#[derive(Debug, PartialEq)]
pub struct NextHop {
    pub ip: Ipv4Addr,
}

#[derive(Debug, PartialEq)]
pub struct MultiExitDisc {
    pub med: u32,
}

#[derive(Debug, PartialEq)]
pub struct LocalPref {
    pub pref: u32,
}

#[derive(Debug, PartialEq)]
pub struct Aggregator {
    pub asn: u32,
    pub ip: Ipv4Addr,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Community {
    pub asn: u16,
    pub value: u16,
}

#[derive(Debug, PartialEq)]
pub struct Communities {
    pub communities: Vec<Community>,
}

impl From<u8> for AttributeType {
    fn from(value: u8) -> Self {
        match value {
            1 => AttributeType::Origin,
            2 => AttributeType::AsPath,
            3 => AttributeType::NextHop,
            4 => AttributeType::MultiExitDisc,
            5 => AttributeType::LocalPref,
            6 => AttributeType::AtomicAggregate,
            7 => AttributeType::Aggregator,
            8 => AttributeType::Communities,
            _ => AttributeType::Unknown(value),
        }
    }
}

impl PathAttribute {
    pub fn try_decode(data: &mut Bytes) -> Result<Self, BgpError> {
        let c_data = data.clone().to_owned();

        let flags_byte = data.get_u8();
        // Parse flag bits
        let flags = PathAttributeFlags {
            optional: (flags_byte & 0x80) != 0, // bit at pos -> boolean
            transitive: (flags_byte & 0x40) != 0,
            partial: (flags_byte & 0x20) != 0,
            extended_length: (flags_byte & 0x10) != 0,
        };

        let type_code_byte = data.get_u8();
        let attr_type = AttributeType::from(type_code_byte);

        let length = if flags.extended_length {
            if data.len() < 2 {
                return Err(ErrorKind::AttributeLengthErr.with_bytes(c_data));
            }
            data.get_u16() as usize
        } else {
            if data.len() < 1 {
                return Err(ErrorKind::AttributeLengthErr.with_bytes(c_data));
            }
            data.get_u8() as usize
        };

        if data.len() < length {
            return Err(ErrorKind::AttributeLengthErr.with_bytes(c_data));
        }

        let mut value_data = data.copy_to_bytes(length);

        let value = AttributeValue::try_decode(&attr_type, &mut value_data)
            .map_err(|err: ErrorKind| err.with_bytes(c_data))?;

        Ok(PathAttribute {
            flags,
            type_code: attr_type,
            value,
        })
    }
}

impl AttributeValue {
    pub fn try_decode(
        type_code: &AttributeType,
        value_data: &mut Bytes,
    ) -> Result<Self, ErrorKind> {
        match type_code {
            &AttributeType::Origin => Ok(AttributeValue::Origin(Origin::try_decode(value_data)?)),
            &AttributeType::AsPath => Ok(AttributeValue::AsPath(AsPath::try_decode(value_data)?)),
            &AttributeType::NextHop => {
                Ok(AttributeValue::NextHop(NextHop::try_decode(value_data)?))
            }
            &AttributeType::MultiExitDisc => Ok(AttributeValue::MultiExitDisc(
                MultiExitDisc::try_decode(value_data)?,
            )),
            &AttributeType::LocalPref => Ok(AttributeValue::LocalPref(LocalPref::try_decode(
                value_data,
            )?)),
            &AttributeType::AtomicAggregate => {
                if value_data.len() > 0 {
                    return Err(ErrorKind::AttributeLengthErr);
                }
                Ok(AttributeValue::AtomicAggregate)
            }
            &AttributeType::Aggregator => Ok(AttributeValue::Aggregator(Aggregator::try_decode(
                value_data,
            )?)),
            &AttributeType::Communities => Ok(AttributeValue::Communities(
                Communities::try_decode(value_data)?,
            )),
            _ => Ok(AttributeValue::Unknown(value_data.clone())),
        }
    }
}

impl Origin {
    const TYPE_CODE: u8 = 1;

    fn try_decode(data: &mut Bytes) -> Result<Self, ErrorKind> {
        let origin_val = data.get_u8();
        let origin_type = match origin_val {
            0 => OriginType::Igp,
            1 => OriginType::Egp,
            2 => OriginType::Incomplete,
            _ => return Err(ErrorKind::InvalidOrigin),
        };

        Ok(Origin { origin_type })
    }
}

impl AsPath {
    const TYPE_CODE: u8 = 2;
    const MIN_LEN: u8 = 4;

    fn try_decode(data: &mut Bytes) -> Result<Self, ErrorKind> {
        let mut segments = Vec::new();

        while !data.is_empty() {
            let seg_type_val = data.get_u8();
            let seg_type = match seg_type_val {
                1 => AsPathSegmentType::AsSet,
                2 => AsPathSegmentType::AsSequence,
                _ => return Err(ErrorKind::MalformedAsPath),
            };

            // TODO: add neogtiation for ASN size
            // count is quantity of 4 octet ASNs
            let count = data.get_u8() as usize;
            let asn_byte_len = count * 4;
            if data.len() < asn_byte_len {
                return Err(ErrorKind::MalformedAsPath);
            }

            let mut asns = Vec::with_capacity(count);
            for _ in 0..count {
                asns.push(data.get_u32());
            }

            segments.push(AsPathSegment {
                segment_type: seg_type,
                asns,
            });
        }

        Ok(AsPath { segments })
    }
}

impl NextHop {
    const TYPE_CODE: u8 = 3;

    fn try_decode(data: &mut Bytes) -> Result<Self, ErrorKind> {
        // TODO: add support for ipv6
        if data.len() < 4 {
            return Err(ErrorKind::AttributeLengthErr);
        }

        Ok(NextHop {
            ip: Ipv4Addr::from_bits(data.get_u32()),
        })
    }
}

impl MultiExitDisc {
    const TYPE_CODE: u8 = 4;

    fn try_decode(data: &mut Bytes) -> Result<Self, ErrorKind> {
        if data.len() != 4 {
            return Err(ErrorKind::AttributeLengthErr);
        }

        Ok(MultiExitDisc {
            med: data.get_u32(),
        })
    }
}

impl LocalPref {
    const TYPE_CODE: u8 = 5;

    fn try_decode(data: &mut Bytes) -> Result<Self, ErrorKind> {
        if data.len() < 4 {
            return Err(ErrorKind::AttributeLengthErr);
        }

        Ok(LocalPref {
            pref: data.get_u32(),
        })
    }
}

impl Aggregator {
    const TYPE_CODE: u8 = 7;

    fn try_decode(data: &mut Bytes) -> Result<Self, ErrorKind> {
        // 2 oct asn + 4 digit ipv4 addr

        let asn = match data.len() {
            8 => data.get_u32(),
            6 => data.get_u16() as u32,
            _ => return Err(ErrorKind::AttributeLengthErr),
        };

        let ip = Ipv4Addr::from_bits(data.get_u32());

        Ok(Aggregator { asn, ip })
    }
}

impl Communities {
    const TYPE_CODE: u8 = 8;

    fn try_decode(data: &mut Bytes) -> Result<Self, ErrorKind> {
        if data.len() % 4 != 0 {
            return Err(ErrorKind::OptionalAttributeError);
        }

        let mut communities = Vec::with_capacity(data.len() / 4);
        while !data.is_empty() {
            communities.push(Community {
                asn: data.get_u16(),
                value: data.get_u16(),
            });
        }

        Ok(Communities { communities })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_decode_origin() {
        let mut data = Bytes::from_static(&[0x40, 0x01, 0x01, 0x00]); // Flags, Type, Length, Value (IGP)
        let attr = PathAttribute::try_decode(&mut data).unwrap();
        assert_eq!(attr.flags.transitive, true);
        assert_eq!(attr.flags.optional, false);
        assert_eq!(attr.type_code, AttributeType::Origin);
        assert_eq!(
            attr.value,
            AttributeValue::Origin(Origin {
                origin_type: OriginType::Igp
            })
        );
    }

    #[test]
    fn test_decode_as_path() {
        // AS_SEQUENCE with two 4-byte ASNs
        let mut data = Bytes::from_static(&[
            0x40, 0x02, 0x0A, // Flags, Type, Length (10)
            0x02, 0x02, // Segment Type (SEQ), Count (2)
            0x00, 0x01, 0x00, 0x01, // 65537
            0x00, 0x01, 0x00, 0x02, // 65538
        ]);
        let attr = PathAttribute::try_decode(&mut data).unwrap();
        assert_eq!(attr.type_code, AttributeType::AsPath);
        match attr.value {
            AttributeValue::AsPath(as_path) => {
                assert_eq!(as_path.segments.len(), 1);
                assert_eq!(
                    as_path.segments[0].segment_type,
                    AsPathSegmentType::AsSequence
                );
                assert_eq!(as_path.segments[0].asns, vec![65537, 65538]);
            }
            _ => panic!("Incorrect attribute value type"),
        }
    }

    #[test]
    fn test_decode_next_hop() {
        let mut data = Bytes::from_static(&[0x40, 0x03, 0x04, 192, 168, 1, 1]);
        let attr = PathAttribute::try_decode(&mut data).unwrap();
        assert_eq!(attr.type_code, AttributeType::NextHop);
        assert_eq!(
            attr.value,
            AttributeValue::NextHop(NextHop {
                ip: Ipv4Addr::new(192, 168, 1, 1)
            })
        );
    }

    #[test]
    fn test_decode_med() {
        let mut data = Bytes::from_static(&[0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x64]); // MED 100
        let attr = PathAttribute::try_decode(&mut data).unwrap();
        assert_eq!(attr.flags.optional, true);
        assert_eq!(attr.type_code, AttributeType::MultiExitDisc);
        assert_eq!(
            attr.value,
            AttributeValue::MultiExitDisc(MultiExitDisc { med: 100 })
        );
    }

    #[test]
    fn test_decode_atomic_aggregate() {
        // Note: Length is 0
        let mut data = Bytes::from_static(&[0x40, 0x06, 0x00]);
        let attr = PathAttribute::try_decode(&mut data).unwrap();
        assert_eq!(attr.type_code, AttributeType::AtomicAggregate);
        assert_eq!(attr.value, AttributeValue::AtomicAggregate);
    }

    #[test]
    fn test_decode_aggregator_4_byte_asn() {
        // 4-byte ASN, so length is 8
        let mut data = Bytes::from_static(&[
            0xC0, 0x07, 0x08, // Flags (Optional, Transitive), Type, Length
            0x00, 0x01, 0x00, 0x01, // ASN 65537
            10, 20, 30, 40, // IP
        ]);
        let attr = PathAttribute::try_decode(&mut data).unwrap();
        assert_eq!(attr.type_code, AttributeType::Aggregator);
        assert_eq!(
            attr.value,
            AttributeValue::Aggregator(Aggregator {
                asn: 65537,
                ip: Ipv4Addr::new(10, 20, 30, 40)
            })
        );
    }

    #[test]
    fn test_decode_communities() {
        // Two communities: NO_EXPORT (65535:65281) and NO_ADVERTISE (65535:65282)
        let mut data = Bytes::from_static(&[
            0xC0, 0x08, 0x08, // Flags, Type, Length
            0xFF, 0xFF, 0xFF, 0x01, // NO_EXPORT (FFFF:FF01)
            0xFF, 0xFF, 0xFF, 0x02, // NO_ADVERTISE (FFFF:FF02)
        ]);
        let attr = PathAttribute::try_decode(&mut data).unwrap();
        assert_eq!(attr.flags.optional, true);
        assert_eq!(attr.flags.transitive, true);
        assert_eq!(attr.type_code, AttributeType::Communities);
        assert_eq!(
            attr.value,
            AttributeValue::Communities(Communities {
                communities: vec![
                    Community {
                        asn: 65535,
                        value: 65281
                    },
                    Community {
                        asn: 65535,
                        value: 65282
                    },
                ]
            })
        );
    }

    #[test]
    fn test_decode_extended_length() {
        // Create a dummy attribute with a value > 255 bytes to test extended length
        let mut raw_data = vec![0x50, 0x99, 0x01, 0x05]; // Flags (Ext Length), Type (Unknown 153), Length (261)
        raw_data.extend_from_slice(&[0; 261]);
        let mut data = Bytes::from(raw_data);

        let attr = PathAttribute::try_decode(&mut data).unwrap();
        assert_eq!(attr.flags.extended_length, true);
        assert_eq!(attr.type_code, AttributeType::Unknown(153));
        match attr.value {
            AttributeValue::Unknown(val) => assert_eq!(val.len(), 261),
            _ => panic!("Incorrect attribute value type"),
        }
    }

    #[test]
    fn test_error_insufficient_data() {
        let mut data = Bytes::from_static(&[0x40, 0x01]); // Header only, no length or value
        let result = PathAttribute::try_decode(&mut data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ErrorKind::AttributeLengthErr);
    }
}
