use bytes::{Buf, Bytes};

use crate::attribute::PathAttribute;
use crate::error::{Error as BgpError, ErrorKind};

pub struct UpdateMessage {
    pub withdrawn_routes: Vec<IpAddrPrefix>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<IpAddrPrefix>,
}

#[derive(Debug, PartialEq)]
pub struct IpAddrPrefix {
    length: u8,
    prefix: Vec<u8>, // TODO: replace with ip addr
}

impl UpdateMessage {
    pub fn try_decode(data: &mut Bytes) -> Result<Self, BgpError> {
        let c_data = data.clone().to_owned();
        if data.len() < 2 {
            return Err(ErrorKind::BadMessageLength.with_bytes(c_data));
        }

        let withdrawn_len = data.get_u16() as usize;

        let withdrawn_routes = if withdrawn_len != 0 {
            if data.len() < withdrawn_len {
                return Err(ErrorKind::MalformedAttributeList.as_err());
            }
            let mut withdrawn_data = data.copy_to_bytes(withdrawn_len);
            IpAddrPrefix::decode_stream(&mut withdrawn_data, 4)?
        } else {
            vec![]
        };

        if data.len() < 2 {
            return Err(ErrorKind::MalformedAttributeList.as_err());
        }
        let attributes_len = data.get_u16() as usize;
        if data.len() < attributes_len {
            return Err(ErrorKind::MalformedAttributeList.as_err());
        }

        let mut attributes_data = data.copy_to_bytes(attributes_len);
        let mut path_attributes = Vec::new();

        while !attributes_data.is_empty() {
            let attr = PathAttribute::try_decode(&mut attributes_data)?;
            path_attributes.push(attr);
        }

        let nlri = IpAddrPrefix::decode_stream(data, 4)?; // NOTE: assumes ipv4

        Ok(UpdateMessage {
            withdrawn_routes,
            path_attributes,
            nlri,
        })
    }
}

impl IpAddrPrefix {
    /// Decodes a stream of prefixes (for NLRI or Withdrawn Routes).
    fn decode_stream(data: &mut Bytes, addr_len: u8) -> Result<Vec<Self>, BgpError> {
        let invalid_network_field_err =
            ErrorKind::InvalidNetworkField.with_bytes(data.clone().to_owned());
        let mut prefixes = Vec::new();
        while !data.is_empty() {
            if data.len() < 1 {
                return Err(invalid_network_field_err);
            }
            let bit_len = data.get_u8();
            let byte_len = (bit_len as usize + 7) / 8;

            if data.len() < byte_len {
                return Err(invalid_network_field_err);
            }
            if bit_len > addr_len * 8 {
                return Err(invalid_network_field_err);
            }

            let mut prefix_bytes = data.copy_to_bytes(byte_len).to_vec();
            prefix_bytes.resize(addr_len as usize, 0);

            let rem = bit_len % 8;
            if rem != 0 {
                if let Some(last_byte) = prefix_bytes.get_mut(byte_len - 1) {
                    let mask = 0xff_u8 << (8 - rem);
                    *last_byte &= mask;
                }
            }

            prefixes.push(IpAddrPrefix {
                length: bit_len,
                prefix: prefix_bytes,
            });
        }
        Ok(prefixes)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attribute::*;
    use std::net::Ipv4Addr;

    use bytes::Bytes;

    #[test]
    fn test_full_update_message() {
        // Construct a realistic BGP UPDATE message payload
        let mut raw_data = vec![];
        // 1. Withdrawn Routes (length = 5 bytes)
        // Withdraw 10.0.0.0/8
        raw_data.extend_from_slice(&[0x00, 0x05]); // Length of withdrawn routes
        raw_data.extend_from_slice(&[0x08, 10]); // 8-bit prefix 10.x.x.x
        // Withdraw 192.168.0.0/16
        raw_data.extend_from_slice(&[0x10, 192, 168]); // 16-bit prefix 192.168.x.x

        // 2. Path Attributes (length = 25 bytes)
        raw_data.extend_from_slice(&[0x00, 0x1B]); // Total path attributes length
        // ORIGIN (IGP)
        raw_data.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
        // AS_PATH (AS_SEQUENCE: 65537)
        raw_data.extend_from_slice(&[0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01]);
        // NEXT_HOP (1.2.3.4)
        raw_data.extend_from_slice(&[0x40, 0x03, 0x04, 1, 2, 3, 4]);
        // LOCAL_PREF (100)
        raw_data.extend_from_slice(&[0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64]);

        // 3. NLRI
        // Announce 172.16.0.0/16
        raw_data.extend_from_slice(&[0x10, 172, 16]);

        let mut data = Bytes::from(raw_data);
        let msg = UpdateMessage::try_decode(&mut data).unwrap();

        // Verify Withdrawn Routes
        assert_eq!(msg.withdrawn_routes.len(), 2);
        assert_eq!(msg.withdrawn_routes[0].length, 8);
        assert_eq!(msg.withdrawn_routes[0].prefix, vec![10, 0, 0, 0]);
        assert_eq!(msg.withdrawn_routes[1].length, 16);
        assert_eq!(msg.withdrawn_routes[1].prefix, vec![192, 168, 0, 0]);

        // Verify Path Attributes
        assert_eq!(msg.path_attributes.len(), 4);
        assert_eq!(msg.path_attributes[0].type_code, AttributeType::Origin);
        assert_eq!(msg.path_attributes[1].type_code, AttributeType::AsPath);
        assert_eq!(msg.path_attributes[2].type_code, AttributeType::NextHop);
        assert_eq!(msg.path_attributes[3].type_code, AttributeType::LocalPref);
        match &msg.path_attributes[2].value {
            AttributeValue::NextHop(nh) => assert_eq!(nh.ip, Ipv4Addr::new(1, 2, 3, 4)),
            _ => panic!("Wrong attribute type"),
        }

        // Verify NLRI
        assert_eq!(msg.nlri.len(), 1);
        assert_eq!(msg.nlri[0].length, 16);
        assert_eq!(msg.nlri[0].prefix, vec![172, 16, 0, 0]);

        // Ensure the buffer is fully consumed
        assert!(data.is_empty());
    }

    #[test]
    fn test_update_no_withdrawn() {
        let mut raw_data = vec![];
        // 1. Withdrawn Routes (length = 0)
        raw_data.extend_from_slice(&[0x00, 0x00]);
        // 2. Path Attributes (length = 5)
        raw_data.extend_from_slice(&[0x00, 0x04]);
        raw_data.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]); // ORIGIN
        // 3. NLRI
        raw_data.extend_from_slice(&[0x10, 172, 16]);

        let mut data = Bytes::from(raw_data);
        let msg = UpdateMessage::try_decode(&mut data).unwrap();

        assert!(msg.withdrawn_routes.is_empty());
        assert_eq!(msg.path_attributes.len(), 1);
        assert_eq!(msg.nlri.len(), 1);
    }

    #[test]
    fn test_update_no_nlri() {
        let mut raw_data = vec![];
        // 1. Withdrawn Routes (length = 3)
        raw_data.extend_from_slice(&[0x00, 0x03]);
        raw_data.extend_from_slice(&[0x10, 192, 168]);
        // 2. Path Attributes (length = 0)
        raw_data.extend_from_slice(&[0x00, 0x00]);
        // 3. No NLRI bytes follow

        let mut data = Bytes::from(raw_data);
        let msg = UpdateMessage::try_decode(&mut data).unwrap();

        assert_eq!(msg.withdrawn_routes.len(), 1);
        assert!(msg.path_attributes.is_empty());
        assert!(msg.nlri.is_empty());
    }
}
