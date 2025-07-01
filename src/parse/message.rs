use std::net::Ipv4Addr;

use bytes::{Buf, Bytes};

use super::header::BgpHeader;

pub trait Validate<E: std::error::Error> {
    fn validate(&self) -> Option<E>;
}

pub enum BgpBody {
    Open(BgpHeader, OpenMessage),
}

pub struct OpenMessage {
    version: u8,
    my_autonomous_system: u16,
    hold_time: u16,
    bgp_id: Ipv4Addr,
    optional_params: Vec<OptionalParam>,
}

pub struct OptionalParam {
    param_type: u8,
    param_value: Vec<u8>,
}

struct OptionalParamVec(Vec<OptionalParam>);

impl TryFrom<&mut Bytes> for OpenMessage {
    type Error = String;

    fn try_from(value: &mut Bytes) -> Result<Self, Self::Error> {
        let version = value.get_u8();
        let my_autonomous_system = value.get_u16();
        let hold_time = value.get_u16();
        let bgp_id = value.get_u32();

        let optional_params_len = value.get_u8();

        let mut params_bytes = value.split_to(optional_params_len as usize);
        if optional_params_len as usize > params_bytes.len() {
            return Err(format!(
                "Optional parameters length {} is shorter than specified {}",
                params_bytes.len(),
                optional_params_len
            ));
        }

        let optional_params = OptionalParamVec::try_from(&mut params_bytes)?.0;

        Ok(OpenMessage {
            version,
            my_autonomous_system,
            hold_time,
            bgp_id: Ipv4Addr::from_bits(bgp_id),
            optional_params,
        })
    }
}

impl TryFrom<&mut Bytes> for OptionalParamVec {
    type Error = String;

    fn try_from(value: &mut Bytes) -> Result<Self, Self::Error> {
        let mut params: Vec<OptionalParam> = Vec::new();

        while value.has_remaining() {
            let code = value.get_u8();
            let length = value.get_u8();
            if value.len() < length as usize {
                return Err("oof".to_string());
            }
            let data = value.copy_to_bytes(length as usize).to_vec();
            params.push(OptionalParam {
                param_type: code,
                param_value: data,
            });
        }

        Ok(OptionalParamVec(params))
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use bytes::{BufMut, BytesMut};

    use super::OpenMessage;

    #[test]
    fn test_open_from_bytes() {
        let mut buf = BytesMut::new();
        buf.put_u8(4); // version
        buf.put_u16(1);
        buf.put_u16(3);
        buf.put_u32(Ipv4Addr::new(0, 0, 0, 0).to_bits());
        buf.put_u8(3);
        buf.put_u8(1);
        buf.put_u8(1);
        buf.put_u8(0);

        let open_message = OpenMessage::try_from(&mut buf.freeze());

        if let Ok(msg) = open_message {
            assert_eq!(msg.version, 4);
            assert_eq!(msg.optional_params.len(), 1);
            if let Some(param) = msg.optional_params.get(0) {
                assert_eq!(param.param_type, 1);
                assert_eq!(param.param_value.get(0), Some(0).as_ref());
            }
        }
    }
}
