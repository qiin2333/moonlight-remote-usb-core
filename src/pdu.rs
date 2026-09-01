use crate::{CoreError, CoreResult};

pub const HEADER_SIZE: usize = 48;
pub const MAX_SIZE: usize = 1024 * 1024;
pub const MAX_TRANSFER_SIZE: usize = MAX_SIZE - HEADER_SIZE;
pub const NON_ISO_PACKETS: i32 = -1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Command {
    Submit = 0x0000_0001,
    Unlink = 0x0000_0002,
    RetSubmit = 0x0000_0003,
    RetUnlink = 0x0000_0004,
}

impl TryFrom<u32> for Command {
    type Error = CoreError;

    fn try_from(value: u32) -> CoreResult<Self> {
        match value {
            1 => Ok(Self::Submit),
            2 => Ok(Self::Unlink),
            3 => Ok(Self::RetSubmit),
            4 => Ok(Self::RetUnlink),
            _ => Err(CoreError::Unsupported),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Direction {
    Out = 0,
    In = 1,
}

impl TryFrom<u32> for Direction {
    type Error = CoreError;

    fn try_from(value: u32) -> CoreResult<Self> {
        match value {
            0 => Ok(Self::Out),
            1 => Ok(Self::In),
            _ => Err(CoreError::Malformed),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitRequest {
    pub seqnum: u32,
    pub device_id: u32,
    pub direction: Direction,
    pub endpoint: u32,
    pub transfer_flags: u32,
    pub transfer_buffer_length: u32,
    pub start_frame: i32,
    pub interval: i32,
    pub setup: [u8; 8],
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlinkRequest {
    pub seqnum: u32,
    pub device_id: u32,
    pub direction: Direction,
    pub endpoint: u32,
    pub target_seqnum: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    Submit(SubmitRequest),
    Unlink(UnlinkRequest),
}

impl Request {
    pub fn decode(wire: &[u8]) -> CoreResult<Self> {
        if wire.len() < HEADER_SIZE {
            return Err(CoreError::Malformed);
        }
        if wire.len() > MAX_SIZE {
            return Err(CoreError::LimitExceeded);
        }
        match Command::try_from(get_u32_be(&wire[0..4]))? {
            Command::Submit => decode_submit(wire).map(Self::Submit),
            Command::Unlink => decode_unlink(wire).map(Self::Unlink),
            _ => Err(CoreError::Unsupported),
        }
    }

    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        match self {
            Self::Submit(request) => request.encode(),
            Self::Unlink(request) => request.encode(),
        }
    }

    #[must_use]
    pub const fn seqnum(&self) -> u32 {
        match self {
            Self::Submit(value) => value.seqnum,
            Self::Unlink(value) => value.seqnum,
        }
    }
}

impl SubmitRequest {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        validate_common(self.seqnum, self.direction, self.endpoint)?;
        let expected_data = match self.direction {
            Direction::Out => self.transfer_buffer_length as usize,
            Direction::In => 0,
        };
        if self.transfer_buffer_length as usize > MAX_TRANSFER_SIZE
            || self.data.len() != expected_data
        {
            return Err(CoreError::Malformed);
        }
        let mut wire = vec![0; HEADER_SIZE + self.data.len()];
        put_common(
            &mut wire,
            Command::Submit,
            self.seqnum,
            self.device_id,
            self.direction,
            self.endpoint,
        );
        put_u32_be(&mut wire[20..24], self.transfer_flags);
        put_u32_be(&mut wire[24..28], self.transfer_buffer_length);
        put_i32_be(&mut wire[28..32], self.start_frame);
        put_i32_be(&mut wire[32..36], NON_ISO_PACKETS);
        put_i32_be(&mut wire[36..40], self.interval);
        wire[40..48].copy_from_slice(&self.setup);
        wire[48..].copy_from_slice(&self.data);
        Ok(wire)
    }
}

impl UnlinkRequest {
    pub fn encode(self) -> CoreResult<Vec<u8>> {
        validate_common(self.seqnum, self.direction, self.endpoint)?;
        if self.target_seqnum == 0 {
            return Err(CoreError::Malformed);
        }
        let mut wire = vec![0; HEADER_SIZE];
        put_common(
            &mut wire,
            Command::Unlink,
            self.seqnum,
            self.device_id,
            self.direction,
            self.endpoint,
        );
        put_u32_be(&mut wire[20..24], self.target_seqnum);
        Ok(wire)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitReply {
    pub seqnum: u32,
    pub direction: Direction,
    pub status: i32,
    pub actual_length: u32,
    pub start_frame: i32,
    pub error_count: i32,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnlinkReply {
    pub seqnum: u32,
    pub status: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    Submit(SubmitReply),
    Unlink(UnlinkReply),
}

impl Reply {
    pub fn decode(wire: &[u8]) -> CoreResult<Self> {
        if wire.len() < HEADER_SIZE || wire.len() > MAX_SIZE {
            return Err(CoreError::Malformed);
        }
        match Command::try_from(get_u32_be(&wire[0..4]))? {
            Command::RetSubmit => decode_submit_reply(wire).map(Self::Submit),
            Command::RetUnlink => decode_unlink_reply(wire).map(Self::Unlink),
            _ => Err(CoreError::Unsupported),
        }
    }

    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        match self {
            Self::Submit(reply) => reply.encode(),
            Self::Unlink(reply) => reply.encode(),
        }
    }
}

impl SubmitReply {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let expected_data_length = match self.direction {
            Direction::In => self.actual_length as usize,
            Direction::Out => 0,
        };
        if self.seqnum == 0
            || self.actual_length as usize > MAX_TRANSFER_SIZE
            || self.data.len() != expected_data_length
        {
            return Err(CoreError::Malformed);
        }
        let mut wire = vec![0; HEADER_SIZE + self.data.len()];
        put_u32_be(&mut wire[0..4], Command::RetSubmit as u32);
        put_u32_be(&mut wire[4..8], self.seqnum);
        put_i32_be(&mut wire[20..24], self.status);
        put_u32_be(&mut wire[24..28], self.actual_length);
        put_i32_be(&mut wire[28..32], self.start_frame);
        put_i32_be(&mut wire[32..36], NON_ISO_PACKETS);
        put_i32_be(&mut wire[36..40], self.error_count);
        wire[48..].copy_from_slice(&self.data);
        Ok(wire)
    }
}

impl UnlinkReply {
    pub fn encode(self) -> CoreResult<Vec<u8>> {
        if self.seqnum == 0 {
            return Err(CoreError::Malformed);
        }
        let mut wire = vec![0; HEADER_SIZE];
        put_u32_be(&mut wire[0..4], Command::RetUnlink as u32);
        put_u32_be(&mut wire[4..8], self.seqnum);
        put_i32_be(&mut wire[20..24], self.status);
        Ok(wire)
    }
}

fn decode_submit(wire: &[u8]) -> CoreResult<SubmitRequest> {
    let seqnum = get_u32_be(&wire[4..8]);
    let direction = Direction::try_from(get_u32_be(&wire[12..16]))?;
    let endpoint = get_u32_be(&wire[16..20]);
    validate_common(seqnum, direction, endpoint)?;
    let transfer_buffer_length = get_i32_be(&wire[24..28]);
    let packet_count = get_i32_be(&wire[32..36]);
    if transfer_buffer_length < 0 || !matches!(packet_count, NON_ISO_PACKETS | 0) {
        return Err(CoreError::Malformed);
    }
    let transfer_buffer_length =
        u32::try_from(transfer_buffer_length).map_err(|_| CoreError::Malformed)?;
    if transfer_buffer_length as usize > MAX_TRANSFER_SIZE {
        return Err(CoreError::LimitExceeded);
    }
    let expected_data = match direction {
        Direction::Out => transfer_buffer_length as usize,
        Direction::In => 0,
    };
    if wire.len() != HEADER_SIZE + expected_data {
        return Err(CoreError::Malformed);
    }
    let mut setup = [0; 8];
    setup.copy_from_slice(&wire[40..48]);
    Ok(SubmitRequest {
        seqnum,
        device_id: get_u32_be(&wire[8..12]),
        direction,
        endpoint,
        transfer_flags: get_u32_be(&wire[20..24]),
        transfer_buffer_length,
        start_frame: get_i32_be(&wire[28..32]),
        interval: get_i32_be(&wire[36..40]),
        setup,
        data: wire[48..].to_vec(),
    })
}

fn decode_unlink(wire: &[u8]) -> CoreResult<UnlinkRequest> {
    if wire.len() != HEADER_SIZE || wire[24..48] != [0; 24] {
        return Err(CoreError::Malformed);
    }
    let value = UnlinkRequest {
        seqnum: get_u32_be(&wire[4..8]),
        device_id: get_u32_be(&wire[8..12]),
        direction: Direction::try_from(get_u32_be(&wire[12..16]))?,
        endpoint: get_u32_be(&wire[16..20]),
        target_seqnum: get_u32_be(&wire[20..24]),
    };
    validate_common(value.seqnum, value.direction, value.endpoint)?;
    if value.target_seqnum == 0 {
        return Err(CoreError::Malformed);
    }
    Ok(value)
}

fn decode_submit_reply(wire: &[u8]) -> CoreResult<SubmitReply> {
    if wire[8..20] != [0; 12] || wire[40..48] != [0; 8] {
        return Err(CoreError::Malformed);
    }
    let seqnum = get_u32_be(&wire[4..8]);
    let actual_length = get_i32_be(&wire[24..28]);
    let packet_count = get_i32_be(&wire[32..36]);
    if seqnum == 0 || actual_length < 0 || !matches!(packet_count, NON_ISO_PACKETS | 0) {
        return Err(CoreError::Malformed);
    }
    let actual_length = u32::try_from(actual_length).map_err(|_| CoreError::Malformed)?;
    let direction = if wire.len() == HEADER_SIZE + actual_length as usize {
        Direction::In
    } else if wire.len() == HEADER_SIZE {
        Direction::Out
    } else {
        return Err(CoreError::Malformed);
    };
    Ok(SubmitReply {
        seqnum,
        direction,
        status: get_i32_be(&wire[20..24]),
        actual_length,
        start_frame: get_i32_be(&wire[28..32]),
        error_count: get_i32_be(&wire[36..40]),
        data: wire[48..].to_vec(),
    })
}

fn decode_unlink_reply(wire: &[u8]) -> CoreResult<UnlinkReply> {
    if wire.len() != HEADER_SIZE || wire[8..20] != [0; 12] || wire[24..48] != [0; 24] {
        return Err(CoreError::Malformed);
    }
    let seqnum = get_u32_be(&wire[4..8]);
    if seqnum == 0 {
        return Err(CoreError::Malformed);
    }
    Ok(UnlinkReply {
        seqnum,
        status: get_i32_be(&wire[20..24]),
    })
}

fn validate_common(seqnum: u32, _direction: Direction, endpoint: u32) -> CoreResult<()> {
    if seqnum == 0 || endpoint > 15 {
        return Err(CoreError::Malformed);
    }
    Ok(())
}

fn put_common(
    wire: &mut [u8],
    command: Command,
    seqnum: u32,
    device_id: u32,
    direction: Direction,
    endpoint: u32,
) {
    put_u32_be(&mut wire[0..4], command as u32);
    put_u32_be(&mut wire[4..8], seqnum);
    put_u32_be(&mut wire[8..12], device_id);
    put_u32_be(&mut wire[12..16], direction as u32);
    put_u32_be(&mut wire[16..20], endpoint);
}

pub(crate) fn get_u16_be(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("fixed-width slice"))
}

pub(crate) fn get_u32_be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("fixed-width slice"))
}

pub(crate) fn get_i32_be(bytes: &[u8]) -> i32 {
    i32::from_be_bytes(bytes.try_into().expect("fixed-width slice"))
}

pub(crate) fn put_u16_be(bytes: &mut [u8], value: u16) {
    bytes.copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u32_be(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_i32_be(bytes: &mut [u8], value: i32) {
    bytes.copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_out_round_trip() {
        let request = Request::Submit(SubmitRequest {
            seqnum: 17,
            device_id: 0x0001_0002,
            direction: Direction::Out,
            endpoint: 2,
            transfer_flags: 0x40,
            transfer_buffer_length: 4,
            start_frame: 0,
            interval: 0,
            setup: [0; 8],
            data: vec![0xa1, 0xb2, 0xc3, 0xd4],
        });
        assert_eq!(
            Request::decode(&request.encode().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn unlink_reserved_bytes_are_strict() {
        let request = Request::Unlink(UnlinkRequest {
            seqnum: 3,
            device_id: 4,
            direction: Direction::Out,
            endpoint: 1,
            target_seqnum: 2,
        });
        let mut wire = request.encode().unwrap();
        wire[24] = 1;
        assert_eq!(Request::decode(&wire), Err(CoreError::Malformed));
    }

    #[test]
    fn replies_round_trip() {
        let reply = Reply::Submit(SubmitReply {
            seqnum: 11,
            direction: Direction::In,
            status: 0,
            actual_length: 3,
            start_frame: 0,
            error_count: 0,
            data: vec![1, 2, 3],
        });
        assert_eq!(Reply::decode(&reply.encode().unwrap()).unwrap(), reply);
    }
}
