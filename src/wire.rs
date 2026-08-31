use crate::broker::{
    MAGIC, get_u16_le, get_u32_le, get_u64_le, put_u16_le, put_u32_le, put_u64_le,
};
use crate::{CoreError, CoreResult, PROTOCOL_VERSION};

pub const HEADER_SIZE: usize = 32;
pub const MAX_PAYLOAD: usize = 128 * 1024;
pub const MAX_REASSEMBLY: usize = 1024 * 1024;
pub const MAX_FRAGMENTS: usize = 4096;
pub const CAPABILITY_PREFIX_SIZE: usize = 34;
pub const OPEN_SIZE: usize = 16;
pub const FRAGMENT_PREFIX_SIZE: usize = 32;
pub const FLAG_MORE: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Capability = 1,
    Open = 2,
    OpenOk = 3,
    OpenReject = 4,
    UsbIpData = 5,
    Close = 6,
}

impl TryFrom<u8> for MessageType {
    type Error = CoreError;

    fn try_from(value: u8) -> CoreResult<Self> {
        match value {
            1 => Ok(Self::Capability),
            2 => Ok(Self::Open),
            3 => Ok(Self::OpenOk),
            4 => Ok(Self::OpenReject),
            5 => Ok(Self::UsbIpData),
            6 => Ok(Self::Close),
            _ => Err(CoreError::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub message_type: MessageType,
    pub flags: u32,
    pub payload_length: u32,
    pub session_token: u64,
    pub sequence: u64,
}

impl FrameHeader {
    pub fn encode(self) -> CoreResult<[u8; HEADER_SIZE]> {
        self.validate()?;
        let mut wire = [0_u8; HEADER_SIZE];
        put_u32_le(&mut wire[0..4], MAGIC);
        wire[4] = u8::try_from(PROTOCOL_VERSION).map_err(|_| CoreError::Internal)?;
        wire[5] = self.message_type as u8;
        put_u16_le(
            &mut wire[6..8],
            u16::try_from(HEADER_SIZE).map_err(|_| CoreError::Internal)?,
        );
        put_u32_le(&mut wire[8..12], self.flags);
        put_u32_le(&mut wire[12..16], self.payload_length);
        put_u64_le(&mut wire[16..24], self.session_token);
        put_u64_le(&mut wire[24..32], self.sequence);
        Ok(wire)
    }

    pub fn decode(wire: &[u8]) -> CoreResult<Self> {
        if wire.len() != HEADER_SIZE {
            return Err(CoreError::Malformed);
        }
        if get_u32_le(&wire[0..4]) != MAGIC {
            return Err(CoreError::BadMagic);
        }
        if u16::from(wire[4]) != PROTOCOL_VERSION {
            return Err(CoreError::VersionMismatch);
        }
        if get_u16_le(&wire[6..8]) as usize != HEADER_SIZE {
            return Err(CoreError::Malformed);
        }
        let value = Self {
            message_type: MessageType::try_from(wire[5])?,
            flags: get_u32_le(&wire[8..12]),
            payload_length: get_u32_le(&wire[12..16]),
            session_token: get_u64_le(&wire[16..24]),
            sequence: get_u64_le(&wire[24..32]),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(self) -> CoreResult<()> {
        if self.session_token == 0 || self.sequence == 0 || self.sequence == u64::MAX {
            return Err(CoreError::SequenceError);
        }
        if self.payload_length as usize > MAX_PAYLOAD {
            return Err(CoreError::LimitExceeded);
        }
        if self.flags & !FLAG_MORE != 0
            || (self.flags != 0 && self.message_type != MessageType::UsbIpData)
        {
            return Err(CoreError::Malformed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    pub lease_token: u64,
    pub attachment_token: u64,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_bcd: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub bus_id: Vec<u8>,
    pub raw_descriptors: Vec<u8>,
    pub endpoints: Vec<Endpoint>,
}

impl Capability {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        self.validate()?;
        let length = CAPABILITY_PREFIX_SIZE
            .checked_add(self.bus_id.len())
            .and_then(|value| value.checked_add(self.raw_descriptors.len()))
            .and_then(|value| value.checked_add(self.endpoints.len() * 8))
            .ok_or(CoreError::LimitExceeded)?;
        if length > MAX_PAYLOAD {
            return Err(CoreError::LimitExceeded);
        }
        let mut payload = vec![0; length];
        put_u64_le(&mut payload[0..8], self.lease_token);
        put_u64_le(&mut payload[8..16], self.attachment_token);
        put_u16_le(&mut payload[16..18], self.vendor_id);
        put_u16_le(&mut payload[18..20], self.product_id);
        put_u16_le(&mut payload[20..22], self.device_bcd);
        payload[22] = self.device_class;
        payload[23] = self.device_subclass;
        payload[24] = self.device_protocol;
        payload[25] = u8::try_from(self.bus_id.len()).map_err(|_| CoreError::LimitExceeded)?;
        put_u16_le(
            &mut payload[26..28],
            u16::try_from(self.endpoints.len()).map_err(|_| CoreError::LimitExceeded)?,
        );
        put_u32_le(
            &mut payload[30..34],
            u32::try_from(self.raw_descriptors.len()).map_err(|_| CoreError::LimitExceeded)?,
        );
        let mut offset = CAPABILITY_PREFIX_SIZE;
        payload[offset..offset + self.bus_id.len()].copy_from_slice(&self.bus_id);
        offset += self.bus_id.len();
        payload[offset..offset + self.raw_descriptors.len()].copy_from_slice(&self.raw_descriptors);
        offset += self.raw_descriptors.len();
        for endpoint in &self.endpoints {
            payload[offset] = endpoint.interface_number;
            payload[offset + 1] = endpoint.alternate_setting;
            payload[offset + 2] = endpoint.address;
            payload[offset + 3] = endpoint.attributes;
            put_u16_le(
                &mut payload[offset + 4..offset + 6],
                endpoint.max_packet_size,
            );
            payload[offset + 6] = endpoint.interval;
            offset += 8;
        }
        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> CoreResult<Self> {
        if payload.len() < CAPABILITY_PREFIX_SIZE || payload[28..30] != [0; 2] {
            return Err(CoreError::Malformed);
        }
        let bus_id_length = usize::from(payload[25]);
        let endpoint_count = usize::from(get_u16_le(&payload[26..28]));
        let descriptor_length = get_u32_le(&payload[30..34]) as usize;
        let expected = CAPABILITY_PREFIX_SIZE
            .checked_add(bus_id_length)
            .and_then(|value| value.checked_add(descriptor_length))
            .and_then(|value| value.checked_add(endpoint_count * 8))
            .ok_or(CoreError::LimitExceeded)?;
        if payload.len() != expected {
            return Err(CoreError::Malformed);
        }
        let bus_start = CAPABILITY_PREFIX_SIZE;
        let descriptor_start = bus_start + bus_id_length;
        let endpoint_start = descriptor_start + descriptor_length;
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for index in 0..endpoint_count {
            let offset = endpoint_start + index * 8;
            if payload[offset + 7] != 0 {
                return Err(CoreError::Malformed);
            }
            endpoints.push(Endpoint {
                interface_number: payload[offset],
                alternate_setting: payload[offset + 1],
                address: payload[offset + 2],
                attributes: payload[offset + 3],
                max_packet_size: get_u16_le(&payload[offset + 4..offset + 6]),
                interval: payload[offset + 6],
            });
        }
        let value = Self {
            lease_token: get_u64_le(&payload[0..8]),
            attachment_token: get_u64_le(&payload[8..16]),
            vendor_id: get_u16_le(&payload[16..18]),
            product_id: get_u16_le(&payload[18..20]),
            device_bcd: get_u16_le(&payload[20..22]),
            device_class: payload[22],
            device_subclass: payload[23],
            device_protocol: payload[24],
            bus_id: payload[bus_start..descriptor_start].to_vec(),
            raw_descriptors: payload[descriptor_start..endpoint_start].to_vec(),
            endpoints,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> CoreResult<()> {
        if self.lease_token == 0
            || self.attachment_token == 0
            || self.bus_id.is_empty()
            || self.bus_id.len() > 31
            || self.bus_id.contains(&0)
            || self.raw_descriptors.is_empty()
            || self.raw_descriptors.len() > 64 * 1024
            || self.endpoints.len() > 256
        {
            return Err(CoreError::Malformed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Open {
    pub lease_token: u64,
    pub attachment_token: u64,
}

impl Open {
    pub fn encode(self) -> CoreResult<[u8; OPEN_SIZE]> {
        if self.lease_token == 0 || self.attachment_token == 0 {
            return Err(CoreError::Malformed);
        }
        let mut payload = [0; OPEN_SIZE];
        put_u64_le(&mut payload[0..8], self.lease_token);
        put_u64_le(&mut payload[8..16], self.attachment_token);
        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> CoreResult<Self> {
        if payload.len() != OPEN_SIZE {
            return Err(CoreError::Malformed);
        }
        let value = Self {
            lease_token: get_u64_le(&payload[0..8]),
            attachment_token: get_u64_le(&payload[8..16]),
        };
        value.encode()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fragment {
    pub lease_token: u64,
    pub pdu_id: u64,
    pub total_length: u32,
    pub offset: u32,
    pub data: Vec<u8>,
    pub more: bool,
}

impl Fragment {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        self.validate()?;
        let mut payload = vec![0; FRAGMENT_PREFIX_SIZE + self.data.len()];
        put_u64_le(&mut payload[0..8], self.lease_token);
        put_u64_le(&mut payload[8..16], self.pdu_id);
        put_u32_le(&mut payload[16..20], self.total_length);
        put_u32_le(&mut payload[20..24], self.offset);
        put_u32_le(
            &mut payload[24..28],
            u32::try_from(self.data.len()).map_err(|_| CoreError::LimitExceeded)?,
        );
        payload[32..].copy_from_slice(&self.data);
        Ok(payload)
    }

    pub fn decode(payload: &[u8], flags: u32) -> CoreResult<Self> {
        if payload.len() < FRAGMENT_PREFIX_SIZE || payload[28..32] != [0; 4] {
            return Err(CoreError::Malformed);
        }
        let chunk_length = get_u32_le(&payload[24..28]) as usize;
        if payload.len() != FRAGMENT_PREFIX_SIZE + chunk_length {
            return Err(CoreError::Malformed);
        }
        let fragment = Self {
            lease_token: get_u64_le(&payload[0..8]),
            pdu_id: get_u64_le(&payload[8..16]),
            total_length: get_u32_le(&payload[16..20]),
            offset: get_u32_le(&payload[20..24]),
            data: payload[32..].to_vec(),
            more: flags == FLAG_MORE,
        };
        fragment.validate()?;
        Ok(fragment)
    }

    fn validate(&self) -> CoreResult<()> {
        let end = u64::from(self.offset) + self.data.len() as u64;
        if self.lease_token == 0
            || self.pdu_id == 0
            || self.data.is_empty()
            || self.total_length == 0
            || self.total_length as usize > MAX_REASSEMBLY
            || end > u64::from(self.total_length)
            || self.more != (end < u64::from(self.total_length))
            || FRAGMENT_PREFIX_SIZE + self.data.len() > MAX_PAYLOAD
        {
            return Err(CoreError::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Reassembler {
    active_pdu: Option<u64>,
    lease_token: u64,
    total_length: usize,
    fragments: usize,
    bytes: Vec<u8>,
}

impl Reassembler {
    pub fn push(&mut self, fragment: Fragment) -> CoreResult<Option<(u64, Vec<u8>)>> {
        fragment.validate()?;
        if let Some(active) = self.active_pdu {
            if active != fragment.pdu_id
                || self.lease_token != fragment.lease_token
                || self.total_length != fragment.total_length as usize
                || fragment.offset as usize != self.bytes.len()
            {
                self.clear();
                return Err(CoreError::SequenceError);
            }
        } else {
            if fragment.offset != 0 {
                return Err(CoreError::SequenceError);
            }
            self.active_pdu = Some(fragment.pdu_id);
            self.lease_token = fragment.lease_token;
            self.total_length = fragment.total_length as usize;
            self.bytes = Vec::with_capacity(self.total_length);
        }
        self.fragments += 1;
        if self.fragments > MAX_FRAGMENTS {
            self.clear();
            return Err(CoreError::LimitExceeded);
        }
        self.bytes.extend_from_slice(&fragment.data);
        if fragment.more {
            return Ok(None);
        }
        if self.bytes.len() != self.total_length {
            self.clear();
            return Err(CoreError::Malformed);
        }
        let pdu_id = self.active_pdu.take().ok_or(CoreError::Internal)?;
        self.lease_token = 0;
        self.total_length = 0;
        self.fragments = 0;
        Ok(Some((pdu_id, core::mem::take(&mut self.bytes))))
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

pub fn encode_frame(header: FrameHeader, payload: &[u8]) -> CoreResult<Vec<u8>> {
    if payload.len() != header.payload_length as usize {
        return Err(CoreError::InvalidArgument);
    }
    validate_payload(header.message_type, header.flags, payload)?;
    let mut wire = Vec::with_capacity(HEADER_SIZE + payload.len());
    wire.extend_from_slice(&header.encode()?);
    wire.extend_from_slice(payload);
    Ok(wire)
}

pub fn decode_frame(wire: &[u8]) -> CoreResult<(FrameHeader, &[u8])> {
    if wire.len() < HEADER_SIZE {
        return Err(CoreError::Malformed);
    }
    let header = FrameHeader::decode(&wire[..HEADER_SIZE])?;
    if wire.len() != HEADER_SIZE + header.payload_length as usize {
        return Err(CoreError::Malformed);
    }
    let payload = &wire[HEADER_SIZE..];
    validate_payload(header.message_type, header.flags, payload)?;
    Ok((header, payload))
}

pub fn validate_payload(kind: MessageType, flags: u32, payload: &[u8]) -> CoreResult<()> {
    match kind {
        MessageType::Capability => Capability::decode(payload).map(|_| ()),
        MessageType::Open => Open::decode(payload).map(|_| ()),
        MessageType::OpenOk if payload.is_empty() => Ok(()),
        MessageType::OpenReject if payload.len() == 4 => {
            let status = get_u32_le(payload);
            if (1..=10).contains(&status) {
                Ok(())
            } else {
                Err(CoreError::Malformed)
            }
        }
        MessageType::UsbIpData => Fragment::decode(payload, flags).map(|_| ()),
        MessageType::Close if payload.len() == 8 && get_u64_le(payload) != 0 => Ok(()),
        _ => Err(CoreError::Malformed),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WirePhase {
    AwaitCapability,
    AwaitOpen,
    AwaitOpenReply,
    Running,
    Closed,
    Failed,
}

#[derive(Debug)]
pub struct WireSession {
    session_token: u64,
    lease_token: u64,
    attachment_token: u64,
    next_rx_sequence: u64,
    next_tx_sequence: u64,
    phase: WirePhase,
}

impl WireSession {
    pub fn new(session_token: u64, lease_token: u64, attachment_token: u64) -> CoreResult<Self> {
        if session_token == 0 || lease_token == 0 || attachment_token == 0 {
            return Err(CoreError::InvalidArgument);
        }
        Ok(Self {
            session_token,
            lease_token,
            attachment_token,
            next_rx_sequence: 1,
            next_tx_sequence: 1,
            phase: WirePhase::AwaitCapability,
        })
    }

    #[must_use]
    pub const fn phase(&self) -> WirePhase {
        self.phase
    }

    pub fn next_header(
        &mut self,
        message_type: MessageType,
        flags: u32,
        payload_length: usize,
    ) -> CoreResult<FrameHeader> {
        if self.next_tx_sequence == u64::MAX {
            return Err(CoreError::SequenceError);
        }
        let payload_length = u32::try_from(payload_length).map_err(|_| CoreError::LimitExceeded)?;
        let header = FrameHeader {
            message_type,
            flags,
            payload_length,
            session_token: self.session_token,
            sequence: self.next_tx_sequence,
        };
        header.validate()?;
        self.next_tx_sequence += 1;
        Ok(header)
    }

    pub fn accept(&mut self, header: FrameHeader, payload: &[u8]) -> CoreResult<()> {
        let result = self.accept_inner(header, payload);
        if result.is_err() {
            self.phase = WirePhase::Failed;
        }
        result
    }

    fn accept_inner(&mut self, header: FrameHeader, payload: &[u8]) -> CoreResult<()> {
        if matches!(self.phase, WirePhase::Closed | WirePhase::Failed) {
            return Err(CoreError::InvalidState);
        }
        if header.session_token != self.session_token {
            return Err(CoreError::TokenMismatch);
        }
        if header.sequence != self.next_rx_sequence {
            return Err(CoreError::SequenceError);
        }
        validate_payload(header.message_type, header.flags, payload)?;
        match (self.phase, header.message_type) {
            (WirePhase::AwaitCapability, MessageType::Capability) => {
                let capability = Capability::decode(payload)?;
                self.check_tokens(capability.lease_token, capability.attachment_token)?;
                self.phase = WirePhase::AwaitOpen;
            }
            (WirePhase::AwaitOpen, MessageType::Open) => {
                let open = Open::decode(payload)?;
                self.check_tokens(open.lease_token, open.attachment_token)?;
                self.phase = WirePhase::AwaitOpenReply;
            }
            (WirePhase::AwaitOpenReply, MessageType::OpenOk) => self.phase = WirePhase::Running,
            (WirePhase::AwaitOpenReply, MessageType::OpenReject) => self.phase = WirePhase::Closed,
            (WirePhase::Running, MessageType::UsbIpData) => {
                let fragment = Fragment::decode(payload, header.flags)?;
                if fragment.lease_token != self.lease_token {
                    return Err(CoreError::TokenMismatch);
                }
            }
            (_, MessageType::Close) => {
                if get_u64_le(payload) != self.lease_token {
                    return Err(CoreError::TokenMismatch);
                }
                self.phase = WirePhase::Closed;
            }
            _ => return Err(CoreError::InvalidState),
        }
        self.next_rx_sequence = self
            .next_rx_sequence
            .checked_add(1)
            .filter(|value| *value != u64::MAX)
            .ok_or(CoreError::SequenceError)?;
        Ok(())
    }

    fn check_tokens(&self, lease_token: u64, attachment_token: u64) -> CoreResult<()> {
        if lease_token != self.lease_token || attachment_token != self.attachment_token {
            return Err(CoreError::TokenMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> Capability {
        Capability {
            lease_token: 9,
            attachment_token: 7,
            vendor_id: 0x054c,
            product_id: 0x0ce6,
            device_bcd: 0x0100,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            bus_id: b"android-1".to_vec(),
            raw_descriptors: vec![0x12, 1, 0, 2],
            endpoints: vec![Endpoint {
                interface_number: 0,
                alternate_setting: 0,
                address: 0x81,
                attributes: 2,
                max_packet_size: 64,
                interval: 1,
            }],
        }
    }

    #[test]
    fn capability_round_trip() {
        let value = capability();
        assert_eq!(Capability::decode(&value.encode().unwrap()).unwrap(), value);
    }

    #[test]
    fn fragmented_pdu_reassembles() {
        let mut reassembler = Reassembler::default();
        let first = Fragment {
            lease_token: 9,
            pdu_id: 11,
            total_length: 5,
            offset: 0,
            data: vec![1, 2, 3],
            more: true,
        };
        let second = Fragment {
            offset: 3,
            data: vec![4, 5],
            more: false,
            ..first.clone()
        };
        assert!(reassembler.push(first).unwrap().is_none());
        assert_eq!(
            reassembler.push(second).unwrap(),
            Some((11, vec![1, 2, 3, 4, 5]))
        );
    }

    #[test]
    fn sequence_and_state_are_strict() {
        let payload = capability().encode().unwrap();
        let mut session = WireSession::new(3, 9, 7).unwrap();
        let header = FrameHeader {
            message_type: MessageType::Capability,
            flags: 0,
            payload_length: u32::try_from(payload.len()).unwrap(),
            session_token: 3,
            sequence: 1,
        };
        session.accept(header, &payload).unwrap();
        assert_eq!(session.phase(), WirePhase::AwaitOpen);
        assert_eq!(
            session.accept(header, &payload),
            Err(CoreError::SequenceError)
        );
        assert_eq!(session.phase(), WirePhase::Failed);
    }
}
