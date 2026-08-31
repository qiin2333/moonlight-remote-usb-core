use crate::{CoreError, CoreResult, PROTOCOL_VERSION};

pub const MAGIC: u32 = 0x4253_5552;
pub const HELLO_SIZE: usize = 84;
pub const MIN_PDU_SIZE: u32 = 49;
pub const MAX_PDU_SIZE: u32 = 1024 * 1024;
pub const MAX_INFLIGHT: u32 = 4096;
pub const MAX_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_WINDOW_BYTES: u64 = MAX_WINDOW_BYTES;
pub const DEFAULT_WINDOW_PDUS: u32 = MAX_INFLIGHT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    pub client_uuid: [u8; 16],
    pub stream_generation: u64,
    pub session_token: u64,
    pub attachment_token: u64,
    pub lease_token: u64,
    pub capability_nonce: [u8; 16],
    pub max_pdu: u32,
    pub max_inflight: u32,
    pub isochronous: bool,
}

impl Hello {
    pub fn validate(&self) -> CoreResult<()> {
        if self.client_uuid == [0; 16]
            || self.stream_generation == 0
            || self.session_token == 0
            || self.attachment_token == 0
            || self.lease_token == 0
            || self.capability_nonce == [0; 16]
            || !(MIN_PDU_SIZE..=MAX_PDU_SIZE).contains(&self.max_pdu)
            || !(1..=MAX_INFLIGHT).contains(&self.max_inflight)
            || self.isochronous
        {
            return Err(CoreError::Malformed);
        }
        Ok(())
    }

    pub fn encode(&self) -> CoreResult<[u8; HELLO_SIZE]> {
        self.validate()?;
        let mut wire = [0_u8; HELLO_SIZE];
        put_u32_le(&mut wire[0..4], MAGIC);
        put_u16_le(&mut wire[4..6], PROTOCOL_VERSION);
        put_u16_le(
            &mut wire[6..8],
            u16::try_from(HELLO_SIZE).map_err(|_| CoreError::Internal)?,
        );
        wire[8..24].copy_from_slice(&self.client_uuid);
        put_u64_le(&mut wire[24..32], self.stream_generation);
        put_u64_le(&mut wire[32..40], self.session_token);
        put_u64_le(&mut wire[40..48], self.attachment_token);
        put_u64_le(&mut wire[48..56], self.lease_token);
        wire[56..72].copy_from_slice(&self.capability_nonce);
        put_u32_le(&mut wire[72..76], self.max_pdu);
        put_u32_le(&mut wire[76..80], self.max_inflight);
        wire[80] = u8::from(self.isochronous);
        Ok(wire)
    }

    pub fn decode(wire: &[u8]) -> CoreResult<Self> {
        if wire.len() != HELLO_SIZE {
            return Err(CoreError::Malformed);
        }
        if get_u32_le(&wire[0..4]) != MAGIC {
            return Err(CoreError::BadMagic);
        }
        if get_u16_le(&wire[4..6]) != PROTOCOL_VERSION {
            return Err(CoreError::VersionMismatch);
        }
        if get_u16_le(&wire[6..8]) as usize != HELLO_SIZE || wire[81..84] != [0; 3] {
            return Err(CoreError::Malformed);
        }
        let mut client_uuid = [0; 16];
        client_uuid.copy_from_slice(&wire[8..24]);
        let mut capability_nonce = [0; 16];
        capability_nonce.copy_from_slice(&wire[56..72]);
        let hello = Self {
            client_uuid,
            stream_generation: get_u64_le(&wire[24..32]),
            session_token: get_u64_le(&wire[32..40]),
            attachment_token: get_u64_le(&wire[40..48]),
            lease_token: get_u64_le(&wire[48..56]),
            capability_nonce,
            max_pdu: get_u32_le(&wire[72..76]),
            max_inflight: get_u32_le(&wire[76..80]),
            isochronous: wire[80] != 0,
        };
        hello.validate()?;
        Ok(hello)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerState {
    New,
    HelloSent,
    Established,
    Closed,
    Failed,
}

#[derive(Debug)]
pub struct BrokerSession {
    expected: Hello,
    state: BrokerState,
    nonce_consumed: bool,
    pub negotiated_max_pdu: u32,
    pub negotiated_max_inflight: u32,
    tx_window_bytes: u64,
    tx_window_pdus: u32,
    rx_window_bytes: u64,
    rx_window_pdus: u32,
    tx_bytes_in_flight: u64,
    tx_pdus_in_flight: u32,
    rx_bytes_in_flight: u64,
    rx_pdus_in_flight: u32,
}

impl BrokerSession {
    pub fn new(
        expected: Hello,
        tx_window_bytes: u64,
        tx_window_pdus: u32,
        rx_window_bytes: u64,
        rx_window_pdus: u32,
    ) -> CoreResult<Self> {
        expected.validate()?;
        let tx_window_bytes = default_u64(tx_window_bytes, DEFAULT_WINDOW_BYTES);
        let tx_window_pdus = default_u32(tx_window_pdus, DEFAULT_WINDOW_PDUS);
        let rx_window_bytes = default_u64(rx_window_bytes, DEFAULT_WINDOW_BYTES);
        let rx_window_pdus = default_u32(rx_window_pdus, DEFAULT_WINDOW_PDUS);
        if tx_window_bytes > MAX_WINDOW_BYTES
            || rx_window_bytes > MAX_WINDOW_BYTES
            || tx_window_pdus > MAX_INFLIGHT
            || rx_window_pdus > MAX_INFLIGHT
        {
            return Err(CoreError::InvalidArgument);
        }
        let negotiated_max_pdu = expected.max_pdu;
        let negotiated_max_inflight = expected.max_inflight;
        Ok(Self {
            expected,
            state: BrokerState::New,
            nonce_consumed: false,
            negotiated_max_pdu,
            negotiated_max_inflight,
            tx_window_bytes,
            tx_window_pdus,
            rx_window_bytes,
            rx_window_pdus,
            tx_bytes_in_flight: 0,
            tx_pdus_in_flight: 0,
            rx_bytes_in_flight: 0,
            rx_pdus_in_flight: 0,
        })
    }

    #[must_use]
    pub const fn state(&self) -> BrokerState {
        self.state
    }

    pub fn mark_hello_sent(&mut self) -> CoreResult<()> {
        if self.state != BrokerState::New {
            return Err(CoreError::InvalidState);
        }
        self.state = BrokerState::HelloSent;
        Ok(())
    }

    pub fn accept_hello(&mut self, wire: &[u8]) -> CoreResult<()> {
        if self.nonce_consumed {
            return Err(CoreError::Duplicate);
        }
        if !matches!(self.state, BrokerState::New | BrokerState::HelloSent) {
            return Err(CoreError::InvalidState);
        }
        let peer = match Hello::decode(wire) {
            Ok(value) => value,
            Err(error) => {
                self.state = BrokerState::Failed;
                return Err(error);
            }
        };
        if !same_identity(&peer, &self.expected) {
            self.state = BrokerState::Failed;
            return Err(CoreError::TokenMismatch);
        }
        if peer.max_pdu > self.expected.max_pdu || peer.max_inflight > self.expected.max_inflight {
            self.state = BrokerState::Failed;
            return Err(CoreError::LimitExceeded);
        }
        self.negotiated_max_pdu = self.expected.max_pdu.min(peer.max_pdu);
        self.negotiated_max_inflight = self.expected.max_inflight.min(peer.max_inflight);
        self.nonce_consumed = true;
        self.state = BrokerState::Established;
        Ok(())
    }

    pub fn reserve_send(&mut self, bytes: usize) -> CoreResult<()> {
        reserve(
            self.state,
            bytes,
            &mut self.tx_bytes_in_flight,
            &mut self.tx_pdus_in_flight,
            self.tx_window_bytes,
            self.tx_window_pdus,
            self.negotiated_max_pdu,
            self.negotiated_max_inflight,
        )
    }

    pub fn ack_send(&mut self, bytes: usize) -> CoreResult<()> {
        consume(
            self.state,
            bytes,
            &mut self.tx_bytes_in_flight,
            &mut self.tx_pdus_in_flight,
        )
    }

    pub fn reserve_receive(&mut self, bytes: usize) -> CoreResult<()> {
        reserve(
            self.state,
            bytes,
            &mut self.rx_bytes_in_flight,
            &mut self.rx_pdus_in_flight,
            self.rx_window_bytes,
            self.rx_window_pdus,
            self.negotiated_max_pdu,
            self.negotiated_max_inflight,
        )
    }

    pub fn consume_receive(&mut self, bytes: usize) -> CoreResult<()> {
        consume(
            self.state,
            bytes,
            &mut self.rx_bytes_in_flight,
            &mut self.rx_pdus_in_flight,
        )
    }

    pub fn close(&mut self) -> CoreResult<()> {
        if self.state == BrokerState::Failed {
            return Err(CoreError::InvalidState);
        }
        self.tx_bytes_in_flight = 0;
        self.tx_pdus_in_flight = 0;
        self.rx_bytes_in_flight = 0;
        self.rx_pdus_in_flight = 0;
        self.state = BrokerState::Closed;
        Ok(())
    }
}

fn same_identity(left: &Hello, right: &Hello) -> bool {
    left.client_uuid == right.client_uuid
        && left.stream_generation == right.stream_generation
        && left.session_token == right.session_token
        && left.attachment_token == right.attachment_token
        && left.lease_token == right.lease_token
        && left.capability_nonce == right.capability_nonce
        && left.isochronous == right.isochronous
}

fn reserve(
    state: BrokerState,
    bytes: usize,
    bytes_in_flight: &mut u64,
    pdus_in_flight: &mut u32,
    window_bytes: u64,
    window_pdus: u32,
    max_pdu: u32,
    max_inflight: u32,
) -> CoreResult<()> {
    if state != BrokerState::Established {
        return Err(CoreError::InvalidState);
    }
    let bytes = u64::try_from(bytes).map_err(|_| CoreError::LimitExceeded)?;
    if bytes == 0 {
        return Err(CoreError::InvalidArgument);
    }
    if bytes > u64::from(max_pdu) || *pdus_in_flight >= max_inflight {
        return Err(CoreError::LimitExceeded);
    }
    if bytes > window_bytes.saturating_sub(*bytes_in_flight) || *pdus_in_flight >= window_pdus {
        return Err(CoreError::WindowExhausted);
    }
    *bytes_in_flight += bytes;
    *pdus_in_flight += 1;
    Ok(())
}

fn consume(
    state: BrokerState,
    bytes: usize,
    bytes_in_flight: &mut u64,
    pdus_in_flight: &mut u32,
) -> CoreResult<()> {
    if state != BrokerState::Established {
        return Err(CoreError::InvalidState);
    }
    let bytes = u64::try_from(bytes).map_err(|_| CoreError::InvalidArgument)?;
    if bytes == 0 || bytes > *bytes_in_flight || *pdus_in_flight == 0 {
        return Err(CoreError::InvalidArgument);
    }
    *bytes_in_flight -= bytes;
    *pdus_in_flight -= 1;
    Ok(())
}

const fn default_u64(value: u64, default: u64) -> u64 {
    if value == 0 { default } else { value }
}

const fn default_u32(value: u32, default: u32) -> u32 {
    if value == 0 { default } else { value }
}

pub(crate) fn get_u16_le(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("fixed-width slice"))
}

pub(crate) fn get_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("fixed-width slice"))
}

pub(crate) fn get_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("fixed-width slice"))
}

pub(crate) fn put_u16_le(bytes: &mut [u8], value: u16) {
    bytes.copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u32_le(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u64_le(bytes: &mut [u8], value: u64) {
    bytes.copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Hello {
        Hello {
            client_uuid: *b"test-client-uuid",
            stream_generation: 2,
            session_token: 3,
            attachment_token: 4,
            lease_token: 5,
            capability_nonce: [6; 16],
            max_pdu: 4096,
            max_inflight: 4,
            isochronous: false,
        }
    }

    #[test]
    fn hello_round_trip_and_replay_guard() {
        let hello = hello();
        let wire = hello.encode().unwrap();
        assert_eq!(Hello::decode(&wire).unwrap(), hello);
        let mut session = BrokerSession::new(hello, 100, 4, 100, 4).unwrap();
        session.mark_hello_sent().unwrap();
        session.accept_hello(&wire).unwrap();
        assert_eq!(session.accept_hello(&wire), Err(CoreError::Duplicate));
    }

    #[test]
    fn windows_are_bounded() {
        let hello = hello();
        let wire = hello.encode().unwrap();
        let mut session = BrokerSession::new(hello, 100, 4, 100, 4).unwrap();
        session.accept_hello(&wire).unwrap();
        session.reserve_send(60).unwrap();
        assert_eq!(session.reserve_send(50), Err(CoreError::WindowExhausted));
        session.ack_send(60).unwrap();
    }
}
