use std::collections::{HashMap, VecDeque};

use crate::broker::{BrokerSession, BrokerState, Hello};
use crate::executor::{Completion, Executor, ExecutorEvent};
use crate::wire::{self, Capability, Fragment, FrameHeader, MessageType, Open, Reassembler};
use crate::{CoreError, CoreResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Role {
    Exporter = 1,
    Importer = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportState {
    New,
    AwaitHello,
    AwaitCapability,
    AwaitOpen,
    AwaitOpenReply,
    Running,
    Closing,
    Closed,
    Failed,
}

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub role: Role,
    pub hello: Hello,
    pub tx_window_bytes: u64,
    pub tx_window_pdus: u32,
    pub rx_window_bytes: u64,
    pub rx_window_pdus: u32,
    pub max_reassembly_size: usize,
    pub max_fragments: usize,
    pub max_transfer_size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    OutputHello(Vec<u8>),
    OutputFrame {
        reservation_id: u64,
        bytes: Vec<u8>,
    },
    Capability(Capability),
    Open(Open),
    Opened,
    OpenRejected(u32),
    Submit {
        request_token: u64,
        request: crate::pdu::SubmitRequest,
    },
    Cancel {
        request_token: u64,
        unlink_seqnum: u32,
    },
    OpaquePdu {
        pdu_id: u64,
        bytes: Vec<u8>,
    },
    Closed,
}

#[derive(Debug)]
pub struct Transport {
    role: Role,
    state: TransportState,
    hello: Hello,
    broker: BrokerSession,
    executor: Executor,
    reassembler: Reassembler,
    next_rx_sequence: u64,
    next_tx_sequence: u64,
    next_internal_pdu_id: u64,
    output_reservations: HashMap<u64, usize>,
    events: VecDeque<TransportEvent>,
    max_reassembly_size: usize,
    max_fragments: usize,
}

impl Transport {
    pub fn new(config: TransportConfig) -> CoreResult<Self> {
        let max_pdu = config.hello.max_pdu as usize;
        if config.max_reassembly_size > max_pdu
            || config.max_transfer_size == 0
            || config.max_transfer_size
                > config
                    .max_reassembly_size
                    .saturating_sub(crate::pdu::HEADER_SIZE)
        {
            return Err(CoreError::InvalidArgument);
        }
        let reassembler = Reassembler::new(config.max_reassembly_size, config.max_fragments)?;
        let executor = Executor::new(config.hello.max_inflight as usize, config.max_transfer_size)?;
        let broker = BrokerSession::new(
            config.hello.clone(),
            config.tx_window_bytes,
            config.tx_window_pdus,
            config.rx_window_bytes,
            config.rx_window_pdus,
        )?;
        Ok(Self {
            role: config.role,
            state: TransportState::New,
            hello: config.hello,
            broker,
            executor,
            reassembler,
            next_rx_sequence: 1,
            next_tx_sequence: 1,
            next_internal_pdu_id: 1_u64 << 63,
            output_reservations: HashMap::new(),
            events: VecDeque::new(),
            max_reassembly_size: config.max_reassembly_size,
            max_fragments: config.max_fragments,
        })
    }

    #[must_use]
    pub const fn state(&self) -> TransportState {
        self.state
    }

    #[must_use]
    pub fn inflight(&self) -> usize {
        self.executor.inflight() + self.output_reservations.len()
    }

    pub fn start(&mut self) -> CoreResult<()> {
        if self.state != TransportState::New {
            return Err(CoreError::InvalidState);
        }
        self.broker.mark_hello_sent()?;
        self.events
            .push_back(TransportEvent::OutputHello(self.hello.encode()?.to_vec()));
        self.state = TransportState::AwaitHello;
        Ok(())
    }

    pub fn accept_hello(&mut self, wire: &[u8]) -> CoreResult<()> {
        if self.state != TransportState::AwaitHello {
            return Err(CoreError::InvalidState);
        }
        self.broker.accept_hello(wire)?;
        self.state = TransportState::AwaitCapability;
        Ok(())
    }

    pub fn send_capability(&mut self, capability: &Capability) -> CoreResult<()> {
        if self.role != Role::Exporter || self.state != TransportState::AwaitCapability {
            return Err(CoreError::InvalidState);
        }
        self.check_tokens(capability.lease_token, capability.attachment_token)?;
        let payload = capability.encode()?;
        self.queue_control(MessageType::Capability, 0, &payload)?;
        self.state = TransportState::AwaitOpen;
        Ok(())
    }

    pub fn send_open(&mut self) -> CoreResult<()> {
        if self.role != Role::Importer || self.state != TransportState::AwaitOpen {
            return Err(CoreError::InvalidState);
        }
        let payload = Open {
            lease_token: self.hello.lease_token,
            attachment_token: self.hello.attachment_token,
        }
        .encode()?;
        self.queue_control(MessageType::Open, 0, &payload)?;
        self.state = TransportState::AwaitOpenReply;
        Ok(())
    }

    pub fn send_open_ok(&mut self) -> CoreResult<()> {
        if self.role != Role::Exporter || self.state != TransportState::AwaitOpenReply {
            return Err(CoreError::InvalidState);
        }
        self.queue_control(MessageType::OpenOk, 0, &[])?;
        self.state = TransportState::Running;
        self.events.push_back(TransportEvent::Opened);
        Ok(())
    }

    pub fn send_open_reject(&mut self, status: u32) -> CoreResult<()> {
        if self.role != Role::Exporter
            || self.state != TransportState::AwaitOpenReply
            || !(1..=10).contains(&status)
        {
            return Err(CoreError::InvalidState);
        }
        self.queue_control(MessageType::OpenReject, 0, &status.to_le_bytes())?;
        self.state = TransportState::Closed;
        Ok(())
    }

    pub fn send_pdu(&mut self, pdu_id: u64, pdu: &[u8]) -> CoreResult<()> {
        if self.state != TransportState::Running || pdu_id == 0 {
            return Err(CoreError::InvalidState);
        }
        if self.output_reservations.contains_key(&pdu_id) {
            return Err(CoreError::Duplicate);
        }
        self.broker.reserve_send(pdu.len())?;
        if let Err(error) = self.fragment_and_queue(pdu_id, pdu) {
            let _ = self.broker.ack_send(pdu.len());
            return Err(error);
        }
        self.output_reservations.insert(pdu_id, pdu.len());
        Ok(())
    }

    pub fn ack_output(&mut self, reservation_id: u64) -> CoreResult<()> {
        if reservation_id == 0 {
            return Ok(());
        }
        let bytes = self
            .output_reservations
            .remove(&reservation_id)
            .ok_or(CoreError::NotFound)?;
        self.broker.ack_send(bytes)
    }

    pub fn accept_frame(&mut self, wire_bytes: &[u8]) -> CoreResult<()> {
        let result = self.accept_frame_inner(wire_bytes);
        if result.is_err() {
            self.state = TransportState::Failed;
            self.reassembler.clear();
        }
        result
    }

    fn accept_frame_inner(&mut self, wire_bytes: &[u8]) -> CoreResult<()> {
        if !matches!(
            self.state,
            TransportState::AwaitCapability
                | TransportState::AwaitOpen
                | TransportState::AwaitOpenReply
                | TransportState::Running
        ) || self.broker.state() != BrokerState::Established
        {
            return Err(CoreError::InvalidState);
        }
        let (header, payload) = wire::decode_frame(wire_bytes)?;
        if header.session_token != self.hello.session_token {
            return Err(CoreError::TokenMismatch);
        }
        if header.sequence != self.next_rx_sequence {
            return Err(CoreError::SequenceError);
        }
        self.next_rx_sequence = next_sequence(self.next_rx_sequence)?;

        match (self.role, self.state, header.message_type) {
            (Role::Importer, TransportState::AwaitCapability, MessageType::Capability) => {
                let capability = Capability::decode(payload)?;
                self.check_tokens(capability.lease_token, capability.attachment_token)?;
                self.events
                    .push_back(TransportEvent::Capability(capability));
                self.state = TransportState::AwaitOpen;
            }
            (Role::Exporter, TransportState::AwaitOpen, MessageType::Open) => {
                let open = Open::decode(payload)?;
                self.check_tokens(open.lease_token, open.attachment_token)?;
                self.events.push_back(TransportEvent::Open(open));
                self.state = TransportState::AwaitOpenReply;
            }
            (Role::Importer, TransportState::AwaitOpenReply, MessageType::OpenOk) => {
                self.state = TransportState::Running;
                self.events.push_back(TransportEvent::Opened);
            }
            (Role::Importer, TransportState::AwaitOpenReply, MessageType::OpenReject) => {
                let status =
                    u32::from_le_bytes(payload.try_into().map_err(|_| CoreError::Malformed)?);
                self.state = TransportState::Closed;
                self.events.push_back(TransportEvent::OpenRejected(status));
            }
            (_, TransportState::Running, MessageType::UsbIpData) => {
                let fragment = Fragment::decode(payload, header.flags)?;
                if fragment.lease_token != self.hello.lease_token {
                    return Err(CoreError::TokenMismatch);
                }
                if fragment.total_length > self.broker.negotiated_max_pdu {
                    return Err(CoreError::LimitExceeded);
                }
                if let Some((pdu_id, pdu)) = self.reassembler.push(fragment)? {
                    let pdu_size = pdu.len();
                    self.broker.reserve_receive(pdu_size)?;
                    let handling = self.handle_pdu(pdu_id, pdu);
                    let consume = self.broker.consume_receive(pdu_size);
                    handling?;
                    consume?;
                }
            }
            (_, _, MessageType::Close) => {
                let lease_token =
                    u64::from_le_bytes(payload.try_into().map_err(|_| CoreError::Malformed)?);
                if lease_token != self.hello.lease_token {
                    return Err(CoreError::TokenMismatch);
                }
                self.state = TransportState::Closed;
                self.broker.close()?;
                self.reassembler.clear();
                self.events.push_back(TransportEvent::Closed);
            }
            _ => return Err(CoreError::InvalidState),
        }
        Ok(())
    }

    fn handle_pdu(&mut self, pdu_id: u64, pdu: Vec<u8>) -> CoreResult<()> {
        if pdu.starts_with(&crate::usbip::VERSION.to_be_bytes()) {
            match self.role {
                Role::Exporter => {
                    crate::usbip::ControlRequest::decode(&pdu)?;
                }
                Role::Importer => {
                    crate::usbip::ControlReply::decode(&pdu)?;
                }
            }
            self.events
                .push_back(TransportEvent::OpaquePdu { pdu_id, bytes: pdu });
            Ok(())
        } else {
            let events = self.executor.accept_pdu(&pdu)?;
            self.handle_executor_events(events)
        }
    }

    pub fn complete(&mut self, request_token: u64, completion: Completion) -> CoreResult<()> {
        if self.state != TransportState::Running {
            return Err(CoreError::InvalidState);
        }
        let events = self.executor.complete(request_token, completion)?;
        self.handle_executor_events(events)
    }

    pub fn complete_cancel(&mut self, request_token: u64, status: i32) -> CoreResult<()> {
        if self.state != TransportState::Running {
            return Err(CoreError::InvalidState);
        }
        let events = self.executor.complete_cancel(request_token, status)?;
        self.handle_executor_events(events)
    }

    fn handle_executor_events(&mut self, events: Vec<ExecutorEvent>) -> CoreResult<()> {
        for event in events {
            match event {
                ExecutorEvent::Submit {
                    request_token,
                    request,
                } => self.events.push_back(TransportEvent::Submit {
                    request_token,
                    request,
                }),
                ExecutorEvent::Cancel {
                    request_token,
                    unlink_seqnum,
                } => self.events.push_back(TransportEvent::Cancel {
                    request_token,
                    unlink_seqnum,
                }),
                ExecutorEvent::Reply { pdu } => {
                    let pdu_id = self.allocate_internal_pdu_id()?;
                    self.send_pdu(pdu_id, &pdu)?;
                }
            }
        }
        Ok(())
    }

    pub fn close(&mut self) -> CoreResult<()> {
        if matches!(self.state, TransportState::Closed | TransportState::Failed) {
            return Ok(());
        }
        self.state = TransportState::Closing;
        let payload = self.hello.lease_token.to_le_bytes();
        self.queue_control(MessageType::Close, 0, &payload)?;
        self.broker.close()?;
        self.reassembler.clear();
        self.state = TransportState::Closed;
        self.events.push_back(TransportEvent::Closed);
        Ok(())
    }

    pub fn next_event(&mut self) -> Option<TransportEvent> {
        self.events.pop_front()
    }

    fn fragment_and_queue(&mut self, pdu_id: u64, pdu: &[u8]) -> CoreResult<()> {
        if pdu.is_empty()
            || pdu.len() > self.broker.negotiated_max_pdu as usize
            || pdu.len() > self.max_reassembly_size
        {
            return Err(CoreError::LimitExceeded);
        }
        let max_chunk = wire::MAX_PAYLOAD - wire::FRAGMENT_PREFIX_SIZE;
        if pdu.len().div_ceil(max_chunk) > self.max_fragments {
            return Err(CoreError::LimitExceeded);
        }
        let mut offset = 0;
        while offset < pdu.len() {
            let end = (offset + max_chunk).min(pdu.len());
            let fragment = Fragment {
                lease_token: self.hello.lease_token,
                pdu_id,
                total_length: u32::try_from(pdu.len()).map_err(|_| CoreError::LimitExceeded)?,
                offset: u32::try_from(offset).map_err(|_| CoreError::LimitExceeded)?,
                data: pdu[offset..end].to_vec(),
                more: end != pdu.len(),
            };
            let flags = if fragment.more { wire::FLAG_MORE } else { 0 };
            let payload = fragment.encode()?;
            let frame = self.make_frame(MessageType::UsbIpData, flags, &payload)?;
            self.events.push_back(TransportEvent::OutputFrame {
                reservation_id: pdu_id,
                bytes: frame,
            });
            offset = end;
        }
        Ok(())
    }

    fn queue_control(
        &mut self,
        message_type: MessageType,
        flags: u32,
        payload: &[u8],
    ) -> CoreResult<()> {
        let bytes = self.make_frame(message_type, flags, payload)?;
        self.events.push_back(TransportEvent::OutputFrame {
            reservation_id: 0,
            bytes,
        });
        Ok(())
    }

    fn make_frame(
        &mut self,
        message_type: MessageType,
        flags: u32,
        payload: &[u8],
    ) -> CoreResult<Vec<u8>> {
        let sequence = self.next_tx_sequence;
        self.next_tx_sequence = next_sequence(sequence)?;
        wire::encode_frame(
            FrameHeader {
                message_type,
                flags,
                payload_length: payload
                    .len()
                    .try_into()
                    .map_err(|_| CoreError::LimitExceeded)?,
                session_token: self.hello.session_token,
                sequence,
            },
            payload,
        )
    }

    fn check_tokens(&self, lease_token: u64, attachment_token: u64) -> CoreResult<()> {
        if lease_token != self.hello.lease_token || attachment_token != self.hello.attachment_token
        {
            return Err(CoreError::TokenMismatch);
        }
        Ok(())
    }

    fn allocate_internal_pdu_id(&mut self) -> CoreResult<u64> {
        let id = self.next_internal_pdu_id;
        self.next_internal_pdu_id = self
            .next_internal_pdu_id
            .checked_add(1)
            .filter(|value| *value != 0)
            .ok_or(CoreError::LimitExceeded)?;
        Ok(id)
    }
}

fn next_sequence(sequence: u64) -> CoreResult<u64> {
    sequence
        .checked_add(1)
        .filter(|value| *value != u64::MAX)
        .ok_or(CoreError::SequenceError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{Direction, Request, SubmitRequest};
    use crate::wire::Endpoint;

    fn hello() -> Hello {
        Hello {
            client_uuid: *b"test-client-uuid",
            stream_generation: 2,
            session_token: 3,
            attachment_token: 7,
            lease_token: 9,
            capability_nonce: [6; 16],
            max_pdu: 4096,
            max_inflight: 4,
            isochronous: false,
        }
    }

    fn capability() -> Capability {
        Capability {
            lease_token: 9,
            attachment_token: 7,
            vendor_id: 1,
            product_id: 2,
            device_bcd: 3,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            bus_id: b"moonlight-1".to_vec(),
            raw_descriptors: vec![18, 1],
            endpoints: vec![Endpoint {
                interface_number: 0,
                alternate_setting: 0,
                address: 0x81,
                attributes: 3,
                max_packet_size: 64,
                interval: 1,
            }],
        }
    }

    #[test]
    fn exporter_handshake_emits_no_hidden_io() {
        let hello = hello();
        let wire = hello.encode().unwrap();
        let mut transport = Transport::new(TransportConfig {
            role: Role::Exporter,
            hello,
            tx_window_bytes: 0,
            tx_window_pdus: 0,
            rx_window_bytes: 0,
            rx_window_pdus: 0,
            max_reassembly_size: 4096,
            max_fragments: 4,
            max_transfer_size: 4096 - crate::pdu::HEADER_SIZE,
        })
        .unwrap();
        transport.start().unwrap();
        assert!(matches!(
            transport.next_event(),
            Some(TransportEvent::OutputHello(_))
        ));
        transport.accept_hello(&wire).unwrap();
        transport.send_capability(&capability()).unwrap();
        assert!(matches!(
            transport.next_event(),
            Some(TransportEvent::OutputFrame { .. })
        ));
    }

    fn running_exporter() -> Transport {
        let hello = hello();
        let hello_wire = hello.encode().unwrap();
        let mut transport = Transport::new(TransportConfig {
            role: Role::Exporter,
            hello,
            tx_window_bytes: 0,
            tx_window_pdus: 0,
            rx_window_bytes: 0,
            rx_window_pdus: 0,
            max_reassembly_size: 4096,
            max_fragments: 4,
            max_transfer_size: 4096 - crate::pdu::HEADER_SIZE,
        })
        .unwrap();
        transport.start().unwrap();
        transport.next_event();
        transport.accept_hello(&hello_wire).unwrap();
        transport.send_capability(&capability()).unwrap();
        transport.next_event();
        let open = Open {
            lease_token: 9,
            attachment_token: 7,
        }
        .encode()
        .unwrap();
        let frame = wire::encode_frame(
            FrameHeader {
                message_type: MessageType::Open,
                flags: 0,
                payload_length: u32::try_from(open.len()).unwrap(),
                session_token: 3,
                sequence: 1,
            },
            &open,
        )
        .unwrap();
        transport.accept_frame(&frame).unwrap();
        assert!(matches!(
            transport.next_event(),
            Some(TransportEvent::Open(_))
        ));
        transport.send_open_ok().unwrap();
        transport.next_event();
        assert_eq!(transport.next_event(), Some(TransportEvent::Opened));
        transport
    }

    #[test]
    fn malformed_urb_is_not_reclassified_as_control_data() {
        let mut transport = running_exporter();
        let mut malformed = vec![0; crate::pdu::HEADER_SIZE];
        malformed[..4].copy_from_slice(&(crate::pdu::Command::Submit as u32).to_be_bytes());
        malformed[4..8].copy_from_slice(&1_u32.to_be_bytes());
        malformed[12..16].copy_from_slice(&2_u32.to_be_bytes());
        let fragment = Fragment {
            lease_token: 9,
            pdu_id: 10,
            total_length: u32::try_from(malformed.len()).unwrap(),
            offset: 0,
            data: malformed,
            more: false,
        };
        let payload = fragment.encode().unwrap();
        let frame = wire::encode_frame(
            FrameHeader {
                message_type: MessageType::UsbIpData,
                flags: 0,
                payload_length: u32::try_from(payload.len()).unwrap(),
                session_token: 3,
                sequence: 2,
            },
            &payload,
        )
        .unwrap();
        assert_eq!(transport.accept_frame(&frame), Err(CoreError::Malformed));
        assert_eq!(transport.state(), TransportState::Failed);
    }

    #[test]
    fn submit_reaches_platform_event_and_completion_returns_pdu() {
        let mut transport = running_exporter();
        let submit = Request::Submit(SubmitRequest {
            seqnum: 17,
            device_id: 1,
            direction: Direction::In,
            endpoint: 1,
            transfer_flags: 0,
            transfer_buffer_length: 3,
            start_frame: 0,
            interval: 0,
            setup: [0; 8],
            data: Vec::new(),
        })
        .encode()
        .unwrap();
        let fragment = Fragment {
            lease_token: 9,
            pdu_id: 11,
            total_length: u32::try_from(submit.len()).unwrap(),
            offset: 0,
            data: submit,
            more: false,
        };
        let payload = fragment.encode().unwrap();
        let frame = wire::encode_frame(
            FrameHeader {
                message_type: MessageType::UsbIpData,
                flags: 0,
                payload_length: u32::try_from(payload.len()).unwrap(),
                session_token: 3,
                sequence: 2,
            },
            &payload,
        )
        .unwrap();
        transport.accept_frame(&frame).unwrap();
        let Some(TransportEvent::Submit { request_token, .. }) = transport.next_event() else {
            panic!("expected submit event");
        };
        transport
            .complete(
                request_token,
                Completion {
                    status: 0,
                    actual_length: 3,
                    start_frame: 0,
                    error_count: 0,
                    data: vec![1, 2, 3],
                },
            )
            .unwrap();
        let Some(TransportEvent::OutputFrame {
            reservation_id,
            bytes,
        }) = transport.next_event()
        else {
            panic!("expected output frame");
        };
        assert_ne!(reservation_id, 0);
        assert_eq!(
            wire::decode_frame(&bytes).unwrap().0.message_type,
            MessageType::UsbIpData
        );
        transport.ack_output(reservation_id).unwrap();
        assert_eq!(transport.inflight(), 0);
    }
}
