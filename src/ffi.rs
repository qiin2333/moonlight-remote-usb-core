//! Versioned C ABI.
//!
//! All raw-pointer handling is contained in this module. No exported function
//! unwinds, stores caller buffers, invokes callbacks, or creates a thread.

#![allow(clippy::missing_safety_doc)]

use core::ptr;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::broker::Hello;
use crate::executor::Completion;
use crate::session::{Role, Session, SessionConfig, SessionEvent, SessionState};
use crate::wire::Capability;
use crate::{ABI_VERSION, CoreError, CoreResult};

pub const EVENT_NONE: u32 = 0;
pub const EVENT_OUTPUT_HELLO: u32 = 1;
pub const EVENT_OUTPUT_FRAME: u32 = 2;
pub const EVENT_CAPABILITY: u32 = 3;
pub const EVENT_OPEN: u32 = 4;
pub const EVENT_OPENED: u32 = 5;
pub const EVENT_OPEN_REJECTED: u32 = 6;
pub const EVENT_SUBMIT: u32 = 7;
pub const EVENT_CANCEL: u32 = 8;
pub const EVENT_OPAQUE_PDU: u32 = 9;
pub const EVENT_CLOSED: u32 = 10;

#[repr(C)]
pub struct RusbSessionConfig {
    pub size: u32,
    pub version: u32,
    pub role: u32,
    pub reserved: u32,
    pub client_uuid: [u8; 16],
    pub stream_generation: u64,
    pub session_token: u64,
    pub attachment_token: u64,
    pub lease_token: u64,
    pub capability_nonce: [u8; 16],
    pub max_pdu: u32,
    pub max_inflight: u32,
    pub isochronous: u8,
    pub reserved_tail: [u8; 7],
    pub tx_window_bytes: u64,
    pub tx_window_pdus: u32,
    pub reserved_tx: u32,
    pub rx_window_bytes: u64,
    pub rx_window_pdus: u32,
    pub reserved_rx: u32,
    pub max_reassembly_size: u32,
    pub max_fragments: u32,
    pub max_transfer_size: u32,
    pub reserved_limits: u32,
}

#[repr(C)]
pub struct RusbCompletion {
    pub size: u32,
    pub version: u32,
    pub status: i32,
    pub actual_length: u32,
    pub start_frame: i32,
    pub error_count: i32,
    pub data: *const u8,
    pub data_length: usize,
}

#[repr(C)]
pub struct RusbEvent {
    pub size: u32,
    pub version: u32,
    pub kind: u32,
    pub flags: u32,
    pub reservation_id: u64,
    pub request_token: u64,
    pub pdu_id: u64,
    pub sequence: u32,
    pub device_id: u32,
    pub direction: u32,
    pub endpoint: u32,
    pub transfer_flags: u32,
    pub transfer_buffer_length: u32,
    pub start_frame: i32,
    pub interval: i32,
    pub status: i32,
    pub setup: [u8; 8],
    pub data: *const u8,
    pub data_length: usize,
}

impl RusbEvent {
    fn empty() -> Self {
        Self {
            size: size_of_u32::<Self>(),
            version: ABI_VERSION,
            kind: EVENT_NONE,
            flags: 0,
            reservation_id: 0,
            request_token: 0,
            pdu_id: 0,
            sequence: 0,
            device_id: 0,
            direction: 0,
            endpoint: 0,
            transfer_flags: 0,
            transfer_buffer_length: 0,
            start_frame: 0,
            interval: 0,
            status: 0,
            setup: [0; 8],
            data: ptr::null(),
            data_length: 0,
        }
    }
}

pub struct RusbSession {
    engine: Session,
    current_event: Option<SessionEvent>,
    scratch: Vec<u8>,
}

#[unsafe(no_mangle)]
pub extern "C" fn rusb_core_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn rusb_core_protocol_version() -> u32 {
    u32::from(crate::PROTOCOL_VERSION)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_create(
    config: *const RusbSessionConfig,
    out_session: *mut *mut RusbSession,
) -> u32 {
    ffi_status(|| {
        if config.is_null() || out_session.is_null() {
            return Err(CoreError::InvalidArgument);
        }
        // SAFETY: pointers were checked for null; the ABI requires readable
        // config storage and writable out storage for this call.
        let config = unsafe { &*config };
        validate_header(
            config.size,
            config.version,
            size_of_u32::<RusbSessionConfig>(),
        )?;
        if config.reserved != 0
            || config.reserved_tail != [0; 7]
            || config.reserved_tx != 0
            || config.reserved_rx != 0
            || config.reserved_limits != 0
        {
            return Err(CoreError::InvalidArgument);
        }
        let role = match config.role {
            1 => Role::Exporter,
            2 => Role::Importer,
            _ => return Err(CoreError::InvalidArgument),
        };
        let engine = Session::new(SessionConfig {
            role,
            hello: Hello {
                client_uuid: config.client_uuid,
                stream_generation: config.stream_generation,
                session_token: config.session_token,
                attachment_token: config.attachment_token,
                lease_token: config.lease_token,
                capability_nonce: config.capability_nonce,
                max_pdu: config.max_pdu,
                max_inflight: config.max_inflight,
                isochronous: config.isochronous != 0,
            },
            tx_window_bytes: config.tx_window_bytes,
            tx_window_pdus: config.tx_window_pdus,
            rx_window_bytes: config.rx_window_bytes,
            rx_window_pdus: config.rx_window_pdus,
            max_reassembly_size: config.max_reassembly_size as usize,
            max_fragments: config.max_fragments as usize,
            max_transfer_size: config.max_transfer_size as usize,
        })?;
        let session = Box::new(RusbSession {
            engine,
            current_event: None,
            scratch: Vec::new(),
        });
        // SAFETY: out_session is writable by the ABI contract and receives
        // ownership of the opaque Box until rusb_session_destroy.
        unsafe { *out_session = Box::into_raw(session) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_destroy(session: *mut RusbSession) -> u32 {
    ffi_status(|| {
        if session.is_null() {
            return Err(CoreError::InvalidArgument);
        }
        // SAFETY: the pointer must have come from rusb_session_create and may
        // be consumed exactly once.
        drop(unsafe { Box::from_raw(session) });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_start(session: *mut RusbSession) -> u32 {
    with_session(session, |session| session.engine.start())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_accept_hello(
    session: *mut RusbSession,
    wire: *const u8,
    wire_size: usize,
) -> u32 {
    with_bytes(session, wire, wire_size, |session, bytes| {
        session.engine.accept_hello(bytes)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_accept_frame(
    session: *mut RusbSession,
    wire: *const u8,
    wire_size: usize,
) -> u32 {
    with_bytes(session, wire, wire_size, |session, bytes| {
        session.engine.accept_frame(bytes)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_send_capability(
    session: *mut RusbSession,
    payload: *const u8,
    payload_size: usize,
) -> u32 {
    with_bytes(session, payload, payload_size, |session, bytes| {
        let capability = Capability::decode(bytes)?;
        session.engine.send_capability(&capability)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_send_open(session: *mut RusbSession) -> u32 {
    with_session(session, |session| session.engine.send_open())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_send_open_result(
    session: *mut RusbSession,
    status: u32,
) -> u32 {
    with_session(session, |session| {
        if status == 0 {
            session.engine.send_open_ok()
        } else {
            session.engine.send_open_reject(status)
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_send_pdu(
    session: *mut RusbSession,
    pdu_id: u64,
    pdu: *const u8,
    pdu_size: usize,
) -> u32 {
    with_bytes(session, pdu, pdu_size, |session, bytes| {
        session.engine.send_pdu(pdu_id, bytes)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_ack_output(
    session: *mut RusbSession,
    reservation_id: u64,
) -> u32 {
    with_session(session, |session| session.engine.ack_output(reservation_id))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_complete(
    session: *mut RusbSession,
    request_token: u64,
    completion: *const RusbCompletion,
) -> u32 {
    ffi_status(|| {
        let session = session_mut(session)?;
        if completion.is_null() {
            return Err(CoreError::InvalidArgument);
        }
        // SAFETY: non-null pointer is borrowed only for this call.
        let completion = unsafe { &*completion };
        validate_header(
            completion.size,
            completion.version,
            size_of_u32::<RusbCompletion>(),
        )?;
        if !session.engine.validate_completion(
            request_token,
            completion.actual_length,
            completion.data_length,
        )? {
            return Ok(());
        }
        let data = borrowed_bytes(completion.data, completion.data_length)?;
        session.engine.complete(
            request_token,
            Completion {
                status: completion.status,
                actual_length: completion.actual_length,
                start_frame: completion.start_frame,
                error_count: completion.error_count,
                data: data.to_vec(),
            },
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_complete_cancel(
    session: *mut RusbSession,
    request_token: u64,
    status: i32,
) -> u32 {
    with_session(session, |session| {
        session.engine.complete_cancel(request_token, status)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_close(session: *mut RusbSession) -> u32 {
    with_session(session, |session| session.engine.close())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_next_event(
    session: *mut RusbSession,
    out_event: *mut RusbEvent,
) -> u32 {
    ffi_status(|| {
        let session = session_mut(session)?;
        if out_event.is_null() {
            return Err(CoreError::InvalidArgument);
        }
        session.current_event = session.engine.next_event();
        session.scratch.clear();
        let mut event = RusbEvent::empty();
        if let Some(current) = session.current_event.as_ref() {
            fill_event(current, &mut session.scratch, &mut event)?;
        }
        // SAFETY: out_event is non-null and writable by the ABI contract.
        unsafe { out_event.write(event) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_state(session: *const RusbSession) -> u32 {
    if session.is_null() {
        return u32::MAX;
    }
    // SAFETY: non-null opaque pointer is borrowed for this read-only call.
    match unsafe { &*session }.engine.state() {
        SessionState::New => 0,
        SessionState::AwaitHello => 1,
        SessionState::AwaitCapability => 2,
        SessionState::AwaitOpen => 3,
        SessionState::AwaitOpenReply => 4,
        SessionState::Running => 5,
        SessionState::Closing => 6,
        SessionState::Closed => 7,
        SessionState::Failed => 8,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rusb_session_inflight(session: *const RusbSession) -> usize {
    if session.is_null() {
        return 0;
    }
    // SAFETY: non-null opaque pointer is borrowed for this read-only call.
    unsafe { &*session }.engine.inflight()
}

fn fill_event(
    current: &SessionEvent,
    scratch: &mut Vec<u8>,
    out: &mut RusbEvent,
) -> CoreResult<()> {
    match current {
        SessionEvent::OutputHello(bytes) => {
            out.kind = EVENT_OUTPUT_HELLO;
            set_data(out, bytes);
        }
        SessionEvent::OutputFrame {
            reservation_id,
            bytes,
        } => {
            out.kind = EVENT_OUTPUT_FRAME;
            out.reservation_id = *reservation_id;
            if bytes.len() >= crate::wire::HEADER_SIZE {
                out.flags =
                    crate::wire::FrameHeader::decode(&bytes[..crate::wire::HEADER_SIZE])?.flags;
            }
            set_data(out, bytes);
        }
        SessionEvent::Capability(capability) => {
            out.kind = EVENT_CAPABILITY;
            *scratch = capability.encode()?;
            set_data(out, scratch);
        }
        SessionEvent::Open(open) => {
            out.kind = EVENT_OPEN;
            out.reservation_id = open.lease_token;
            out.pdu_id = open.attachment_token;
        }
        SessionEvent::Opened => out.kind = EVENT_OPENED,
        SessionEvent::OpenRejected(status) => {
            out.kind = EVENT_OPEN_REJECTED;
            out.status = i32::try_from(*status).map_err(|_| CoreError::Internal)?;
        }
        SessionEvent::Submit {
            request_token,
            request,
        } => {
            out.kind = EVENT_SUBMIT;
            out.request_token = *request_token;
            out.sequence = request.seqnum;
            out.device_id = request.device_id;
            out.direction = request.direction as u32;
            out.endpoint = request.endpoint;
            out.transfer_flags = request.transfer_flags;
            out.transfer_buffer_length = request.transfer_buffer_length;
            out.start_frame = request.start_frame;
            out.interval = request.interval;
            out.setup = request.setup;
            set_data(out, &request.data);
        }
        SessionEvent::Cancel {
            request_token,
            unlink_seqnum,
        } => {
            out.kind = EVENT_CANCEL;
            out.request_token = *request_token;
            out.sequence = *unlink_seqnum;
        }
        SessionEvent::OpaquePdu { pdu_id, bytes } => {
            out.kind = EVENT_OPAQUE_PDU;
            out.pdu_id = *pdu_id;
            set_data(out, bytes);
        }
        SessionEvent::Closed => out.kind = EVENT_CLOSED,
    }
    Ok(())
}

fn set_data(event: &mut RusbEvent, bytes: &[u8]) {
    event.data = if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    };
    event.data_length = bytes.len();
}

fn with_session(
    session: *mut RusbSession,
    operation: impl FnOnce(&mut RusbSession) -> CoreResult<()>,
) -> u32 {
    ffi_status(|| operation(session_mut(session)?))
}

fn with_bytes(
    session: *mut RusbSession,
    bytes: *const u8,
    bytes_size: usize,
    operation: impl FnOnce(&mut RusbSession, &[u8]) -> CoreResult<()>,
) -> u32 {
    ffi_status(|| {
        let session = session_mut(session)?;
        let bytes = borrowed_bytes(bytes, bytes_size)?;
        operation(session, bytes)
    })
}

fn session_mut<'a>(session: *mut RusbSession) -> CoreResult<&'a mut RusbSession> {
    if session.is_null() {
        return Err(CoreError::InvalidArgument);
    }
    // SAFETY: the C ABI requires exclusive owner-loop access for every
    // mutating call and the pointer remains owned by the caller.
    Ok(unsafe { &mut *session })
}

fn borrowed_bytes<'a>(bytes: *const u8, size: usize) -> CoreResult<&'a [u8]> {
    if size == 0 {
        return Ok(&[]);
    }
    if bytes.is_null() || size > isize::MAX as usize {
        return Err(CoreError::InvalidArgument);
    }
    // SAFETY: the caller promises a readable byte range for this call; size
    // has been bounded to Rust's slice limit.
    Ok(unsafe { core::slice::from_raw_parts(bytes, size) })
}

fn validate_header(size: u32, version: u32, minimum_size: u32) -> CoreResult<()> {
    if size < minimum_size {
        return Err(CoreError::BufferTooSmall);
    }
    if version != ABI_VERSION {
        return Err(CoreError::VersionMismatch);
    }
    Ok(())
}

fn ffi_status(operation: impl FnOnce() -> CoreResult<()>) -> u32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => error.code(),
        Err(_) => CoreError::Internal.code(),
    }
}

fn size_of_u32<T>() -> u32 {
    u32::try_from(core::mem::size_of::<T>()).unwrap_or(u32::MAX)
}
