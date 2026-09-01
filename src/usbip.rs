use crate::pdu::{get_u16_be, get_u32_be, put_u16_be, put_u32_be};
use crate::{CoreError, CoreResult};

pub const VERSION: u16 = 0x0111;
pub const OP_REQUEST: u16 = 0x8000;
pub const OP_IMPORT: u16 = 0x0003;
pub const OP_DEVLIST: u16 = 0x0005;
pub const OP_REQ_IMPORT: u16 = OP_REQUEST | OP_IMPORT;
pub const OP_REP_IMPORT: u16 = OP_IMPORT;
pub const OP_REQ_DEVLIST: u16 = OP_REQUEST | OP_DEVLIST;
pub const OP_REP_DEVLIST: u16 = OP_DEVLIST;
pub const COMMON_SIZE: usize = 8;
pub const BUS_ID_SIZE: usize = 32;
pub const DEVICE_SIZE: usize = 312;
pub const INTERFACE_SIZE: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Common {
    pub code: u16,
    pub status: u32,
}

impl Common {
    pub fn encode(self) -> CoreResult<[u8; COMMON_SIZE]> {
        if !is_known_code(self.code) || self.status > 5 {
            return Err(CoreError::Malformed);
        }
        let mut wire = [0; COMMON_SIZE];
        put_u16_be(&mut wire[0..2], VERSION);
        put_u16_be(&mut wire[2..4], self.code);
        put_u32_be(&mut wire[4..8], self.status);
        Ok(wire)
    }

    pub fn decode(wire: &[u8], expected_code: Option<u16>) -> CoreResult<Self> {
        if wire.len() < COMMON_SIZE {
            return Err(CoreError::Malformed);
        }
        if get_u16_be(&wire[0..2]) != VERSION {
            return Err(CoreError::VersionMismatch);
        }
        let value = Self {
            code: get_u16_be(&wire[2..4]),
            status: get_u32_be(&wire[4..8]),
        };
        if !is_known_code(value.code)
            || expected_code.is_some_and(|code| code != value.code)
            || value.status > 5
        {
            return Err(CoreError::Malformed);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlRequest {
    DeviceList,
    Import { bus_id: String },
}

impl ControlRequest {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        match self {
            Self::DeviceList => Ok(Common {
                code: OP_REQ_DEVLIST,
                status: 0,
            }
            .encode()?
            .to_vec()),
            Self::Import { bus_id } => {
                validate_bus_id(bus_id)?;
                let mut wire = vec![0; COMMON_SIZE + BUS_ID_SIZE];
                wire[..COMMON_SIZE].copy_from_slice(
                    &Common {
                        code: OP_REQ_IMPORT,
                        status: 0,
                    }
                    .encode()?,
                );
                wire[COMMON_SIZE..COMMON_SIZE + bus_id.len()].copy_from_slice(bus_id.as_bytes());
                Ok(wire)
            }
        }
    }

    pub fn decode(wire: &[u8]) -> CoreResult<Self> {
        let common = Common::decode(wire, None)?;
        if common.status != 0 {
            return Err(CoreError::Malformed);
        }
        match common.code {
            OP_REQ_DEVLIST if wire.len() == COMMON_SIZE => Ok(Self::DeviceList),
            OP_REQ_DEVLIST if wire.len() == COMMON_SIZE + 4 && wire[8..12] == [0; 4] => {
                Ok(Self::DeviceList)
            }
            OP_REQ_IMPORT if wire.len() == COMMON_SIZE + BUS_ID_SIZE => {
                let bus_id = decode_c_field(&wire[COMMON_SIZE..])?;
                validate_bus_id(&bus_id)?;
                Ok(Self::Import { bus_id })
            }
            _ => Err(CoreError::Malformed),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Device {
    pub path: String,
    pub bus_id: String,
    pub bus_number: u32,
    pub device_number: u32,
    pub speed: u32,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_bcd: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub configuration_value: u8,
    pub configuration_count: u8,
    pub interface_count: u8,
}

impl Device {
    pub fn encode(&self) -> CoreResult<[u8; DEVICE_SIZE]> {
        validate_c_field(&self.path, 256)?;
        validate_bus_id(&self.bus_id)?;
        let mut wire = [0; DEVICE_SIZE];
        wire[..self.path.len()].copy_from_slice(self.path.as_bytes());
        wire[256..256 + self.bus_id.len()].copy_from_slice(self.bus_id.as_bytes());
        put_u32_be(&mut wire[288..292], self.bus_number);
        put_u32_be(&mut wire[292..296], self.device_number);
        put_u32_be(&mut wire[296..300], self.speed);
        put_u16_be(&mut wire[300..302], self.vendor_id);
        put_u16_be(&mut wire[302..304], self.product_id);
        put_u16_be(&mut wire[304..306], self.device_bcd);
        wire[306] = self.device_class;
        wire[307] = self.device_subclass;
        wire[308] = self.device_protocol;
        wire[309] = self.configuration_value;
        wire[310] = self.configuration_count;
        wire[311] = self.interface_count;
        Ok(wire)
    }

    pub fn decode(wire: &[u8]) -> CoreResult<Self> {
        if wire.len() != DEVICE_SIZE {
            return Err(CoreError::Malformed);
        }
        Ok(Self {
            path: decode_c_field(&wire[..256])?,
            bus_id: decode_c_field(&wire[256..288])?,
            bus_number: get_u32_be(&wire[288..292]),
            device_number: get_u32_be(&wire[292..296]),
            speed: get_u32_be(&wire[296..300]),
            vendor_id: get_u16_be(&wire[300..302]),
            product_id: get_u16_be(&wire[302..304]),
            device_bcd: get_u16_be(&wire[304..306]),
            device_class: wire[306],
            device_subclass: wire[307],
            device_protocol: wire[308],
            configuration_value: wire[309],
            configuration_count: wire[310],
            interface_count: wire[311],
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interface {
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
}

impl Interface {
    #[must_use]
    pub const fn encode(self) -> [u8; INTERFACE_SIZE] {
        [self.class, self.subclass, self.protocol, 0]
    }

    pub fn decode(wire: &[u8]) -> CoreResult<Self> {
        if wire.len() != INTERFACE_SIZE || wire[3] != 0 {
            return Err(CoreError::Malformed);
        }
        Ok(Self {
            class: wire[0],
            subclass: wire[1],
            protocol: wire[2],
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRecord {
    pub device: Device,
    pub interfaces: Vec<Interface>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlReply {
    DeviceList {
        status: u32,
        devices: Vec<DeviceRecord>,
    },
    Import {
        status: u32,
        device: Option<Device>,
    },
}

impl ControlReply {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        match self {
            Self::DeviceList { status, devices } => {
                if *status != 0 {
                    return Ok(Common {
                        code: OP_REP_DEVLIST,
                        status: *status,
                    }
                    .encode()?
                    .to_vec());
                }
                if devices.len() > 1024 {
                    return Err(CoreError::LimitExceeded);
                }
                let mut wire = Vec::new();
                wire.extend_from_slice(
                    &Common {
                        code: OP_REP_DEVLIST,
                        status: 0,
                    }
                    .encode()?,
                );
                let device_count =
                    u32::try_from(devices.len()).map_err(|_| CoreError::LimitExceeded)?;
                wire.extend_from_slice(&device_count.to_be_bytes());
                for record in devices {
                    if record.interfaces.len() != usize::from(record.device.interface_count) {
                        return Err(CoreError::Malformed);
                    }
                    wire.extend_from_slice(&record.device.encode()?);
                    for interface in &record.interfaces {
                        wire.extend_from_slice(&interface.encode());
                    }
                }
                if wire.len() > 4 * 1024 * 1024 {
                    return Err(CoreError::LimitExceeded);
                }
                Ok(wire)
            }
            Self::Import { status, device } => {
                if (*status == 0) != device.is_some() {
                    return Err(CoreError::Malformed);
                }
                let mut wire = Common {
                    code: OP_REP_IMPORT,
                    status: *status,
                }
                .encode()?
                .to_vec();
                if let Some(device) = device {
                    wire.extend_from_slice(&device.encode()?);
                }
                Ok(wire)
            }
        }
    }

    pub fn decode(wire: &[u8]) -> CoreResult<Self> {
        let common = Common::decode(wire, None)?;
        match common.code {
            OP_REP_IMPORT => {
                if common.status == 0 {
                    if wire.len() != COMMON_SIZE + DEVICE_SIZE {
                        return Err(CoreError::Malformed);
                    }
                    Ok(Self::Import {
                        status: 0,
                        device: Some(Device::decode(&wire[COMMON_SIZE..])?),
                    })
                } else if wire.len() == COMMON_SIZE {
                    Ok(Self::Import {
                        status: common.status,
                        device: None,
                    })
                } else {
                    Err(CoreError::Malformed)
                }
            }
            OP_REP_DEVLIST => {
                if common.status != 0 {
                    return if wire.len() == COMMON_SIZE {
                        Ok(Self::DeviceList {
                            status: common.status,
                            devices: Vec::new(),
                        })
                    } else {
                        Err(CoreError::Malformed)
                    };
                }
                if wire.len() < COMMON_SIZE + 4 || wire.len() > 4 * 1024 * 1024 {
                    return Err(CoreError::Malformed);
                }
                let device_count = get_u32_be(&wire[8..12]) as usize;
                if device_count > 1024 {
                    return Err(CoreError::LimitExceeded);
                }
                let mut offset: usize = 12;
                let mut devices = Vec::with_capacity(device_count);
                for _ in 0..device_count {
                    let device_end = offset
                        .checked_add(DEVICE_SIZE)
                        .ok_or(CoreError::LimitExceeded)?;
                    if device_end > wire.len() {
                        return Err(CoreError::Malformed);
                    }
                    let device = Device::decode(&wire[offset..device_end])?;
                    offset = device_end;
                    let interface_count = usize::from(device.interface_count);
                    let interfaces_end = offset
                        .checked_add(interface_count * INTERFACE_SIZE)
                        .ok_or(CoreError::LimitExceeded)?;
                    if interfaces_end > wire.len() {
                        return Err(CoreError::Malformed);
                    }
                    let mut interfaces = Vec::with_capacity(interface_count);
                    for chunk in wire[offset..interfaces_end].chunks_exact(INTERFACE_SIZE) {
                        interfaces.push(Interface::decode(chunk)?);
                    }
                    offset = interfaces_end;
                    devices.push(DeviceRecord { device, interfaces });
                }
                if offset != wire.len() {
                    return Err(CoreError::Malformed);
                }
                Ok(Self::DeviceList { status: 0, devices })
            }
            _ => Err(CoreError::Unsupported),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerState {
    New,
    DeviceListReplyPending,
    Ready,
    ImportReplyPending,
    Imported,
    Closed,
    Failed,
}

#[derive(Debug)]
pub struct ServerSession {
    expected_bus_id: String,
    state: ServerState,
}

impl ServerSession {
    pub fn new(expected_bus_id: String) -> CoreResult<Self> {
        validate_bus_id(&expected_bus_id)?;
        Ok(Self {
            expected_bus_id,
            state: ServerState::New,
        })
    }

    #[must_use]
    pub const fn state(&self) -> ServerState {
        self.state
    }

    pub fn accept_request(&mut self, wire: &[u8]) -> CoreResult<ControlRequest> {
        if matches!(self.state, ServerState::Closed | ServerState::Failed) {
            return Err(CoreError::InvalidState);
        }
        let request = ControlRequest::decode(wire)?;
        match &request {
            ControlRequest::DeviceList
                if matches!(self.state, ServerState::New | ServerState::Ready) =>
            {
                self.state = ServerState::DeviceListReplyPending;
            }
            ControlRequest::Import { bus_id }
                if matches!(self.state, ServerState::New | ServerState::Ready)
                    && bus_id == &self.expected_bus_id =>
            {
                self.state = ServerState::ImportReplyPending;
            }
            _ => {
                self.state = ServerState::Failed;
                return Err(CoreError::InvalidState);
            }
        }
        Ok(request)
    }

    pub fn complete_device_list(&mut self, status: u32, device_count: usize) -> CoreResult<()> {
        if self.state != ServerState::DeviceListReplyPending
            || status > 5
            || (status != 0 && device_count != 0)
        {
            return Err(CoreError::InvalidState);
        }
        self.state = ServerState::Ready;
        Ok(())
    }

    pub fn complete_import(&mut self, status: u32, device: Option<&Device>) -> CoreResult<()> {
        if self.state != ServerState::ImportReplyPending || status > 5 {
            return Err(CoreError::InvalidState);
        }
        if status == 0 {
            let device = device.ok_or(CoreError::InvalidArgument)?;
            if device.bus_id != self.expected_bus_id {
                self.state = ServerState::Failed;
                return Err(CoreError::TokenMismatch);
            }
            self.state = ServerState::Imported;
        } else {
            if device.is_some() {
                return Err(CoreError::InvalidArgument);
            }
            self.state = ServerState::Ready;
        }
        Ok(())
    }

    pub fn accept_data(&self) -> CoreResult<()> {
        if self.state == ServerState::Imported {
            Ok(())
        } else {
            Err(CoreError::InvalidState)
        }
    }

    pub fn close(&mut self) {
        self.state = ServerState::Closed;
    }
}

const fn is_known_code(code: u16) -> bool {
    matches!(
        code,
        OP_REQ_IMPORT | OP_REP_IMPORT | OP_REQ_DEVLIST | OP_REP_DEVLIST
    )
}

fn validate_bus_id(value: &str) -> CoreResult<()> {
    validate_c_field(value, BUS_ID_SIZE)
}

fn validate_c_field(value: &str, capacity: usize) -> CoreResult<()> {
    if value.is_empty() || value.len() >= capacity || value.as_bytes().contains(&0) {
        return Err(CoreError::Malformed);
    }
    Ok(())
}

fn decode_c_field(bytes: &[u8]) -> CoreResult<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0 || bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(CoreError::Malformed);
    }
    String::from_utf8(bytes[..end].to_vec()).map_err(|_| CoreError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let import = ControlRequest::Import {
            bus_id: "moonlight-1".into(),
        };
        assert_eq!(
            ControlRequest::decode(&import.encode().unwrap()).unwrap(),
            import
        );
        let list = ControlRequest::DeviceList;
        assert_eq!(
            ControlRequest::decode(&list.encode().unwrap()).unwrap(),
            list
        );
    }

    #[test]
    fn import_is_bound_to_advertised_bus_id() {
        let mut session = ServerSession::new("moonlight-1".into()).unwrap();
        let other = ControlRequest::Import {
            bus_id: "other".into(),
        }
        .encode()
        .unwrap();
        assert_eq!(session.accept_request(&other), Err(CoreError::InvalidState));
        assert_eq!(session.state(), ServerState::Failed);
    }
}
