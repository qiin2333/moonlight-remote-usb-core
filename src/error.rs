use core::fmt;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CoreError {
    InvalidArgument = 1,
    BufferTooSmall = 2,
    VersionMismatch = 3,
    BadMagic = 4,
    Malformed = 5,
    TokenMismatch = 6,
    SequenceError = 7,
    InvalidState = 8,
    LimitExceeded = 9,
    WindowExhausted = 10,
    Duplicate = 11,
    NotFound = 12,
    Busy = 13,
    Unsupported = 14,
    NoMemory = 15,
    Internal = 255,
}

impl CoreError {
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid argument",
            Self::BufferTooSmall => "buffer too small",
            Self::VersionMismatch => "version mismatch",
            Self::BadMagic => "bad magic",
            Self::Malformed => "malformed message",
            Self::TokenMismatch => "token mismatch",
            Self::SequenceError => "sequence error",
            Self::InvalidState => "invalid state",
            Self::LimitExceeded => "limit exceeded",
            Self::WindowExhausted => "flow-control window exhausted",
            Self::Duplicate => "duplicate request",
            Self::NotFound => "request not found",
            Self::Busy => "resource busy",
            Self::Unsupported => "unsupported operation",
            Self::NoMemory => "allocation failed",
            Self::Internal => "internal error",
        })
    }
}

impl std::error::Error for CoreError {}
