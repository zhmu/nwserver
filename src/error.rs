#[derive(Debug)]
pub enum NetWareError {
    ConnectionNotLoggedIn,
    OutOfHandles,
    IoError(std::io::Error),
    InvalidFileHandle,
    BadDirectoryHandle,
    NoDirectoryHandlesLeft,
    InvalidPath,
    DirectoryIoError,
    NoSuchSet,
    NoFilesFound,
    UnsupportedRequest,
    StringTooLong,
    RequestLengthMismatch,
}

impl NetWareError {
    pub fn to_error_code(&self) -> u8 {
        return match self {
            NetWareError::ConnectionNotLoggedIn => 0x7d,
            NetWareError::OutOfHandles => 0x81,
            NetWareError::IoError(_) => 0x83,
            NetWareError::InvalidFileHandle => 0x88,
            NetWareError::BadDirectoryHandle => 0x9b,
            NetWareError::NoDirectoryHandlesLeft => 0x9d,
            NetWareError::InvalidPath => 0x9c,
            NetWareError::DirectoryIoError => 0xa1,
            NetWareError::NoSuchSet => 0xec,
            NetWareError::NoFilesFound => 0xff,
            NetWareError::UnsupportedRequest | NetWareError::StringTooLong |
            NetWareError::RequestLengthMismatch => { 0xff },
        }
    }
}

impl From<std::io::Error> for NetWareError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}
