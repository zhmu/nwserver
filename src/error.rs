/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
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
    NoSuchVolume,
    NoConnectionsAvailable,
    NoSuchObject,
    NoSuchProperty,
    BadStationNumber,
    StationNotLoggedOn,
    NoKeyAvailable,
    InvalidPassword,
    NoSuchMember,
    PropertyExists,
    InvalidPropertyFlags,
    NoCreatePrivileges,
    NoDeletePrivileges,
    ServerLoginLocked,
    NoWritePrivileges,
    NoMoreDirectoryEntries,
    NoConsoleRights,
    TrusteeNotFound,
    MemberExists,
}

impl NetWareError {
    pub fn to_error_code(&self) -> u8 {
        match self {
            NetWareError::NoKeyAvailable => 0x96,
            NetWareError::ConnectionNotLoggedIn => 0x7d,
            NetWareError::OutOfHandles => 0x81,
            NetWareError::IoError(_) => 0x83,
            NetWareError::NoCreatePrivileges => 0x84,
            NetWareError::InvalidFileHandle => 0x88,
            NetWareError::NoDeletePrivileges => 0x8a,
            NetWareError::NoWritePrivileges => 0x94,
            NetWareError::BadDirectoryHandle => 0x9b,
            NetWareError::NoDirectoryHandlesLeft => 0x9d,
            NetWareError::InvalidPath => 0x9c,
            NetWareError::DirectoryIoError => 0xa1,
            NetWareError::ServerLoginLocked => 0xc5,
            NetWareError::NoConsoleRights => 0xc6,
            NetWareError::InvalidPassword => 0xde,
            NetWareError::MemberExists => 0xe9,
            NetWareError::NoSuchMember => 0xea,
            NetWareError::NoSuchSet => 0xec,
            NetWareError::PropertyExists => 0xed,
            NetWareError::NoSuchProperty | NetWareError::StationNotLoggedOn => 0xfb,
            NetWareError::NoSuchObject => 0xfc,
            NetWareError::BadStationNumber => 0xfd,
            NetWareError::TrusteeNotFound => 0xfe,
            NetWareError::NoFilesFound => 0xff,
            NetWareError::UnsupportedRequest | NetWareError::StringTooLong |
            NetWareError::RequestLengthMismatch | NetWareError::NoSuchVolume |
            NetWareError::NoConnectionsAvailable | NetWareError::InvalidPropertyFlags |
            NetWareError::NoMoreDirectoryEntries => 0xff,
        }
    }
}

impl From<std::io::Error> for NetWareError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}
