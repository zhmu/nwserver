use crate::types::*;
use crate::error::*;
use crate::ncp::PathString;

use std::io::Read;
use byteorder::{BigEndian, ReadBytesExt};

use nwserver_macros::NcpPacket;

#[derive(Debug)]
pub struct NcpHeader {
    pub request_type: u16,
    pub sequence_number: u8,
    pub connection_number: u8,
    pub task_number: u8,
    pub reserved: u8,
    pub function_code: u8,
}

impl NcpHeader {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let request_type = rdr.read_u16::<BigEndian>()?;
        let sequence_number = rdr.read_u8()?;
        let connection_number = rdr.read_u8()?;
        let task_number = rdr.read_u8()?;
        let reserved = rdr.read_u8()?;
        let function_code = rdr.read_u8()?;
        Ok(Self{ request_type, sequence_number, connection_number, task_number, reserved, function_code })
    }
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct GetFileServerInfo {
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct ReadPropertyValue {
    object_type: u16,
    object_name: MaxBoundedString,
    segment_number: u8,
    property_name: MaxBoundedString,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct NegotiateBufferSize {
    pub proposed_buffer_size: u16
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct FileSearchInit {
    pub handle: u8,
    pub path: PathString,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct FileSearchContinue {
    pub volume_number: u8,
    pub directory_id: u16,
    pub search_sequence: u16,
    pub search_attr: u8,
    pub search_path: MaxBoundedString,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct GetBigPacketNCPMaxPacketSize {
    pub proposed_max_size: u16,
    pub security_flag: u8,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct PacketBurstConnectionRequest {
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct GetFileServerDateAndTime {
}


#[derive(Debug)]
#[derive(NcpPacket)]
pub struct GetEffectiveDirectoryRights {
    pub directory_handle: u8,
    pub directory_path: PathString,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct GetVolumeInfoWithHandle {
    pub directory_handle: u8
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct AllocateTemporaryDirectoryHandle {
    pub source_directory_handle: u8,
    pub handle_name: u8,
    pub directory_path: PathString,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct DeallocateDirectoryHandle {
    pub directory_handle: u8,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct OpenFile {
    pub directory_handle: u8,
    pub search_attr: u8,
    pub desired_access: u8,
    pub filename: PathString,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct ReadFromFile {
    _reserved: u8,
    _file_handle_hi: u32,
    pub file_handle: u16,
    pub offset: u32,
    pub length: u16,
}

#[derive(Debug)]
#[derive(NcpPacket)]
pub struct CloseFile {
    _reserved: u8,
    _file_handle_hi: u32,
    pub file_handle: u16,
}

pub enum Request {
    UnrecognizedRequest(u8, u8),
    GetFileServerInfo(GetFileServerInfo),
    ReadPropertyValue(ReadPropertyValue),
    NegotiateBufferSize(NegotiateBufferSize),
    FileSearchInit(FileSearchInit),
    FileSearchContinue(FileSearchContinue),
    GetBigPacketNCPMaxPacketSize(GetBigPacketNCPMaxPacketSize),
    PacketBurstConnectionRequest(PacketBurstConnectionRequest),
    GetFileServerDateAndTime(GetFileServerDateAndTime),
    GetEffectiveDirectoryRights(GetEffectiveDirectoryRights),
    GetVolumeInfoWithHandle(GetVolumeInfoWithHandle),
    AllocateTemporaryDirectoryHandle(AllocateTemporaryDirectoryHandle),
    DeallocateDirectoryHandle(DeallocateDirectoryHandle),
    OpenFile(OpenFile),
    ReadFromFile(ReadFromFile),
    CloseFile(CloseFile),
}

impl Request {
    pub fn from<T: Read + ReadBytesExt>(header: &NcpHeader, rdr: &mut T) -> Result<Self, NetWareError> {
        return match header.function_code {
            20 => { Ok(Request::GetFileServerDateAndTime(GetFileServerDateAndTime::from(rdr)?)) },
            22 => { Request::from_22(rdr) },
            23 => { Request::from_23(rdr) },
            33 => { Ok(Request::NegotiateBufferSize(NegotiateBufferSize::from(rdr)?)) },
            62 => { Ok(Request::FileSearchInit(FileSearchInit::from(rdr)?)) },
            63 => { Ok(Request::FileSearchContinue(FileSearchContinue::from(rdr)?)) },
            66 => { Ok(Request::CloseFile(CloseFile::from(rdr)?)) },
            72 => { Ok(Request::ReadFromFile(ReadFromFile::from(rdr)?)) },
            76 => { Ok(Request::OpenFile(OpenFile::from(rdr)?)) },
            97 => { Ok(Request::GetBigPacketNCPMaxPacketSize(GetBigPacketNCPMaxPacketSize::from(rdr)?)) },
            101 => { Ok(Request::PacketBurstConnectionRequest(PacketBurstConnectionRequest::from(rdr)?)) },
            _ => {
                Ok(Request::UnrecognizedRequest(header.function_code, 0))
            },
        }
    }

    fn from_22<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let sub_func_struc_len = rdr.read_u16::<BigEndian>()?;
        let sub_func = rdr.read_u8()?;
/*
        if payload.len() != 2 + (sub_func_struc_len as usize) {
            return Err(NetWareError::RequestLengthMismatch);
        }
*/
        return match sub_func {
            3 => { Ok(Request::GetEffectiveDirectoryRights(GetEffectiveDirectoryRights::from(rdr)?)) },
            19 => { Ok(Request::AllocateTemporaryDirectoryHandle(AllocateTemporaryDirectoryHandle::from(rdr)?)) },
            20 => { Ok(Request::DeallocateDirectoryHandle(DeallocateDirectoryHandle::from(rdr)?)) },
            21 => { Ok(Request::GetVolumeInfoWithHandle(GetVolumeInfoWithHandle::from(rdr)?)) },
            _ => { Ok(Request::UnrecognizedRequest(22, sub_func)) },
        }
    }

    fn from_23<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let sub_func_struc_len = rdr.read_u16::<BigEndian>()?;
        let sub_func = rdr.read_u8()?;
/*
        if payload.len() != 2 + (sub_func_struc_len as usize) {
            warn!("{}: request 23 struct length mismatch (got {}, but payload length is {}), dropping",
                conn_nr, sub_func_struc_len, payload.len());
            return Err(NetWareError::RequestLengthMismatch);
        }
*/
        return match sub_func {
            17 => { Ok(Request::GetFileServerInfo(GetFileServerInfo::from(rdr)?)) },
            61 => { Ok(Request::ReadPropertyValue(ReadPropertyValue::from(rdr)?)) },
            _ => { Ok(Request::UnrecognizedRequest(23, sub_func)) },
        }
    }
}
