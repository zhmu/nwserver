use crate::types::*;
use crate::error::*;
use crate::ncp::PathString;

use std::io::Read;
use byteorder::{BigEndian, ReadBytesExt};

#[derive(Debug)]
pub struct NcpRequest {
    pub request_type: u16,
    pub sequence_number: u8,
    pub connection_number: u8,
    pub task_number: u8,
    pub reserved: u8,
    pub function_code: u8,
}

impl NcpRequest {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let request_type = rdr.read_u16::<BigEndian>()?;
        let sequence_number = rdr.read_u8()?;
        let connection_number = rdr.read_u8()?;
        let task_number = rdr.read_u8()?;
        let reserved = rdr.read_u8()?;
        let function_code = rdr.read_u8()?;
        Ok(NcpRequest{ request_type, sequence_number, connection_number, task_number, reserved, function_code })
    }
}

#[derive(Debug)]
pub struct GetFileServerInfo {
}

impl GetFileServerInfo {
    pub fn from<T: Read + ReadBytesExt>(_rdr: &mut T) -> Result<Self, NetWareError> {
        Ok(Self{})
    }
}

#[derive(Debug)]
pub struct ReadPropertyValue {
    object_type: u16,
    object_name: MaxBoundedString,
    segment_number: u8,
    property_name: MaxBoundedString,
}

impl ReadPropertyValue {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let object_type = rdr.read_u16::<BigEndian>()?;
        let object_name = MaxBoundedString::from(rdr)?;
        let segment_number = rdr.read_u8()?;
        let property_name = MaxBoundedString::from(rdr)?;
        Ok(Self{ object_type, object_name, segment_number, property_name })
    }
}

#[derive(Debug)]
pub struct NegotiateBufferSize {
    pub proposed_buffer_size: u16
}

impl NegotiateBufferSize {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let proposed_buffer_size = rdr.read_u16::<BigEndian>()?;
        Ok(Self{ proposed_buffer_size })
    }
}

#[derive(Debug)]
pub struct FileSearchInit {
    pub handle: u8,
    pub path: PathString,
}

impl FileSearchInit {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let handle = rdr.read_u8()?;
        let path = PathString::from(rdr)?;
        Ok(Self{ handle, path })
    }
}

#[derive(Debug)]
pub struct FileSearchContinue {
    pub volume_number: u8,
    pub directory_id: u16,
    pub search_sequence: u16,
    pub search_attr: u8,
    pub search_path: MaxBoundedString,
}

impl FileSearchContinue {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let volume_number = rdr.read_u8()?;
        let directory_id = rdr.read_u16::<BigEndian>()?;
        let search_sequence = rdr.read_u16::<BigEndian>()?;
        let search_attr = rdr.read_u8()?;
        let search_path = MaxBoundedString::from(rdr)?;
        Ok(Self{ volume_number, directory_id, search_sequence, search_attr, search_path })
    }
}

#[derive(Debug)]
pub struct GetBigPacketNCPMaxPacketSize {
    pub proposed_max_size: u16,
    pub security_flag: u8,
}

impl GetBigPacketNCPMaxPacketSize {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let proposed_max_size = rdr.read_u16::<BigEndian>()?;
        let security_flag = rdr.read_u8()?;
        Ok(Self{ proposed_max_size, security_flag })
    }
}

#[derive(Debug)]
pub struct PacketBurstConnectionRequest {
}

impl PacketBurstConnectionRequest {
    pub fn from<T: Read + ReadBytesExt>(_rdr: &mut T) -> Result<Self, NetWareError> {
        Ok(Self{})
    }
}

#[derive(Debug)]
pub struct GetFileServerDateAndTime {
}

impl GetFileServerDateAndTime {
    pub fn from<T: Read + ReadBytesExt>(_rdr: &mut T) -> Result<Self, NetWareError> {
        Ok(Self{})
    }
}

#[derive(Debug)]
pub struct GetEffectiveDirectoryRights {
    pub directory_handle: u8,
    pub directory_path: PathString,
}

impl GetEffectiveDirectoryRights {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let directory_handle = rdr.read_u8()?;
        let directory_path = PathString::from(rdr)?;
        Ok(Self{ directory_handle, directory_path })
    }
}

#[derive(Debug)]
pub struct GetVolumeInfoWithHandle {
    pub directory_handle: u8
}

impl GetVolumeInfoWithHandle {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let directory_handle = rdr.read_u8()?;
        Ok(Self{ directory_handle })
    }
}

#[derive(Debug)]
pub struct AllocateTemporaryDirectoryHandle {
    pub source_directory_handle: u8,
    pub handle_name: u8,
    pub directory_path: PathString,
}

impl AllocateTemporaryDirectoryHandle {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let source_directory_handle = rdr.read_u8()?;
        let handle_name = rdr.read_u8()?;
        let directory_path = PathString::from(rdr)?;
        Ok(Self{ source_directory_handle, handle_name, directory_path })
    }
}

#[derive(Debug)]
pub struct DeallocateDirectoryHandle {
    pub directory_handle: u8,
}

impl DeallocateDirectoryHandle {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let directory_handle = rdr.read_u8()?;
        Ok(Self{ directory_handle })
    }
}

#[derive(Debug)]
pub struct OpenFile {
    pub directory_handle: u8,
    pub search_attr: u8,
    pub desired_access: u8,
    pub filename: PathString,
}

impl OpenFile {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let directory_handle = rdr.read_u8()?;
        let search_attr = rdr.read_u8()?;
        let desired_access = rdr.read_u8()?;
        let filename = PathString::from(rdr)?;
        Ok(Self{ directory_handle, search_attr, desired_access, filename })
    }
}

#[derive(Debug)]
pub struct ReadFromFile {
    _reserved: u8,
    _file_handle_hi: u32,
    pub file_handle: u16,
    pub offset: u32,
    pub length: u16,
}

impl ReadFromFile {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let _reserved = rdr.read_u8()?;
        let _file_handle_hi = rdr.read_u32::<BigEndian>()?;
        let file_handle = rdr.read_u16::<BigEndian>()?;
        let offset = rdr.read_u32::<BigEndian>()?;
        let length = rdr.read_u16::<BigEndian>()?;
        Ok(Self{ _reserved, _file_handle_hi, file_handle, offset, length })
    }
}

#[derive(Debug)]
pub struct CloseFile {
    _reserved: u8,
    _file_handle_hi: u32,
    pub file_handle: u16,
}

impl CloseFile {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let _reserved = rdr.read_u8()?;
        let _file_handle_hi = rdr.read_u32::<BigEndian>()?;
        let file_handle = rdr.read_u16::<BigEndian>()?;
        Ok(Self{ _reserved, _file_handle_hi, file_handle })
    }
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
    pub fn from<T: Read + ReadBytesExt>(request: &NcpRequest, rdr: &mut T) -> Result<Self, NetWareError> {
        return match request.function_code {
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
                Ok(Request::UnrecognizedRequest(request.function_code, 0))
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
