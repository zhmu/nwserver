/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::types::*;
use crate::error::*;

use std::fmt;
use std::io::Read;
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};

use nwserver_macros::NcpPacket;

const REQUEST_TYPE_CREATE_SERVICE_CONNECTION: u16 = 0x1111;
const REQUEST_TYPE_REQUEST: u16 = 0x2222;
const _REQUEST_TYPE_REPLY: u16 = 0x3333;
const REQUEST_TYPE_DESTROY_SERVICE_CONNECTION: u16 = 0x5555;

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

#[derive(NcpPacket)]
pub struct GetFileServerInfo {
//    #[descr="Get file server information"]
}

#[derive(NcpPacket)]
pub struct ReadPropertyValue {
    #[descr="Read property value"]
    pub object_type: u16,
    pub object_name: MaxBoundedString,
    pub segment_number: u8,
    pub property_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct Logout {
}

#[derive(NcpPacket)]
pub struct NegotiateBufferSize {
    #[descr="Negotiate buffer size"]
    pub proposed_buffer_size: u16
}

#[derive(NcpPacket)]
pub struct FileSearchInit {
    #[descr="File search initialize"]
    pub handle: u8,
    pub path: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct FileSearchContinue {
    #[descr="File search continue"]
    pub volume_number: u8,
    pub directory_id: u16,
    pub search_sequence: u16,
    pub search_attr: u8,
    pub search_path: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct GetBigPacketNCPMaxPacketSize {
    #[descr="Get big packet NCP max packet size"]
    pub proposed_max_size: u16,
    pub security_flag: u8,
}

#[derive(NcpPacket)]
pub struct PacketBurstConnectionRequest {
//    #[descr="Packet burst connection request"]
}

#[derive(NcpPacket)]
pub struct GetFileServerDateAndTime {
//    #[descr="Get file server date and time"]
}


#[derive(NcpPacket)]
pub struct GetEffectiveDirectoryRights {
    #[descr="Get effective directory rights"]
    pub directory_handle: u8,
    pub directory_path: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct GetVolumeInfoWithHandle {
    #[descr="Get volume information with handle"]
    pub directory_handle: u8
}

#[derive(NcpPacket)]
pub struct AllocateTemporaryDirectoryHandle {
    #[descr="Allocate temporary directory handle"]
    pub source_directory_handle: u8,
    pub handle_name: u8,
    pub directory_path: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct DeallocateDirectoryHandle {
    #[descr="Deallocate directory handle"]
    pub directory_handle: u8,
}

#[derive(NcpPacket)]
pub struct OpenFile {
    #[descr="Open file"]
    pub directory_handle: u8,
    pub search_attr: u8,
    pub desired_access: u8,
    pub filename: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct ReadFromFile {
    #[descr="Read from file"]
    _reserved: u8,
    pub file_handle: NcpFileHandle,
    pub offset: u32,
    pub length: u16,
}

#[derive(NcpPacket)]
pub struct CloseFile {
    #[descr="Close file"]
    _reserved: u8,
    pub file_handle: NcpFileHandle,
}

#[derive(NcpPacket)]
pub struct GetDirectoryPath {
    #[descr="Get directory path"]
    pub directory_handle: u8,
}

#[derive(NcpPacket)]
pub struct SearchForFile {
    #[descr="Search for a file"]
    pub last_search_index: u16,
    pub directory_handle: u8,
    pub search_attr: u8,
    pub filename: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct LockPhysicalRecordOld {
    pub lock_flag: u8,
    pub file_handle: NcpFileHandle,
    pub lock_area_start_offset: u32,
    pub lock_area_length: u32,
    pub lock_timeout: u16,
}

#[derive(NcpPacket)]
pub struct ClearPhysicalRecord {
    _reserved: u8,
    pub file_handle: NcpFileHandle,
    pub lock_area_start_offset: u32,
    pub lock_area_length: u32,
}

#[derive(NcpPacket)]
pub struct EndOfJob {
}

#[derive(NcpPacket)]
pub struct GetBinderyAccessLevel {
}

#[derive(NcpPacket)]
pub struct GetBinderyObjectName {
    pub object_id: u32
}

#[derive(NcpPacket)]
pub struct ScanBinderyObject {
    pub last_object_seen: u32,
    pub search_object_type: u16,
    pub search_object_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct GetStationLoggedInfo {
    pub target_connection_num: LeU32,
}

#[derive(NcpPacket)]
pub struct GetInternetAddress {
    pub target_connection_num: LeU32,
}

#[derive(NcpPacket)]
pub struct GetLoginKey {
}

#[derive(NcpPacket)]
pub struct KeyedObjectLogin {
    pub key: LoginKey,
    pub object_type: u16,
    pub object_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct GetBinderyObjectID {
    pub object_type: u16,
    pub object_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct KeyedVerifyPassword {
    pub key: LoginKey,
    pub object_type: u16,
    pub object_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct KeyedChangePassword {
    pub key: LoginKey,
    pub object_type: u16,
    pub object_name: MaxBoundedString,
    pub new_password: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct DeleteObjectFromSet {
    pub object_type: u16,
    pub object_name: MaxBoundedString,
    pub property_name: MaxBoundedString,
    pub member_type: u16,
    pub member_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct IsObjectInSet {
    pub object_type: u16,
    pub object_name: MaxBoundedString,
    pub property_name: MaxBoundedString,
    pub member_type: u16,
    pub member_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct GetBinderyObjectAccessLevel {
    pub object_id: u32,
}

#[derive(NcpPacket)]
pub struct AddBinderyObjectToSet {
    pub object_type: u16,
    pub object_name: MaxBoundedString,
    pub property_name: MaxBoundedString,
    pub member_type: u16,
    pub member_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct CreateProperty {
    pub object_type: u16,
    pub object_name: MaxBoundedString,
    pub property_flags: u8,
    pub property_security: u8,
    pub property_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct WritePropertyValue {
    pub object_type: u16,
    pub object_name: MaxBoundedString,
    pub segment_number: u8,
    pub more_flag: u8,
    pub property_name: MaxBoundedString,
    pub property_value: PropertyValue,
}

#[derive(NcpPacket)]
pub struct CreateBinderyObject {
    pub object_flags: u8,
    pub object_security: u8,
    pub object_type: u16,
    pub object_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct DeleteBinderyObject {
    pub object_type: u16,
    pub object_name: MaxBoundedString,
}

#[derive(NcpPacket)]
pub struct CreateServiceConnection {
}

#[derive(NcpPacket)]
pub struct DestroyServiceConnection {
}

#[derive(Debug)]
pub enum Request {
    UnrecognizedRequest(u16, u8, u8),
    GetFileServerInfo(GetFileServerInfo),
    ReadPropertyValue(ReadPropertyValue),
    Logout(Logout),
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
    GetDirectoryPath(GetDirectoryPath),
    SearchForFile(SearchForFile),
    LockPhysicalRecordOld(LockPhysicalRecordOld),
    ClearPhysicalRecord(ClearPhysicalRecord),
    GetBinderyAccessLevel(GetBinderyAccessLevel),
    GetBinderyObjectName(GetBinderyObjectName),
    ScanBinderyObject(ScanBinderyObject),
    EndOfJob(EndOfJob),
    GetStationLoggedInfo(GetStationLoggedInfo),
    GetInternetAddress(GetInternetAddress),
    GetLoginKey(GetLoginKey),
    KeyedObjectLogin(KeyedObjectLogin),
    GetBinderyObjectID(GetBinderyObjectID),
    KeyedVerifyPassword(KeyedVerifyPassword),
    KeyedChangePassword(KeyedChangePassword),
    DeleteObjectFromSet(DeleteObjectFromSet),
    IsObjectInSet(IsObjectInSet),
    GetBinderyObjectAccessLevel(GetBinderyObjectAccessLevel),
    AddBinderyObjectToSet(AddBinderyObjectToSet),
    CreateProperty(CreateProperty),
    WritePropertyValue(WritePropertyValue),
    CreateBinderyObject(CreateBinderyObject),
    DeleteBinderyObject(DeleteBinderyObject),
    CreateServiceConnection(CreateServiceConnection),
    DestroyServiceConnection(DestroyServiceConnection),
}

impl Request {
    pub fn from<T: Read + ReadBytesExt>(header: &NcpHeader, rdr: &mut T) -> Result<Self, NetWareError> {
        match header.request_type {
            REQUEST_TYPE_CREATE_SERVICE_CONNECTION => { Ok(Request::CreateServiceConnection(CreateServiceConnection::from(rdr)?)) },
            REQUEST_TYPE_DESTROY_SERVICE_CONNECTION => { Ok(Request::DestroyServiceConnection(DestroyServiceConnection::from(rdr)?)) },
            REQUEST_TYPE_REQUEST => { Request::from_2222(header, rdr) }
            _ => { Ok(Request::UnrecognizedRequest(header.request_type, 0, 0)) }
        }
    }

    pub fn from_2222<T: Read + ReadBytesExt>(header: &NcpHeader, rdr: &mut T) -> Result<Self, NetWareError> {
        return match header.function_code {
            20 => { Ok(Request::GetFileServerDateAndTime(GetFileServerDateAndTime::from(rdr)?)) },
            22 => { Request::from_2222_22(rdr) },
            23 => { Request::from_2222_23(rdr) },
            24 => { Ok(Request::EndOfJob(EndOfJob::from(rdr)?)) },
            25 => { Ok(Request::Logout(Logout::from(rdr)?)) },
            26 => { Ok(Request::LockPhysicalRecordOld(LockPhysicalRecordOld::from(rdr)?)) },
            30 => { Ok(Request::ClearPhysicalRecord(ClearPhysicalRecord::from(rdr)?)) },
            33 => { Ok(Request::NegotiateBufferSize(NegotiateBufferSize::from(rdr)?)) },
            62 => { Ok(Request::FileSearchInit(FileSearchInit::from(rdr)?)) },
            63 => { Ok(Request::FileSearchContinue(FileSearchContinue::from(rdr)?)) },
            64 => { Ok(Request::SearchForFile(SearchForFile::from(rdr)?)) },
            66 => { Ok(Request::CloseFile(CloseFile::from(rdr)?)) },
            72 => { Ok(Request::ReadFromFile(ReadFromFile::from(rdr)?)) },
            76 => { Ok(Request::OpenFile(OpenFile::from(rdr)?)) },
            97 => { Ok(Request::GetBigPacketNCPMaxPacketSize(GetBigPacketNCPMaxPacketSize::from(rdr)?)) },
            101 => { Ok(Request::PacketBurstConnectionRequest(PacketBurstConnectionRequest::from(rdr)?)) },
            _ => {
                Ok(Request::UnrecognizedRequest(header.request_type, header.function_code, 0))
            },
        }
    }

    fn from_2222_22<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let _sub_func_struc_len = rdr.read_u16::<BigEndian>()?;
        let sub_func = rdr.read_u8()?;
/*
        if payload.len() != 2 + (sub_func_struc_len as usize) {
            return Err(NetWareError::RequestLengthMismatch);
        }
*/
        return match sub_func {
            1 => { Ok(Request::GetDirectoryPath(GetDirectoryPath::from(rdr)?)) },
            3 => { Ok(Request::GetEffectiveDirectoryRights(GetEffectiveDirectoryRights::from(rdr)?)) },
            19 => { Ok(Request::AllocateTemporaryDirectoryHandle(AllocateTemporaryDirectoryHandle::from(rdr)?)) },
            20 => { Ok(Request::DeallocateDirectoryHandle(DeallocateDirectoryHandle::from(rdr)?)) },
            21 => { Ok(Request::GetVolumeInfoWithHandle(GetVolumeInfoWithHandle::from(rdr)?)) },
            _ => { Ok(Request::UnrecognizedRequest(REQUEST_TYPE_REQUEST, 22, sub_func)) },
        }
    }

    fn from_2222_23<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let _sub_func_struc_len = rdr.read_u16::<BigEndian>()?;
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
            23 => { Ok(Request::GetLoginKey(GetLoginKey::from(rdr)?)) },
            24 => { Ok(Request::KeyedObjectLogin(KeyedObjectLogin::from(rdr)?)) },
            26 => { Ok(Request::GetInternetAddress(GetInternetAddress::from(rdr)?)) },
            28 => { Ok(Request::GetStationLoggedInfo(GetStationLoggedInfo::from(rdr)?)) },
            50 => { Ok(Request::CreateBinderyObject(CreateBinderyObject::from(rdr)?)) },
            51 => { Ok(Request::DeleteBinderyObject(DeleteBinderyObject::from(rdr)?)) },
            53 => { Ok(Request::GetBinderyObjectID(GetBinderyObjectID::from(rdr)?)) },
            54 => { Ok(Request::GetBinderyObjectName(GetBinderyObjectName::from(rdr)?)) },
            55 => { Ok(Request::ScanBinderyObject(ScanBinderyObject::from(rdr)?)) },
            57 => { Ok(Request::CreateProperty(CreateProperty::from(rdr)?)) },
            61 => { Ok(Request::ReadPropertyValue(ReadPropertyValue::from(rdr)?)) },
            62 => { Ok(Request::WritePropertyValue(WritePropertyValue::from(rdr)?)) },
            65 => { Ok(Request::AddBinderyObjectToSet(AddBinderyObjectToSet::from(rdr)?)) },
            66 => { Ok(Request::DeleteObjectFromSet(DeleteObjectFromSet::from(rdr)?)) },
            67 => { Ok(Request::IsObjectInSet(IsObjectInSet::from(rdr)?)) },
            70 => { Ok(Request::GetBinderyAccessLevel(GetBinderyAccessLevel::from(rdr)?)) },
            72 => { Ok(Request::GetBinderyObjectAccessLevel(GetBinderyObjectAccessLevel::from(rdr)?)) },
            74 => { Ok(Request::KeyedVerifyPassword(KeyedVerifyPassword::from(rdr)?)) },
            75 => { Ok(Request::KeyedChangePassword(KeyedChangePassword::from(rdr)?)) },
            _ => { Ok(Request::UnrecognizedRequest(REQUEST_TYPE_REQUEST, 23, sub_func)) },
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:?}", self)
    }
}
