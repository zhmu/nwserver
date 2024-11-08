/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::bindery;
use crate::config;
use crate::consts;
use crate::clients;
use crate::ipx;
use crate::trustee;
use crate::types::*;
use crate::error::NetWareError;
use crate::ncp;

use std::io::{Cursor, Read};

use log::*;

use byteorder::{ByteOrder, BigEndian, ReadBytesExt};
use pnet::packet::Packet;

const REQUEST_TYPE_REPLY: u16 = 0x3333;

const CONNECTION_STATUS_NO_CONNECTIONS_AVAILABLE: u8 = 0x04;
const _CONNECTION_STATUS_SERVER_DOWN: u8 = 0x10;

pub struct NcpService<'a> {
    config: &'a config::Configuration,
    tx: &'a ipx::Transmitter,
    clients: clients::Clients<'a>,
    bindery: bindery::Bindery,
    trustee_db: trustee::TrusteeDB,
}

const NCP_REPLY_HEADER_LENGTH: usize = 8;
const NCP_REPLY_MAX_LENGTH: usize = consts::MAX_PAYLOAD_SIZE + NCP_REPLY_HEADER_LENGTH + 3;

pub struct NcpReplyPacket {
    payload: [ u8; NCP_REPLY_MAX_LENGTH ],
    payload_length: usize,
}

impl NcpReplyPacket {
    pub fn new(header: &ncp::parser::NcpHeader) -> Self {
        let payload = [ 0u8; NCP_REPLY_MAX_LENGTH ];
        let mut result = NcpReplyPacket{ payload, payload_length: 0 };
        result.add_u16(REQUEST_TYPE_REPLY);
        result.add_u8(header.sequence_number);
        result.add_u8(header.connection_number);
        result.add_u8(header.task_number);
        result.add_u8(0); // reserved
        result.add_u8(0); // completion code
        result.add_u8(0); // connection status
        result
    }

    pub fn set_connection_number(&mut self, conn: u8) {
        self.payload[3] = conn;
    }

    pub fn set_completion_code(&mut self, code: u8) {
        self.payload[6] = code;
    }

    pub fn set_connection_status(&mut self, status: u8) {
        self.payload[7] = status;
    }
}

impl DataStreamer for NcpReplyPacket {
    fn add_data(&mut self, value: &[u8]) {
        let end = self.payload_length + value.len();
        assert!(end <= NCP_REPLY_MAX_LENGTH);
        self.payload[self.payload_length..end].copy_from_slice(value);
        self.payload_length = end;
    }

    fn add_u8(&mut self, value: u8) {
        assert!(self.payload_length < NCP_REPLY_MAX_LENGTH);
        self.payload[self.payload_length] = value;
        self.payload_length += 1;
    }

    fn add_u16(&mut self, value: u16) {
        assert!(self.payload_length + 2 <= NCP_REPLY_MAX_LENGTH);
        BigEndian::write_u16(&mut self.payload[self.payload_length..], value);
        self.payload_length += 2;
    }

    fn add_u32(&mut self, value: u32) {
        assert!(self.payload_length + 4 <= NCP_REPLY_MAX_LENGTH);
        BigEndian::write_u32(&mut self.payload[self.payload_length..], value);
        self.payload_length += 4;
    }

    fn fill_u8(&mut self, amount: usize, value: u8) {
        for _ in 0..amount {
            self.add_u8(value);
        }
    }
}

impl<'a> NcpService<'a> {
    pub fn new(config: &'a config::Configuration, tx: &'a ipx::Transmitter) -> Self {
        let clients = clients::Clients::new();
        let mut bindery = bindery::Bindery::new(config);
        let mut initialise_bindery = false;
        if let Some(path) = config.get_bindery_file() {
            if let Err(e) = bindery.load(path) {
                error!("unable to load bindery from {}: {:?}", path, e);
                initialise_bindery = true;
            }
        } else {
            initialise_bindery = true;
        }
        if initialise_bindery {
            info!("initialising bindery users and groups");
            bindery.create_users_and_groups(config).expect("unable to create bindery users/groups");
        }

        let mut trustee_db = trustee::TrusteeDB::new();
        let mut initialise_trustees = false;
        if let Some(path) = config.get_trustee_file() {
            if let Err(e) = trustee_db.load(config, &mut bindery, path) {
                error!("unable to load trustees from {}: {:?}", path, e);
                initialise_trustees = true;
            }
        } else {
            initialise_trustees = true;
        }
        if initialise_trustees {
            info!("initialising trustee database");
            let sys_volume = config.get_volumes().get_volume_by_name("SYS").expect("SYS volume not found");
            let sys_index: usize = sys_volume.number.into();

            let rwcemf = trustee::RIGHT_READ | trustee::RIGHT_WRITE | trustee::RIGHT_CREATE | trustee::RIGHT_OPEN | trustee::RIGHT_ERASE | trustee::RIGHT_MODIFY | trustee::RIGHT_FILESCAN;
            trustee_db.add_trustee_for_path(sys_index, "", trustee::Trustee{ object_id: bindery::ID_SUPERVISOR, rights: rwcemf | trustee::RIGHT_PARENTAL | trustee::RIGHT_SUPERVISOR });
            trustee_db.add_trustee_for_path(sys_index, "LOGIN", trustee::Trustee{ object_id: bindery::ID_NOT_LOGGED_IN, rights: trustee::RIGHT_READ | trustee::RIGHT_FILESCAN });

            let everyone_id = bindery.get_object_by_name(MaxBoundedString::from_str("EVERYONE"), bindery::TYPE_USER_GROUP).expect("cannot find EVERYONE group").id;
            trustee_db.add_trustee_for_path(sys_index, "LOGIN", trustee::Trustee{ object_id: everyone_id, rights: trustee::RIGHT_READ | trustee::RIGHT_FILESCAN | trustee::RIGHT_OPEN });
            trustee_db.add_trustee_for_path(sys_index, "PUBLIC", trustee::Trustee{ object_id: everyone_id, rights: trustee::RIGHT_READ | trustee::RIGHT_FILESCAN | trustee::RIGHT_OPEN });
            trustee_db.add_trustee_for_path(sys_index, "TEMP", trustee::Trustee{ object_id: everyone_id, rights: rwcemf });
            trustee_db.add_trustee_for_path(sys_index, "MAIL", trustee::Trustee{ object_id: everyone_id, rights: trustee::RIGHT_CREATE });
        }

        NcpService{ config, tx, clients, bindery, trustee_db }
    }

    fn send_reply(&self, dest: &IpxAddr, data: &[u8]) {
        let mut src = self.config.get_server_address();
        src.set_socket(consts::IPX_SOCKET_NCP);
        self.tx.send(&src, dest, data)
    }

    pub fn process_packet(&mut self, packet: &ipx::IpxPacket) -> Result<(), NetWareError> {
        let source = packet.get_source();
        let payload = packet.payload();
        let mut rdr = Cursor::new(payload);
        let header = ncp::parser::NcpHeader::from(&mut rdr)?;
        self.process_request(&source, &header, &mut rdr);
        Ok(())
    }

    fn send(&self, dest: &IpxAddr, result: Result<(), NetWareError>, reply: &mut NcpReplyPacket) {
        match result {
            Ok(_) => { },
            Err(err) => {
                assert_eq!(reply.payload_length, NCP_REPLY_HEADER_LENGTH);
                reply.set_completion_code(err.to_error_code());
            }
        }
        self.send_reply(dest, &reply.payload[0..reply.payload_length]);
    }

    fn process_request<T: Read + ReadBytesExt>(&mut self, dest: &IpxAddr, header: &ncp::parser::NcpHeader, rdr: &mut T) {
        let req = ncp::parser::Request::from(header, rdr);
        if req.is_err() { return }
        let req = req.unwrap();
        let mut reply = NcpReplyPacket::new(header);

        // CreateServiceConnection is special, it doesn't yet have a valid
        // connection index
        if let ncp::parser::Request::CreateServiceConnection(args) = req {
            trace!("create_service_connection(): dest {}", dest);
            let result = self.create_service_connection(header, dest, &args, &mut reply);
            self.send(dest, result, &mut reply);
            return;
        }

        // All other requests need us to have a connection
        let result = self.clients.get_mut_connection(header, dest);
        if let Err(e) = result {
            self.send(dest, Err(e), &mut reply);
            return;
        }
        let conn = result.unwrap();

        trace!("{}: {}", header.connection_number, req);
        let result = match req {
            ncp::parser::Request::UnrecognizedRequest(a, b, c) => {
                warn!("{}: unrecognized request type {} code {} subrequest {}", header.connection_number - 1, a, b, c);
                Err(NetWareError::UnsupportedRequest)
            }
            ncp::parser::Request::CreateServiceConnection(_) => {
                unreachable!()
            },
            ncp::parser::Request::DestroyServiceConnection(args) => {
                ncp::connection::destroy_service_connection(conn, &args, &mut reply)
            },
            ncp::parser::Request::GetFileServerInfo(args) => {
                ncp::server::process_request_23_17_get_fileserver_info(self.config, &self.clients, &args, &mut reply)
            },
            ncp::parser::Request::ReadPropertyValue(args) => {
                ncp::bindery::process_request_23_61_read_property_value(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::NegotiateBufferSize(args) => {
                ncp::connection::process_request_33_negotiate_buffer_size(conn, &args, &mut reply)
            },
            ncp::parser::Request::FileSearchInit(args) => {
                ncp::filesystem::process_request_62_file_search_init(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::FileSearchContinue(args) => {
                ncp::filesystem::process_request_63_file_search_continue(conn, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::GetBigPacketNCPMaxPacketSize(args) => {
                ncp::connection::process_request_97_get_big_packet_ncp_max_packet_size(conn, &args, &mut reply)
            },
            ncp::parser::Request::PacketBurstConnectionRequest(args) => {
                ncp::packetburst::process_request_101_packet_burst_connection_request(conn, &args, &mut reply)
            },
            ncp::parser::Request::GetFileServerDateAndTime(args) => {
                ncp::server::process_request_20_get_fileserver_date_and_time(conn, &args, &mut reply)
            },
            ncp::parser::Request::GetEffectiveDirectoryRights(args) => {
                ncp::filesystem::process_request_22_3_get_effective_directory_rights(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::GetVolumeInfoWithHandle(args) => {
                ncp::filesystem::process_request_22_21_get_volume_info_with_handle(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::DeallocateDirectoryHandle(args) => {
                ncp::filesystem::process_request_22_20_deallocate_dir_handle(conn, &args, &mut reply)
            },
            ncp::parser::Request::AllocateTemporaryDirectoryHandle(args) => {
                ncp::filesystem::process_request_22_19_allocate_temp_dir_handle(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::AllocatePermanentDirectoryHandle(args) => {
                ncp::filesystem::process_request_22_18_allocate_perm_dir_handle(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::GetDirectoryPath(args) => {
                ncp::filesystem::process_request_22_1_get_directory_path(conn, &args, &mut reply)
            },
            ncp::parser::Request::OpenFile(args) => {
                ncp::filesystem::process_request_76_open_file(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::ReadFromFile(args) => {
                ncp::filesystem::process_request_72_read_from_file(conn, &args, &mut reply)
            },
            ncp::parser::Request::CloseFile(args) => {
                ncp::filesystem::process_request_66_close_file(conn, &args, &mut reply)
            },
            ncp::parser::Request::SearchForFile(args) => {
                ncp::filesystem::process_request_64_search_for_file(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::LockPhysicalRecordOld(args) => {
                ncp::sync::process_request_26_lock_physical_record_old(conn, &args, &mut reply)
            },
            ncp::parser::Request::ClearPhysicalRecord(args) => {
                ncp::sync::process_request_30_clear_physical_record(conn, &args, &mut reply)
            },
            ncp::parser::Request::GetBinderyAccessLevel(args) => {
                ncp::bindery::process_request_23_70_get_bindery_access_level(conn, &args, &mut reply)
            },
            ncp::parser::Request::GetBinderyObjectName(args) => {
                ncp::bindery::process_request_23_54_get_bindery_object_name(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::ScanBinderyObject(args) => {
                ncp::bindery::process_request_23_55_scan_bindery_object(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::EndOfJob(args) => {
                ncp::connection::process_request_24_end_of_job(conn, &args, &mut reply)
            },
            ncp::parser::Request::Logout(args) => {
                ncp::connection::process_request_25_logout(conn, self.config, &args, &mut reply)
            },
            ncp::parser::Request::GetStationLoggedInfo(args) => {
                ncp::connection::process_request_23_28_get_station_logged_info(&mut self.clients, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::GetInternetAddress(args) => {
                ncp::connection::process_request_23_26_get_internet_address(&mut self.clients, &args, &mut reply)
            },
            ncp::parser::Request::GetLoginKey(args) => {
                ncp::connection::process_request_23_23_get_login_key(conn, &args, &mut reply)
            },
            ncp::parser::Request::KeyedObjectLogin(args) => {
                ncp::connection::process_request_23_24_keyed_object_login(conn, self.config, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::GetBinderyObjectID(args) => {
                ncp::bindery::process_request_23_53_get_bindery_object_id(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::KeyedVerifyPassword(args) => {
                ncp::bindery::process_request_23_74_keyed_verify_password(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::KeyedChangePassword(args) => {
                ncp::bindery::process_request_23_75_keyed_change_password(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::DeleteObjectFromSet(args) => {
                ncp::bindery::process_request_23_66_delete_object_from_set(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::IsObjectInSet(args) => {
                ncp::bindery::process_request_23_67_is_object_in_set(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::GetBinderyObjectAccessLevel(args) => {
                ncp::bindery::process_request_23_72_get_bindery_object_access_level(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::AddBinderyObjectToSet(args) => {
                ncp::bindery::process_request_23_65_add_bindery_object_to_set(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::CreateProperty(args) => {
                ncp::bindery::process_request_23_57_create_property(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::WritePropertyValue(args) => {
                ncp::bindery::process_request_23_62_write_property_value(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::CreateBinderyObject(args) => {
                ncp::bindery::process_request_23_50_create_bindery_object(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::DeleteBinderyObject(args) => {
                ncp::bindery::process_request_23_51_delete_bindery_object(conn, &mut self.bindery, &args, &mut reply)
            },
            ncp::parser::Request::CreateDirectory(args) => {
                ncp::filesystem::process_request_22_10_create_directory(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::DeleteDirectory(args) => {
                ncp::filesystem::process_request_22_11_delete_directory(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::DownFileServer(args) => {
                ncp::server::process_request_23_211_down_file_server(conn, &args, &mut reply)
            }
            ncp::parser::Request::GetVolumeInfoWithNumber(args) => {
                ncp::filesystem::process_request_18_get_volume_info_with_number(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::CreateFile(args) => {
                ncp::filesystem::process_request_67_create_file(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::WriteToFile(args) => {
                ncp::filesystem::process_request_73_write_to_file(conn, &args, &mut reply)
            },
            ncp::parser::Request::EraseFile(args) => {
                ncp::filesystem::process_request_68_erase_file(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::SetDirectoryHandle(args) => {
                ncp::filesystem::process_request_22_0_set_directory_handle(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::GetEffectiveRightsForDirectoryEntry(args) => {
                ncp::filesystem::process_request_22_42_get_effective_rights_for_directory_entry(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::ScanVolumeUserDiskRestrictions(args) => {
                ncp::filesystem::process_request_22_32_scan_volume_user_disk_restrictions(conn, self.config, &args, &mut reply)
            },
            ncp::parser::Request::ScanFileOrDirectoryForExtendedTrustees(args) => {
                ncp::filesystem::process_request_22_38_scan_file_or_directory_for_extended_trustees(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::GetVolumeName(args) => {
                ncp::filesystem::process_request_22_6_get_volume_name(conn, self.config, &args, &mut reply)
            },
            ncp::parser::Request::ScanBinderyObjectTrusteePath(args) => {
                ncp::bindery::process_request_23_71_scan_bindery_object_trustee_path(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::ScanDirectoryInformation(args) => {
                ncp::filesystem::process_request_22_2_scan_directory_information(conn, self.config, &self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::CheckConsolePrivileges(args) => {
                ncp::server::process_request_23_200_check_console_privileges(conn, &args, &mut reply)
            }
            ncp::parser::Request::AddExtendedTrusteeToDirectoryOrFile(args) => {
                ncp::filesystem::process_request_22_39_add_extended_trustee_to_directory_or_file(conn, self.config, &mut self.trustee_db, &args, &mut reply)
            },
            ncp::parser::Request::RemoveExtendedTrusteeFromDirectoryOrFile(args) => {
                ncp::filesystem::process_request_22_43_remove_extended_trustee_from_directory_or_file(conn, self.config, &mut self.trustee_db, &args, &mut reply)
            },
        };
        self.send(dest, result, &mut reply);
    }

    fn create_service_connection(&mut self, header: &ncp::parser::NcpHeader, dest: &IpxAddr, _args: &ncp::parser::CreateServiceConnection, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
        if header.sequence_number != 0 || header.connection_number != 0xff {
            error!("rejecting to create connection for {}, invalid sequence/connection number", dest);
            reply.set_completion_code(0xff);
            return Ok(())
        }
        if let Ok(conn) = self.clients.allocate_connection(self.config, dest) {
            reply.set_connection_number((conn + 1) as u8);
        } else {
            reply.set_completion_code(0xff);
            reply.set_connection_status(CONNECTION_STATUS_NO_CONNECTIONS_AVAILABLE);
        }
        Ok(())
    }
}

impl<'a> Drop for NcpService<'a> {
    fn drop(&mut self) {
        if let Some(path) = self.config.get_bindery_file() {
            match self.bindery.save(path) {
                Ok(()) => { info!("bindery saved to '{}'", path); },
                Err(e) => { error!("unable to save bindery to '{}': {:?}", path, e); },
            }
        }
        if let Some(path) = self.config.get_trustee_file() {
            match self.trustee_db.save(self.config, &mut self.bindery, path) {
                Ok(()) => { info!("trustees saved to '{}'", path); },
                Err(e) => { error!("unable to save trustees to '{}': {:?}", path, e); },
            }
        }
    }
}
