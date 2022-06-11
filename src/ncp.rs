use crate::config;
use crate::consts;
use crate::clients;
use crate::ipx;
use crate::types::*;
use crate::error::NetWareError;
use crate::ncp_parser;
use crate::handle;

use std::fs::File;

use chrono::{Local, Timelike, Datelike};
use log::*;

use byteorder::{ByteOrder, BigEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use pnet::packet::Packet;

const MAX_BUFFER_SIZE: u16 = 1024;

const REQUEST_TYPE_REPLY: u16 = 0x3333;

const CONNECTION_STATUS_NO_CONNECTIONS_AVAILABLE: u8 = 0x04;
const _CONNECTION_STATUS_SERVER_DOWN: u8 = 0x10;

const MAX_PATH_LENGTH: usize = 64;

const _SA_HIDDEN: u8 = 0x02;
const _SA_SYSTEM: u8 = 0x04;
const SA_SUBDIR_ONLY: u8 = 0x10;

const _ATTR_READ_ONLY: u8 = 0x01;
const _ATTR_HIDDEN: u8 = 0x02;
const _ATTR_SYSTEM: u8 = 0x04;
const _ATTR_EXECUTE_ONLY: u8 = 0x08;
const ATTR_SUBDIRECTORY: u8 = 0x10;
const _ATTR_ARCHIVE: u8 = 0x20;
const _ATTR_EXECUTE_CONFIRM: u8 = 0x40;
const _ATTR_SHAREABLE: u8 = 0x80;

pub type PathString = BoundedString<MAX_PATH_LENGTH>;

pub struct NcpService<'a> {
    config: &'a config::Configuration,
    tx: &'a ipx::Transmitter,
    clients: clients::Clients<'a>,
}

const NCP_REPLY_HEADER_LENGTH: usize = 8;
const NCP_REPLY_MAX_LENGTH: usize = (MAX_BUFFER_SIZE as usize) + NCP_REPLY_HEADER_LENGTH + 3;

struct NcpReplyPacket {
    payload: [ u8; NCP_REPLY_MAX_LENGTH ],
    payload_length: usize,
}

impl NcpReplyPacket {
    pub fn new(header: &ncp_parser::NcpHeader) -> Self {
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
        assert!(self.payload_length + 1 <= NCP_REPLY_MAX_LENGTH);
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
        NcpService{ config, tx, clients }
    }

    fn send_reply(&self, dest: &IpxAddr, data: &[u8]) {
        let server_addr = self.config.get_server_address();
        let mut src = server_addr.clone();
        src.set_socket(consts::IPX_SOCKET_NCP);
        self.tx.send(&src, dest, &data)
    }

    pub fn process_packet(&mut self, packet: &ipx::IpxPacket) -> Result<(), NetWareError> {
        let source = packet.get_source();
        let payload = packet.payload();
        let mut rdr = Cursor::new(payload);
        let header = ncp_parser::NcpHeader::from(&mut rdr)?;
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

    fn process_request<T: Read + ReadBytesExt>(&mut self, dest: &IpxAddr, header: &ncp_parser::NcpHeader, rdr: &mut T) {
        let req = ncp_parser::Request::from(header, rdr);
        if req.is_err() { return }
        let req = req.unwrap();
        let mut reply = NcpReplyPacket::new(header);

        if let ncp_parser::Request::CreateServiceConnection(args) = req {
            trace!("create_service_connection(): dest {}", dest);
            let result = self.create_service_connection(header, dest, &args, &mut reply);
            self.send(dest, result, &mut reply);
            return;
        }

        //let _conn = self.clients.get_connection(&header)?;
        trace!("{}: {}", header.connection_number, req);
        let result = match req {
            ncp_parser::Request::UnrecognizedRequest(a, b, c) => {
                warn!("{}: unrecognized request type {} code {} subrequest {}", header.connection_number - 1, a, b, c);
                Err(NetWareError::UnsupportedRequest)
            }
            ncp_parser::Request::CreateServiceConnection(_) => {
                unreachable!()
            },
            ncp_parser::Request::DestroyServiceConnection(args) => {
                self.destroy_service_connection(header, dest, &args, &mut reply)
            },
            ncp_parser::Request::GetFileServerInfo(args) => {
                process_request_23_17_get_fileserver_info(self.config, &self.clients, &header, &args, &mut reply)
            },
            ncp_parser::Request::ReadPropertyValue(args) => {
                process_request_23_61_read_property_value(&header, &args, &mut reply)
            },
            ncp_parser::Request::NegotiateBufferSize(args) => {
                process_request_33_negotiate_buffer_size(&header, &args, &mut reply)
            },
            ncp_parser::Request::FileSearchInit(args) => {
                process_request_62_file_search_init(&mut self.clients, &header, &args, &mut reply)
            },
            ncp_parser::Request::FileSearchContinue(args) => {
                process_request_63_file_search_continue(&mut self.clients, &header, &args, &mut reply)
            },
            ncp_parser::Request::GetBigPacketNCPMaxPacketSize(args) => {
                process_request_97_get_big_packet_ncp_max_packet_size(&header, &args, &mut reply)
            },
            ncp_parser::Request::PacketBurstConnectionRequest(args) => {
                process_request_101_packet_burst_connection_request(&header, &args, &mut reply)
            },
            ncp_parser::Request::GetFileServerDateAndTime(args) => {
                process_request_20_get_fileserver_date_and_time(&header, &args, &mut reply)
            },
            ncp_parser::Request::GetEffectiveDirectoryRights(args) => {
                process_request_22_3_get_effective_directory_rights(&mut self.clients, &header, &args, &mut reply)
            },
            ncp_parser::Request::GetVolumeInfoWithHandle(args) => {
                process_request_22_21_get_volume_info_with_handle(&self.clients, &header, &args, &mut reply)
            },
            ncp_parser::Request::DeallocateDirectoryHandle(args) => {
                process_request_22_20_deallocate_dir_handle(&mut self.clients, &header, &args, &mut reply)
            },
            ncp_parser::Request::AllocateTemporaryDirectoryHandle(args) => {
                process_request_22_19_allocate_temp_dir_handle(&mut self.clients, &self.config, &header, &args, &mut reply)
            },
            ncp_parser::Request::OpenFile(args) => {
                process_request_76_open_file(&mut self.clients, &header, &args, &mut reply)
            },
            ncp_parser::Request::ReadFromFile(args) => {
                process_request_72_read_from_file(&mut self.clients, &header, &args, &mut reply)
            },
            ncp_parser::Request::CloseFile(args) => {
                process_request_66_close_file(&mut self.clients, &header, &args, &mut reply)
            },
        };
        self.send(dest, result, &mut reply);
    }

    fn create_service_connection(&mut self, header: &ncp_parser::NcpHeader, dest: &IpxAddr, _args: &ncp_parser::CreateServiceConnection, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
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

    fn destroy_service_connection(&mut self, header: &ncp_parser::NcpHeader, dest: &IpxAddr, _args: &ncp_parser::DestroyServiceConnection, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
        trace!("{}: destroy_service_connection(): dest {}", header.connection_number, dest);
        if let Err(_) = self.clients.disconnect(dest, header) {
            reply.set_completion_code(0xff);
        }
        Ok(())
    }
}

fn retrieve_directory_contents(path: &Path) -> Result<Vec<DosFileName>, std::io::Error> {
    let mut results: Vec<DosFileName> = Vec::new();

    let md = std::fs::metadata(path)?;
    if md.is_dir() {
        let entries = std::fs::read_dir(path)?;
        for entry in entries {
            if let Ok(item) = entry {
                let f = item.file_name();
                if let Some(file_name) = f.to_str() {
                    if let Some(file_name) = DosFileName::from_str(file_name) {
                        results.push(file_name.clone());
                    }
                }
            }
        }
    } else if md.is_file() {
        if let Some(file_name) = path.file_name() {
            if let Some(file_name) = file_name.to_str() {
                if let Some(file_name) = DosFileName::from_str(file_name) {
                    results.push(file_name);
                }
            }
        }
    }
    Ok(results)
}

fn combine_dh_path(dh: &handle::DirectoryHandle, sub_path: &PathString) -> PathString {
    let mut path = dh.path.clone();
    if !sub_path.is_empty() {
        path.append_str("/");
        path.append(&sub_path);
    }
    path
}

fn extract_filename_from(path: &str) -> Result<DosFileName, NetWareError> {
    let p;
    if let Some(n) = path.rfind('/') {
        p = &path[n + 1..];
    } else {
        p = &path;
    }
    DosFileName::from_str(p).ok_or(NetWareError::InvalidPath)
}

fn create_system_path(dh: &handle::DirectoryHandle, sub_path: &PathString) -> Result<String, NetWareError> {
    let path = combine_dh_path(dh, sub_path);
    let volume = dh.volume.unwrap();
    if !path.is_empty() {
        let path = format!("{}/{}", volume.path, path);
        return Ok(str::replace(&path, "\\", "/"))
    }
    Ok(volume.path.as_str().to_string())
}


fn process_request_62_file_search_init(clients: &mut clients::Clients, header: &ncp_parser::NcpHeader, args: &ncp_parser::FileSearchInit, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_mut_connection(&header); // XXX error handling ?
    let source_dh = conn.get_dir_handle(args.handle)?;
    let path = create_system_path(source_dh, &args.path)?;
    let volume_nr = source_dh.volume.as_ref().unwrap().number;
    let contents = retrieve_directory_contents(Path::new(&path))?;

    // XXX verify existance, access etc
    //let conn = clients.get_mut_connection(&header);
    let sh = conn.allocate_search_handle(path, contents);
    reply.add_u8(volume_nr);
    let directory_id = sh.id;
    reply.add_u16(directory_id);
    let search_sequence_number = 0xffff;
    reply.add_u16(search_sequence_number);
    let dir_access_rights = 0xff;
    reply.add_u8(dir_access_rights);
    Ok(())
}

fn process_request_22_20_deallocate_dir_handle(clients: &mut clients::Clients, header: &ncp_parser::NcpHeader, args: &ncp_parser::DeallocateDirectoryHandle, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_mut_connection(&header);
    let dh = conn.get_mut_dir_handle(args.directory_handle)?;
    *dh = handle::DirectoryHandle::zero();
    Ok(())
}

fn process_request_76_open_file(clients: &mut clients::Clients, header: &ncp_parser::NcpHeader, args: &ncp_parser::OpenFile, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_connection(&header)?;
    let dh = conn.get_dir_handle(args.directory_handle)?;
    let path = create_system_path(dh, &args.filename)?;

    let filename = extract_filename_from(&path)?;
    if let Ok(f) = File::open(&path) {
        let md = f.metadata()?;
        let conn = clients.get_mut_connection(&header);
        let (fh_index, _) = conn.allocate_file_handle(f)?;
        reply.add_u32(0);
        reply.add_u16(fh_index as u16);
        reply.add_u16(0); // reserved
        filename.to(reply);
        reply.add_u8(0); // attributes
        reply.add_u8(0); // file execute type
        reply.add_u32(md.len() as u32); // file length
        reply.add_u16(0); // creation date TODO
        reply.add_u16(0); // last access date TODO
        reply.add_u16(0); // last update date TODO
        reply.add_u16(0); // last update time TODO
        Ok(())
    } else {
        Err(NetWareError::InvalidPath)
    }
}

fn process_request_72_read_from_file(clients: &mut clients::Clients, header: &ncp_parser::NcpHeader, args: &ncp_parser::ReadFromFile, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_mut_connection(&header);
    let fh = conn.get_mut_file_handle(args.file_handle as u8)?;
    let mut file = fh.file.as_ref().unwrap();
    file.seek(SeekFrom::Start(args.offset as u64))?;

    let mut data = vec![ 0u8; args.length.into() ];
    let count = file.read(&mut data)?;
    reply.add_u16(count as u16);
    // Reads from unaligned offsets must insert a dummy byte
    let odd = args.offset & 1;
    if odd != 0 { reply.add_u8(0); }
    reply.add_data(&data[0..count]);
    Ok(())
}

fn process_request_66_close_file(clients: &mut clients::Clients, header: &ncp_parser::NcpHeader, args: &ncp_parser::CloseFile, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_mut_connection(&header);
    let fh = conn.get_mut_file_handle(args.file_handle as u8)?;
    *fh = handle::FileHandle::zero();
    Ok(())
}

fn process_request_22_19_allocate_temp_dir_handle<'a>(clients: &mut clients::Clients<'a>, config: &'a config::Configuration, header: &ncp_parser::NcpHeader, args: &ncp_parser::AllocateTemporaryDirectoryHandle, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_mut_connection(&header);
    let source_dh = conn.get_dir_handle(args.source_directory_handle)?;
    let path = combine_dh_path(source_dh, &args.directory_path);
    // XXX verify existance etc

    let volume_number = source_dh.volume.unwrap().number as usize;
    let (new_dh_index, new_dh) = conn.alloc_dir_handle(&config, volume_number)?;
    new_dh.path = path;
    reply.add_u8(new_dh_index);
    let access_rights_mask = 0xff; // TODO
    reply.add_u8(access_rights_mask);
    Ok(())
}

fn process_request_23_17_get_fileserver_info(config: &config::Configuration, clients: &clients::Clients,_header: &ncp_parser::NcpHeader, _args: &ncp_parser::GetFileServerInfo, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    reply.add_data(config.get_server_name().buffer());
    reply.add_u8(3); // FileServiceVersion
    reply.add_u8(12); // FileServiceSubVersion
    reply.add_u16(consts::MAX_CONNECTIONS as u16); // MaximumServiceConnections
    let connections_in_use = clients.count_in_use() as u16;
    reply.add_u16(connections_in_use);
    reply.add_u16(1); // NumberMountedVolumes
    reply.add_u8(0); // Revision
    reply.add_u8(2); // SFTLevel
    reply.add_u8(1); // TTSLevel
    reply.add_u16(connections_in_use); // MaxConnectionsEverUsed
    reply.add_u8(0); // AccountVersion
    reply.add_u8(0); // VAPVersion
    reply.add_u8(0); // QueueVersion
    reply.add_u8(0); // PrintVersion
    reply.add_u8(0); // VirtualConsoleVersion
    reply.add_u8(0); // RestrictionLevel
    reply.add_u8(0); // InternetBridge
    reply.add_u8(0); // MixedModePathFlag
    reply.add_u8(0); // LocalLoginInfoCcode
    reply.add_u16(0); // ProductMajorVersion
    reply.add_u16(0); // ProductMinorVersion
    reply.add_u16(0); // ProductRevisionVersion
    reply.add_u8(0); // OSLanguageID
    reply.add_u8(0); // 64BitOffsetsSupportedFlag
    reply.fill_u8(50, 0); // Reserved
    Ok(())
}

fn process_request_23_61_read_property_value(_header: &ncp_parser::NcpHeader, _args: &ncp_parser::ReadPropertyValue, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::NoSuchSet)
}

fn process_request_33_negotiate_buffer_size(_header: &ncp_parser::NcpHeader, args: &ncp_parser::NegotiateBufferSize, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let accepted_buffer_size = if args.proposed_buffer_size > MAX_BUFFER_SIZE { MAX_BUFFER_SIZE } else { args.proposed_buffer_size };

    reply.add_u16(accepted_buffer_size);
    Ok(())
}

fn process_request_63_file_search_continue(clients: &mut clients::Clients, header: &ncp_parser::NcpHeader, args: &ncp_parser::FileSearchContinue, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_connection(&header)?;
    if let Some(sh) = conn.get_search_handle(args.directory_id) {
        if let Some(path) = &sh.path {
            if let Some(entries) = &sh.entries {
                let mut index = args.search_sequence as usize;
                if index == 0xffff { index = 0; }

                let want_files = (args.search_attr & SA_SUBDIR_ONLY) == 0;
                let want_dirs = (args.search_attr & SA_SUBDIR_ONLY) != 0;
                while index < entries.len() {
                    let entry = entries[index];
                    index += 1;

                    if !entry.matches(&args.search_path.data()) { continue; }

                    // XXX verify match, etc.
                    let p = format!("{}/{}", path, entry);
                    if let Ok(md) = std::fs::metadata(&p) {
                        let ft = md.file_type();
                        if ft.is_dir() && want_dirs {
                            reply.add_u16(index as u16); // search sequence
                            reply.add_u16(args.directory_id); // directory id
                            entry.to(reply); // file name
                            let attr = ATTR_SUBDIRECTORY;
                            reply.add_u8(attr); // directory attributes
                            reply.add_u8(0xff); // directory access rights
                            reply.add_u16(0); // creation date
                            reply.add_u16(0); // creation time
                            reply.add_u32(0); // owner id
                            reply.add_u16(0); // reserved
                            reply.add_u16(0xd1d1); // directory magic
                            return Ok(())
                        }
                        if ft.is_file() && want_files {
                            reply.add_u16(index as u16); // search sequence
                            reply.add_u16(args.directory_id); // directory id
                            entry.to(reply); // file name
                            reply.add_u8(0); // file attributes
                            reply.add_u8(0); // file mode
                            reply.add_u32(md.len() as u32); // file length
                            reply.add_u16(0); // creation date
                            reply.add_u16(0); // access date
                            reply.add_u16(0); // update date
                            reply.add_u16(0); // update time
                            return Ok(())
                        }
                    }
                }
            }
        }
    }
    Err(NetWareError::NoFilesFound)
}

fn process_request_97_get_big_packet_ncp_max_packet_size(_header: &ncp_parser::NcpHeader, _args: &ncp_parser::GetBigPacketNCPMaxPacketSize, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::UnsupportedRequest)
}

fn process_request_101_packet_burst_connection_request(_header: &ncp_parser::NcpHeader, _args: &ncp_parser::PacketBurstConnectionRequest, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::UnsupportedRequest)
}

fn process_request_20_get_fileserver_date_and_time(_header: &ncp_parser::NcpHeader, _args: &ncp_parser::GetFileServerDateAndTime, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let now = Local::now();

    reply.add_u8((now.year() - 1900) as u8); // Year
    reply.add_u8(now.month() as u8); // Month
    reply.add_u8(now.day() as u8); // Day
    reply.add_u8(now.hour() as u8); // Hour
    reply.add_u8(now.minute() as u8); // Minute
    reply.add_u8(now.second() as u8); // Second
    let weekday = now.date().weekday();
    reply.add_u8(weekday.num_days_from_sunday() as u8); // Day of the week
    Ok(())
}

fn process_request_22_3_get_effective_directory_rights(clients: &mut clients::Clients, header: &ncp_parser::NcpHeader, args: &ncp_parser::GetEffectiveDirectoryRights, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_connection(&header)?;
    let dh = conn.get_dir_handle(args.directory_handle)?;
    let path = create_system_path(dh, &args.directory_path)?;
    let md = std::fs::metadata(&path)?;
    if !md.file_type().is_dir() {
        return Err(NetWareError::InvalidPath);
    }
    let effective_rights_mask = 0xffff;
    reply.add_u16(effective_rights_mask);
    Ok(())
}

fn process_request_22_21_get_volume_info_with_handle(clients: &clients::Clients, header: &ncp_parser::NcpHeader, args: &ncp_parser::GetVolumeInfoWithHandle, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let conn = clients.get_connection(&header)?;
    let dh = conn.get_dir_handle(args.directory_handle)?;
    let volume = dh.volume.unwrap();

    let sectors_per_cluster = 128; // 64k
    reply.add_u16(sectors_per_cluster);
    let total_volume_sectors = 1000;
    reply.add_u16(total_volume_sectors);
    let available_clusters = 900;
    reply.add_u16(available_clusters);
    let total_directory_slots = 1000;
    reply.add_u16(total_directory_slots);
    let available_directory_slots = 1000;
    reply.add_u16(available_directory_slots);
    volume.name.to_raw(reply);
    let removable_flag = 0;
    reply.add_u16(removable_flag);
    Ok(())
}
