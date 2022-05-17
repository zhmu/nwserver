use crate::config;
use crate::consts;
use crate::ipx;
use crate::types::*;
use crate::error::NetWareError;
use crate::ncp_parser;
use crate::connection;
use crate::handle;

use std::fs::File;

use chrono::{Local, Timelike, Datelike};
use log::*;

use byteorder::{ByteOrder, BigEndian};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use pnet::packet::Packet;

const MAX_BUFFER_SIZE: u16 = 1024;

const REQUEST_TYPE_CREATE_SERVICE_CONNECTION: u16 = 0x1111;
const REQUEST_TYPE_REQUEST: u16 = 0x2222;
const REQUEST_TYPE_REPLY: u16 = 0x3333;
const REQUEST_TYPE_DESTROY_SERVICE_CONNECTION: u16 = 0x5555;

const CONNECTION_STATUS_NO_CONNECTIONS_AVAILABLE: u8 = 0x04;
const _CONNECTION_STATUS_SERVER_DOWN: u8 = 0x10;

const ERR_INVALID_PATH: u8 = 0x9c;

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
    connections: [ connection::Connection; consts::MAX_CONNECTIONS ],
}

const NCP_REQUEST_LENGTH: usize = 7;
const NCP_REPLY_LENGTH: usize = 8;

struct NcpReply {
    reply_type: u16,
    sequence_number: u8,
    connection_number: u8,
    task_number: u8,
    reserved: u8,
    completion_code: u8,
    connection_status: u8
}

impl NcpReply {
    pub fn new(request: &ncp_parser::NcpRequest, completion_code: u8) -> Self {
        let reply_type = REQUEST_TYPE_REPLY;
        let sequence_number = request.sequence_number;
        let connection_number = request.connection_number;
        let task_number = request.task_number;
        let reserved = 0;
        let connection_status = 0;
        NcpReply{ reply_type, sequence_number, connection_number, task_number, reserved, completion_code, connection_status }
    }

    pub fn to(&self, buffer: &mut [u8]) {
        BigEndian::write_u16(&mut buffer[0..], self.reply_type);
        buffer[2] = self.sequence_number;
        buffer[3] = self.connection_number;
        buffer[4] = self.task_number;
        buffer[5] = self.reserved;
        buffer[6] = self.completion_code;
        buffer[7] = self.connection_status;
    }

    pub fn set_completion_code(&mut self, code: u8) {
        self.completion_code = code;
    }
}

struct NcpReplyPacket<const MAX_SIZE: usize> {
    reply: NcpReply,
    payload: [ u8; MAX_SIZE ],
    payload_length: usize,
}

impl<const MAX_SIZE: usize> NcpReplyPacket<MAX_SIZE> {
    pub fn new(request: &ncp_parser::NcpRequest) -> Self {
        let reply = NcpReply::new(request, 0);
        let payload = [ 0u8; MAX_SIZE ];
        NcpReplyPacket{ reply, payload, payload_length: 0 }
    }

    pub fn set_completion_code(&mut self, code: u8) {
        self.reply.set_completion_code(code);
    }

    pub fn send(&self, s: &NcpService) {
/*
        if self.payload_length < MAX_SIZE {
            println!("warning: NcpReplyPacket payload length is only {} out of max {}", self.payload_length, MAX_SIZE);
        }
*/
        let conn = &s.connections[(self.reply.connection_number - 1) as usize];
        s.send_reply(&conn.dest, &self.reply, &self.payload[0..self.payload_length]);
    }
}

impl<const MAX_SIZE: usize> DataStreamer for NcpReplyPacket<MAX_SIZE> {
    fn add_data(&mut self, value: &[u8]) {
        let end = self.payload_length + value.len();
        assert!(end <= MAX_SIZE);
        self.payload[self.payload_length..end].copy_from_slice(value);
        self.payload_length = end;
    }

    fn add_u8(&mut self, value: u8) {
        assert!(self.payload_length + 1 <= MAX_SIZE);
        self.payload[self.payload_length] = value;
        self.payload_length += 1;
    }

    fn add_u16(&mut self, value: u16) {
        assert!(self.payload_length + 2 <= MAX_SIZE);
        BigEndian::write_u16(&mut self.payload[self.payload_length..], value);
        self.payload_length += 2;
    }

    fn add_u32(&mut self, value: u32) {
        assert!(self.payload_length + 4 <= MAX_SIZE);
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
        const CONN_INIT: connection::Connection = connection::Connection::zero();
        let connections = [ CONN_INIT; consts::MAX_CONNECTIONS ];
        NcpService{ config, tx, connections }
    }

    fn send_reply(&self, dest: &IpxAddr, reply: &NcpReply, payload: &[u8]) {
        let mut buffer = [ 0u8; 4096 /* XXX */ ];
        reply.to(&mut buffer[0..NCP_REPLY_LENGTH]);

        let payload_length = payload.len();
        buffer[NCP_REPLY_LENGTH..NCP_REPLY_LENGTH + payload_length].copy_from_slice(&payload);

        let server_addr = self.config.get_server_address();
        let mut src = server_addr.clone();
        src.set_socket(consts::IPX_SOCKET_NCP);
        self.tx.send(&src, dest, &buffer[0..NCP_REPLY_LENGTH + payload_length]);
    }

    pub fn process_packet(&mut self, packet: &ipx::IpxPacket) -> Result<(), NetWareError> {
        let source = packet.get_source();
        let payload = packet.payload();
        let mut rdr = Cursor::new(payload);
        let request = ncp_parser::NcpRequest::from(&mut rdr)?;
        match request.request_type {
            REQUEST_TYPE_CREATE_SERVICE_CONNECTION => { self.create_service_connection(&source, &request); },
            REQUEST_TYPE_DESTROY_SERVICE_CONNECTION => { self.destroy_service_connection(&source, &request); },
            REQUEST_TYPE_REQUEST => { self.handle_request(&source, &request, &payload[NCP_REQUEST_LENGTH..]); },
            _ => {
                warn!("ignoring unrecognized NCP request {:?}", request);
            }
        }
        Ok(())
    }

    fn process_request(&mut self, request: &ncp_parser::NcpRequest, payload: &[u8]) -> Result<(), NetWareError> {
        let mut rdr = Cursor::new(&payload);
        let req = ncp_parser::Request::from(request, &mut rdr)?;
        return match req {
            ncp_parser::Request::UnrecognizedRequest(a, b) => {
                warn!("{}: unrecognized request {} subrequest {}", request.connection_number - 1, a, b);
                Err(NetWareError::UnsupportedRequest)
            }
            ncp_parser::Request::GetFileServerInfo(args) => {
                self.process_request_23_17_get_fileserver_info(&request, &args)
            },
            ncp_parser::Request::ReadPropertyValue(args) => {
                self.process_request_23_61_read_property_value(&request, &args)
            },
            ncp_parser::Request::NegotiateBufferSize(args) => {
                self.process_request_33_negotiate_buffer_size(&request, &args)
            },
            ncp_parser::Request::FileSearchInit(args) => {
                self.process_request_62_file_search_init(&request, &args)
            },
            ncp_parser::Request::FileSearchContinue(args) => {
                self.process_request_63_file_search_continue(&request, &args)
            },
            ncp_parser::Request::GetBigPacketNCPMaxPacketSize(args) => {
                self.process_request_97_get_big_packet_ncp_max_packet_size(&request, &args)
            },
            ncp_parser::Request::PacketBurstConnectionRequest(args) => {
                self.process_request_101_packet_burst_connection_request(&request, &args)
            },
            ncp_parser::Request::GetFileServerDateAndTime(args) => {
                self.process_request_20_get_fileserver_date_and_time(&request, &args)
            },
            ncp_parser::Request::GetEffectiveDirectoryRights(args) => {
                self.process_request_22_3_get_effective_directory_rights(&request, &args)
            },
            ncp_parser::Request::GetVolumeInfoWithHandle(args) => {
                self.process_request_22_21_get_volume_info_with_handle(&request, &args)
            },
            ncp_parser::Request::AllocateTemporaryDirectoryHandle(args) => {
                self.process_request_22_19_allocate_temp_dir_handle(&request, &args)
            },
            ncp_parser::Request::DeallocateDirectoryHandle(args) => {
                self.process_request_22_20_deallocate_dir_handle(&request, &args)
            },
            ncp_parser::Request::OpenFile(args) => {
                self.process_request_76_open_file(&request, &args)
            },
            ncp_parser::Request::ReadFromFile(args) => {
                self.process_request_72_read_from_file(&request, &args)
            },
            ncp_parser::Request::CloseFile(args) => {
                self.process_request_66_close_file(&request, &args)
            },
        }
    }

   fn process_request_23_17_get_fileserver_info(&mut self, request: &ncp_parser::NcpRequest, _args: &ncp_parser::GetFileServerInfo) -> Result<(), NetWareError> {
        let mut reply = NcpReplyPacket::<128>::new(request);
        reply.add_data(self.config.get_server_name().buffer());
        reply.add_u8(3); // FileServiceVersion
        reply.add_u8(12); // FileServiceSubVersion
        reply.add_u16(consts::MAX_CONNECTIONS as u16); // MaximumServiceConnections
        let connections_in_use = self.connections.iter().filter(|&e| e.in_use()).count() as u16;
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
        reply.add_u8(0); // TODO LocalLoginInfoCcode
        reply.add_u16(0); // ProductMajorVersion
        reply.add_u16(0); // ProductMinorVersion
        reply.add_u16(0); // ProductRevisionVersion
        reply.add_u8(0); // OSLanguageID
        reply.add_u8(0); // 64BitOffsetsSupportedFlag
        reply.fill_u8(50, 0); // Reserved
        reply.send(&self);
        Ok(())
    }

    fn process_request_23_61_read_property_value(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::ReadPropertyValue) -> Result<(), NetWareError> {
        trace!("{}: Read property value, {:?}", request.connection_number, args);
        Err(NetWareError::NoSuchSet)
    }

    fn process_request_33_negotiate_buffer_size(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::NegotiateBufferSize) -> Result<(), NetWareError> {
        trace!("{}: Negotiate buffer size, {:?}", request.connection_number, args);

        let accepted_buffer_size = if args.proposed_buffer_size > MAX_BUFFER_SIZE { MAX_BUFFER_SIZE } else { args.proposed_buffer_size };

        let mut reply = NcpReplyPacket::<2>::new(request);
        reply.add_u16(accepted_buffer_size);
        reply.send(&self);
        Ok(())
    }

    fn process_request_62_file_search_init(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::FileSearchInit) -> Result<(), NetWareError> {
        trace!("{}: File search initialize, {:?}", request.connection_number, args);

        let conn = self.get_connection(&request);
        let source_dh = conn.get_dir_handle(args.handle)?;
        let path = self.create_system_path(source_dh, &args.path)?;
        let volume_number = source_dh.volume_number.unwrap();
        let contents = retrieve_directory_contents(Path::new(&path))?;

        // XXX verify existance, access etc
        let conn = self.get_mut_connection(&request);
        let sh = conn.allocate_search_handle(path, contents);
        let mut reply = NcpReplyPacket::<6>::new(request);
        reply.add_u8(volume_number);
        let directory_id = sh.id;
        reply.add_u16(directory_id);
        let search_sequence_number = 0xffff;
        reply.add_u16(search_sequence_number);
        let dir_access_rights = 0xff;
        reply.add_u8(dir_access_rights);
        reply.send(&self);
        Ok(())
    }

    fn process_request_63_file_search_continue(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::FileSearchContinue) -> Result<(), NetWareError> {
        trace!("{}: File search continue, {:?}", request.connection_number, args);

        let conn = self.get_connection(&request);
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
                                let mut reply = NcpReplyPacket::<32>::new(request);
                                reply.add_u16(index as u16); // search sequence
                                reply.add_u16(args.directory_id); // directory id
                                entry.to(&mut reply); // file name
                                let attr = ATTR_SUBDIRECTORY;
                                reply.add_u8(attr); // directory attributes
                                reply.add_u8(0xff); // directory access rights
                                reply.add_u16(0); // creation date
                                reply.add_u16(0); // creation time
                                reply.add_u32(0); // owner id
                                reply.add_u16(0); // reserved
                                reply.add_u16(0xd1d1); // directory magic
                                reply.send(&self);
                                return Ok(())
                            }
                            if ft.is_file() && want_files {
                                let mut reply = NcpReplyPacket::<32>::new(request);
                                reply.add_u16(index as u16); // search sequence
                                reply.add_u16(args.directory_id); // directory id
                                entry.to(&mut reply); // file name
                                reply.add_u8(0); // file attributes
                                reply.add_u8(0); // file mode
                                reply.add_u32(md.len() as u32); // file length
                                reply.add_u16(0); // creation date
                                reply.add_u16(0); // access date
                                reply.add_u16(0); // update date
                                reply.add_u16(0); // update time
                                reply.send(&self);
                                return Ok(())
                            }
                        }
                    }
                }
            }
        }
        Err(NetWareError::NoFilesFound)
    }

    fn process_request_97_get_big_packet_ncp_max_packet_size(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::GetBigPacketNCPMaxPacketSize) -> Result<(), NetWareError> {
        trace!("{}: unsupported: Get Big Packet NCP Max Packet Size, {:?}", request.connection_number, args);
        Err(NetWareError::UnsupportedRequest)
    }

    fn process_request_101_packet_burst_connection_request(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::PacketBurstConnectionRequest) -> Result<(), NetWareError> {
        trace!("{}: Packet burst connection request, {:?}", request.connection_number, args);
        Err(NetWareError::UnsupportedRequest)
    }

    fn process_request_20_get_fileserver_date_and_time(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::GetFileServerDateAndTime) -> Result<(), NetWareError> {
        trace!("{}: Get file server date and time, {:?}", request.connection_number, args);
        let now = Local::now();

        let mut reply = NcpReplyPacket::<7>::new(request);
        reply.add_u8((now.year() - 1900) as u8); // Year
        reply.add_u8(now.month() as u8); // Month
        reply.add_u8(now.day() as u8); // Day
        reply.add_u8(now.hour() as u8); // Hour
        reply.add_u8(now.minute() as u8); // Minute
        reply.add_u8(now.second() as u8); // Second
        let weekday = now.date().weekday();
        reply.add_u8(weekday.num_days_from_sunday() as u8); // Day of the week
        reply.send(&self);
        Ok(())
    }

    fn process_request_22_3_get_effective_directory_rights(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::GetEffectiveDirectoryRights) -> Result<(), NetWareError> {
        trace!("{}: Get effective directory rights, {:?}", request.connection_number, args);

        let conn = self.get_connection(&request);
        let dh = conn.get_dir_handle(args.directory_handle)?;
        let path = self.create_system_path(dh, &args.directory_path)?;
        let md = std::fs::metadata(&path)?;
        if !md.file_type().is_dir() {
            return Err(NetWareError::InvalidPath);
        }
        let mut reply = NcpReplyPacket::<2>::new(request);
        let effective_rights_mask = 0xffff;
        reply.add_u16(effective_rights_mask);
        reply.send(&self);
        Ok(())
    }

    fn process_request_22_21_get_volume_info_with_handle(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::GetVolumeInfoWithHandle) -> Result<(), NetWareError> {
        trace!("{}: Get volume info with handle, {:?}", request.connection_number, args);

        let conn = self.get_connection(&request);
        let dh = conn.get_dir_handle(args.directory_handle)?;
        let volume = self.get_volume_by_number(dh.volume_number.unwrap())?;

        let mut reply = NcpReplyPacket::<28>::new(request);
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
        volume.name.to_raw(&mut reply);
        let removable_flag = 0;
        reply.add_u16(removable_flag);
        reply.send(&self);
        Ok(())
    }

    fn process_request_22_19_allocate_temp_dir_handle(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::AllocateTemporaryDirectoryHandle) -> Result<(), NetWareError> {
        trace!("{}: Allocate temporary directory handle, {:?}", request.connection_number, args);

        let conn = self.get_mut_connection(&request);
        let source_dh = conn.get_dir_handle(args.source_directory_handle)?;
        let path = combine_dh_path(source_dh, &args.directory_path);
        // XXX verify existance etc

        let volume_number = source_dh.volume_number.unwrap();
        let (new_dh_index, new_dh) = conn.alloc_dir_handle(volume_number)?;
        new_dh.path = path;
        let mut reply = NcpReplyPacket::<2>::new(request);
        reply.add_u8(new_dh_index);
        let access_rights_mask = 0xff; // TODO
        reply.add_u8(access_rights_mask);
        reply.send(&self);
        Ok(())
    }

    fn process_request_22_20_deallocate_dir_handle(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::DeallocateDirectoryHandle) -> Result<(), NetWareError> {
        trace!("{}: Deallocate directory handle, {:?}", request.connection_number, args);

        let conn = self.get_mut_connection(&request);
        let dh = conn.get_mut_dir_handle(args.directory_handle)?;
        *dh = handle::DirectoryHandle::zero();
        self.send_completion_code_reply(request, 0);
        Ok(())
    }

    fn process_request_76_open_file(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::OpenFile) -> Result<(), NetWareError> {
        trace!("{}: Open file, {:?}", request.connection_number, args);

        let conn = self.get_connection(&request);
        let dh = conn.get_dir_handle(args.directory_handle)?;
        let path = self.create_system_path(dh, &args.filename)?;

        if let Some(filename) = extract_filename_from(&path) {
            if let Ok(f) = File::open(&path) {
                let md = f.metadata()?;
                let conn = self.get_mut_connection(&request);
                let (fh_index, _) = conn.allocate_file_handle(f)?;
                let mut reply = NcpReplyPacket::<36>::new(request);
                reply.add_u32(0);
                reply.add_u16(fh_index as u16);
                reply.add_u16(0); // reserved
                filename.to(&mut reply);
                reply.add_u8(0); // attributes
                reply.add_u8(0); // file execute type
                reply.add_u32(md.len() as u32); // file length
                reply.add_u16(0); // creation date TODO
                reply.add_u16(0); // last access date TODO
                reply.add_u16(0); // last update date TODO
                reply.add_u16(0); // last update time TODO
                reply.send(&self);
            } else {
                self.send_completion_code_reply(request, ERR_INVALID_PATH);
            }
        } else {
            error!("cannot extract 8.3 filename from '{}' ?!", path);
            self.send_completion_code_reply(request, ERR_INVALID_PATH);
        }
        Ok(())
    }

    fn process_request_72_read_from_file(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::ReadFromFile) -> Result<(), NetWareError> {
        trace!("{}: Read from file, {:?}", request.connection_number, args);

        let conn = self.get_mut_connection(&request);
        let fh = conn.get_mut_file_handle(args.file_handle as u8)?;
        let mut file = fh.file.as_ref().unwrap();
        file.seek(SeekFrom::Start(args.offset as u64))?;

        let mut data = vec![ 0u8; args.length.into() ];
        let count = file.read(&mut data)?;
        let mut reply = NcpReplyPacket::<{2 + 65536}>::new(request);
        reply.add_u16(count as u16);
        // Reads from unaligned offsets must insert a dummy byte
        let odd = args.offset & 1;
        if odd != 0 { reply.add_u8(0); }
        reply.add_data(&data[0..count]);
        reply.send(&self);
        Ok(())
    }

    fn process_request_66_close_file(&mut self, request: &ncp_parser::NcpRequest, args: &ncp_parser::CloseFile) -> Result<(), NetWareError> {
        trace!("{}: Close file, {:?}", request.connection_number, args);

        let conn = self.get_mut_connection(&request);
        let fh = conn.get_mut_file_handle(args.file_handle as u8)?;
        *fh = handle::FileHandle::zero();
        self.send_completion_code_reply(request, 0);
        Ok(())
    }

    fn get_connection_index(&self, dest: &IpxAddr, request: &ncp_parser::NcpRequest) -> Option<usize> {
        let connection_number = request.connection_number as usize;
        if connection_number >= 1 && connection_number < consts::MAX_CONNECTIONS {
            let index = connection_number - 1;
            let conn = &self.connections[index];
            if conn.dest == *dest {
                return Some(index);
            }
        }
        None
    }

    fn get_connection(&self, request: &ncp_parser::NcpRequest) -> &connection::Connection {
        let connection_number = request.connection_number as usize;
        if connection_number >= 1 && connection_number < consts::MAX_CONNECTIONS {
            let index = connection_number - 1;
            return &self.connections[index];
        }
        unreachable!()
    }

    fn get_mut_connection(&mut self, request: &ncp_parser::NcpRequest) -> &mut connection::Connection {
        let connection_number = request.connection_number as usize;
        if connection_number >= 1 && connection_number < consts::MAX_CONNECTIONS {
            let index = connection_number - 1;
            return &mut self.connections[index];
        }
        unreachable!()
    }

    fn handle_request(&mut self, dest: &IpxAddr, request: &ncp_parser::NcpRequest, payload: &[u8]) {
        if self.get_connection_index(dest, request).is_none() {
            // 'dest' does not own this connection - reject
            let e = NetWareError::ConnectionNotLoggedIn;
            self.send_completion_code_reply(request, e.to_error_code())
        }
        match self.process_request(&request, payload) {
            Ok(_) => { },
            Err(e) => {
                error!("request yielded error {:?}", e);
                self.send_completion_code_reply(request, e.to_error_code())
            }
        }
    }

    fn allocate_connection(&mut self, dest: &IpxAddr) -> Option<usize> {
        for (n, conn) in self.connections.iter_mut().enumerate() {
            if conn.in_use() { continue; }

            *conn = connection::Connection::allocate(dest);
            return Some(n);
        }
        None
    }

    fn create_service_connection(&mut self, dest: &IpxAddr, request: &ncp_parser::NcpRequest) {
        trace!("create_service_connection(): dest {}", dest);
        if request.sequence_number != 0 || request.connection_number != 0xff {
            error!("rejecting to create connection for {}, invalid sequence/connection number", dest);
            return
        }
        let mut reply = NcpReply::new(&request, 0);
        if let Some(conn) = self.allocate_connection(dest) {
            reply.connection_number = (conn + 1) as u8;
        } else {
            reply.completion_code = 0xff;
            reply.connection_status = CONNECTION_STATUS_NO_CONNECTIONS_AVAILABLE;
        }
        self.send_reply(dest, &reply, &[]);
    }

    fn destroy_service_connection(&mut self, dest: &IpxAddr, request: &ncp_parser::NcpRequest) {
        trace!("{}: destroy_service_connection(): dest {}", request.connection_number, dest);
        let mut reply = NcpReply::new(&request, 0);
        if let Some(index) = self.get_connection_index(dest, request) {
            let conn = &mut self.connections[index];
            *conn = connection::Connection::zero();
        } else {
            reply.connection_status = 0xff;
        }
        self.send_reply(dest, &reply, &[]);
    }

    fn send_completion_code_reply(&mut self, request: &ncp_parser::NcpRequest, code: u8) {
        let mut reply = NcpReplyPacket::<0>::new(request);
        reply.set_completion_code(code);
        reply.send(&self);
    }

    fn create_system_path(&self, dh: &handle::DirectoryHandle, sub_path: &PathString) -> Result<String, NetWareError> {
        let path = combine_dh_path(dh, sub_path);
        let volume = self.get_volume_by_number(dh.volume_number.unwrap())?;
        if !path.is_empty() {
            let path = format!("{}/{}", volume.path, path);
            return Ok(str::replace(&path, "\\", "/"))
        }
        Ok(volume.path.as_str().to_string())
    }

    fn get_volume_by_number(&self, volume: u8) -> Result<&config::Volume, NetWareError> {
        let index = volume as usize;
        let volumes = self.config.get_volumes();
        return if index < volumes.len() {
            Ok(&volumes[index])
        } else {
            Err(NetWareError::NoSuchVolume)
        }
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

fn extract_filename_from(path: &str) -> Option<DosFileName> {
    if let Some(n) = path.rfind('/') {
        return DosFileName::from_str(&path[n + 1..]);
    }
    DosFileName::from_str(&path)
}
