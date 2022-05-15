use crate::config;
use crate::consts;
use crate::ipx;
use crate::types::*;

use std::fs::File;

use chrono::{Local, Timelike, Datelike};
use log::*;

use byteorder::{ByteOrder, ReadBytesExt, BigEndian};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use pnet::packet::Packet;

const VOLUME_SYS: u8 = 1;

const MAX_BUFFER_SIZE: u16 = 1024;

const REQUEST_TYPE_CREATE_SERVICE_CONNECTION: u16 = 0x1111;
const REQUEST_TYPE_REQUEST: u16 = 0x2222;
const REQUEST_TYPE_REPLY: u16 = 0x3333;
const REQUEST_TYPE_DESTROY_SERVICE_CONNECTION: u16 = 0x5555;

const CONNECTION_STATUS_NO_CONNECTIONS_AVAILABLE: u8 = 0x04;
const _CONNECTION_STATUS_SERVER_DOWN: u8 = 0x10;

const ERR_CONNECTION_NOT_LOGGED_IN: u8 = 0x7d;
const ERR_OUT_OF_HANDLES: u8 = 0x81;
const _ERR_NO_OPEN_PRIVILEGES: u8 = 0x82;
const ERR_HARD_IO_ERROR: u8 = 0x83;
const ERR_INVALID_FILE_HANDLE: u8 = 0x88;
const ERR_BAD_DIRECTORY_HANDLE: u8 = 0x9b;
const ERR_NO_DIRECTORY_HANDLES: u8 = 0x9d;
const _ERR_OUT_OF_MEMORY: u8 = 0x96;
const ERR_INVALID_PATH: u8 = 0x9c;
const ERR_BAD_DIRECTORY_IO_ERROR: u8 = 0xa1;
const ERR_NO_SUCH_SET: u8 = 0xec;
const ERR_NO_FILES_FOUND: u8 = 0xff;
const ERR_UNSUPPORTED_REQUEST: u8 = 0xff;

const MAX_PATH_LENGTH: usize = 64;
const MAX_VOLUME_NAME_LENGTH : usize = 16;
const MAX_OPEN_FILES: usize = 16;

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

type PathString = BoundedString<MAX_PATH_LENGTH>;

struct Volume {
    name: BoundedString<MAX_VOLUME_NAME_LENGTH>,
    root: String,
}

impl Volume {
    pub const fn zero() -> Self {
        let name = BoundedString::empty();
        Self{ name, root: String::new() }
    }
}

#[derive(Debug)]
struct FileHandle {
    file: Option<std::fs::File>,
}

impl FileHandle {
    const fn zero() -> Self {
        Self{ file: None }
    }

    pub fn is_available(&self) -> bool {
        self.file.is_none()
    }
}

#[derive(Debug,Clone,Copy)]
struct DirectoryHandle {
    volume_number: u8,
    path: PathString,
}

impl DirectoryHandle {
    const fn zero() -> Self {
        let path = PathString::empty();
        Self{ volume_number: 0, path }
    }

    fn is_available(&self) -> bool {
        self.volume_number == 0
    }
}

#[derive(Debug)]
struct SearchHandle {
    id: u16,
    path: Option<String>,
    entries: Option<Vec<DosFileName>>,
}

impl SearchHandle {
    const fn zero() -> Self {
        Self{ id: 0, path: None, entries: None }
    }
}

const MAX_SEARCH_HANDLES: usize = 16;
const MAX_DIR_HANDLES: usize = 32;

#[derive(Debug)]
struct Connection {
    dest: IpxAddr,
    sequence_number: u8,
    dir_handle: [ DirectoryHandle; MAX_DIR_HANDLES ],
    search_handle: [ SearchHandle; MAX_SEARCH_HANDLES ],
    next_search_handle: usize,
    file_handle: [ FileHandle; MAX_OPEN_FILES ],
}

impl Connection {
    const fn zero() -> Self {
        const INIT_DIR_HANDLE: DirectoryHandle = DirectoryHandle::zero();
        let dir_handle = [ INIT_DIR_HANDLE; MAX_DIR_HANDLES ];
        const INIT_SEARCH_HANDLE: SearchHandle = SearchHandle::zero();
        let search_handle = [ INIT_SEARCH_HANDLE ; MAX_SEARCH_HANDLES ];
        let next_search_handle = 0;
        const INIT_FILE_HANDLE: FileHandle = FileHandle::zero();
        let file_handle = [ INIT_FILE_HANDLE; MAX_OPEN_FILES ];
        Connection{ dest: IpxAddr::zero(), sequence_number: 0, dir_handle, search_handle, next_search_handle, file_handle }
    }

    pub fn allocate(dest: &IpxAddr) -> Self {
        let mut c = Connection::zero();
        c.dest = *dest;
        let dh = c.alloc_dir_handle(VOLUME_SYS);
        let dh = dh.unwrap();
        assert!(dh.0 == 1); // must be first directory handle
        c
    }

    pub fn in_use(&self) -> bool {
        !self.dest.is_zero()
    }

    pub fn alloc_dir_handle(&mut self, volume_number: u8) -> Option<(u8, &mut DirectoryHandle)> {
        for (n, dh) in self.dir_handle.iter_mut().enumerate() {
            if !dh.is_available() { continue; }

            *dh = DirectoryHandle::zero();
            dh.volume_number = volume_number;
            return Some(((n + 1) as u8, dh))
        }
        None
    }

    pub fn get_dir_handle(&self, index: u8) -> Option<&DirectoryHandle> {
        let index = index as usize;
        return if index >= 1 && index < self.dir_handle.len() {
            Some(&self.dir_handle[index - 1])
        } else {
            None
        }
    }

    pub fn get_mut_dir_handle(&mut self, index: u8) -> Option<&mut DirectoryHandle> {
        let index = index as usize;
        return if index >= 1 && index < self.dir_handle.len() {
            Some(&mut self.dir_handle[index - 1])
        } else {
            None
        }
    }

    fn allocate_search_handle(&mut self, path: String, contents: Vec<DosFileName>) -> &mut SearchHandle {
        let index = self.next_search_handle % self.search_handle.len();
        self.next_search_handle += 1;

        let sh = &mut self.search_handle[index];
        *sh = SearchHandle::zero();
        sh.id = self.next_search_handle as u16; // XXX is this safe?
        sh.path = Some(path);
        sh.entries = Some(contents);
        sh
    }

    pub fn get_search_handle(&self, id: u16) -> Option<&SearchHandle> {
        for sh in &self.search_handle {
            if sh.entries.is_some() && sh.id == id {
                return Some(sh)
            }
        }
        None
    }

    fn allocate_file_handle(&mut self, file: std::fs::File) -> Option<(u8, &mut FileHandle)> {
        for (n, fh) in self.file_handle.iter_mut().enumerate() {
            if !fh.is_available() { continue; }

            *fh = FileHandle::zero();
            fh.file = Some(file);
            return Some(((n + 1) as u8, fh))
        }
        None
    }

    pub fn get_mut_file_handle(&mut self, index: u8) -> Option<&mut FileHandle> {
        let index = index as usize;
        return if index >= 1 && index < self.file_handle.len() {
            Some(&mut self.file_handle[index - 1])
        } else {
            None
        }
    }
}

pub struct NcpService<'a> {
    config: &'a config::Configuration,
    tx: &'a ipx::Transmitter,
    connections: [ Connection; consts::MAX_CONNECTIONS ],
    volumes: [ Volume; consts::MAX_VOLUMES ],
}

#[derive(Debug)]
struct NcpRequest {
    request_type: u16,
    sequence_number: u8,
    connection_number: u8,
    task_number: u8,
    reserved: u8,
    function_code: u8,
}

impl NcpRequest {
    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Option<Self> {
        let request_type = rdr.read_u16::<BigEndian>().ok()?;
        let sequence_number = rdr.read_u8().ok()?;
        let connection_number = rdr.read_u8().ok()?;
        let task_number = rdr.read_u8().ok()?;
        let reserved = rdr.read_u8().ok()?;
        let function_code = rdr.read_u8().ok()?;
        Some(NcpRequest{ request_type, sequence_number, connection_number, task_number, reserved, function_code })
    }
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
    pub fn new(request: &NcpRequest, completion_code: u8) -> Self {
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
    pub fn new(request: &NcpRequest) -> Self {
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
        const CONN_INIT: Connection = Connection::zero();
        let connections = [ CONN_INIT; consts::MAX_CONNECTIONS ];
        const VOL_INIT: Volume = Volume::zero();
        let mut volumes = [ VOL_INIT; consts::MAX_VOLUMES ];
        let sys_vol = &mut volumes[(VOLUME_SYS - 1) as usize];
        sys_vol.name = BoundedString::from_str("SYS");
        sys_vol.root = config.get_sys_volume_path();
        NcpService{ config, tx, connections, volumes }
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

    pub fn process_packet(&mut self, packet: &ipx::IpxPacket) -> Result<(), std::io::Error> {
        let source = packet.get_source();
        let payload = packet.payload();
        let mut rdr = Cursor::new(payload);
        if let Some(request) = NcpRequest::from(&mut rdr) {
            match request.request_type {
                REQUEST_TYPE_CREATE_SERVICE_CONNECTION => { self.create_service_connection(&source, &request); },
                REQUEST_TYPE_DESTROY_SERVICE_CONNECTION => { self.destroy_service_connection(&source, &request); },
                REQUEST_TYPE_REQUEST => { self.handle_request(&source, &request, &payload[NCP_REQUEST_LENGTH..]); },
                _ => {
                    warn!("ignoring unrecognized NCP request {:?}", request);
                }
            }
        }
        Ok(())
    }

    fn process_request(&mut self, request: &NcpRequest, payload: &[u8]) {
        match request.function_code {
            20 => { self.process_request_20_get_fileserver_date_and_time(&request, payload); }
            22 => { self.process_request_22(&request, payload); },
            23 => { self.process_request_23(&request, payload); },
            33 => { self.process_request_33_negotiate_buffer_size(&request, payload); },
            62 => { self.process_request_62_file_search_init(&request, payload); },
            63 => { self.process_request_63_file_search_continue(&request, payload); },
            66 => { self.process_request_66_close_file(&request, payload); },
            72 => { self.process_request_72_read_from_file(&request, payload); },
            76 => { self.process_request_76_open_file(&request, payload); },
            97 => { self.process_request_97_get_big_packet_ncp_max_packet_size(&request, payload); },
            101 => { self.process_request_101_packet_burst_connection_request(&request, payload); },
            _ => {
                warn!("{}: unrecognized request {}", request.connection_number - 1, request.function_code);
                self.send_completion_code_reply(request, ERR_UNSUPPORTED_REQUEST);
            },
        }
    }

    fn process_request_22(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let conn_nr = request.connection_number - 1;
        let mut rdr = Cursor::new(payload);
        let sub_func_struc_len = rdr.read_u16::<BigEndian>().ok()?;
        let sub_func = rdr.read_u8().ok()?;
        if payload.len() != 2 + (sub_func_struc_len as usize) {
            warn!("{}: request 22 struct length mismatch (got {}, but payload length is {}), dropping",
                conn_nr, sub_func_struc_len, payload.len());
            return None;
        }
        let payload = &payload[3..];
        match sub_func {
            3 => { self.process_request_22_3_get_effective_directory_rights(&request, payload); },
            19 => { self.process_request_22_19_allocate_temp_dir_handle(&request, payload); },
            20 => { self.process_request_22_20_deallocate_dir_handle(&request, payload); },
            21 => { self.process_request_22_21_get_volume_info_with_handle(&request, payload); },
            _ => {
                warn!("{}: unrecognized request 22 subfunc {} struc_len {}", conn_nr, sub_func, sub_func_struc_len);
                self.send_completion_code_reply(request, ERR_UNSUPPORTED_REQUEST);
            }
        }
        Some(())
    }

    fn process_request_23(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let conn_nr = request.connection_number - 1;
        let mut rdr = Cursor::new(payload);
        let sub_func_struc_len = rdr.read_u16::<BigEndian>().ok()?;
        let sub_func = rdr.read_u8().ok()?;
        if payload.len() != 2 + (sub_func_struc_len as usize) {
            warn!("{}: request 23 struct length mismatch (got {}, but payload length is {}), dropping",
                conn_nr, sub_func_struc_len, payload.len());
            return None;
        }
        let payload = &payload[3..];
        match sub_func {
            17 => { self.process_request_23_17_get_fileserver_info(&request, payload); },
            61 => { self.process_request_23_61_read_property_value(&request, payload); },
            _ => {
                warn!("{}: unrecognized request 23 subfunc {} struc_len {}", conn_nr, sub_func, sub_func_struc_len);
                self.send_completion_code_reply(request, ERR_UNSUPPORTED_REQUEST);
            }
        }
        Some(())
    }

   fn process_request_23_17_get_fileserver_info(&mut self, request: &NcpRequest, _payload: &[u8]) {
        let mut reply = NcpReplyPacket::<128>::new(request);
        reply.add_data(self.config.get_server_name());
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
    }

    fn process_request_23_61_read_property_value(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let object_type = rdr.read_u16::<BigEndian>().ok()?;
        let object_name = MaxBoundedString::from(&mut rdr)?;
        let segment_number = rdr.read_u8().ok()?;
        let property_name = MaxBoundedString::from(&mut rdr)?;
        info!("{}: Read property value, object type {:x} object '{}' segment {} property '{}'", request.connection_number, object_type, object_name, segment_number, property_name);

        self.send_completion_code_reply(request, ERR_NO_SUCH_SET);
        Some(())
    }

    fn process_request_33_negotiate_buffer_size(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let proposed_buffer_size = rdr.read_u16::<BigEndian>().ok()?;
        info!("{}: Negotiate buffer size, proposed_buffer_size {}", request.connection_number, proposed_buffer_size);

        let accepted_buffer_size = if proposed_buffer_size > MAX_BUFFER_SIZE { MAX_BUFFER_SIZE } else { proposed_buffer_size };

        let mut reply = NcpReplyPacket::<2>::new(request);
        reply.add_u16(accepted_buffer_size);
        reply.send(&self);
        Some(())
    }

    fn process_request_62_file_search_init(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let handle = rdr.read_u8().ok()?;
        let path = PathString::from(&mut rdr)?;
        info!("{}: File search initialize, handle {} path {}", request.connection_number, handle, path);

        let conn = self.get_connection(&request);
        if let Some(source_dh) = conn.get_dir_handle(handle) {
            let path = self.create_system_path(source_dh, &path);
            let volume_number = source_dh.volume_number; // XXX assumes this can't traverse volumes
            if let Some(contents) = retrieve_directory_contents(Path::new(&path)) {
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
            } else {
                self.send_completion_code_reply(request, ERR_BAD_DIRECTORY_IO_ERROR);
            }
        } else {
            self.send_completion_code_reply(request, ERR_BAD_DIRECTORY_HANDLE);
        }
        Some(())
    }

    fn process_request_63_file_search_continue(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let volume_number = rdr.read_u8().ok()?;
        let directory_id = rdr.read_u16::<BigEndian>().ok()?;
        let search_sequence = rdr.read_u16::<BigEndian>().ok()?;
        let search_attr = rdr.read_u8().ok()?;
        let search_path = MaxBoundedString::from(&mut rdr)?;
        info!("{}: File search continue, volume_number {} directory_id {} search_sequence {} search_attr {} search_path {}", request.connection_number, volume_number, directory_id, search_sequence, search_attr, search_path);

        let conn = self.get_connection(&request);
        if let Some(sh) = conn.get_search_handle(directory_id) {
            if let Some(path) = &sh.path {
                if let Some(entries) = &sh.entries {
                    let mut index = search_sequence as usize;
                    if index == 0xffff { index = 0; }

                    let want_files = (search_attr & SA_SUBDIR_ONLY) == 0;
                    let want_dirs = (search_attr & SA_SUBDIR_ONLY) != 0;
                    while index < entries.len() {
                        let entry = entries[index];
                        index += 1;

                        if !entry.matches(&search_path.data()) { continue; }

                        // XXX verify match, etc.
                        let p = format!("{}/{}", path, entry);
                        if let Ok(md) = std::fs::metadata(&p) {
                            let ft = md.file_type();
                            if ft.is_dir() && want_dirs {
                                let mut reply = NcpReplyPacket::<32>::new(request);
                                reply.add_u16(index as u16); // search sequence
                                reply.add_u16(directory_id); // directory id
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
                                return Some(())
                            }
                            if ft.is_file() && want_files {
                                let mut reply = NcpReplyPacket::<32>::new(request);
                                reply.add_u16(index as u16); // search sequence
                                reply.add_u16(directory_id); // directory id
                                entry.to(&mut reply); // file name
                                reply.add_u8(0); // file attributes
                                reply.add_u8(0); // file mode
                                reply.add_u32(md.len() as u32); // file length
                                reply.add_u16(0); // creation date
                                reply.add_u16(0); // access date
                                reply.add_u16(0); // update date
                                reply.add_u16(0); // update time
                                reply.send(&self);
                                return Some(())
                            }
                        }
                    }
                }
            }
        }
        self.send_completion_code_reply(request, ERR_NO_FILES_FOUND);
        Some(())
    }

    fn process_request_97_get_big_packet_ncp_max_packet_size(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let proposed_max_size = rdr.read_u16::<BigEndian>().ok()?;
        let security_flag = rdr.read_u8().ok()?;
        info!("{}: unsupported: Get Big Packet NCP Max Packet Size, proposed_max_size {} security_flag {:x}", request.connection_number, proposed_max_size, security_flag);

        self.send_completion_code_reply(request, ERR_UNSUPPORTED_REQUEST);
        Some(())
    }

    fn process_request_101_packet_burst_connection_request(&mut self, request: &NcpRequest, _payload: &[u8]) -> Option<()> {
        info!("{}: unsupported: Packet burst connection request (unsupported)", request.connection_number);
        self.send_completion_code_reply(request, ERR_UNSUPPORTED_REQUEST);
        Some(())
    }

    fn process_request_20_get_fileserver_date_and_time(&mut self, request: &NcpRequest, _payload: &[u8]) -> Option<()> {
        info!("{}: Get file server date and time", request.connection_number);
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
        Some(())
    }

    fn process_request_22_3_get_effective_directory_rights(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let directory_handle = rdr.read_u8().ok()?;
        let directory_path = PathString::from(&mut rdr)?;
        info!("{}: Get effective directory rights, handle {} path '{}'", request.connection_number, directory_handle, directory_path);

        let conn = self.get_connection(&request);
        if let Some(dh) = conn.get_dir_handle(directory_handle) {
            let path = self.create_system_path(dh, &directory_path);
            if let Ok(md) = std::fs::metadata(&path) {
                if md.file_type().is_dir() {
                    let mut reply = NcpReplyPacket::<2>::new(request);
                    let effective_rights_mask = 0xffff;
                    reply.add_u16(effective_rights_mask);
                    reply.send(&self);
                } else {
                    self.send_completion_code_reply(request, ERR_INVALID_PATH);
                }
            } else {
                self.send_completion_code_reply(request, ERR_INVALID_PATH);
            }
        } else {
            self.send_completion_code_reply(request, ERR_BAD_DIRECTORY_HANDLE);
        }
        Some(())
    }

    fn process_request_22_21_get_volume_info_with_handle(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let directory_handle = rdr.read_u8().ok()?;
        info!("{}: Get volume info with handle, handle {}", request.connection_number, directory_handle);

        let conn = self.get_connection(&request);
        if let Some(dh) = conn.get_dir_handle(directory_handle) {
            let volume = &self.volumes[(dh.volume_number - 1) as usize];

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
        } else {
            self.send_completion_code_reply(request, ERR_BAD_DIRECTORY_HANDLE);
        }
        Some(())
    }

    fn process_request_22_19_allocate_temp_dir_handle(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let source_directory_handle = rdr.read_u8().ok()?;
        let handle_name = rdr.read_u8().ok()?;
        let directory_path = PathString::from(&mut rdr)?;
        info!("{}: Allocate temporary directory handle, source handle {} name {} path '{}'", request.connection_number, source_directory_handle, handle_name, directory_path);

        let conn = self.get_mut_connection(&request);
        if let Some(source_dh) = conn.get_dir_handle(source_directory_handle) {
            let path = combine_dh_path(source_dh, &directory_path);
            // XXX verify existance etc

            let volume_number = source_dh.volume_number;
            if let Some((new_dh_index, new_dh)) = conn.alloc_dir_handle(volume_number) {
                new_dh.path = path;
                let mut reply = NcpReplyPacket::<2>::new(request);
                reply.add_u8(new_dh_index);
                let access_rights_mask = 0xff; // TODO
                reply.add_u8(access_rights_mask);
                reply.send(&self);
            } else {
                self.send_completion_code_reply(request, ERR_NO_DIRECTORY_HANDLES);
            }
        } else {
            self.send_completion_code_reply(request, ERR_BAD_DIRECTORY_HANDLE);
        }
        Some(())
    }

    fn process_request_22_20_deallocate_dir_handle(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let directory_handle = rdr.read_u8().ok()?;
        info!("{}: Deallocate directory handle, handle {}", request.connection_number, directory_handle);

        let conn = self.get_mut_connection(&request);
        if let Some(dh) = conn.get_mut_dir_handle(directory_handle) {
            *dh = DirectoryHandle::zero();
            self.send_completion_code_reply(request, 0);
        } else {
            self.send_completion_code_reply(request, ERR_BAD_DIRECTORY_HANDLE);
        }
        Some(())
    }

    fn process_request_76_open_file(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let directory_handle = rdr.read_u8().ok()?;
        let search_attr = rdr.read_u8().ok()?;
        let desired_access = rdr.read_u8().ok()?;
        let filename = PathString::from(&mut rdr)?;
        info!("{}: Open file, handle {} search_attr {} desired_access {} filename '{}'", request.connection_number, directory_handle, search_attr, desired_access, filename);

        let conn = self.get_connection(&request);
        if let Some(dh) = conn.get_dir_handle(directory_handle) {
            let path = self.create_system_path(dh, &filename);

            if let Some(filename) = extract_filename_from(&path) {
                if let Ok(f) = File::open(&path) {
                    if let Ok(md) = f.metadata() {
                        let conn = self.get_mut_connection(&request);
                        if let Some((fh_index, _)) = conn.allocate_file_handle(f) {
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
                            self.send_completion_code_reply(request, ERR_OUT_OF_HANDLES);
                        }
                    } else {
                        error!("cannot extract metadata from '{}' ?!", path);
                        self.send_completion_code_reply(request, ERR_INVALID_PATH);
                    }
                } else {
                    self.send_completion_code_reply(request, ERR_INVALID_PATH);
                }
            } else {
                error!("cannot extract 8.3 filename from '{}' ?!", path);
                self.send_completion_code_reply(request, ERR_INVALID_PATH);
            }
        } else {
            self.send_completion_code_reply(request, ERR_BAD_DIRECTORY_HANDLE);
        }
        Some(())
    }

    fn process_request_72_read_from_file(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let _reserved = rdr.read_u8().ok()?;
        let _file_handle_hi = rdr.read_u32::<BigEndian>().ok()?;
        let file_handle = rdr.read_u16::<BigEndian>().ok()?;
        let offset = rdr.read_u32::<BigEndian>().ok()?;
        let length = rdr.read_u16::<BigEndian>().ok()?;
        let odd = offset & 1;
        info!("{}: Read from file, handle {} offset {} length {}", request.connection_number, file_handle, offset, length);

        let conn = self.get_mut_connection(&request);
        if let Some(fh) = conn.get_mut_file_handle(file_handle as u8) {
            let mut file = fh.file.as_ref().unwrap();
            file.seek(SeekFrom::Start(offset as u64)).ok()?;

            let mut data = vec![ 0u8; length.into() ];
            if let Ok(count) = file.read(&mut data) {
                let mut reply = NcpReplyPacket::<{2 + 65536}>::new(request);
                reply.add_u16(count as u16);
                // Reads from unaligned offsets must insert a dummy byte
                if odd != 0 { reply.add_u8(0); }
                reply.add_data(&data[0..count]);
                reply.send(&self);
            } else {
                error!("read error!");
                self.send_completion_code_reply(request, ERR_HARD_IO_ERROR);
            }
        } else {
            self.send_completion_code_reply(request, ERR_INVALID_FILE_HANDLE);
        }

        Some(())
    }

    fn process_request_66_close_file(&mut self, request: &NcpRequest, payload: &[u8]) -> Option<()> {
        let mut rdr = Cursor::new(payload);
        let _reserved = rdr.read_u8().ok()?;
        let _file_handle_hi = rdr.read_u32::<BigEndian>().ok()?;
        let file_handle = rdr.read_u16::<BigEndian>().ok()?;
        info!("{}: Close file, handle {}", request.connection_number, file_handle);

        let conn = self.get_mut_connection(&request);
        if let Some(fh) = conn.get_mut_file_handle(file_handle as u8) {
            *fh = FileHandle::zero();
            self.send_completion_code_reply(request, 0);
        } else {
            self.send_completion_code_reply(request, ERR_INVALID_FILE_HANDLE);
        }

        Some(())
    }

    fn get_connection_index(&self, dest: &IpxAddr, request: &NcpRequest) -> Option<usize> {
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

    fn get_connection(&self, request: &NcpRequest) -> &Connection {
        let connection_number = request.connection_number as usize;
        if connection_number >= 1 && connection_number < consts::MAX_CONNECTIONS {
            let index = connection_number - 1;
            return &self.connections[index];
        }
        unreachable!()
    }

    fn get_mut_connection(&mut self, request: &NcpRequest) -> &mut Connection {
        let connection_number = request.connection_number as usize;
        if connection_number >= 1 && connection_number < consts::MAX_CONNECTIONS {
            let index = connection_number - 1;
            return &mut self.connections[index];
        }
        unreachable!()
    }

    fn handle_request(&mut self, dest: &IpxAddr, request: &NcpRequest, payload: &[u8]) {
        if self.get_connection_index(dest, request).is_none() {
            // 'dest' does not own this connection - reject
            let reply = NcpReply::new(&request, ERR_CONNECTION_NOT_LOGGED_IN);
            self.send_reply(dest, &reply, &[]);
            return;
        }
        self.process_request(&request, payload);
    }

    fn allocate_connection(&mut self, dest: &IpxAddr) -> Option<usize> {
        for (n, conn) in self.connections.iter_mut().enumerate() {
            if conn.in_use() { continue; }

            *conn = Connection::allocate(dest);
            return Some(n);
        }
        None
    }

    fn create_service_connection(&mut self, dest: &IpxAddr, request: &NcpRequest) {
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

    fn destroy_service_connection(&mut self, dest: &IpxAddr, request: &NcpRequest) {
        trace!("{}: destroy_service_connection(): dest {}", request.connection_number, dest);
        let mut reply = NcpReply::new(&request, 0);
        if let Some(index) = self.get_connection_index(dest, request) {
            let conn = &mut self.connections[index];
            *conn = Connection::zero();
        } else {
            reply.connection_status = 0xff;
        }
        self.send_reply(dest, &reply, &[]);
    }

    fn send_completion_code_reply(&mut self, request: &NcpRequest, code: u8) {
        let mut reply = NcpReplyPacket::<0>::new(request);
        reply.set_completion_code(code);
        reply.send(&self);
    }

    fn create_system_path(&self, dh: &DirectoryHandle, sub_path: &PathString) -> String {
        let path = combine_dh_path(dh, sub_path);
        let volume = &self.volumes[(dh.volume_number - 1) as usize];
        if !path.is_empty() {
            let path = format!("{}/{}", volume.root, path);
            return str::replace(&path, "\\", "/")
        }
        volume.root.as_str().to_string()
    }
}

fn retrieve_directory_contents(path: &Path) -> Option<Vec<DosFileName>> {
    if let Ok(entries) = std::fs::read_dir(path) {
        let mut results: Vec<DosFileName> = Vec::new();
        for entry in entries {
            if let Ok(item) = entry {
                let f = item.file_name();
                let file_name = f.to_str()?;
                if let Some(file_name) = DosFileName::from_str(file_name) {
                    results.push(file_name.clone());
                }
            }
        }
        return Some(results);
    }
    None
}

fn combine_dh_path(dh: &DirectoryHandle, sub_path: &PathString) -> PathString {
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
