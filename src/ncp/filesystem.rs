/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::connection;
use crate::config;
use super::parser;
use crate::handle;
use crate::types::*;
use crate::error::*;
use crate::ncp_service::NcpReplyPacket;

use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use std::path::Path;

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

fn combine_paths(dir1: &str, dir2: &str, dir3: &str) -> String {
    let mut result = String::new();
    for d in &[ dir1, dir2, dir3 ] {
        let d = d.trim_start_matches(|c: char| { c == '\\' } );

        if d.is_empty() { continue; }
        if !result.is_empty() { result.push_str("/"); }
        result.push_str(d);
    }
    result.replace("\\", "/")
}

struct NetWarePath {
    volume: u8,
    writeable: bool,
    volume_path: String,
    local_path: String,
}

fn find_volume_by_name<'a>(config: &'a config::Configuration, vol_name: &str) -> Result<&'a config::Volume, NetWareError> {
    let vol_name = MaxBoundedString::from_str(vol_name);
    for vol in config.get_volumes() {
        if vol.name.equals(vol_name) {
            return Ok(vol)
        }
    }
    Err(NetWareError::NoSuchVolume)
}


impl NetWarePath {
    pub fn new(conn: &connection::Connection, config: &config::Configuration, dh: u8, path: &MaxBoundedString) -> Result<Self, NetWareError> {
        let volume;
        let local_path;
        let volume_path;
        if dh == 0 {
            // No directory handle supplied; this means we need to seperate path into VOL:PATH
            let path = path.as_str();
            let colon = path.find(':');
            if colon.is_none() { return Err(NetWareError::NoSuchVolume); }
            let colon = colon.unwrap();

            volume = find_volume_by_name(config, &path[0..colon])?;
            volume_path = path[colon + 1..].to_string();
            local_path = combine_paths(&volume.path, &volume_path, "");
        } else {
            // Base the path on the supplied directory handle
            let dh = conn.get_dir_handle(dh)?;
            volume = dh.volume.unwrap();
            volume_path = path.to_string();
            local_path = combine_paths(&volume.path, dh.path.as_str(), &volume_path);
        }
        Ok(NetWarePath{ volume: volume.number, volume_path, local_path, writeable: volume.writeable })
    }

    // Yields the index of the volume, i.e. 0 for SYS
    pub fn get_volume_index(&self) -> u8 {
        self.volume
    }

    // Yields the path on the local filesystem, i.e. /opt/nwserver/vol/sys/LOGIN/LOGIN.EXE
    pub fn get_local_path(&self) -> &String {
        &self.local_path
    }

    // Yields the path on the volume, i.e. LOGIN/LOGIN.EXE
    pub fn get_volume_path(&self) -> &String {
        &self.volume_path
    }

    pub fn get_access_rights(&self) -> u8 {
        0xff // TODO
    }

    pub fn is_writeable(&self) -> bool {
        self.writeable
    }
}

pub fn process_request_62_file_search_init<'a>(conn: &mut connection::Connection, config: &'a config::Configuration, args: &parser::FileSearchInit, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let nw_path = NetWarePath::new(conn, config, args.handle, &args.path)?;
    let contents = retrieve_directory_contents(nw_path.get_local_path())?;

    // XXX verify existance, access etc
    let sh = conn.allocate_search_handle(nw_path.get_local_path(), contents);
    reply.add_u8(nw_path.get_volume_index());
    let directory_id = sh.id;
    reply.add_u16(directory_id);
    let search_sequence_number = 0xffff;
    reply.add_u16(search_sequence_number);
    reply.add_u8(nw_path.get_access_rights());
    Ok(())
}

pub fn process_request_63_file_search_continue(conn: &mut connection::Connection, args: &parser::FileSearchContinue, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
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

pub fn process_request_22_3_get_effective_directory_rights<'a>(conn: &mut connection::Connection, config: &'a config::Configuration, args: &parser::GetEffectiveDirectoryRights, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let nw_path = NetWarePath::new(conn, config, args.directory_handle, &args.directory_path)?;
    let md = std::fs::metadata(nw_path.get_local_path());
    if md.is_err() || !md.unwrap().file_type().is_dir() {
        return Err(NetWareError::InvalidPath);
    }
    reply.add_u8(nw_path.get_access_rights());
    Ok(())
}

pub fn process_request_22_21_get_volume_info_with_handle(conn: &mut connection::Connection, args: &parser::GetVolumeInfoWithHandle, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
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

pub fn process_request_22_20_deallocate_dir_handle(conn: &mut connection::Connection, args: &parser::DeallocateDirectoryHandle, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let dh = conn.get_mut_dir_handle(args.directory_handle)?;
    *dh = handle::DirectoryHandle::zero();
    Ok(())
}

pub fn process_request_22_19_allocate_temp_dir_handle<'a>(conn: &mut connection::Connection<'a>, config: &'a config::Configuration, args: &parser::AllocateTemporaryDirectoryHandle, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    // Construct destination path and ensure it exists
    let nw_path = NetWarePath::new(conn, config, args.source_directory_handle, &args.directory_path)?;
    let md = std::fs::metadata(&nw_path.get_local_path());
    if md.is_err() || !md.unwrap().is_dir() {
        return Err(NetWareError::InvalidPath);
    }

    // Create the new handle
    let (new_dh_index, new_dh) = conn.alloc_dir_handle(&config, nw_path.get_volume_index() as usize)?;
    new_dh.path = MaxBoundedString::from_str(nw_path.get_volume_path());

    reply.add_u8(new_dh_index);
    reply.add_u8(nw_path.get_access_rights());
    Ok(())
}

pub fn process_request_22_18_allocate_perm_dir_handle<'a>(conn: &mut connection::Connection<'a>, config: &'a config::Configuration, args: &parser::AllocatePermanentDirectoryHandle, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    // TODO check is handle_name exists and overwrite it if needed?

    // Construct destination path and ensure it exists
    let nw_path = NetWarePath::new(conn, config, args.source_directory_handle, &args.directory_path)?;
    let md = std::fs::metadata(&nw_path.get_local_path());
    if md.is_err() || !md.unwrap().is_dir() {
        return Err(NetWareError::InvalidPath);
    }

    // Create the new handle
    let (new_dh_index, new_dh) = conn.alloc_dir_handle(&config, nw_path.get_volume_index() as usize)?;
    new_dh.path = MaxBoundedString::from_str(nw_path.get_volume_path());

    reply.add_u8(new_dh_index);
    reply.add_u8(nw_path.get_access_rights());
    Ok(())
}

pub fn process_request_22_1_get_directory_path<'a>(conn: &mut connection::Connection<'a>, args: &parser::GetDirectoryPath, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let dh = conn.get_dir_handle(args.directory_handle)?;
    // TODO does dh.path contain the proper seperators ?
    let volume = dh.volume.unwrap();
    let length = volume.name.len() + 1 + dh.path.len();
    reply.add_u8(length as u8);
    reply.add_data(&volume.name.data()[0..volume.name.len()]);
    reply.add_u8(0x3a); // :
    reply.add_data(&dh.path.data()[0..dh.path.len()]);
    Ok(())
}

pub fn process_request_76_open_file<'a>(conn: &mut connection::Connection, config: &'a config::Configuration, args: &parser::OpenFile, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let nw_path = NetWarePath::new(conn, config, args.directory_handle, &args.filename)?;

    let filename = extract_filename_from(nw_path.get_local_path())?;
    if let Ok(f) = File::open(nw_path.get_local_path()) {
        let md = f.metadata()?;
        let (fh_index, _) = conn.allocate_file_handle(f)?;
        let ncp_fh = NcpFileHandle::new(fh_index);
        ncp_fh.to(reply);
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

pub fn process_request_72_read_from_file(conn: &mut connection::Connection, args: &parser::ReadFromFile, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let fh = conn.get_mut_file_handle(args.file_handle.get_value())?;
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

pub fn process_request_66_close_file(conn: &mut connection::Connection, args: &parser::CloseFile, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let fh = conn.get_mut_file_handle(args.file_handle.get_value())?;
    *fh = handle::FileHandle::zero();
    Ok(())
}

pub fn process_request_64_search_for_file<'a>(conn: &mut connection::Connection, config: &'a config::Configuration, args: &parser::SearchForFile, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let (path, filename) = split_path(&args.filename);
    let nw_path = NetWarePath::new(conn, config, args.directory_handle, &path)?;
    println!("sff '{}' '{}'", nw_path.get_local_path(), nw_path.get_volume_path());
    let entries = retrieve_directory_contents(nw_path.get_local_path())?;

    let mut index = args.last_search_index as usize;
    if index == 0xffff { index = 0; }

    while index < entries.len() {
        let entry = entries[index];
        index += 1;

        if !entry.matches(&filename.data()) { continue; }

        // XXX verify match, etc.
        let p = format!("{}/{}", path, entry);
        if let Ok(md) = std::fs::metadata(&p) {
            if md.file_type().is_file() {
                reply.add_u16(index as u16); // next search index
                reply.add_u16(0); // reserved
                entry.to(reply); // file name
                let attr = 0;
                reply.add_u8(attr); // file attributes
                reply.add_u8(0); // file execute type
                reply.add_u32(md.len() as u32); // file length
                reply.add_u16(0); // creation date
                reply.add_u16(0); // access date
                reply.add_u16(0); // update date
                reply.add_u16(0); // update time
                return Ok(())
            }
        }
    }
    Err(NetWareError::NoFilesFound)
}

pub fn process_request_22_10_create_directory<'a>(conn: &mut connection::Connection, config: &'a config::Configuration, args: &parser::CreateDirectory, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let nw_path = NetWarePath::new(conn, config, args.directory_handle, &args.path)?;
    if !nw_path.is_writeable() {
        return Err(NetWareError::NoCreatePrivileges)
    }

    return match std::fs::create_dir(nw_path.get_local_path()) {
        Ok(_) => Ok(()),
        Err(_) => Err(NetWareError::DirectoryIoError),
    }
}

pub fn process_request_22_11_delete_directory<'a>(conn: &mut connection::Connection, config: &'a config::Configuration, args: &parser::DeleteDirectory, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let nw_path = NetWarePath::new(conn, config, args.directory_handle, &args.path)?;
    if !nw_path.is_writeable() {
        return Err(NetWareError::NoDeletePrivileges)
    }

    return match std::fs::remove_dir(nw_path.get_local_path()) {
        Ok(_) => Ok(()),
        Err(_) => Err(NetWareError::DirectoryIoError),
    }
}

fn retrieve_directory_contents(path: &String) -> Result<Vec<DosFileName>, std::io::Error> {
    let path = Path::new(path);
    let mut results: Vec<DosFileName> = Vec::new();

    if let Ok(md) = std::fs::metadata(path) {
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
    }
    Ok(results)
}

fn find_last_slash(path: &MaxBoundedString) -> Option<usize> {
    let mut last_slash_index: Option<usize> = None;
    for index in 0..path.len() {
        if path.data()[index] == 0x5c /* \ */ {
            last_slash_index = Some(index);
        }
    }
    last_slash_index
}

// Takes FOO/BAR/BAZ.TXT, returns ("FOO/BAR", "BAZ.TXT")
fn split_path(path: &MaxBoundedString) -> (MaxBoundedString, MaxBoundedString) {
    if let Some(n) = find_last_slash(path) {
        let data = path.data();
        let path = MaxBoundedString::from_slice(&data[0..n]);
        let filename = MaxBoundedString::from_slice(&data[n + 1..]);
        return (path, filename)
    }
    return (MaxBoundedString::empty(), *path)
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
