/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::bindery;
use crate::consts;
use crate::types::*;
use crate::handle;
use crate::error::NetWareError;
use crate::config;

use byteorder::{ByteOrder, BigEndian};
use log::*;

pub struct Connection<'a> {
    pub dest: IpxAddr,
    dir_handle: [ handle::DirectoryHandle<'a>; consts::MAX_DIR_HANDLES ],
    search_handle: [ handle::SearchHandle; consts::MAX_SEARCH_HANDLES ],
    next_search_handle: usize,
    file_handle: [ handle::FileHandle; consts::MAX_OPEN_FILES ],
    pub login_key: Option<LoginKey>,
    pub logged_in_object_id: bindery::ObjectID,
    pub bindery_security: bindery::Security,
    security_equals_ids: [ bindery::ObjectID; consts::MAX_SECURITY_EQUALS_IDS ],
}

impl<'a> Connection<'a> {
    pub const fn zero() -> Self {
        const INIT_DIR_HANDLE: handle::DirectoryHandle = handle::DirectoryHandle::zero();
        let dir_handle = [ INIT_DIR_HANDLE; consts::MAX_DIR_HANDLES ];
        const INIT_SEARCH_HANDLE: handle::SearchHandle = handle::SearchHandle::zero();
        let search_handle = [ INIT_SEARCH_HANDLE; consts::MAX_SEARCH_HANDLES ];
        let next_search_handle = 0;
        const INIT_FILE_HANDLE: handle::FileHandle = handle::FileHandle::zero();
        let file_handle = [ INIT_FILE_HANDLE; consts::MAX_OPEN_FILES ];
        let logged_in_object_id = 0;
        let bindery_security = 0;
        let security_equals_ids = [ bindery::ID_EMPTY; consts::MAX_SECURITY_EQUALS_IDS ];
        Connection{ dest: IpxAddr::zero(), dir_handle, search_handle, next_search_handle, file_handle, login_key: None, logged_in_object_id, bindery_security, security_equals_ids }
    }

    pub fn is_logged_on(&self) -> bool {
        self.logged_in_object_id != bindery::ID_NOT_LOGGED_IN
    }

    pub fn get_security_equivalent_ids(&self) -> &[ bindery::ObjectID; consts::MAX_SECURITY_EQUALS_IDS] {
        &self.security_equals_ids
    }

    pub fn allocate(config: &'a config::Configuration, dest: &IpxAddr) -> Self {
        let mut c = Connection::zero();
        c.dest = *dest;
        c.logout(config);
        c
    }

    pub fn logout(&mut self, config: &'a config::Configuration) {
        self.login_key = None;
        self.logged_in_object_id = bindery::ID_NOT_LOGGED_IN;
        self.bindery_security = bindery::SECURITY_NOT_LOGGED_IN;
        self.security_equals_ids = [ bindery::ID_EMPTY; consts::MAX_SECURITY_EQUALS_IDS ];
        self.security_equals_ids[0] = bindery::ID_NOT_LOGGED_IN;

        // Reset all directory handles
        const INIT_DIR_HANDLE: handle::DirectoryHandle = handle::DirectoryHandle::zero();
        self.dir_handle = [ INIT_DIR_HANDLE; consts::MAX_DIR_HANDLES ];

        // Reset all search handles
        const INIT_SEARCH_HANDLE: handle::SearchHandle = handle::SearchHandle::zero();
        self.search_handle = [ INIT_SEARCH_HANDLE; consts::MAX_SEARCH_HANDLES ];
        self.next_search_handle = 0;

        // Reset all file handles
        const INIT_FILE_HANDLE: handle::FileHandle = handle::FileHandle::zero();
        self.file_handle = [ INIT_FILE_HANDLE; consts::MAX_OPEN_FILES ];

        // Set up the login directory handle; it is special as it will never be
        let login_dh = &mut self.dir_handle[(handle::DH_INDEX_LOGIN - 1) as usize];
        let volume = config.get_volumes().get_volume_by_number(config.get_login_volume() as usize).expect("login volume not found");
        login_dh.volume = Some(volume);
        login_dh.typ = handle::DirectoryHandleType::Permanent;
        login_dh.path = MaxBoundedString::from_str(config.get_login_root());
    }

    pub fn is_supervisor_equivalent(&self) -> bool {
        self.security_equals_ids.iter().any(|id| *id == bindery::ID_SUPERVISOR)
    }

    pub fn has_console_rights(&self) -> bool {
        // TODO Also consider OPERATORS property of file server bindery object
        self.is_supervisor_equivalent()
    }

    pub fn login(&mut self, bindery: &mut bindery::Bindery, object_id: bindery::ObjectID) {
        self.logged_in_object_id = object_id;
        self.security_equals_ids = [ bindery::ID_EMPTY; consts::MAX_SECURITY_EQUALS_IDS ];
        self.security_equals_ids[0] = object_id;

        let object = bindery.get_mut_object_by_id(object_id).expect("cannot find object?");
        if let Ok(security_equals) = object.get_property_by_name("SECURITY_EQUALS") {
            // XXX This only handles the first property segment
            let mut n = 1;
            if let Some(value) = security_equals.get_segment(0) {
                for offset in (0..consts::PROPERTY_SEGMENT_LENGTH).step_by(4) {
                    let buf = &value[offset..offset + 4];
                    let value_id = BigEndian::read_u32(buf);
                    if value_id != bindery::ID_EMPTY {
                        if n < consts::MAX_SECURITY_EQUALS_IDS {
                            self.security_equals_ids[n] = value_id;
                            n += 1;
                        } else {
                            warn!("ignoring security equivalence, out of items!");
                        }
                    }
                }
            }
        }

        self.bindery_security = if self.is_supervisor_equivalent() { 0x33 } else { 0x11 };
    }

    pub fn in_use(&self) -> bool {
        !self.dest.is_zero()
    }

    pub fn free_temp_dir_handles(&mut self) -> usize {
        let mut num_freed = 0;
        for dh in self.dir_handle.iter_mut() {
            if dh.is_available() { continue; }
            if dh.typ != handle::DirectoryHandleType::Temporary { continue; }

            *dh = handle::DirectoryHandle::zero();
            num_freed += 1;
        }
        num_freed
    }

    pub fn alloc_dir_handle(&mut self, config: &'a config::Configuration, typ: handle::DirectoryHandleType, volume_index: usize) -> Result<(u8, &mut handle::DirectoryHandle<'a>), NetWareError> {
       if let Some((n, dh)) = self.dir_handle
            .iter_mut()
            .enumerate()
            .find(|(n, dh)|
                // Never allocate the login directory handle
                *n != (handle::DH_INDEX_LOGIN - 1) as usize &&
                dh.is_available()) {
            *dh = handle::DirectoryHandle::zero();
            let volume = config.get_volumes().get_volume_by_number(volume_index)?;
            dh.volume = Some(volume);
            dh.typ = typ;
            return Ok(((n + 1) as u8, dh))
        }
        Err(NetWareError::NoDirectoryHandlesLeft)
    }

    pub fn get_dir_handle(&self, index: u8) -> Result<&handle::DirectoryHandle, NetWareError> {
        let index = index as usize;
        if index >= 1 && index < self.dir_handle.len() {
            let dh = &self.dir_handle[index - 1];
            if dh.volume.is_some() {
                return Ok(dh)
            }
        }
        Err(NetWareError::BadDirectoryHandle)
    }

    pub fn get_mut_dir_handle(&mut self, index: u8) -> Result<&mut handle::DirectoryHandle<'a>, NetWareError> {
        let index = index as usize;
        if index >= 1 && index < self.dir_handle.len() {
            let dh = &mut self.dir_handle[index - 1];
            if dh.volume.is_some() {
                return Ok(dh)
            }
        }
        Err(NetWareError::BadDirectoryHandle)
    }

    pub fn allocate_search_handle(&mut self, local_path: &String, volume: u8, volume_path: &String, contents: Vec<DosFileName>) -> &mut handle::SearchHandle {
        let index = self.next_search_handle % self.search_handle.len();
        self.next_search_handle += 1;

        let sh = &mut self.search_handle[index];
        *sh = handle::SearchHandle::zero();
        sh.id = self.next_search_handle as u16; // XXX is this safe?
        sh.local_path = Some(local_path.to_string());
        sh.volume = volume;
        sh.volume_path = Some(volume_path.to_string());
        sh.entries = Some(contents);
        sh
    }

    pub fn get_search_handle(&self, id: u16) -> Option<&handle::SearchHandle> {
        self.search_handle.iter().find(|sh| sh.entries.is_some() && sh.id == id)
    }

    pub fn allocate_file_handle(&mut self, file: std::fs::File) -> Result<(usize, &mut handle::FileHandle), NetWareError> {
        if let Some((n, fh)) = self.file_handle.iter_mut().enumerate().find(|(_, fh)| fh.is_available()) {
            *fh = handle::FileHandle::zero();
            fh.file = Some(file);
            return Ok(((n + 1), fh))
        }
        Err(NetWareError::OutOfHandles)
    }

    pub fn get_mut_file_handle(&mut self, index: usize) -> Result<&mut handle::FileHandle, NetWareError> {
        if index >= 1 && index < self.file_handle.len() {
            Ok(&mut self.file_handle[index - 1])
        } else {
            Err(NetWareError::InvalidFileHandle)
        }
    }
}

