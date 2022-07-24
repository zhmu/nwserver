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

pub struct Connection<'a> {
    pub dest: IpxAddr,
    dir_handle: [ handle::DirectoryHandle<'a>; consts::MAX_DIR_HANDLES ],
    search_handle: [ handle::SearchHandle; consts::MAX_SEARCH_HANDLES ],
    next_search_handle: usize,
    file_handle: [ handle::FileHandle; consts::MAX_OPEN_FILES ],
    pub login_key: Option<LoginKey>,
    pub logged_in_object_id: bindery::ObjectID,
    pub bindery_security: bindery::Security,
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
        Connection{ dest: IpxAddr::zero(), dir_handle, search_handle, next_search_handle, file_handle, login_key: None, logged_in_object_id, bindery_security }
    }

    pub fn is_logged_on(&self) -> bool {
        self.logged_in_object_id != bindery::ID_NOT_LOGGED_IN
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

        // Allocate a single directory handle
        let dh = self.alloc_dir_handle(config, config.get_login_volume() as usize);
        let dh = dh.unwrap();
        assert!(dh.0 == 1); // must be first directory handle
        dh.1.path = MaxBoundedString::from_str(config.get_login_root());
    }

    pub fn in_use(&self) -> bool {
        !self.dest.is_zero()
    }

    pub fn alloc_dir_handle(&mut self, config: &'a config::Configuration, volume_index: usize) -> Result<(u8, &mut handle::DirectoryHandle<'a>), NetWareError> {
        for (n, dh) in self.dir_handle.iter_mut().enumerate() {
            if !dh.is_available() { continue; }

            *dh = handle::DirectoryHandle::zero();
            let volume = config.get_volumes().get_volume_by_number(volume_index)?;
            dh.volume = Some(volume);
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

    pub fn allocate_search_handle(&mut self, path: &String, contents: Vec<DosFileName>) -> &mut handle::SearchHandle {
        let index = self.next_search_handle % self.search_handle.len();
        self.next_search_handle += 1;

        let sh = &mut self.search_handle[index];
        *sh = handle::SearchHandle::zero();
        sh.id = self.next_search_handle as u16; // XXX is this safe?
        sh.path = Some(path.to_string());
        sh.entries = Some(contents);
        sh
    }

    pub fn get_search_handle(&self, id: u16) -> Option<&handle::SearchHandle> {
        for sh in &self.search_handle {
            if sh.entries.is_some() && sh.id == id {
                return Some(sh)
            }
        }
        None
    }

    pub fn allocate_file_handle(&mut self, file: std::fs::File) -> Result<(usize, &mut handle::FileHandle), NetWareError> {
        for (n, fh) in self.file_handle.iter_mut().enumerate() {
            if !fh.is_available() { continue; }

            *fh = handle::FileHandle::zero();
            fh.file = Some(file);
            return Ok(((n + 1), fh))
        }
        Err(NetWareError::OutOfHandles)
    }

    pub fn get_mut_file_handle(&mut self, index: usize) -> Result<&mut handle::FileHandle, NetWareError> {
        return if index >= 1 && index < self.file_handle.len() {
            Ok(&mut self.file_handle[index - 1])
        } else {
            Err(NetWareError::InvalidFileHandle)
        }
    }
}

