use crate::consts;
use crate::types::*;
use crate::handle;
use crate::error::NetWareError;

const VOLUME_LOGIN: u8 = 0;

#[derive(Debug)]
pub struct Connection {
    pub dest: IpxAddr,
    sequence_number: u8,
    dir_handle: [ handle::DirectoryHandle; consts::MAX_DIR_HANDLES ],
    search_handle: [ handle::SearchHandle; consts::MAX_SEARCH_HANDLES ],
    next_search_handle: usize,
    file_handle: [ handle::FileHandle; consts::MAX_OPEN_FILES ],
}

impl Connection {
    pub const fn zero() -> Self {
        const INIT_DIR_HANDLE: handle::DirectoryHandle = handle::DirectoryHandle::zero();
        let dir_handle = [ INIT_DIR_HANDLE; consts::MAX_DIR_HANDLES ];
        const INIT_SEARCH_HANDLE: handle::SearchHandle = handle::SearchHandle::zero();
        let search_handle = [ INIT_SEARCH_HANDLE; consts::MAX_SEARCH_HANDLES ];
        let next_search_handle = 0;
        const INIT_FILE_HANDLE: handle::FileHandle = handle::FileHandle::zero();
        let file_handle = [ INIT_FILE_HANDLE; consts::MAX_OPEN_FILES ];
        Connection{ dest: IpxAddr::zero(), sequence_number: 0, dir_handle, search_handle, next_search_handle, file_handle }
    }

    pub fn allocate(dest: &IpxAddr) -> Self {
        let mut c = Connection::zero();
        c.dest = *dest;
        let dh = c.alloc_dir_handle(VOLUME_LOGIN);
        let dh = dh.unwrap();
        assert!(dh.0 == 1); // must be first directory handle
        c
    }

    pub fn in_use(&self) -> bool {
        !self.dest.is_zero()
    }

    pub fn alloc_dir_handle(&mut self, volume_number: u8) -> Result<(u8, &mut handle::DirectoryHandle), NetWareError> {
        for (n, dh) in self.dir_handle.iter_mut().enumerate() {
            if !dh.is_available() { continue; }

            *dh = handle::DirectoryHandle::zero();
            dh.volume_number = Some(volume_number);
            return Ok(((n + 1) as u8, dh))
        }
        Err(NetWareError::NoDirectoryHandlesLeft)
    }

    pub fn get_dir_handle(&self, index: u8) -> Result<&handle::DirectoryHandle, NetWareError> {
        let index = index as usize;
        if index >= 1 && index < self.dir_handle.len() {
            let dh = &self.dir_handle[index - 1];
            if dh.volume_number.is_some() {
                return Ok(dh)
            }
        }
        Err(NetWareError::BadDirectoryHandle)
    }

    pub fn get_mut_dir_handle(&mut self, index: u8) -> Result<&mut handle::DirectoryHandle, NetWareError> {
        let index = index as usize;
        if index >= 1 && index < self.dir_handle.len() {
            let dh = &mut self.dir_handle[index - 1];
            if dh.volume_number.is_some() {
                return Ok(dh)
            }
        }
        Err(NetWareError::BadDirectoryHandle)
    }

    pub fn allocate_search_handle(&mut self, path: String, contents: Vec<DosFileName>) -> &mut handle::SearchHandle {
        let index = self.next_search_handle % self.search_handle.len();
        self.next_search_handle += 1;

        let sh = &mut self.search_handle[index];
        *sh = handle::SearchHandle::zero();
        sh.id = self.next_search_handle as u16; // XXX is this safe?
        sh.path = Some(path);
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

    pub fn allocate_file_handle(&mut self, file: std::fs::File) -> Result<(u8, &mut handle::FileHandle), NetWareError> {
        for (n, fh) in self.file_handle.iter_mut().enumerate() {
            if !fh.is_available() { continue; }

            *fh = handle::FileHandle::zero();
            fh.file = Some(file);
            return Ok(((n + 1) as u8, fh))
        }
        Err(NetWareError::OutOfHandles)
    }

    pub fn get_mut_file_handle(&mut self, index: u8) -> Result<&mut handle::FileHandle, NetWareError> {
        let index = index as usize;
        return if index >= 1 && index < self.file_handle.len() {
            Ok(&mut self.file_handle[index - 1])
        } else {
            Err(NetWareError::InvalidFileHandle)
        }
    }
}

