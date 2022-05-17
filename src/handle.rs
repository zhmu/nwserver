use crate::ncp::PathString; // TODO move this to types
use crate::types::*;

#[derive(Debug)]
pub struct FileHandle {
    pub file: Option<std::fs::File>,
}

impl FileHandle {
    pub const fn zero() -> Self {
        Self{ file: None }
    }

    pub fn is_available(&self) -> bool {
        self.file.is_none()
    }
}

#[derive(Debug,Clone,Copy)]
pub struct DirectoryHandle {
    pub volume_number: Option<u8>,
    pub path: PathString,
}

impl DirectoryHandle {
    pub const fn zero() -> Self {
        let path = PathString::empty();
        Self{ volume_number: None, path }
    }

    pub fn is_available(&self) -> bool {
        self.volume_number.is_none()
    }
}

#[derive(Debug)]
pub struct SearchHandle {
    pub id: u16,
    pub path: Option<String>,
    pub entries: Option<Vec<DosFileName>>,
}

impl SearchHandle {
    pub const fn zero() -> Self {
        Self{ id: 0, path: None, entries: None }
    }
}
