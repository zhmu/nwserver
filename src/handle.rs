/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::types::*;
use crate::config;

#[derive(Debug)]
pub struct FileHandle {
    pub file: Option<std::fs::File>,
    pub writable: bool
}

impl FileHandle {
    pub const fn zero() -> Self {
        Self{ file: None, writable: false }
    }

    pub fn is_available(&self) -> bool {
        self.file.is_none()
    }
}

#[derive(PartialEq)]
pub enum DirectoryHandleType {
    Invalid,
    Permanent,
    Temporary,
}

// Directory handle 0 indicates a full path (VOL:PATH) is to be used
// Directory handle 1 is special and used for the SYS:LOGIN (or equivalent) path

pub const DH_INDEX_ABSOLUTE: u8 = 0;
pub const DH_INDEX_LOGIN: u8 = 1;

pub struct DirectoryHandle<'a> {
    pub volume: Option<&'a config::Volume>,
    pub path: MaxBoundedString,
    pub typ: DirectoryHandleType,
}

impl<'a> DirectoryHandle<'a> {
    pub const fn zero() -> Self {
        let path = MaxBoundedString::empty();
        Self{ volume: None, path, typ: DirectoryHandleType::Invalid }
    }

    pub fn is_available(&self) -> bool {
        self.volume.is_none()
    }
}

#[derive(Debug)]
pub struct SearchHandle {
    pub id: u16,
    pub local_path: Option<String>,
    pub volume: u8,
    pub volume_path: Option<String>,
    pub entries: Option<Vec<DosFileName>>,
}

impl SearchHandle {
    pub const fn zero() -> Self {
        Self{ id: 0, local_path: None, volume: 0, volume_path: None, entries: None }
    }
}
