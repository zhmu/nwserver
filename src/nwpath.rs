/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::config;
use crate::trustee;
use crate::handle;
use crate::connection;
use crate::error::*;
use crate::types::*;

fn combine_paths(dir1: &str, dir2: &str) -> String {
    let mut result = String::new();
    for d in &[ dir1, dir2 ] {
        let d = d.trim_start_matches(|c: char| { c == '\\' } );

        if d.is_empty() { continue; }
        if !result.is_empty() { result.push('/'); }
        result.push_str(d);
    }
    result.replace('\\', "/")
}

pub struct Path {
    volume: u8,
    volume_path: String,
    local_path: String,
    rights: u16,
}

impl Path {
    pub fn new(conn: &connection::Connection, config: &config::Configuration, trustee_db: &trustee::TrusteeDB, dh: u8, path: &MaxBoundedString) -> Result<Self, NetWareError> {
        let volume;
        let local_path;
        let volume_path;
        if dh == handle::DH_INDEX_ABSOLUTE {
            // No directory handle supplied; this means we need to seperate path into VOL:PATH
            let path = path.as_str();
            let colon = path.find(':');
            if colon.is_none() { return Err(NetWareError::NoSuchVolume); }
            let colon = colon.unwrap();

            volume = config.get_volumes().get_volume_by_name(&path[0..colon])?;
            volume_path = path[colon + 1..].to_string();
            local_path = combine_paths(&volume.path, &volume_path);

        } else {
            // Base the path on the supplied directory handle
            let dh = conn.get_dir_handle(dh)?;
            volume = dh.volume.unwrap();
            volume_path = combine_paths(dh.path.as_str(), &path.to_string());
            local_path = combine_paths(&volume.path, &volume_path);
        }

        let volume_path = volume_path.strip_prefix('/').unwrap_or(&volume_path).to_string();

        let mut rights = trustee_db.determine_rights(conn.get_security_equivalent_ids(), volume.number.into(), &volume_path);
        if !volume.writeable {
            // Revoke rights if non-writable volume
            rights &= !(trustee::RIGHT_WRITE | trustee::RIGHT_CREATE | trustee::RIGHT_ERASE | trustee::RIGHT_MODIFY);
        }

        Ok(Self{ volume: volume.number, volume_path, local_path, rights })
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

    pub fn get_access_rights(&self) -> u16 {
        self.rights
    }

    pub fn has_right(&self, right: u16) -> bool {
        (self.rights & right) != 0
    }
}
