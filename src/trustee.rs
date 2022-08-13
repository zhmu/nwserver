/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */

use crate::bindery;
use crate::config;
use crate::util;
use log::*;

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

type Rights = u16;

pub const RIGHT_NONE: Rights = 0;
pub const RIGHT_READ: Rights = 0x1;
pub const RIGHT_WRITE: Rights = 0x2;
pub const RIGHT_OPEN: Rights = 0x4; // open existing files in directory
pub const RIGHT_CREATE: Rights = 0x8;
pub const RIGHT_ERASE: Rights = 0x10;
pub const RIGHT_PARENTAL: Rights = 0x20; // parental rights (create/remove subdirs, make other objects trustees of this dir/subdir)
pub const RIGHT_FILESCAN: Rights = 0x40;
pub const RIGHT_MODIFY: Rights = 0x80;
pub const RIGHT_SUPERVISOR: Rights = 0x100;

#[derive(Debug)]
pub enum TrusteeError {
    IoError(std::io::Error),
    TomlError(toml::de::Error),
    VolumeNotFound(String),
    ObjectNotFound(String),
}

impl From<std::io::Error> for TrusteeError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<toml::de::Error> for TrusteeError {
    fn from(e: toml::de::Error) -> Self {
        Self::TomlError(e)
    }
}

pub struct Trustee {
    pub object_id: bindery::ObjectID,
    pub rights: Rights
}

pub struct TrusteePath {
    pub path: String,
    pub trustees: Vec<Trustee>,
}

type Trustees = Vec<TrusteePath>;

pub struct TrusteeDB {
    pub entries: Vec<Trustees>,
}

/*
 * Iterator for paths to look up in trustee-order.
 * i.e. given FOO/BAR/BAZ, yields "", "FOO", "FOO/BAR" and "FOO/BAR/BAZ".
 */
struct TrusteePathIterator<'a> {
    path: &'a str,
    pos: usize,
}

impl<'a> Iterator for TrusteePathIterator<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == usize::MAX {
            self.pos = 0;
            return Some(&self.path[0..0]);
        }

        if self.pos >= self.path.len() { return None; }
        let slice_end;
        if let Some(n) = self.path[self.pos..].find("/").map(|i| i + self.pos) {
            self.pos = n + 1;
            slice_end = n;
        } else {
            self.pos = self.path.len();
            slice_end = self.path.len();
        }
        Some(&self.path[0..slice_end])
    }
}

impl<'a> TrusteePathIterator<'a> {
    pub fn from(path: &'a str) -> Self {
        Self{ path, pos: usize::MAX }
    }
}

impl TrusteeDB {
    pub fn new() -> Self {
        Self{ entries: Vec::new() }
    }

    pub fn add_trustee_for_path(&mut self, volume_index: usize, path: &str, trustee: Trustee) {
        while volume_index >= self.entries.len() {
            self.entries.push(Vec::new());
        }

        let volume_entries = &mut self.entries[volume_index];
        if let Some(p) = volume_entries.iter_mut().find(|i| i.path == path) {
            if let Some(e) = p.trustees.iter_mut().find(|t| t.object_id == trustee.object_id) {
                e.rights = trustee.rights;
            } else {
                p.trustees.push(trustee);
            }
        } else {
            volume_entries.push(TrusteePath{ path: path.to_string(), trustees: vec![ trustee ] });
        }
    }

    pub fn remove_trustee_from_path(&mut self, volume_index: usize, path: &str, object_id: bindery::ObjectID) -> bool {
        if volume_index >= self.entries.len() { return false; }

        let volume_entries = &mut self.entries[volume_index];
        if let Some((index, p)) = volume_entries.iter_mut().enumerate().find(|(_,i)| i.path == path) {
            p.trustees.retain(|t| t.object_id != object_id);
            if p.trustees.is_empty() {
                volume_entries.remove(index);
            }
            return true;
        }
        false
    }

    pub fn get_path_trustees(&self, volume_index: usize, path: &str) -> Option<&TrusteePath> {
        let volume_entries = self.entries.get(volume_index)?;
        volume_entries.iter().filter(|i| i.path == path).next()
    }

    pub fn determine_rights(&self, security_object_ids: &[ bindery::ObjectID ], volume_index: usize, trustee_path: &str) -> u16 {
        // FIXME: the runtime of this function is horrible
        let mut rights: u16 = 0;
        for path in TrusteePathIterator::from(trustee_path) {
            for id in security_object_ids {
                if *id == bindery::ID_EMPTY { continue; }
                if let Some(tp) = self.get_path_trustees(volume_index, &path) {
                    for trustee in &tp.trustees {
                        if trustee.object_id == *id {
                            println!("found rights id {} rights {}", trustee.object_id, trustee.rights);
                            rights = trustee.rights;
                            if (rights & RIGHT_SUPERVISOR) != 0 {
                                info!("short-circuiting path '{}' for object id {} due to supervisor rights", trustee_path, security_object_ids.first().unwrap_or(&0));
                                return rights;
                            }
                        }
                    }
                }
            }
        }
        rights
    }

    pub fn get_indexed_trustee_by_object_id(&self, object_id: bindery::ObjectID, volume_index: usize, sequence: u16) -> Option<(&str, &Trustee)> {
        let volume_entries = self.entries.get(volume_index)?;
        let mut current_sequence: u16 = 0;
        for p in volume_entries {
            for tp in &p.trustees {
                if tp.object_id != object_id { continue; }
                if current_sequence == sequence {
                    return Some((&p.path, tp))
                }
                current_sequence += 1;
            }
        }
        None
    }

    pub fn load(&mut self, config: &config::Configuration, bindery: &mut bindery::Bindery, fname: &str) -> Result<(), TrusteeError> {
        let content = std::fs::read_to_string(fname)?;
        let toml: TomlConfig = toml::from_str(&content)?;
        let volumes = config.get_volumes();

        for (vol_name, vol_paths) in &toml.trustees {
            let vol_name = &vol_name.to_string().to_uppercase();
            let volume = volumes.get_volume_by_name(vol_name).map_err(|_| TrusteeError::VolumeNotFound(vol_name.to_string()))?;
            for (path_name, path_trustees) in vol_paths {
                let mut path_name = path_name.to_string().to_uppercase();
                if path_name == "/" {
                    path_name = String::new();
                }

                for (object_name, object_rights) in path_trustees {
                    let object_name = &object_name.to_string().to_uppercase();
                    let rights = parse_rights_from_str(object_rights).expect("cannot parse rights");

                    let object_id = util::str_to_object_id(bindery, object_name).ok_or(TrusteeError::ObjectNotFound(object_name.to_string()))?;
                    self.add_trustee_for_path(volume.number.into(), &path_name, Trustee{ object_id, rights });
                }
            }
        }
        Ok(())
    }

    pub fn save(&mut self, config: &config::Configuration, bindery: &mut bindery::Bindery, fname: &str) -> Result<(), TrusteeError> {
        let mut toml_trustees = TomlConfig{ trustees: TomlTrustees::new() };
        let volumes = config.get_volumes();

        for (volume_number, volume_trustees) in self.entries.iter().enumerate() {
            let volume_name = volumes.get_volume_by_number(volume_number).unwrap().name.as_str();

            let mut toml_object = TomlTrustee::new();
            for trustee_path in volume_trustees {
                let mut toml_obj_rights = TomlObjectRights::new();
                for trustee in &trustee_path.trustees {
                    let object_name = util::object_id_to_str(bindery, trustee.object_id);
                    let rights = convert_rights_to_str(trustee.rights);
                    toml_obj_rights.insert(object_name, rights);
                }
                let toml_path;
                if trustee_path.path.is_empty() {
                    toml_path = "/".to_string();
                } else {
                    toml_path = trustee_path.path.clone();
                }
                toml_object.insert(toml_path, toml_obj_rights);
            }
            toml_trustees.trustees.insert(volume_name.to_string(), toml_object);
        }

        let toml = toml::to_string(&toml_trustees).expect("cannot encode toml");
        std::fs::write(fname, toml)?;
        Ok(())
    }
}

fn parse_rights_from_str(rights: &str) -> Option<u16> {
    let mut result: u16 = 0;
    for ch in rights.chars() {
        let ch = ch.to_uppercase().next()?;
        result += match ch {
            'R' => { RIGHT_READ },
            'W' => { RIGHT_WRITE },
            'O' => { RIGHT_OPEN },
            'C' => { RIGHT_CREATE },
            'E' => { RIGHT_ERASE },
            'A' => { RIGHT_PARENTAL },
            'F' => { RIGHT_FILESCAN },
            'M' => { RIGHT_MODIFY },
            'S' => { RIGHT_SUPERVISOR },
            _ => { return None; }
        };
    }
    Some(result)
}

fn convert_rights_to_str(rights: u16) -> String {
    let mut result = String::new();
    if (rights & RIGHT_READ) != 0 { result += "r"; }
    if (rights & RIGHT_WRITE) != 0 { result += "w"; }
    if (rights & RIGHT_OPEN) != 0 { result += "o" }
    if (rights & RIGHT_CREATE) != 0 { result += "c"; }
    if (rights & RIGHT_ERASE) != 0 { result += "e"; }
    if (rights & RIGHT_PARENTAL) != 0 { result += "a"; }
    if (rights & RIGHT_FILESCAN) != 0 { result += "f"; }
    if (rights & RIGHT_MODIFY) != 0 { result += "m"; }
    if (rights & RIGHT_SUPERVISOR) != 0 { result += "s"; }
    result
}

// { user: rights }
type TomlObjectRights = BTreeMap<String, String>;
// Path -> { user = rights }
type TomlTrustee = BTreeMap<String, TomlObjectRights>;
// Volume -> Trustee
type TomlTrustees = BTreeMap<String, TomlTrustee>;

#[derive(Serialize,Deserialize)]
struct TomlConfig {
    trustees: TomlTrustees,
}


#[cfg(test)]
mod tests {
    use crate::trustee;
    use crate::trustee::TrusteePathIterator;

    #[test]
    fn path_iterator_empty() {
        let mut path = TrusteePathIterator::from("");
        assert_eq!(path.next().unwrap(), "");
        assert!(path.next().is_none());
    }

    #[test]
    fn path_iterator_one_piece() {
        let mut path = TrusteePathIterator::from("FOO");
        assert_eq!(path.next().unwrap(), "");
        assert_eq!(path.next().unwrap(), "FOO");
        assert!(path.next().is_none());
    }

    #[test]
    fn path_iterator_two_pieces() {
        let mut path = TrusteePathIterator::from("FOO/BAR");
        assert_eq!(path.next().unwrap(), "");
        assert_eq!(path.next().unwrap(), "FOO");
        assert_eq!(path.next().unwrap(), "FOO/BAR");
        assert!(path.next().is_none());
    }

    #[test]
    fn path_iterator_three_pieces() {
        let mut path = TrusteePathIterator::from("FOO/BAR/BAZ");
        assert_eq!(path.next().unwrap(), "");
        assert_eq!(path.next().unwrap(), "FOO");
        assert_eq!(path.next().unwrap(), "FOO/BAR");
        assert_eq!(path.next().unwrap(), "FOO/BAR/BAZ");
        assert!(path.next().is_none());
    }

    #[test]
    fn initially_empty() {
        let trustees_db = trustee::TrusteeDB::new();
        assert!(trustees_db.get_path_trustees(0, "").is_none());
    }

    #[test]
    fn direct_path_lookup_succeeds() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 123, rights: trustee::RIGHT_READ});
        let tp = trustees_db.get_path_trustees(0, "FOO").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 123);
        assert_eq!(t.rights, trustee::RIGHT_READ);
    }

    #[test]
    fn path_lookup_ignores_nonmatches() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 123, rights: trustee::RIGHT_READ });
        assert!(trustees_db.get_path_trustees(0, "F").is_none());
    }

    #[test]
    fn single_path_can_contain_multiple_trustees() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_READ });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: trustee::RIGHT_WRITE });

        let tp = trustees_db.get_path_trustees(0, "FOO").unwrap();
        assert_eq!(tp.trustees.len(), 2);
        let first_t = &tp.trustees[0];
        assert_eq!(first_t.object_id, 1);
        assert_eq!(first_t.rights, trustee::RIGHT_READ);
        let second_t = &tp.trustees[1];
        assert_eq!(second_t.object_id, 2);
        assert_eq!(second_t.rights, trustee::RIGHT_WRITE);
    }

    #[test]
    fn trustee_object_rights_can_be_updated() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_READ });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_WRITE });

        let tp = trustees_db.get_path_trustees(0, "FOO").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 1);
        assert_eq!(t.rights, trustee::RIGHT_WRITE);
    }

    #[test]
    fn updating_trustee_object_rights_does_not_change_others() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_READ });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: trustee::RIGHT_WRITE });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: trustee::RIGHT_CREATE });

        let tp = trustees_db.get_path_trustees(0, "FOO").unwrap();
        assert_eq!(tp.trustees.len(), 2);
        let first_t = &tp.trustees[0];
        assert_eq!(first_t.object_id, 1);
        assert_eq!(first_t.rights, trustee::RIGHT_READ);
        let second_t = &tp.trustees[1];
        assert_eq!(second_t.object_id, 2);
        assert_eq!(second_t.rights, trustee::RIGHT_CREATE);
    }

    #[test]
    fn remove_trustee_with_one_entry_removes_entire_entry() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 123, rights: trustee::RIGHT_READ });
        assert!(trustees_db.remove_trustee_from_path(0, "FOO", 123));

        assert!(trustees_db.get_path_trustees(0, "FOO").is_none());
    }

    #[test]
    fn remove_trustee_with_multiple_entries_removes_only_one_trustee() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_READ });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: trustee::RIGHT_WRITE });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 3, rights: trustee::RIGHT_CREATE });
        assert!(trustees_db.remove_trustee_from_path(0, "FOO", 2));

        let tp = trustees_db.get_path_trustees(0, "FOO").unwrap();
        assert_eq!(tp.trustees.len(), 2);
        let first_t = &tp.trustees[0];
        assert_eq!(first_t.object_id, 1);
        assert_eq!(first_t.rights, trustee::RIGHT_READ);
        let second_t = &tp.trustees[1];
        assert_eq!(second_t.object_id, 3);
        assert_eq!(second_t.rights, trustee::RIGHT_CREATE);
    }

    #[test]
    fn determine_rights_succeeds_with_no_rights() {
        let trustees_db = trustee::TrusteeDB::new();
        let rights = trustees_db.determine_rights(&[ 1 ], 0, "");
        assert_eq!(rights, 0);
    }

    #[test]
    fn determine_rights_direct_match() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_READ });
        let rights = trustees_db.determine_rights(&[ 1 ], 0, "FOO");
        assert_eq!(rights, trustee::RIGHT_READ);
    }

    #[test]
    fn determine_rights_skips_non_matches() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 5, rights: trustee::RIGHT_READ });
        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO");
        assert_eq!(rights, trustee::RIGHT_NONE);
    }

    #[test]
    fn determine_rights_matches_equivalent_objects() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 3, rights: trustee::RIGHT_READ });
        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO");
        assert_eq!(rights, trustee::RIGHT_READ);
    }

    #[test]
    fn determine_rights_matches_objects_in_order() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_READ });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: trustee::RIGHT_WRITE });
        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO");
        // TODO is this what I want? If so, I should reconsider the SECURITY_EQUALS sorting in connection.rs ...
        assert_eq!(rights, trustee::RIGHT_WRITE);
    }

    #[test]
    fn determine_rights_supervisor_overiddes_all() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_SUPERVISOR });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: trustee::RIGHT_READ});
        let rights = trustees_db.determine_rights(&[ 1, 2 ], 0, "FOO");
        assert_eq!(rights, trustee::RIGHT_SUPERVISOR);
    }

    #[test]
    fn determine_rights_matches_parent() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 123, rights: trustee::RIGHT_READ });
        let rights = trustees_db.determine_rights(&[ 123 ], 0, "FOO/BAR");
        assert_eq!(rights, trustee::RIGHT_READ);
    }

    #[test]
    fn determine_rights_finds_closest_parent() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_READ });
        trustees_db.add_trustee_for_path(0, "FOO/BAR", trustee::Trustee{ object_id: 2, rights: trustee::RIGHT_WRITE });
        trustees_db.add_trustee_for_path(0, "FOO/BAR/BAZ", trustee::Trustee{ object_id: 3, rights: trustee::RIGHT_CREATE });

        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO/A");
        assert_eq!(rights, trustee::RIGHT_READ);

        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO/BAR/Z");
        assert_eq!(rights, trustee::RIGHT_WRITE);

        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO/BAR/BAZ/1");
        assert_eq!(rights, trustee::RIGHT_CREATE);
    }

    #[test]
    fn determine_rights_uses_root_trustee() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "", trustee::Trustee{ object_id: 123, rights: trustee::RIGHT_READ});
        let rights = trustees_db.determine_rights(&[ 123 ], 0, "FOO");
        assert_eq!(rights, trustee::RIGHT_READ);
    }
}
