/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */

use crate::bindery;
use log::*;

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

    pub fn remove_trustee_from_path(&mut self, volume_index: usize, path: &str, object_id: bindery::ObjectID) {
        if volume_index >= self.entries.len() { return; }

        let volume_entries = &mut self.entries[volume_index];
        if let Some((index, p)) = volume_entries.iter_mut().enumerate().find(|(_,i)| i.path == path) {
            p.trustees.retain(|t| t.object_id != object_id);
            if p.trustees.is_empty() {
                self.entries.remove(index);
            }
        }
    }

    pub fn find_trustees_for_path(&self, volume_index: usize, path: &str) -> Option<&TrusteePath> {
        let volume_entries = self.entries.get(volume_index)?;
        let mut result: Option<&TrusteePath> = None;
        for p in volume_entries {
            if !path.starts_with(&p.path) { continue; }

            if !p.path.is_empty() {
                if let Some(extra_char) = path.chars().nth(p.path.len()) {
                    println!("extra_char '{}'", extra_char);
                    if extra_char != '/' as char { continue; }
                }
            }
            if let Some(result) = result {
                if result.path.len() > p.path.len() { continue; }
            }
            result = Some(p);
        }
        result
    }

    pub fn get_path_trustees(&self, volume_index: usize, path: &str) -> Option<&TrusteePath> {
        let volume_entries = self.entries.get(volume_index)?;
        for p in volume_entries {
            if p.path != path { continue; }
            return Some(p);
        }
        println!("get_path_trustees '{}' not found", path);
        None
    }

    pub fn determine_rights(&self, security_object_ids: &[ bindery::ObjectID ], volume_index: usize, trustee_path: &str) -> u16 {
        // FIXME: the runtime of this function is horrible
        let mut rights: u16 = 0;
        for path in TrusteePathIterator::from(trustee_path) {
            for id in security_object_ids {
                if *id == bindery::ID_EMPTY { continue; }
                if let Some(tp) = self.find_trustees_for_path(volume_index, &path) {
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
        assert!(trustees_db.find_trustees_for_path(0, "").is_none());
    }

    #[test]
    fn direct_path_lookup_succeeds() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 123, rights: 456 });
        let tp = trustees_db.find_trustees_for_path(0, "FOO").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 123);
        assert_eq!(t.rights, 456);
    }

    #[test]
    fn path_lookup_ignores_nonmatches() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 123, rights: 456 });
        assert!(trustees_db.find_trustees_for_path(0, "F").is_none());
    }

    #[test]
    fn path_lookup_finds_parent() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 123, rights: 456 });
        let tp = trustees_db.find_trustees_for_path(0, "FOO/BAR").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 123);
        assert_eq!(t.rights, 456);
    }

    #[test]
    fn path_lookup_finds_closest_parent() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path(0, "FOO/BAR", trustee::Trustee{ object_id: 2, rights: 20 });
        trustees_db.add_trustee_for_path(0, "FOO/BAR/BAZ", trustee::Trustee{ object_id: 3, rights: 30 });

        let tp = trustees_db.find_trustees_for_path(0, "FOO/A").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 1);
        assert_eq!(t.rights, 10);

        let tp = trustees_db.find_trustees_for_path(0, "FOO/BAR/Z").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 2);
        assert_eq!(t.rights, 20);

        let tp = trustees_db.find_trustees_for_path(0, "FOO/BAR/BAZ/1").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 3);
        assert_eq!(t.rights, 30);
    }

    #[test]
    fn path_lookup_finds_root() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "", trustee::Trustee{ object_id: 123, rights: 456 });
        let tp = trustees_db.find_trustees_for_path(0, "FOO").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 123);
        assert_eq!(t.rights, 456);
    }

    #[test]
    fn single_path_can_contain_multiple_trustees() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: 20 });

        let tp = trustees_db.find_trustees_for_path(0, "FOO").unwrap();
        assert_eq!(tp.trustees.len(), 2);
        let first_t = &tp.trustees[0];
        assert_eq!(first_t.object_id, 1);
        assert_eq!(first_t.rights, 10);
        let second_t = &tp.trustees[1];
        assert_eq!(second_t.object_id, 2);
        assert_eq!(second_t.rights, 20);
    }

    #[test]
    fn trustee_object_rights_can_be_updated() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: 20 });

        let tp = trustees_db.find_trustees_for_path(0, "FOO").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 1);
        assert_eq!(t.rights, 20);
    }

    #[test]
    fn updating_trustee_object_rights_does_not_change_others() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: 20 });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: 100 });

        let tp = trustees_db.find_trustees_for_path(0, "FOO").unwrap();
        assert_eq!(tp.trustees.len(), 2);
        let first_t = &tp.trustees[0];
        assert_eq!(first_t.object_id, 1);
        assert_eq!(first_t.rights, 10);
        let second_t = &tp.trustees[1];
        assert_eq!(second_t.object_id, 2);
        assert_eq!(second_t.rights, 100);
    }

    #[test]
    fn remove_trustee_with_one_entry_removes_entire_entry() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 123, rights: 456 });
        trustees_db.remove_trustee_from_path(0, "FOO", 123);

        assert!(trustees_db.find_trustees_for_path(0, "FOO").is_none());
    }

    #[test]
    fn remove_trustee_with_multiple_entries_removes_only_one_trustee() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: 20 });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 3, rights: 30 });
        trustees_db.remove_trustee_from_path(0, "FOO", 2);

        let tp = trustees_db.find_trustees_for_path(0, "FOO").unwrap();
        assert_eq!(tp.trustees.len(), 2);
        let first_t = &tp.trustees[0];
        assert_eq!(first_t.object_id, 1);
        assert_eq!(first_t.rights, 10);
        let second_t = &tp.trustees[1];
        assert_eq!(second_t.object_id, 3);
        assert_eq!(second_t.rights, 30);
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
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        let rights = trustees_db.determine_rights(&[ 1 ], 0, "FOO");
        assert_eq!(rights, 10);
    }

    #[test]
    fn determine_rights_skips_non_matches() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 5, rights: 10 });
        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO");
        assert_eq!(rights, 0);
    }

    #[test]
    fn determine_rights_matches_equivalent_objects() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 3, rights: 10 });
        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO");
        assert_eq!(rights, 10);
    }

    #[test]
    fn determine_rights_matches_objects_in_order() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: 20 });
        let rights = trustees_db.determine_rights(&[ 1, 2, 3 ], 0, "FOO");
        // TODO is this what I want?
        assert_eq!(rights, 20);
    }

    #[test]
    fn determine_rights_supervisor_overiddes_all() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path(0, "", trustee::Trustee{ object_id: 1, rights: trustee::RIGHT_SUPERVISOR });
        trustees_db.add_trustee_for_path(0, "FOO", trustee::Trustee{ object_id: 2, rights: trustee::RIGHT_READ});
        let rights = trustees_db.determine_rights(&[ 1, 2 ], 0, "FOO");
        assert_eq!(rights, trustee::RIGHT_SUPERVISOR);
    }
}
