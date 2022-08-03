/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */

use crate::bindery;

type Rights = u16;

pub const RIGHT_READ: Rights = 0x1;
pub const RIGHT_WRITE: Rights = 0x2;
pub const RIGHT_CREATE: Rights = 0x8;
pub const RIGHT_ERASE: Rights = 0x10;
pub const RIGHT_ACCESS_CONTROL: Rights = 0x20;
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


pub struct TrusteeDB {
    pub entries: Vec<TrusteePath>,
}

impl TrusteeDB {
    pub fn new() -> Self {
        Self{ entries: Vec::new() }
    }

    pub fn add_trustee_for_path(&mut self, path: &str, trustee: Trustee) {
        if let Some(p) = self.entries.iter_mut().find(|i| i.path == path) {
            if let Some(e) = p.trustees.iter_mut().find(|t| t.object_id == trustee.object_id) {
                e.rights = trustee.rights;
            } else {
                p.trustees.push(trustee);
            }
        } else {
            self.entries.push(TrusteePath{ path: path.to_string(), trustees: vec![ trustee ] });
        }
    }

    pub fn remove_trustee_from_path(&mut self, path: &str, object_id: bindery::ObjectID) {
        if let Some((index, p)) = self.entries.iter_mut().enumerate().find(|(_,i)| i.path == path) {
            p.trustees.retain(|t| t.object_id != object_id);
            if p.trustees.is_empty() {
                self.entries.remove(index);
            }
        }
    }

    pub fn find_trustees_for_path(&self, path: &str) -> Option<&TrusteePath> {
        let mut result: Option<&TrusteePath> = None;
        for p in &self.entries {
            if !path.starts_with(&p.path) { continue; }

            if let Some(extra_char) = path.chars().nth(p.path.len()) {
                if extra_char != '/' as char { continue; }
            }
            if let Some(result) = result {
                if result.path.len() > p.path.len() { continue; }
            }
            result = Some(p);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::trustee;

    #[test]
    fn initially_empty() {
        let trustees_db = trustee::TrusteeDB::new();
        assert!(trustees_db.find_trustees_for_path("").is_none());
    }

    #[test]
    fn direct_path_lookup_succeeds() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 123, rights: 456 });
        let tp = trustees_db.find_trustees_for_path("FOO").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 123);
        assert_eq!(t.rights, 456);
    }

    #[test]
    fn path_lookup_ignores_nonmatches() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 123, rights: 456 });
        assert!(trustees_db.find_trustees_for_path("F").is_none());
    }

    #[test]
    fn path_lookup_finds_parent() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 123, rights: 456 });
        let tp = trustees_db.find_trustees_for_path("FOO/BAR").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 123);
        assert_eq!(t.rights, 456);
    }

    #[test]
    fn path_lookup_finds_closest_parent() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path("FOO/BAR", trustee::Trustee{ object_id: 2, rights: 20 });
        trustees_db.add_trustee_for_path("FOO/BAR/BAZ", trustee::Trustee{ object_id: 3, rights: 30 });

        let tp = trustees_db.find_trustees_for_path("FOO/A").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 1);
        assert_eq!(t.rights, 10);

        let tp = trustees_db.find_trustees_for_path("FOO/BAR/Z").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 2);
        assert_eq!(t.rights, 20);

        let tp = trustees_db.find_trustees_for_path("FOO/BAR/BAZ/1").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 3);
        assert_eq!(t.rights, 30);
    }

    #[test]
    fn single_path_can_contain_multiple_trustees() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 2, rights: 20 });

        let tp = trustees_db.find_trustees_for_path("FOO").unwrap();
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
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 1, rights: 20 });

        let tp = trustees_db.find_trustees_for_path("FOO").unwrap();
        let t = tp.trustees.first().unwrap();
        assert_eq!(t.object_id, 1);
        assert_eq!(t.rights, 20);
    }

    #[test]
    fn updating_trustee_object_rights_does_not_change_others() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 2, rights: 20 });
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 2, rights: 100 });

        let tp = trustees_db.find_trustees_for_path("FOO").unwrap();
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
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 123, rights: 456 });
        trustees_db.remove_trustee_from_path("FOO", 123);

        assert!(trustees_db.find_trustees_for_path("FOO").is_none());
    }

    #[test]
    fn remove_trustee_with_multiple_entries_removes_only_one_trustee() {
        let mut trustees_db = trustee::TrusteeDB::new();
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 1, rights: 10 });
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 2, rights: 20 });
        trustees_db.add_trustee_for_path("FOO", trustee::Trustee{ object_id: 3, rights: 30 });
        trustees_db.remove_trustee_from_path("FOO", 2);

        let tp = trustees_db.find_trustees_for_path("FOO").unwrap();
        assert_eq!(tp.trustees.len(), 2);
        let first_t = &tp.trustees[0];
        assert_eq!(first_t.object_id, 1);
        assert_eq!(first_t.rights, 10);
        let second_t = &tp.trustees[1];
        assert_eq!(second_t.object_id, 3);
        assert_eq!(second_t.rights, 30);
    }
}
