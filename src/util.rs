/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::bindery;
use crate::types::*;

pub fn str_to_object_id(bindery: &bindery::Bindery, s: &str) -> Option<bindery::ObjectID> {
    return if let Ok(object) = bindery.get_object_by_name2(MaxBoundedString::from_str(s), bindery::TYPE_WILD) {
        Some(object.id)
    } else if s.starts_with("*") {
        bindery::ObjectID::from_str_radix(&s[1..], 16).ok()
    } else {
        None
    }
}

pub fn object_id_to_str(bindery: &bindery::Bindery, object_id: bindery::ObjectID) -> String {
    return if let Ok(object) = bindery.get_object_by_id2(object_id) {
        object.name.as_str().to_string()
    } else {
        format!("*{:x}", object_id)
    }
}

pub fn construct_trustee_path(volume_path: &str, entry: &DosFileName) -> String {
    return if !volume_path.is_empty() {
        format!("{}/{}", volume_path, entry)
    } else {
        format!("{}", entry)
    }
}

