/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::bindery;
use crate::types::*;

pub fn str_to_object_id(bindery: &bindery::Bindery, s: &str) -> Option<bindery::ObjectID> {
    if let Ok(object) = bindery.get_object_by_name(MaxBoundedString::from_str(s), bindery::TYPE_WILD) {
        Some(object.id)
    } else if let Some(id) = s.strip_prefix('*') {
        bindery::ObjectID::from_str_radix(id, 16).ok()
    } else {
        None
    }
}

pub fn object_id_to_str(bindery: &bindery::Bindery, object_id: bindery::ObjectID) -> String {
    if let Ok(object) = bindery.get_object_by_id(object_id) {
        object.name.as_str().to_string()
    } else {
        format!("*{:x}", object_id)
    }
}

pub fn construct_trustee_path(volume_path: &str, entry: &DosFileName) -> String {
    if !volume_path.is_empty() {
        format!("{}/{}", volume_path, entry)
    } else {
        format!("{}", entry)
    }
}

