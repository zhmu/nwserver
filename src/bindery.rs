/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::bindery;
use crate::consts;
use crate::config;
use crate::crypto;
use crate::util;
use crate::error::*;
use crate::types::*;
use byteorder::{ByteOrder, BigEndian};

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

pub type ObjectID = u32;
pub type ObjectType = u16;
pub type Flag = u8;
pub type Security = u8;

pub const TYPE_WILD: ObjectType = 0xffff;
pub const TYPE_USER: ObjectType = 0x0001;
pub const TYPE_USER_GROUP: ObjectType = 0x0002;
pub const TYPE_FILE_SERVER: ObjectType = 0x0004;

pub const ID_EMPTY: ObjectID = 0;
pub const ID_SUPERVISOR: ObjectID = 1;
pub const ID_NOT_LOGGED_IN: ObjectID = 0xffffffff;

const ID_BASE: ObjectID = 0x1000000;

pub const FLAG_STATIC: Flag = 0x00;
pub const FLAG_DYNAMIC: Flag = 0x01;
pub const FLAG_SET: Flag = 0x02;
pub const FLAG_MASK: Flag = 0x03;

pub const SECURITY_NOT_LOGGED_IN: Security = 0x00;

pub const SECURITY_ANYONE: Security = 0x00;
pub const SECURITY_LOGGED_IN: Security = 0x01;
pub const SECURITY_OBJECT: Security = 0x02;
pub const SECURITY_SUPERVISOR: Security = 0x03;
pub const SECURITY_SERVER: Security = 0x04;

type PropertyData = [ u8; consts::PROPERTY_SEGMENT_LENGTH ];

const ITEMS_PER_SET: usize = consts::PROPERTY_SEGMENT_LENGTH / 4;

pub struct Property {
    pub name: BoundedString< { consts::PROPERTY_NAME_LENGTH }>,
    pub values: Vec<PropertyData>,
    pub flag: Flag,
    pub security: Security,
}

impl Property {
    pub fn new(name: &str, flag: Flag, security: Security) -> Self {
        let name = BoundedString::from_str(name);
        let property_data = [ 0u8; consts::PROPERTY_SEGMENT_LENGTH ];
        Self{ name, flag, security, values: vec![ property_data ]  }
    }

    fn decode_index(&mut self, index: usize) -> &mut [u8] {
        let value_index = index / ITEMS_PER_SET;
        let value_offset = (index % ITEMS_PER_SET) * 4;
        &mut self.values[value_index][value_offset..value_offset + 4]
    }

    pub fn set_data(&mut self, data: &[u8]) {
        let mut offset: usize = 0;
        let mut n: usize = 0;
        while offset < data.len() {
            if self.values.len() == n {
                let property_data = [ 0u8; consts::PROPERTY_SEGMENT_LENGTH ];
                self.values.push(property_data);
            }
            let value = &mut self.values[n];
            let bytes_to_copy = std::cmp::min(data.len() - offset, consts::PROPERTY_SEGMENT_LENGTH);
            value[0..bytes_to_copy].copy_from_slice(&data[offset..offset + bytes_to_copy]);

            offset += consts::PROPERTY_SEGMENT_LENGTH;
            n += 1;
        }
    }

    pub fn get_segment(&self, segment_nr: usize) -> Option<&PropertyData> {
        if segment_nr < self.values.len() {
            Some(&self.values[segment_nr])
        } else {
            None
        }
    }

    pub fn get_mut_segment(&mut self, segment_nr: usize) -> Option<&mut PropertyData> {
        if segment_nr < self.values.len() {
            Some(&mut self.values[segment_nr])
        } else {
            None
        }
    }

    pub fn add_member_to_set(&mut self, member_id: ObjectID) -> Result<(), NetWareError> {
        if (self.flag & FLAG_SET) == 0 { return Err(NetWareError::NoSuchSet); }

        let mut iter = bindery::PropertySetValues::new(self);
        if iter.any(|id| id == member_id) { return Err(NetWareError::MemberExists); }

        let mut iter = bindery::PropertySetValues::new(self);
        if let Some(avail_index) = iter.position(|id| id == ID_EMPTY) {
            let buf = self.decode_index(avail_index);
            BigEndian::write_u32(buf, member_id);
            return Ok(());
        }

        todo!(); // need to add new property
    }

    pub fn remove_member_from_set(&mut self, member_id: ObjectID) -> Result<(), NetWareError> {
        if (self.flag & FLAG_SET) == 0 { return Err(NetWareError::NoSuchSet); }

        let mut iter = bindery::PropertySetValues::new(self);
        if let Some(avail_index) = iter.position(|id| id == member_id) {
            let buf = self.decode_index(avail_index);
            BigEndian::write_u32(buf, ID_EMPTY);
            return Ok(());
        }
        Err(NetWareError::NoSuchMember)
    }

    pub fn is_member_of_set(&self, member_id: ObjectID) -> Result<(), NetWareError> {
        if (self.flag & FLAG_SET) == 0 { return Err(NetWareError::NoSuchSet); }

        let mut iter = bindery::PropertySetValues::new(self);
        if iter.any(|id| id == member_id) {
            return Ok(());
        }
        Err(NetWareError::NoSuchMember)
    }
}

pub struct PropertySetValues<'a> {
    property: &'a Property,
    offset: usize,
}

impl<'a> PropertySetValues<'a> {
    pub fn new(property: &'a Property) -> Self {
        Self{ property, offset: 0 }
    }
}

impl<'a> Iterator for PropertySetValues<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let item_size = std::mem::size_of::<Self::Item>();
        let value_index = self.offset / consts::PROPERTY_SEGMENT_LENGTH;
        let value_offset = self.offset % consts::PROPERTY_SEGMENT_LENGTH;
        if value_index < self.property.values.len() {
            let buf = &self.property.values[value_index][value_offset..value_offset + item_size];
            let value_id = BigEndian::read_u32(buf);
            self.offset += item_size;
            Some(value_id)
        } else {
            None
        }
    }
}

pub struct Object {
    pub id: ObjectID,
    pub typ: ObjectType,
    pub flag: Flag,
    pub name: BoundedString< { consts::OBJECT_NAME_LENGTH }>,
    pub security: Security,
    pub properties: Vec<Property>,
}

impl Object {
    pub fn new(id: ObjectID, name: &str, typ: ObjectType, flag: Flag, security: Security) -> Self {
        let name = BoundedString::from_str(name);
        Self{ id, name, typ, flag, security, properties: Vec::new() }
    }

    pub fn contains_property(&self, name: &str) -> bool {
        let name = MaxBoundedString::from_str(name);
        for prop in &self.properties {
            if prop.name.equals(name) {
                return true;
            }
        }
        false
    }

    pub fn get_mut_property_by_name(&mut self, name: &str) -> Result<&mut Property, NetWareError> {
        let name = MaxBoundedString::from_str(name);
        if let Some(prop) = self.properties.iter_mut().find(|p| p.name.equals(name)) {
            return Ok(prop)
        }
        Err(NetWareError::NoSuchProperty)
    }

    pub fn get_property_by_name(&mut self, name: &str) -> Result<&Property, NetWareError> {
        let name = MaxBoundedString::from_str(name);
        if let Some(prop) = self.properties.iter().find(|p| p.name.equals(name)) {
            return Ok(prop)
        }
        Err(NetWareError::NoSuchProperty)
    }

    pub fn get_or_create_property_by_name(&mut self, name: &str, flags: Flag, security: Security) -> Result<&mut Property, NetWareError> {
        // TODO Workaround borrow checker (should be fixed by NLL, one day...)
        if self.contains_property(name) {
            return self.get_mut_property_by_name(name);
        }
        self.create_property(name, flags, security)
    }

    pub fn create_property(&mut self, name: &str, flags: Flag, security: Security) -> Result<&mut Property, NetWareError> {
        if (flags & !bindery::FLAG_MASK) != 0 {
            return Err(NetWareError::InvalidPropertyFlags);
        }

        // TODO Verify security
        let property = Property::new(name, flags, security);
        self.properties.push(property);
        Ok(self.properties.last_mut().unwrap())
    }
}

pub struct Bindery {
    pub objects: Vec<Object>,
    pub next_id: ObjectID,
}

#[derive(Serialize,Deserialize)]
struct TomlProperty {
    name: String,
    flag: u64,
    security: u64,
    value: Option<String>,
    members: Option<Vec<String>>,
}

#[derive(Serialize,Deserialize)]
struct TomlObject {
    name: String,
    r#type: u64,
    flag: u64,
    security: u64,
    property: Vec<TomlProperty>,
}

#[derive(Serialize,Deserialize)]
struct TomlBindery {
    object: BTreeMap<String, TomlObject>,
}

impl Bindery {
    pub fn new(config: &config::Configuration) -> Self {
        let mut bindery = Self{ objects: Vec::new(), next_id: ID_BASE };
        bindery.add_file_server(config.get_server_name().as_str(), config.get_server_address()).expect("cannot create fileserver bindery object");
        bindery
    }

    pub fn create_users_and_groups(&mut self, config: &config::Configuration) -> Result<(), NetWareError> {
        // Create users
        for (name, user) in config.get_users() {
            let name = name.to_uppercase();
            let is_supervisor = name == "SUPERVISOR";
            let user_id = if is_supervisor { Some(bindery::ID_SUPERVISOR) } else { None };
            let user_id = self.add_user(&name, user_id)?;
            let password = &user.initial_password.as_deref().unwrap_or("");
            self.set_password(user_id, password)?;
        }

        // Create groups
        for (name, group) in config.get_groups() {
            let name = name.to_uppercase();
            let group_id = self.add_group(&name)?;
            for member in &group.members {
                let member = member.to_uppercase();
                let object_name = MaxBoundedString::from_str(&member);
                if let Ok(user) = self.get_object_by_name(object_name, TYPE_USER) {
                    let user_id = user.id;
                    self.add_member_to_group(group_id, user_id)?;
                    self.add_group_to_member(user_id, group_id)?;
                } else {
                    panic!("user '{}' not found", object_name); // TODO
                }
            }
        }
        Ok(())
    }

    fn generate_next_id(&mut self) -> ObjectID {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn get_mut_object_by_name(&mut self, object_name: MaxBoundedString, object_type: ObjectType) -> Result<&mut Object, NetWareError> {
        for object in self.objects.iter_mut() {
            if object.name.equals(object_name) && (object_type == TYPE_WILD || object.typ == object_type) {
                return Ok(object)
            }
        }
        Err(NetWareError::NoSuchObject)
    }

    pub fn get_object_by_name(&self, object_name: MaxBoundedString, object_type: ObjectType) -> Result<&Object, NetWareError> {
        for object in &self.objects {
            if object.name.equals(object_name) && (object_type == TYPE_WILD || object.typ == object_type) {
                return Ok(object)
            }
        }
        Err(NetWareError::NoSuchObject)
    }

    pub fn get_mut_object_by_id(&mut self, object_id: ObjectID) -> Result<&mut Object, NetWareError> {
        if let Some(object) = self.objects.iter_mut().find(|o| o.id == object_id) {
            return Ok(object)
        }
        Err(NetWareError::NoSuchObject)
    }

    pub fn get_object_by_id(&self, object_id: ObjectID) -> Result<&Object, NetWareError> {
        if let Some(object) = self.objects.iter().find(|o| o.id == object_id) {
            return Ok(object)
        }
        Err(NetWareError::NoSuchObject)
    }

    pub fn create_object(&mut self, object_id: Option<ObjectID>, name: &str, typ: ObjectType, flags: Flag, security: Security) -> Result<&mut Object, NetWareError> {
        if (flags & !bindery::FLAG_MASK) != 0 {
            return Err(NetWareError::InvalidPropertyFlags); // XXX object
        }

        let object_id = object_id.unwrap_or_else(|| self.generate_next_id());
        let object = Object::new(object_id, name, typ, flags, security);
        self.objects.push(object);
        Ok(self.objects.last_mut().unwrap())
    }

    pub fn delete_object_by_id(&mut self, object_id: ObjectID) -> Result<(), NetWareError> {
        for (n, object) in self.objects.iter().enumerate() {
            if object.id == object_id {
                self.objects.remove(n);
                return Ok(());
            }
        }
        Err(NetWareError::NoSuchObject)
    }

    fn add_file_server(&mut self, server_name: &str, server_addr: IpxAddr) -> Result<(), NetWareError> {
        let server = self.create_object(None, server_name, TYPE_FILE_SERVER, FLAG_DYNAMIC, 0x40)?;

        let net_addr = server.create_property("NET_ADDRESS", FLAG_DYNAMIC, 0x40)?;
        let mut addr_buffer = [ 0u8; 12 ];
        server_addr.to(&mut addr_buffer);
        net_addr.set_data(&addr_buffer);
        Ok(())
    }

    fn set_password(&mut self, object_id: ObjectID, password: &str) -> Result<(), NetWareError> {
        let object = self.get_mut_object_by_id(object_id)?;

        let password_data = crypto::encrypt_bindery_password(object.id, password);

        let password = object.get_mut_property_by_name("PASSWORD")?;

        password.set_data(&password_data);
        Ok(())
    }

    fn add_user(&mut self, user_name: &str, user_id: Option<bindery::ObjectID>) -> Result<ObjectID, NetWareError> {
        let user = self.create_object(user_id, user_name, TYPE_USER, FLAG_STATIC, 0x31)?;
        user.create_property("PASSWORD", FLAG_STATIC, 0x44)?;
        user.create_property("GROUPS_I'M_IN", FLAG_STATIC | FLAG_SET, 0x31)?;
        user.create_property("SECURITY_EQUALS", FLAG_STATIC | FLAG_SET, 0x32)?;
        Ok(user.id)
    }

    fn add_group(&mut self, group_name: &str) -> Result<ObjectID, NetWareError> {
        let group = self.create_object(None, group_name, TYPE_USER_GROUP, FLAG_STATIC, 0x31)?;
        group.create_property("GROUP_MEMBERS", FLAG_STATIC | FLAG_SET, 0x31)?;
        Ok(group.id)
    }

    fn add_member_to_group(&mut self, group_id: bindery::ObjectID, member_id: bindery::ObjectID) -> Result<(), NetWareError> {
        let group = self.get_mut_object_by_id(group_id)?;
        let members = group.get_mut_property_by_name("GROUP_MEMBERS")?;
        members.add_member_to_set(member_id)?;
        Ok(())
    }

    fn add_group_to_member(&mut self, member_id: bindery::ObjectID, group_id: bindery::ObjectID) -> Result<(), NetWareError> {
        let member = self.get_mut_object_by_id(member_id)?;
        let groups_im_in = member.get_mut_property_by_name("GROUPS_I'M_IN")?;
        groups_im_in.add_member_to_set(group_id)?;
        let security_equals = member.get_mut_property_by_name("SECURITY_EQUALS")?;
        security_equals.add_member_to_set(group_id)?;
        Ok(())
    }

    pub fn save(&self, fname: &str) -> Result<(), NetWareError> {
        let mut toml_bindery = TomlBindery{ object: BTreeMap::new() };
        for object in &self.objects {
            if (object.flag & FLAG_DYNAMIC) != 0 { continue; }

            let mut toml_object = TomlObject{
                name: object.name.to_string(),
                r#type: object.typ.into(),
                flag: object.flag.into(),
                security: object.security.into(),
                property: Vec::new()
            };
            for property in &object.properties {
                if (property.flag & FLAG_DYNAMIC) != 0 { continue; }
                let mut toml_property = TomlProperty{
                    name: property.name.to_string(),
                    flag: property.flag.into(),
                    security: property.security.into(),
                    value: None,
                    members: None,
                };

                if (property.flag & FLAG_SET) == 0 {
                    let mut value = String::new();
                    for data in &property.values {
                        for v in data {
                            value += format!("{:02x}", v).as_str();
                        }
                    }

                    // Trim trailing zero's from the value, we do not need to store these
                    let mut last_index = value.len();
                    while last_index > 2 && &value[last_index - 2..last_index] == "00" {
                        last_index -= 2;
                    }
                    value = value[..last_index].to_string();
                    if !value.is_empty() {
                        toml_property.value = Some(value);
                    }
                } else {
                    let mut members: Vec<String> = Vec::new();
                    for value in &property.values {
                        for offset in (0..consts::PROPERTY_SEGMENT_LENGTH).step_by(4) {
                            let buf = &value[offset..offset + 4];
                            let value_id = BigEndian::read_u32(buf);
                            if value_id != ID_EMPTY {
                                members.push(util::object_id_to_str(self, value_id));
                            }
                        }
                    }
                    toml_property.members = Some(members);
                }
                toml_object.property.push(toml_property);
            }

            let id = format!("{:08x}", object.id).to_string();
            toml_bindery.object.insert(id, toml_object);
        }

        let toml = toml::to_string(&toml_bindery).expect("cannot encode toml");
        std::fs::write(fname, toml)?;
        Ok(())
    }

    pub fn load(&mut self, fname: &str) -> Result<(), NetWareError> {
        let data = std::fs::read_to_string(fname)?;
        let toml: TomlBindery = toml::from_str(&data).expect("cannot decode toml");
        for (id, toml_object) in &toml.object {
            let id = u32::from_str_radix(id, 16).expect("need a hex int");
            let typ = toml_object.r#type as u16;
            let flag = toml_object.flag as Flag;
            let security = toml_object.security as Security;
            let object = self.create_object(Some(id), &toml_object.name, typ, flag, security)?;
            for toml_property in &toml_object.property {
                let flag = toml_property.flag as Flag;
                let security = toml_property.security as Security;
                let prop = object.create_property(&toml_property.name, flag, security)?;
                if let Some(value) = &toml_property.value {
                    if (value.len() % 2) != 0 {
                        panic!("invalid property data length");
                    }

                    let mut data = vec![ 0u8; value.len() / 2 ];
                    for (n, m) in (0..value.len()).step_by(2).enumerate() {
                        let value = u8::from_str_radix(&value[m..m + 2], 16).expect("corrupt value");
                        data[n] = value;
                    }
                    prop.set_data(&data);
                }
            }
        }

        // Second pass to resolve all set members
        for (id, toml_object) in &toml.object {
            let id = u32::from_str_radix(id, 16).unwrap();
            for toml_property in &toml_object.property {
                if let Some(members) = &toml_property.members {
                    for member in members {
                        if let Some(member_id) = util::str_to_object_id(self, member) {
                            // TODO This is a bit unfortunate ...
                            let object = self.get_mut_object_by_id(id).unwrap();
                            let prop = object.get_mut_property_by_name(&toml_property.name).unwrap();
                            prop.add_member_to_set(member_id).expect("unable to add member");
                        }
                    }
                }
            }
        }

        if let Some(max_object_id) = self.objects.iter().map(|o| o.id).max() {
            self.next_id = max_object_id + 1;
        } else {
            self.next_id = ID_BASE;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::bindery;
    use crate::consts;

    #[test]
    fn property_holds_data() {
        let mut prop = bindery::Property::new("TEST", bindery::FLAG_STATIC, 0);
        let mut test_data = [ 0u8; consts::PROPERTY_SEGMENT_LENGTH ];
        for n in 0..consts::PROPERTY_SEGMENT_LENGTH {
            test_data[n] = 255 ^ n as u8;
        }
        prop.set_data(&test_data);

        let seg = prop.get_segment(0).unwrap();
        assert_eq!(&seg[..], &test_data[..]);
        assert!(prop.get_segment(1).is_none());
    }

    #[test]
    fn property_can_hold_multiple_segments() {
        let mut prop = bindery::Property::new("TEST", bindery::FLAG_STATIC, 0);
        let mut test_data = [ 0u8; 17 + consts::PROPERTY_SEGMENT_LENGTH ];
        for n in 0..consts::PROPERTY_SEGMENT_LENGTH {
            test_data[n] = 255 ^ (n * 2) as u8;
        }
        prop.set_data(&test_data);

        let seg = prop.get_segment(0).unwrap();
        assert_eq!(&seg[..], &test_data[0..consts::PROPERTY_SEGMENT_LENGTH]);
        let seg = prop.get_segment(1).unwrap();
        assert_eq!(&seg[..17], &test_data[consts::PROPERTY_SEGMENT_LENGTH..]);
        assert!(prop.get_segment(2).is_none());
    }

    const IDS_PER_PROPERTY_VALUE: u32 = 32;

    #[test]
    fn initially_property_set_is_empty() {
        let prop = bindery::Property::new("TEST", bindery::FLAG_SET, 0);
        let mut iter = bindery::PropertySetValues::new(&prop);
        for _ in 0..IDS_PER_PROPERTY_VALUE {
            let value = iter.next().unwrap();
            assert_eq!(value, 0);
        }
    }

    #[test]
    fn set_property_can_have_32_items() {
        let mut prop = bindery::Property::new("TEST", bindery::FLAG_SET, 0);
        for n in 0..IDS_PER_PROPERTY_VALUE {
            prop.add_member_to_set(1 + n).unwrap();
        }
        let mut iter = bindery::PropertySetValues::new(&prop);
        for n in 0..IDS_PER_PROPERTY_VALUE {
            let value = iter.next().unwrap();
            assert_eq!(value, 1 + n);
        }
    }

    #[test]
    fn set_property_items_can_be_removed() {
        let mut prop = bindery::Property::new("TEST", bindery::FLAG_SET, 0);
        prop.add_member_to_set(1).unwrap();
        prop.add_member_to_set(2).unwrap();
        prop.add_member_to_set(3).unwrap();
        prop.remove_member_from_set(2).unwrap();

        let mut iter = bindery::PropertySetValues::new(&prop);
        assert_eq!(iter.next().unwrap(), 1);
        assert_eq!(iter.next().unwrap(), 0);
        assert_eq!(iter.next().unwrap(), 3);
        for _ in 0..(IDS_PER_PROPERTY_VALUE - 3) {
            assert_eq!(iter.next().unwrap(), 0);
        }
    }

    #[test]
    fn nonexistent_set_property_items_are_not_removed() {
        let mut prop = bindery::Property::new("TEST", bindery::FLAG_SET, 0);
        prop.add_member_to_set(1).unwrap();
        prop.add_member_to_set(2).unwrap();
        prop.add_member_to_set(3).unwrap();
        assert!(prop.remove_member_from_set(4).is_err());

        let mut iter = bindery::PropertySetValues::new(&prop);
        assert_eq!(iter.next().unwrap(), 1);
        assert_eq!(iter.next().unwrap(), 2);
        assert_eq!(iter.next().unwrap(), 3);
        for _ in 0..(IDS_PER_PROPERTY_VALUE - 3) {
            assert_eq!(iter.next().unwrap(), 0);
        }
    }

    #[test]
    fn duplicate_ids_are_not_added_to_a_property_set() {
        let mut prop = bindery::Property::new("TEST", bindery::FLAG_SET, 0);
        prop.add_member_to_set(1).unwrap();
        assert!(prop.add_member_to_set(1).is_err());

        let mut iter = bindery::PropertySetValues::new(&prop);
        assert_eq!(iter.next().unwrap(), 1);
        for _ in 0..(IDS_PER_PROPERTY_VALUE - 1) {
            assert_eq!(iter.next().unwrap(), 0);
        }
    }

    #[ignore]
    #[test]
    fn adding_more_set_items_creates_multiple_property_values() {
        let mut prop = bindery::Property::new("TEST", bindery::FLAG_SET, 0);
        for n in 0..IDS_PER_PROPERTY_VALUE {
            prop.add_member_to_set(1 + n).unwrap();
        }
        prop.add_member_to_set(2 + IDS_PER_PROPERTY_VALUE).unwrap();
    }
}
