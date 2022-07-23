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

    pub fn set_data(&mut self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= consts::PROPERTY_SEGMENT_LENGTH);
        let value = self.values.first_mut().unwrap();
        value[offset..offset + data.len()].copy_from_slice(&data);
    }

    pub fn get_segment(&mut self, segment_nr: usize) -> Option<&mut PropertyData> {
        return if segment_nr < self.values.len() {
            Some(&mut self.values[segment_nr])
        } else {
            None
        }
    }

    pub fn add_member_to_set(&mut self, member_id: ObjectID) -> Result<(), NetWareError> {
        for value in &mut self.values {
            for offset in (0..128).step_by(4) {
                let buf = &mut value[offset..offset + 4];
                let value_id = BigEndian::read_u32(buf);
                if value_id == ID_EMPTY {
                    BigEndian::write_u32(buf, member_id);
                    return Ok(());
                }
            }
        }
        todo!(); // need to add new property
    }

    pub fn remove_member_from_set(&mut self, member_id: ObjectID) -> Result<(), NetWareError> {
        for value in &mut self.values {
            for offset in (0..128).step_by(4) {
                let buf = &mut value[offset..offset + 4];
                let value_id = BigEndian::read_u32(buf);
                if value_id == member_id {
                    BigEndian::write_u32(buf, ID_EMPTY);
                    return Ok(());
                }
            }
        }
        Err(NetWareError::NoSuchMember)
    }

    pub fn is_member_of_set(&mut self, member_id: ObjectID) -> Result<(), NetWareError> {
        for value in &mut self.values {
            for offset in (0..128).step_by(4) {
                let buf = &mut value[offset..offset + 4];
                let value_id = BigEndian::read_u32(buf);
                if value_id == member_id {
                    return Ok(());
                }
            }
        }
        Err(NetWareError::NoSuchMember)
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

    pub fn get_property_by_name(&mut self, name: MaxBoundedString) -> Result<&mut Property, NetWareError> {
        for prop in self.properties.iter_mut() {
            if prop.name.equals(name) {
                return Ok(prop)
            }
        }
        Err(NetWareError::NoSuchProperty)
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
    value: String,
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
            self.set_password(user_id, &password)?;
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

    fn is_supervisor(&mut self, object_id: ObjectID) -> bool {
        // TODO Check security equivalences, etc
        object_id == bindery::ID_SUPERVISOR
    }

    fn generate_next_id(&mut self) -> ObjectID {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn get_object_by_name(&mut self, object_name: MaxBoundedString, object_type: ObjectType) -> Result<&mut Object, NetWareError> {
        for object in self.objects.iter_mut() {
            if object.name.equals(object_name) && object.typ == object_type {
                return Ok(object)
            }
        }
        Err(NetWareError::NoSuchObject)
    }

    pub fn get_object_by_id(&mut self, object_id: ObjectID) -> Result<&mut Object, NetWareError> {
        for object in self.objects.iter_mut() {
            if object.id == object_id {
                return Ok(object)
            }
        }
        Err(NetWareError::NoSuchObject)
    }

    pub fn create_object(&mut self, object_id: Option<ObjectID>, name: &str, typ: ObjectType, flags: Flag, security: Security) -> Result<&mut Object, NetWareError> {
        if (flags & !bindery::FLAG_MASK) != 0 {
            return Err(NetWareError::InvalidPropertyFlags); // XXX object
        }

        let object_id = if object_id.is_some() { object_id.unwrap() } else { self.generate_next_id() };
        let object = Object::new(object_id, name, typ, flags, security);
        self.objects.push(object);
        Ok(self.objects.last_mut().unwrap())
    }

    fn add_file_server(&mut self, server_name: &str, server_addr: IpxAddr) -> Result<(), NetWareError> {
        let object_id = self.generate_next_id();
        let mut server = self.create_object(None, server_name, TYPE_FILE_SERVER, FLAG_DYNAMIC, 0x40)?;

        let mut net_addr = server.create_property("NET_ADDRESS", FLAG_DYNAMIC, 0x40)?;
        let mut addr_buffer = [ 0u8; 12 ];
        server_addr.to(&mut addr_buffer);
        net_addr.set_data(0, &addr_buffer);
        Ok(())
    }

    fn set_password(&mut self, object_id: ObjectID, password: &str) -> Result<(), NetWareError> {
        let object = self.get_object_by_id(object_id)?;

        let password_data = crypto::encrypt_bindery_password(object.id, password);

        let password = object.get_property_by_name(MaxBoundedString::from_str("PASSWORD"))?;

        password.set_data(0, &password_data);
        Ok(())
    }

    fn add_user(&mut self, user_name: &str, user_id: Option<bindery::ObjectID>) -> Result<ObjectID, NetWareError> {
        let mut user = self.create_object(user_id, user_name, TYPE_USER, FLAG_STATIC, 0x31)?;
        user.create_property("PASSWORD", FLAG_STATIC, 0x44)?;
        user.create_property("GROUPS_I'M_IN", FLAG_STATIC | FLAG_SET, 0x31)?;
        user.create_property("SECURITY_EQUALS", FLAG_STATIC | FLAG_SET, 0x32)?;
        Ok(user.id)
    }

    fn add_group(&mut self, group_name: &str) -> Result<ObjectID, NetWareError> {
        let mut group = self.create_object(None, group_name, TYPE_USER_GROUP, FLAG_STATIC, 0x31)?;
        group.create_property("GROUP_MEMBERS", FLAG_STATIC | FLAG_SET, 0x31)?;
        Ok(group.id)
    }

    fn add_member_to_group(&mut self, group_id: bindery::ObjectID, member_id: bindery::ObjectID) -> Result<(), NetWareError> {
        let group = self.get_object_by_id(group_id)?;
        let members = group.get_property_by_name(MaxBoundedString::from_str("GROUP_MEMBERS"))?;
        members.add_member_to_set(member_id)?;
        Ok(())
    }

    fn add_group_to_member(&mut self, member_id: bindery::ObjectID, group_id: bindery::ObjectID) -> Result<(), NetWareError> {
        let member = self.get_object_by_id(member_id)?;
        let groups_im_in = member.get_property_by_name(MaxBoundedString::from_str("GROUPS_I'M_IN"))?;
        groups_im_in.add_member_to_set(group_id)?;
        let security_equals = member.get_property_by_name(MaxBoundedString::from_str("SECURITY_EQUALS"))?;
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
                    value: String::new()
                };
                for data in &property.values {
                    for v in data {
                        toml_property.value += format!("{:02x}", v).as_str();
                    }
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
            let mut object = self.create_object(Some(id), &toml_object.name, typ, flag, security)?;
            for toml_property in &toml_object.property {
                let flag = toml_property.flag as Flag;
                let security = toml_property.security as Security;
                let mut prop = object.create_property(&toml_property.name, flag, security)?;
                if (toml_property.value.len() % (2 * consts::PROPERTY_SEGMENT_LENGTH)) != 0 {
                    panic!("invalid property data length");
                }
                let chars_per_segment = 2 * consts::PROPERTY_SEGMENT_LENGTH;
                for n in 0..(toml_property.value.len() / chars_per_segment) {
                    let mut data: PropertyData = [ 0u8; consts::PROPERTY_SEGMENT_LENGTH ];
                    for m in 0..consts::PROPERTY_SEGMENT_LENGTH {
                        let index = chars_per_segment * n + m * 2;
                        data[m] = u8::from_str_radix(&toml_property.value[index..index + 2], 16).expect("corrupt value");
                    }
                    prop.set_data(n * consts::PROPERTY_SEGMENT_LENGTH, &data);
                }
            }
        }
        Ok(())
    }
}
