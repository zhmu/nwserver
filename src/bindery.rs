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
use crate::types::*;

pub type ObjectID = u32;
pub type ObjectType = u16;
pub type Flag = u8;
pub type Security = u8;

pub const TYPE_WILD: ObjectType = 0xffff;
pub const TYPE_USER: ObjectType = 0x0001;
pub const TYPE_USER_GROUP: ObjectType = 0x0002;
pub const TYPE_FILE_SERVER: ObjectType = 0x0004;

pub const ID_SUPERVISOR: ObjectID = 1;
pub const ID_NOT_LOGGED_IN: ObjectID = 0xffffffff;

const ID_BASE: ObjectID = 0x1000000;

pub const FLAG_STATIC: Flag = 0x00;
pub const FLAG_DYNAMIC: Flag = 0x01;

pub const SECURITY_NOT_LOGGED_IN: Security = 0x00;

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
        assert_eq!(offset, 0);
        assert!(data.len() < consts::PROPERTY_SEGMENT_LENGTH);
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

    pub fn get_property_by_name(&mut self, name: MaxBoundedString) -> Option<&mut Property> {
        for prop in self.properties.iter_mut() {
            if prop.name.equals(name) {
                return Some(prop)
            }
        }
        None
    }
}

pub struct Bindery {
    pub objects: Vec<Object>,
    pub next_id: ObjectID,
}

impl Bindery {
    pub fn new(config: &config::Configuration) -> Self {
        let mut bindery = Self{ objects: Vec::new(), next_id: ID_BASE };
        bindery.add_file_server(config.get_server_name().as_str(), config.get_server_address());
        let supervisor_id = bindery.add_user("SUPERVISOR", Some(bindery::ID_SUPERVISOR));
        bindery.set_password(supervisor_id, "");
        let guest_id = bindery.add_user("GUEST", None);
        bindery.set_password(guest_id, "");
        bindery
    }

    fn generate_next_id(&mut self) -> ObjectID {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn get_object_by_name(&mut self, object_name: MaxBoundedString, object_type: ObjectType) -> Option<&mut Object> {
        for object in self.objects.iter_mut() {
            if object.name.equals(object_name) && object.typ == object_type {
                return Some(object)
            }
        }
        None
    }

    pub fn get_object_by_id(&mut self, object_id: ObjectID) -> Option<&mut Object> {
        for object in self.objects.iter_mut() {
            if object.id == object_id {
                return Some(object)
            }
        }
        None
    }

    fn add_file_server(&mut self, server_name: &str, server_addr: IpxAddr) {
        let object_id = self.generate_next_id();
        let mut server = Object::new(object_id, server_name, TYPE_FILE_SERVER, FLAG_DYNAMIC, 0x40);
        let mut net_addr = Property::new("NET_ADDRESS", FLAG_DYNAMIC, 0x40);
        let mut addr_buffer = [ 0u8; 12 ];
        server_addr.to(&mut addr_buffer);
        net_addr.set_data(0, &addr_buffer);
        server.properties.push(net_addr);
        self.objects.push(server);
    }

    fn set_password(&mut self, object_id: ObjectID, password: &str) -> Option<()> {
        let object = self.get_object_by_id(object_id);
        if object.is_none() { return None; }
        let object = object.unwrap();

        let password_data = crypto::encrypt_bindery_password(object.id, password);

        let password = object.get_property_by_name(MaxBoundedString::from_str("PASSWORD"));
        if password.is_none() { return None; }
        let password = password.unwrap();

        password.set_data(0, &password_data);
        Some(())
    }

    fn add_user(&mut self, user_name: &str, user_id: Option<bindery::ObjectID>) -> ObjectID {
        let object_id = match user_id {
            Some(n) => { n },
            None => { self.generate_next_id() }
        };
        let mut user = Object::new(object_id, user_name, TYPE_USER, FLAG_STATIC, 0x13);
        let password = Property::new("PASSWORD", FLAG_STATIC, 0x04);
        user.properties.push(password);
        self.objects.push(user);
        object_id
    }
}
