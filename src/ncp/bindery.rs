/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::bindery;
use crate::connection;
use crate::config;
use crate::crypto;
use crate::error::*;
use crate::types::*;
use super::parser;
use crate::trustee;
use crate::ncp_service::NcpReplyPacket;

use std::convert::TryInto;

const ANY_OBJECT_TYPE: bindery::ObjectType = 0xffff;
const RESET_OBJECT_ID: bindery::ObjectID = 0xffffffff;

pub fn process_request_23_61_read_property_value(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::ReadPropertyValue, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    if args.object_type == bindery::TYPE_WILD { return Err(NetWareError::NoSuchObject); }
    if args.segment_number == 0 { return Err(NetWareError::NoSuchProperty); }

    let segment_number = (args.segment_number - 1) as usize;
    let object = bindery.get_object_by_name(args.object_name, args.object_type)?;
    let prop = object.get_property_by_name(args.property_name.as_str())?;
    return if segment_number < prop.values.len() {
        reply.add_data(&prop.values[segment_number]);
        reply.add_u8(if segment_number == prop.values.len() - 1 { 0 } else { 0xff });
        reply.add_u8(prop.flag);
        Ok(())
    } else {
        Err(NetWareError::NoSuchProperty)
    }
}

pub fn process_request_23_70_get_bindery_access_level(conn: &mut connection::Connection, _args: &parser::GetBinderyAccessLevel, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    reply.add_u8(conn.bindery_security);
    reply.add_u32(conn.logged_in_object_id);
    Ok(())
}

pub fn process_request_23_54_get_bindery_object_name(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::GetBinderyObjectName, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let object = bindery.get_object_by_id(args.object_id)?;
    reply.add_u32(object.id); // ObjectID
    reply.add_u16(object.typ); // ObjectType
    object.name.to_raw(reply); // ObjectName
    Ok(())
}

pub fn process_request_23_55_scan_bindery_object(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::ScanBinderyObject, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let mut return_matching_object = args.last_object_seen == RESET_OBJECT_ID;
    for object in &bindery.objects {
        if args.search_object_type != ANY_OBJECT_TYPE && object.typ != args.search_object_type { continue; }

        // TODO match wildcard

        if return_matching_object {
            reply.add_u32(object.id); // ObjectID
            reply.add_u16(object.typ); // ObjectType
            object.name.to_raw(reply); // ObjectName
            reply.add_u8(object.flag); // ObjectFlags
            reply.add_u8(object.security); // ObjectSecurity
            reply.add_u8(if object.properties.is_empty() { 0 } else { 0xff }); // ObjectHasProperties
            return Ok(())
        }
        return_matching_object = args.last_object_seen == object.id;
    }
    Err(NetWareError::NoSuchObject)
}

pub fn process_request_23_53_get_bindery_object_id(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::GetBinderyObjectID, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    if args.object_type == bindery::TYPE_WILD { return Err(NetWareError::NoSuchObject); }

    let object = bindery.get_object_by_name(args.object_name, args.object_type)?;
    reply.add_u32(object.id); // ObjectID
    reply.add_u16(object.typ); // ObjectType
    object.name.to_raw(reply); // ObjectName
    Ok(())
}

pub fn process_request_23_74_keyed_verify_password(conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::KeyedVerifyPassword, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    if conn.login_key.is_none() { return Err(NetWareError::NoKeyAvailable); }
    let login_key = conn.login_key.as_ref().unwrap();

    let object = bindery.get_object_by_name(args.object_name, args.object_type)?;
    let property = object.get_property_by_name("PASSWORD")?;
    let segment = property.get_segment(0).unwrap();
    let crypted_password = crypto::encrypt(login_key.data(), segment[0..16].try_into().unwrap());
    if crypted_password != *args.key.data() { return Err(NetWareError::InvalidPassword) }
    Ok(())
}

pub fn process_request_23_75_keyed_change_password(conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::KeyedChangePassword, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    if conn.login_key.is_none() { return Err(NetWareError::NoKeyAvailable); }
    let login_key = conn.login_key.as_ref().unwrap();

    let object = bindery.get_object_by_name(args.object_name, args.object_type)?;
    if object.contains_property("PASSWORD") {
        let mut property = object.get_property_by_name("PASSWORD")?;
        let segment = property.get_segment(0).unwrap();
        let crypted_password = crypto::encrypt(login_key.data(), segment[0..16].try_into().unwrap());
        if crypted_password != *args.key.data() { return Err(NetWareError::InvalidPassword) }
    } else {
        object.create_property("PASSWORD", bindery::FLAG_STATIC, 0x44)?;
    }
    let mut property = object.get_property_by_name("PASSWORD")?;
    let segment = property.get_segment(0).unwrap();
    if args.new_password.len() < 16 { return Err(NetWareError::InvalidPassword) }

    let new_password = args.new_password.data();
    let a = crypto::decrypt(segment[0..8].try_into().unwrap(), new_password[0..8].try_into().unwrap());
    let b = crypto::decrypt(segment[8..16].try_into().unwrap(), new_password[8..16].try_into().unwrap());

    property.set_data(0, &a);
    property.set_data(8, &b);
    Ok(())
}

pub fn process_request_23_66_delete_object_from_set(conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::DeleteObjectFromSet, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let member = bindery.get_object_by_name(args.member_name, args.member_type)?;
    let member_id = member.id;

    let group = bindery.get_object_by_name(args.object_name, args.object_type)?;
    let members = group.get_property_by_name(args.property_name.as_str())?;

    members.remove_member_from_set(member_id)?;
    Ok(())
}

pub fn process_request_23_67_is_object_in_set(conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::IsObjectInSet, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let member = bindery.get_object_by_name(args.member_name, args.member_type)?;
    let member_id = member.id;

    let group = bindery.get_object_by_name(args.object_name, args.object_type)?;
    let members = group.get_property_by_name(args.property_name.as_str())?;

    members.is_member_of_set(member_id)
}

pub fn process_request_23_72_get_bindery_object_access_level(conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::GetBinderyObjectAccessLevel, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let object = bindery.get_object_by_id(args.object_id)?;

    let access_level = 0x33; // TODO
    reply.add_u8(access_level); // ObjectAccessLevel
    Ok(())
}

pub fn process_request_23_65_add_bindery_object_to_set(conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::AddBinderyObjectToSet, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let member = bindery.get_object_by_name(args.member_name, args.member_type)?;
    let member_id = member.id;

    let group = bindery.get_object_by_name(args.object_name, args.object_type)?;
    let members = group.get_property_by_name(args.property_name.as_str())?;

    members.add_member_to_set(member_id)?;
    Ok(())
}

pub fn process_request_23_57_create_property(conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::CreateProperty, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let object = bindery.get_object_by_name(args.object_name, args.object_type)?;

    if let Ok(_) = object.get_property_by_name(args.property_name.as_str()) {
        return Err(NetWareError::PropertyExists);
    }

    // TODO Check permissions
    object.create_property(args.property_name.as_str(), args.property_flags, args.property_security)?;
    Ok(())
}

pub fn process_request_23_62_write_property_value(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::WritePropertyValue, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    if args.object_type == bindery::TYPE_WILD { return Err(NetWareError::NoSuchObject); }
    if args.segment_number == 0 { return Err(NetWareError::NoSuchProperty); }
    if args.more_flag != 0 { return Err(NetWareError::UnsupportedRequest); } // TODO

    let segment_number = (args.segment_number - 1) as usize;
    let object = bindery.get_object_by_name(args.object_name, args.object_type)?;
    let prop = object.get_property_by_name(args.property_name.as_str())?;
    // TODO check security
    return if segment_number < prop.values.len() {
        prop.values[segment_number].copy_from_slice(args.property_value.data());

        // TODO: truncate
        Ok(())
    } else {
        Err(NetWareError::NoSuchProperty)
    }
}

pub fn process_request_23_50_create_bindery_object(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::CreateBinderyObject, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    if args.object_type == bindery::TYPE_WILD { return Err(NetWareError::NoSuchObject); }

    let object_name = args.object_name.as_str();
    bindery.create_object(None, object_name, args.object_type, args.object_flags, args.object_security)?;
    Ok(())
}

pub fn process_request_23_51_delete_bindery_object(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::DeleteBinderyObject, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    if args.object_type == bindery::TYPE_WILD { return Err(NetWareError::NoSuchObject); }

    let object = bindery.get_object_by_name(args.object_name, args.object_type)?;
    let object_id = object.id;
    bindery.delete_object_by_id(object_id)?;
    Ok(())
}

pub fn process_request_23_71_scan_bindery_object_trustee_path<'a>(conn: &mut connection::Connection<'a>, config: &'a config::Configuration, trustee_db: &trustee::TrusteeDB, args: &parser::ScanBinderyObjectTrusteePath, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let volume = config.get_volumes().get_volume_by_number(args.volume_number as usize)?;
    let sequence = if args.last_sequence_number == 0xffff { 0 } else { args.last_sequence_number };

    let object_id;
    let access_mask;
    let path;
    if let Some((trustee_path, trustee)) = trustee_db.get_indexed_trustee_by_object_id(args.object_id, volume.number as usize, sequence) {
        object_id = trustee.object_id;
        access_mask = trustee.rights & 0xff;
        path = MaxBoundedString::from_str(&format!("{}:{}", volume.name, trustee_path).to_string());
    } else {
        object_id = bindery::ID_EMPTY;
        access_mask = 0;
        path = MaxBoundedString::empty();
    }
    reply.add_u16(sequence.wrapping_add(1));
    reply.add_u32(object_id);
    reply.add_u8((access_mask & 0xff) as u8);
    path.to(reply);
    Ok(())
}

