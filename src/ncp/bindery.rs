/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::bindery;
use crate::connection;
use crate::error::*;
use crate::types::*;
use super::parser;
use crate::ncp_service::NcpReplyPacket;

const ANY_OBJECT_TYPE: bindery::ObjectType = 0xffff;
const RESET_OBJECT_ID: bindery::ObjectID = 0xffffffff;

pub fn process_request_23_61_read_property_value(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::ReadPropertyValue, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    if args.object_type == bindery::TYPE_WILD { return Err(NetWareError::NoSuchObject); }
    if args.segment_number == 0 { return Err(NetWareError::NoSuchProperty); }

    let segment_number = (args.segment_number - 1) as usize;
    return match bindery.get_object_by_name(args.object_name, args.object_type) {
        Some(object) => {
            return match object.get_property_by_name(args.property_name) {
                Some(prop) => {
                    return if segment_number < prop.values.len() {
                        reply.add_data(&prop.values[segment_number]);
                        reply.add_u8(if segment_number == prop.values.len() - 1 { 0 } else { 0xff });
                        reply.add_u8(prop.flag);
                        Ok(())
                    } else {
                        Err(NetWareError::NoSuchProperty)
                    }
                },
                None => {
                    Err(NetWareError::NoSuchProperty)
                }
            }
        },
        None => {
            Err(NetWareError::NoSuchObject)
        }
    }
}

pub fn process_request_23_70_get_bindery_access_level(conn: &mut connection::Connection, _args: &parser::GetBinderyAccessLevel, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    reply.add_u8(conn.bindery_security);
    reply.add_u32(conn.logged_in_object_id);
    Ok(())
}

pub fn process_request_23_54_get_bindery_object_name(_conn: &mut connection::Connection, bindery: &mut bindery::Bindery, args: &parser::GetBinderyObjectName, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    return match bindery.get_object_by_id(args.object_id) {
        Some(object) => {
            reply.add_u32(object.id); // ObjectID
            reply.add_u16(object.typ); // ObjectType
            object.name.to_raw(reply); // ObjectName
            Ok(())
        },
        None => {
            Err(NetWareError::NoSuchObject)
        }
    }
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

    return match bindery.get_object_by_name(args.object_name, args.object_type) {
        Some(object) => {
            reply.add_u32(object.id); // ObjectID
            reply.add_u16(object.typ); // ObjectType
            object.name.to_raw(reply); // ObjectName
            Ok(())
        },
        None => {
            Err(NetWareError::NoSuchObject)
        }
    }
}

