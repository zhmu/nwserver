/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::connection;
use crate::error::*;
use crate::types::*;
use super::parser;
use crate::ncp_service::NcpReplyPacket;

pub fn process_request_23_61_read_property_value(_conn: &mut connection::Connection, _args: &parser::ReadPropertyValue, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::NoSuchSet)
}

pub fn process_request_23_70_get_bindery_access_level(_conn: &mut connection::Connection, _args: &parser::GetBinderyAccessLevel, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    reply.add_u8(0x00); // not logged in
    reply.add_u32(0xffffffff); // NOT-LOGGED-IN
    Ok(())
}

pub fn process_request_23_54_get_bindery_object_name(_conn: &mut connection::Connection, _args: &parser::GetBinderyObjectName, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::NoSuchObject)
}
