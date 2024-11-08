/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::bindery;
use crate::connection;
use crate::crypto;
use crate::clients;
use crate::config;
use crate::consts;
use super::parser;
use crate::error::*;
use crate::types::*;
use crate::ncp_service::NcpReplyPacket;

use std::convert::TryInto;
use log::*;

pub fn destroy_service_connection(conn: &mut connection::Connection, _args: &parser::DestroyServiceConnection, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    *conn = connection::Connection::zero();
    Ok(())
}

pub fn process_request_33_negotiate_buffer_size(_conn: &mut connection::Connection, args: &parser::NegotiateBufferSize, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let max_buffer_size = consts::MAX_PAYLOAD_SIZE as u16;
    let accepted_buffer_size = if args.proposed_buffer_size > max_buffer_size { max_buffer_size } else { args.proposed_buffer_size };

    reply.add_u16(accepted_buffer_size);
    Ok(())
}

pub fn process_request_97_get_big_packet_ncp_max_packet_size(_conn: &mut connection::Connection, _args: &parser::GetBigPacketNCPMaxPacketSize, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::UnsupportedRequest)
}

pub fn process_request_24_end_of_job(conn: &mut connection::Connection, _args: &parser::EndOfJob, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let num_dh_freed = conn.free_temp_dir_handles();
    info!("freed {} temporary directory handles", num_dh_freed);
    Ok(())
}

pub fn process_request_25_logout<'a>(conn: &mut connection::Connection<'a>, config: &'a config::Configuration, _args: &parser::Logout, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    conn.logout(config);
    Ok(())
}

pub fn process_request_23_28_get_station_logged_info(clients: &mut clients::Clients, bindery: &mut bindery::Bindery, args: &parser::GetStationLoggedInfo, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let client = clients.get_connection_by_number(args.target_connection_num)?;
    // This is what NW does - should we make this optional?
    if !client.is_logged_on() { return Err(NetWareError::StationNotLoggedOn) }

    reply.add_u32(client.logged_in_object_id);
    if let Ok(object) = bindery.get_object_by_id(client.logged_in_object_id) {
        reply.add_u16(object.typ); // UserType
        object.name.to_raw(reply); // UserName
    } else {
        reply.add_u16(0);
        reply.fill_u8(48, 0);
    }
    reply.fill_u8(7, 0); // LoginTime
    reply.add_u8(0); // reserved
    Ok(())
}

pub fn process_request_23_26_get_internet_address(clients: &mut clients::Clients, args: &parser::GetInternetAddress, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let client = clients.get_connection_by_number(args.target_connection_num)?;
    // This may be what NW does - should we make this optional?
    if !client.is_logged_on() { return Err(NetWareError::StationNotLoggedOn) }

    let mut addr = [ 0u8; 12 ];
    client.dest.to(&mut addr);
    reply.add_data(&addr); // NetworkAddressStrut
    reply.add_u8(consts::CONNECTION_TYPE_NCP); // ConnectionType
    Ok(())
}

pub fn process_request_23_23_get_login_key(conn: &mut connection::Connection, _args: &parser::GetLoginKey, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let login_key = LoginKey::generate();
    login_key.to(reply);
    conn.login_key = Some(login_key);
    Ok(())
}

pub fn process_request_23_24_keyed_object_login(conn: &mut connection::Connection, config: &config::Configuration, bindery: &mut bindery::Bindery, args: &parser::KeyedObjectLogin, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    // TODO: This error isn't the correct one
    if !config.is_login_allowed() { return Err(NetWareError::ServerLoginLocked); }

    if conn.login_key.is_none() { return Err(NetWareError::NoKeyAvailable); }
    let login_key = conn.login_key.as_ref().unwrap();

    let object = bindery.get_mut_object_by_name(args.object_name, args.object_type)?;
    let property = object.get_mut_property_by_name("PASSWORD")?;

    let segment = property.get_segment(0).unwrap();
    let crypted_password = crypto::encrypt(login_key.data(), segment[0..16].try_into().unwrap());
    if crypted_password != *args.key.data() { return Err(NetWareError::InvalidPassword) }

    let object_id = object.id;
    conn.login(bindery, object_id);
    Ok(())
}
