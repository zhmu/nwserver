/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::config;
use crate::connection;
use crate::consts;
use crate::clients;
use crate::error::*;
use crate::types::*;
use crate::ncp_service::NcpReplyPacket;
use super::parser;

use log::*;

use chrono::{Local, Timelike, Datelike};

pub fn process_request_23_17_get_fileserver_info(config: &config::Configuration, clients: &clients::Clients, _args: &parser::GetFileServerInfo, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    reply.add_data(config.get_server_name().buffer());
    reply.add_u8(3); // FileServiceVersion
    reply.add_u8(12); // FileServiceSubVersion
    reply.add_u16(consts::MAX_CONNECTIONS as u16); // MaximumServiceConnections
    let connections_in_use = clients.count_in_use() as u16;
    reply.add_u16(connections_in_use);
    reply.add_u16(1); // NumberMountedVolumes
    reply.add_u8(0); // Revision
    reply.add_u8(2); // SFTLevel
    reply.add_u8(1); // TTSLevel
    reply.add_u16(connections_in_use); // MaxConnectionsEverUsed
    reply.add_u8(0); // AccountVersion
    reply.add_u8(0); // VAPVersion
    reply.add_u8(0); // QueueVersion
    reply.add_u8(0); // PrintVersion
    reply.add_u8(0); // VirtualConsoleVersion
    reply.add_u8(0); // RestrictionLevel
    reply.add_u8(0); // InternetBridge
    reply.add_u8(0); // MixedModePathFlag
    reply.add_u8(0); // LocalLoginInfoCcode
    reply.add_u16(0); // ProductMajorVersion
    reply.add_u16(0); // ProductMinorVersion
    reply.add_u16(0); // ProductRevisionVersion
    reply.add_u8(0); // OSLanguageID
    reply.add_u8(0); // 64BitOffsetsSupportedFlag
    reply.fill_u8(50, 0); // Reserved
    Ok(())
}

pub fn process_request_20_get_fileserver_date_and_time(_conn: &mut connection::Connection, _args: &parser::GetFileServerDateAndTime, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    let now = Local::now();

    reply.add_u8((now.year() - 1900) as u8); // Year
    reply.add_u8(now.month() as u8); // Month
    reply.add_u8(now.day() as u8); // Day
    reply.add_u8(now.hour() as u8); // Hour
    reply.add_u8(now.minute() as u8); // Minute
    reply.add_u8(now.second() as u8); // Second
    let weekday = now.date().weekday();
    reply.add_u8(weekday.num_days_from_sunday() as u8); // Day of the week
    Ok(())
}

pub fn process_request_23_211_down_file_server(_conn: &mut connection::Connection, _args: &parser::DownFileServer, reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    info!("SERVER DOWN REQUESTED - EXITING!");
    nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGINT).expect("can't send SIGINT to self");
    Ok(())
}
