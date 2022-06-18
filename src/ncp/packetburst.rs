/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::connection;
use super::parser;
use crate::error::*;
use crate::ncp_service::NcpReplyPacket;

pub fn process_request_101_packet_burst_connection_request(_conn: &mut connection::Connection, _args: &parser::PacketBurstConnectionRequest, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::UnsupportedRequest)
}

