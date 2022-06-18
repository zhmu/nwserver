/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::connection;
use crate::error::*;
use super::parser;
use crate::ncp_service::NcpReplyPacket;

pub fn process_request_23_61_read_property_value(_conn: &mut connection::Connection, _args: &parser::ReadPropertyValue, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::NoSuchSet)
}

