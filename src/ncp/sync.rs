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

pub fn process_request_26_lock_physical_record_old(_conn: &mut connection::Connection, _args: &parser::LockPhysicalRecordOld, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Ok(())
}

pub fn process_request_30_clear_physical_record(_conn: &mut connection::Connection, _args: &parser::ClearPhysicalRecord, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Ok(())
}

