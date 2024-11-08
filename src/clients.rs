/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::connection::Connection;
use crate::consts;
use crate::config;
use crate::types::*;
use crate::error::NetWareError;
use crate::ncp::parser::NcpHeader;

pub struct Clients<'a> {
    client: [ Connection<'a>; consts::MAX_CONNECTIONS ],
}

impl<'a> Default for Clients<'a> {
    fn default() -> Self {
        const CONN_INIT: Connection = Connection::zero();
        let client = [ CONN_INIT; consts::MAX_CONNECTIONS ];
        Self{ client }
    }
}

impl<'a> Clients<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count_in_use(&self) -> usize {
        self.client.iter().filter(|&e| e.in_use()).count()
    }

    pub fn allocate_connection(&mut self, config: &'a config::Configuration, dest: &IpxAddr) -> Result<usize, NetWareError> {
        for (n, conn) in self.client.iter_mut().enumerate() {
            if conn.in_use() { continue; }

            *conn = Connection::allocate(config, dest);
            return Ok(n);
        }
        Err(NetWareError::NoConnectionsAvailable)
    }

    pub fn get_mut_connection(&mut self, header: &NcpHeader, dest: &IpxAddr) -> Result<&mut Connection<'a>, NetWareError> {
        let connection_number = header.connection_number as usize;
        if (1..consts::MAX_CONNECTIONS).contains(&connection_number) {
            let index = connection_number - 1;
            let conn = &mut self.client[index];
            if conn.dest == *dest {
                return Ok(conn);
            }
        }
        Err(NetWareError::ConnectionNotLoggedIn)
    }

    pub fn get_connection_by_number(&mut self, connection_number: u32) -> Result<&mut Connection<'a>, NetWareError> {
        let connection_number = connection_number as usize;
        if (1..consts::MAX_CONNECTIONS).contains(&connection_number) {
            let index = connection_number - 1;
            return Ok(&mut self.client[index]);
        }
        Err(NetWareError::BadStationNumber)
    }

/*
    pub fn disconnect(&mut self, dest: &IpxAddr, header: &NcpHeader) -> Result<(), NetWareError> {
        let index = self.get_connection_index(dest, header)?;
        let conn = &mut self.client[index];
        *conn = Connection::zero();
        Ok(())
    }
*/

}

