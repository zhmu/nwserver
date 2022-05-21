use crate::connection::Connection;
use crate::consts;
use crate::types::*;
use crate::error::NetWareError;
use crate::ncp_parser::NcpHeader;

pub struct Clients {
    client: [ Connection; consts::MAX_CONNECTIONS ],
}

impl Clients {
    pub fn new() -> Self {
        const CONN_INIT: Connection = Connection::zero();
        let client = [ CONN_INIT; consts::MAX_CONNECTIONS ];
        Self{ client }
    }

    pub fn count_in_use(&self) -> usize {
        self.client.iter().filter(|&e| e.in_use()).count()
    }

    pub fn allocate_connection(&mut self, dest: &IpxAddr) -> Result<usize, NetWareError> {
        for (n, conn) in self.client.iter_mut().enumerate() {
            if conn.in_use() { continue; }

            *conn = Connection::allocate(dest);
            return Ok(n);
        }
        Err(NetWareError::NoConnectionsAvailable)
    }

    pub fn get_connection_index(&self, dest: &IpxAddr, header: &NcpHeader) -> Result<usize, NetWareError> {
        let connection_number = header.connection_number as usize;
        if connection_number >= 1 && connection_number < consts::MAX_CONNECTIONS {
            let index = connection_number - 1;
            let conn = &self.client[index];
            if conn.dest == *dest {
                return Ok(index);
            }
        }
        Err(NetWareError::ConnectionNotLoggedIn)
    }

    pub fn get_connection(&self, header: &NcpHeader) -> Result<&Connection, NetWareError> {
        self.get_connection_by_number(header.connection_number)
    }

    pub fn get_connection_by_number(&self, nr: u8) -> Result<&Connection, NetWareError> {
        let nr = nr as usize;
        if nr >= 1 && nr < consts::MAX_CONNECTIONS {
            let index = nr - 1;
            return Ok(&self.client[index]);
        }
        Err(NetWareError::ConnectionNotLoggedIn)
    }


    pub fn get_mut_connection(&mut self, header: &NcpHeader) -> &mut Connection {
        let connection_number = header.connection_number as usize;
        if connection_number >= 1 && connection_number < consts::MAX_CONNECTIONS {
            let index = connection_number - 1;
            return &mut self.client[index];
        }
        unreachable!()
    }

    pub fn disconnect(&mut self, dest: &IpxAddr, header: &NcpHeader) -> Result<(), NetWareError> {
        let index = self.get_connection_index(dest, header)?;
        let conn = &mut self.client[index];
        *conn = Connection::zero();
        Ok(())
    }

}

