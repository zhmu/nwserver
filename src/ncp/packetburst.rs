use crate::connection;
use super::parser;
use crate::error::*;
use crate::ncp_service::NcpReplyPacket;

pub fn process_request_101_packet_burst_connection_request(_conn: &mut connection::Connection, _args: &parser::PacketBurstConnectionRequest, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::UnsupportedRequest)
}

