use crate::connection;
use crate::consts;
use super::parser;
use crate::error::*;
use crate::types::*;
use crate::ncp_service::NcpReplyPacket;

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
