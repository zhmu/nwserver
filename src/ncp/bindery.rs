use crate::connection;
use crate::error::*;
use super::parser;
use crate::ncp_service::NcpReplyPacket;

pub fn process_request_23_61_read_property_value(_conn: &mut connection::Connection, _args: &parser::ReadPropertyValue, _reply: &mut NcpReplyPacket) -> Result<(), NetWareError> {
    Err(NetWareError::NoSuchSet)
}

