use std::io::Cursor;
use std::io::Read;
use crate::types::IpxAddr;
use crate::config;
use crate::consts;
use crate::ipx;
use pnet::util::MacAddr;
use pnet::packet::Packet;

use log::*;

use byteorder::{ByteOrder, ReadBytesExt, BigEndian};

const SAP_OP_GSR: u16 = 1; // General Service Request
const SAP_OP_GSP: u16 = 2; // General Service Response
const SAP_OP_NSR: u16 = 3; // Nearest Service Request
const SAP_OP_NSP: u16 = 4; // Nearest Service Response

const SAP_SERVICE_TYPE_FILESERVER: u16 = 4;

#[derive(Debug)]
pub struct SapEntry {
    service_type: u16,
    server_name: [ u8; consts::SERVER_NAME_LENGTH ],
    address: IpxAddr,
    hops: u16,
}

fn parse_sap_record<T: Read + ReadBytesExt>(rdr: &mut T) -> Option<SapEntry> {
    let service_type = rdr.read_u16::<BigEndian>().ok()?;
    let mut server_name = [ 0u8; consts::SERVER_NAME_LENGTH ];
    rdr.read(&mut server_name).ok()?;
    let address = IpxAddr::from(rdr)?;
    let hops = rdr.read_u16::<BigEndian>().ok()?;
    Some(SapEntry { service_type, server_name, address, hops })
}

pub struct SapService<'a> {
    config: &'a config::Configuration,
    tx: &'a ipx::Transmitter,
}

impl<'a> SapService<'a> {
    pub fn new(config: &'a config::Configuration, tx: &'a ipx::Transmitter) -> Self {
        SapService{ config, tx }
    }

    pub fn build_sap_response(&self, buffer: &mut [u8]) {
        BigEndian::write_u16(&mut buffer[0..], SAP_SERVICE_TYPE_FILESERVER);
        buffer[2..2 + consts::SERVER_NAME_LENGTH].copy_from_slice(self.config.get_server_name());
        let mut addr = self.config.get_server_address();
        addr.set_socket(consts::IPX_SOCKET_NCP);
        addr.to(&mut buffer[50..]);
        let hops = 1;
        BigEndian::write_u16(&mut buffer[62..], hops);
    }

    fn send_packet(&self, dest: &IpxAddr, op: u16) {
        let mut buffer = [ 0u8; 66 ];
        BigEndian::write_u16(&mut buffer[0..], op);
        self.build_sap_response(&mut buffer[2..]);

        // Always use the network address to send SAP packets from
        let mut src = self.config.get_network_address().clone();
        src.set_socket(consts::IPX_SOCKET_SAP);
        let mut dst = dest.clone();
        dst.set_network(src.network());
        self.tx.send(&src, &dst, &buffer);
    }

    pub fn advertise(&self) {
        // Send SAP broadcasts to the network address
        let mut dst = self.config.get_network_address().clone();
        dst.set_host(&MacAddr::broadcast());
        dst.set_socket(consts::IPX_SOCKET_SAP);
        self.send_packet(&dst, SAP_OP_GSP);
    }

    pub fn process_packet(&mut self, packet: &ipx::IpxPacket) -> Result<(), std::io::Error> {
        let data = packet.payload();
        let mut rdr = Cursor::new(&data);
        let operation = rdr.read_u16::<BigEndian>()?;
        match operation {
            SAP_OP_GSP | SAP_OP_NSP => {
                info!("SAP_OP_GSP / SAP_OP_NSP");
                loop {
                    let sap = parse_sap_record(&mut rdr);
                    if sap.is_none() { break; }
                    trace!("sap record {:x?}", sap);
                }
            },
            SAP_OP_GSR => {
                info!("SAP_OP_GSR");
                //self.send_packet(&packet.get_source(), SAP_OP_GSP);
            },
            SAP_OP_NSR => {
                info!("SAP_OP_NSR");
                self.send_packet(&packet.get_source(), SAP_OP_NSP);
            },
            _ => {
                warn!("Ignoring unrecognized SAP operation {:x}", operation);
            }
        }
        Ok(())
    }
}
