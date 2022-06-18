/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use std::io::Cursor;
use std::io::Read;
use crate::types::IpxAddr;
use crate::config;
use crate::consts;
use crate::ipx;
use pnet::packet::Packet;

use log::*;

use byteorder::{ByteOrder, ReadBytesExt, BigEndian};

const RIP_OP_REQUEST: u16 = 1; // Request information
const RIP_OP_RESPONSE: u16 = 2; // Provide information

#[derive(Debug)]
pub struct RipEntry {
    dest: u32,
    metric: u16,
    ticks: u16,
}

impl RipEntry {
    fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Option<RipEntry> {
        let dest = rdr.read_u32::<BigEndian>().ok()?;
        let metric = rdr.read_u16::<BigEndian>().ok()?;
        let ticks = rdr.read_u16::<BigEndian>().ok()?;
        Some(RipEntry{ dest, metric, ticks })
    }
}

pub struct RipService<'a> {
    config: &'a config::Configuration,
    tx: &'a ipx::Transmitter,
}

impl<'a> RipService<'a> {
    pub fn new(config: &'a config::Configuration, tx: &'a ipx::Transmitter) -> Self {
        RipService{ config, tx }
    }

    pub fn build_rip_response(&self, dest: u32, buffer: &mut [u8]) {
        BigEndian::write_u16(&mut buffer[0..2], RIP_OP_RESPONSE);
        BigEndian::write_u32(&mut buffer[2..6], dest);
        let metric = 1;
        BigEndian::write_u16(&mut buffer[6..8], metric);
        let ticks = 100;
        BigEndian::write_u16(&mut buffer[8..10], ticks);
    }

    fn send_response(&self, dest_ipx_network: u32, dst: &IpxAddr) {
        let mut buffer = [ 0u8; 10 ];
        self.build_rip_response(dest_ipx_network, &mut buffer[0..]);

        let server_addr = self.config.get_server_address();
        let mut src = server_addr.clone();
        src.set_socket(consts::IPX_SOCKET_RIP);
        // Always fill out the network address so clients known which IPX
        // network they are on
        let mut dst = dst.clone();
        dst.set_network(self.config.get_network_address().network());
        self.tx.send(&src, &dst, &buffer);
    }

    pub fn process_packet(&mut self, packet: &ipx::IpxPacket) -> Result<(), std::io::Error> {
        let data = packet.payload();
        let mut rdr = Cursor::new(&data);
        let operation = rdr.read_u16::<BigEndian>()?;
        match operation {
            RIP_OP_REQUEST => {
                loop {
                    let rip = RipEntry::from(&mut rdr);
                    if rip.is_none() { break; }
                    let rip = rip.unwrap();
                    info!("RIP_OP_REQUEST: {:x?}", rip);

                    let server_ipx_network = self.config.get_server_address().network();
                    if rip.dest == server_ipx_network {
                        self.send_response(server_ipx_network, &packet.get_source());
                    } else {
                        info!("ignoring RIP request for network {:x} which is not my IPX network", rip.dest);
                    }
                }
            },
            _ => {
                warn!("Ignoring unrecognized RIP operation {:x}", operation);
            }
        }
        Ok(())
    }
}
