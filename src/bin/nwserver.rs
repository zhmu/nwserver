/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
extern crate nwserver;

use log::*;
use pretty_env_logger;

use nwserver::ipx;
use nwserver::rip;
use nwserver::sap;
use nwserver::ncp_service;
use nwserver::consts;
use nwserver::config;

use signal_hook;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::{Error, ErrorKind};
use nix::unistd::{User, Group};

struct NWServer<'a> {
    config: &'a config::Configuration,
    _tx: &'a ipx::Transmitter,
    rip: rip::RipService<'a>,
    sap: sap::SapService<'a>,
    ncp: ncp_service::NcpService<'a>,
}

impl<'a> NWServer<'a> {
    pub fn new(config: &'a config::Configuration, tx: &'a ipx::Transmitter) -> Self {
        let sap = sap::SapService::new(&config, &tx);
        let rip = rip::RipService::new(&config, &tx);
        let ncp = ncp_service::NcpService::new(&config, &tx);
        NWServer{ config: &config, _tx: tx, sap, rip, ncp }
    }

    fn must_process_packet(&self, ipx: &ipx::IpxPacket) -> bool {
        let dest_addr = ipx.get_dest();

        // Process anything sent to our server address
        let server_addr = self.config.get_server_address();
        if dest_addr.network() == server_addr.network() && dest_addr.host() == server_addr.host() { return true; }


        // Process anything send to our MAC address
        let net_addr = self.config.get_network_address();
        if dest_addr.host() == net_addr.host() { return true; }

        // Must always process broadcasts
        dest_addr.host().is_broadcast()
    }

    fn process_packet(&mut self, ipx: &ipx::IpxPacket) {
        if !self.must_process_packet(ipx) {
            println!("not for me src {:?} {:?}", ipx.get_dest(), self.config.get_server_address());
            return;
        }

        match ipx.get_dest().socket() {
            consts::IPX_SOCKET_SAP => {
                if let Err(e) = self.sap.process_packet(&ipx) {
                    error!("unable to parse sap packet {:?}", e);
                }
            },
            consts::IPX_SOCKET_RIP => {
                if let Err(e) = self.rip.process_packet(&ipx) {
                    error!("unable to parse rip packet {:?}", e);
                }
            },
            consts::IPX_SOCKET_NCP => {
                if let Err(e) = self.ncp.process_packet(&ipx) {
                    error!("unable to parse ncp packet {:?}", e);
                }
            },
            _ => { }
        }
    }
}

fn change_credentials(unix: &config::TomlUnix) -> Result<(), std::io::Error> {
    if let Some(groupname) = &unix.group {
        let group = Group::from_name(&groupname)?;
        if let Some(group) = group {
            let gid = group.gid;
            nix::unistd::setresgid(gid, gid, gid).map_err(|e| Error::new(ErrorKind::Other, format!("cannot change gid: {}", e)))?;
        } else {
            return Err(Error::new(ErrorKind::Other, format!("group '{}' not found", groupname)));
        }
    }

    if let Some(username) = &unix.user {
        let user = User::from_name(&username)?;
        if let Some(user) = user {
            let uid = user.uid;
            nix::unistd::setresuid(uid, uid, uid).map_err(|e| Error::new(ErrorKind::Other, format!("cannot change uid: {}", e)))?;
        } else {
            return Err(Error::new(ErrorKind::Other, format!("user '{}' not found", username)));
        }
    }

    Ok(())
}

fn main() -> Result<(), std::io::Error> {
    pretty_env_logger::init();

    let config_toml = std::fs::read_to_string("config.toml")?;
    let config = config::Configuration::new(&config_toml);
    if let Err(err) = config {
        println!("error parsing configuration: {:?}", err);
        std::process::exit(1);
    }
    let mut config = config.unwrap();

    let interface = config.get_network_interface();
    let endpoint = ipx::create_endpoint(interface);
    if let Err(e) = &endpoint {
        println!("Unable to create IPX endpoint: {}", e);
        println!();
        println!("Listing all available network interfaces:");
        for i in ipx::get_network_interfaces() {
            println!("{} {}", i.name, i.descr);
        }
        return Ok(())
    }
    let (mut receiver, transmitter) = endpoint.unwrap();

    if let Some(unix) = config.get_unix() {
        change_credentials(unix)?;
    }

    info!("Using interface {} mac {}", interface, transmitter.get_mac_address());

    config.set_mac_address(&transmitter.get_mac_address());

    let mut server = NWServer::new(&config, &transmitter);
    server.sap.advertise();

    let terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&terminate))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&terminate))?;
    while !terminate.load(Ordering::Relaxed) {
        if let Some(packet) = receiver.next() {
            server.process_packet(&packet);
        }
    }

    info!("Terminating");
    Ok(())
}
