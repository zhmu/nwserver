extern crate nwserver;

use log::*;
use pretty_env_logger;

use nwserver::ipx;
use nwserver::rip;
use nwserver::sap;
use nwserver::ncp_service;
use nwserver::consts;
use nwserver::config;

struct NWServer<'a> {
    _config: &'a config::Configuration,
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
        NWServer{ _config: &config, _tx: tx, sap, rip, ncp }
    }

    fn process_packet(&mut self, ipx: &ipx::IpxPacket) {
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
    info!("Using interface {} mac {}", interface, transmitter.get_mac_address());

    config.set_mac_address(&transmitter.get_mac_address());

    let mut server = NWServer::new(&config, &transmitter);
    server.sap.advertise();

    loop {
        if let Some(packet) = receiver.next() {
            server.process_packet(&packet);
        }
    }
    //Ok(())
}
