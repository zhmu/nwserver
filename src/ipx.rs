use pnet::packet::ethernet::EtherTypes;
use pnet_macros::packet;
use pnet_macros_support::types::*;

use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use std::convert::TryInto;
use std::cell::RefCell;
use pnet::util::MacAddr;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::datalink;

use log::*;
use crate::types::IpxAddr;

const ETHERNET_HEADER_LENGTH: usize = 14;
const IPX_HEADER_LENGTH: usize = 30;

// https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange
#[packet]
pub struct Ipx {
    pub checksum: u16be, // always 0xffff
    pub total_length: u16be, // including header
    pub transport_control: u8, // hop count
    pub packet_type: u8,
    #[construct_with(u32, u8, u8, u8, u8, u8, u8, u16)]
    pub dest: IpxAddr,
    #[construct_with(u32, u8, u8, u8, u8, u8, u8, u16)]
    pub source: IpxAddr,
    #[length_fn = "ipx_payload_length"]
    #[payload]
    payload: Vec<u8>,
}

fn ipx_payload_length(ipx: &IpxPacket) -> usize {
    (ipx.get_total_length() as usize).saturating_sub(IPX_HEADER_LENGTH)
}

pub struct Receiver {
    rx: Box<dyn DataLinkReceiver>,
    payload: Vec<u8>,
}

impl Receiver {
    pub fn next(&mut self) -> Option<IpxPacket> {
        loop {
            match self.rx.next() {
                Ok(packet) => {
                    let ethernet_packet = EthernetPacket::new(packet);
                    if let Some(packet) = ethernet_packet {
                        if packet.get_ethertype() == EtherTypes::Ipx {
                            let payload = packet.payload();
                            self.payload[0..payload.len()].copy_from_slice(payload);
                            return IpxPacket::new(&self.payload);
                        }
                    }
                },
                Err(err) => {
                    panic!("cannot read IPX endpoint: {}", err);
                }
            }
        }
    }
}

pub struct Transmitter {
    tx: RefCell<Box<dyn DataLinkSender>>,
    mac: MacAddr,
}

impl Transmitter {
    pub fn get_mac_address(&self) -> MacAddr {
        self.mac
    }

    pub fn send(&self, source: &IpxAddr, dest: &IpxAddr, payload: &[u8]) {
        let mut buffer = vec![ 0u8; ETHERNET_HEADER_LENGTH + IPX_HEADER_LENGTH + payload.len() ];
        {
            let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer[0..]).unwrap();
            ethernet_packet.set_destination(dest.host());
            ethernet_packet.set_source(source.host());
            ethernet_packet.set_ethertype(EtherTypes::Ipx);
        }

        {
            let mut ipx_packet = MutableIpxPacket::new(&mut buffer[ETHERNET_HEADER_LENGTH..]).unwrap();
            ipx_packet.set_checksum(0xffff);
            ipx_packet.set_total_length((IPX_HEADER_LENGTH + payload.len()).try_into().unwrap());
            ipx_packet.set_transport_control(0);
            ipx_packet.set_packet_type(0);
            ipx_packet.set_dest(*dest);
            ipx_packet.set_source(*source);
            ipx_packet.set_payload(payload);
        }

        match self.tx.borrow_mut().send_to(&buffer, None) {
            Some(v) => {
                match v {
                    Err(e) => { error!("unable to send IPX packet: {}", e) },
                    Ok(_) => { },
                }
            },
            None => { error!("unable to send IPX packet") },
        }
    }
}

pub struct Interface {
    pub name: String,
    pub descr: String,
}

pub fn get_network_interfaces() -> Vec<Interface> {
    let mut result: Vec<Interface> = Vec::new();
    for i in datalink::interfaces() {
        result.push(Interface{ name: i.name, descr: i.description });
    }
    result
}

pub fn create_endpoint(interface: &str) -> Result<(Receiver, Transmitter), std::io::Error> {
    // On UNIX, interface names are the norm. Yet on Windows, it is easier to
    // match a description. We attempt both here.
    let interface_name_match = |iface: &NetworkInterface| iface.name == interface || iface.description == interface;

    let net_interface = datalink::interfaces().into_iter().filter(interface_name_match).next();
    if net_interface.is_none() {
        let err_string = format!("network interface '{}' not found", interface);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, err_string));
    }
    let net_interface = net_interface.unwrap();
    let mac = net_interface.mac.unwrap();

    let config = datalink::Config{ ..Default::default() };
    let (tx, rx) = match datalink::channel(&net_interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => { return Err(e); }
    };
    let transmitter = Transmitter{ tx: RefCell::new(tx), mac };
    let receiver = Receiver{ rx, payload: vec![ 0u8; config.read_buffer_size ] };
    Ok((receiver, transmitter))
}
