use crate::types::IpxAddr;
use crate::consts;

use pnet::util::MacAddr;

pub struct Configuration {
    // The unique server address, i.e. <internal_ipx_network>.000000000001
    server_address: IpxAddr,
    // The address of the server on the network, i.e. <ipx network>.<mac addr>
    network_address: IpxAddr,
    server_name: [ u8; consts::SERVER_NAME_LENGTH ],
}

impl Configuration {
    pub fn new() -> Self {
        let ipx_network = 0x1234;
        let internal_ipx_net = 0xdeadf00d;
        let server_address = IpxAddr::new(internal_ipx_net, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0);
        let network_address = IpxAddr::new(ipx_network, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0);
        let mut server_name = [ 0u8; consts::SERVER_NAME_LENGTH ];
        let server_name_string = "BUCKET";
        for (n, v) in server_name_string.as_bytes().iter().enumerate() {
            server_name[n] = *v;
        }
        Self{ server_address, network_address, server_name }
    }

    pub fn set_mac_address(&mut self, mac: &MacAddr) {
        self.network_address.set_host(mac);
    }

    pub fn get_server_name(&self) -> &[u8] {
        &self.server_name
    }

    pub fn get_server_address(&self) -> IpxAddr {
        self.server_address
    }

    pub fn get_network_address(&self) -> IpxAddr {
        self.network_address
    }

    pub fn get_sys_volume_path(&self) -> String {
        "/nfs/rink/nwserver/sys".to_string()
    }
}
