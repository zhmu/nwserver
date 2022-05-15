use crate::types::IpxAddr;
use crate::consts;
use serde::Deserialize;

use pnet::util::MacAddr;

#[derive(Debug)]
pub enum ConfigError {
    IoError(std::io::Error),
    TomlError(toml::de::Error),
    ServerNameTooLong,
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::TomlError(e)
    }
}

pub struct Configuration {
    network_interface: String,
    // The unique server address, i.e. <internal_ipx_network>.000000000001
    server_address: IpxAddr,
    // The address of the server on the network, i.e. <ipx network>.<mac addr>
    network_address: IpxAddr,
    server_name: [ u8; consts::SERVER_NAME_LENGTH ],
}

#[derive(Deserialize)]
struct TomlConfig {
    server_name: String,
    network: TomlNetwork,
}

#[derive(Deserialize)]
struct TomlNetwork {
    ipx_network: u32,
    internal_ipx_network: u32,
    interface: String,
}

impl Configuration {
    pub fn new(content: &str) -> Result<Self, ConfigError> {
        let config: TomlConfig = toml::from_str(&content)?;

        let network_interface = config.network.interface;
        let server_address = IpxAddr::new(config.network.internal_ipx_network, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0);
        let network_address = IpxAddr::new(config.network.ipx_network, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0);
        let mut server_name = [ 0u8; consts::SERVER_NAME_LENGTH ];
        let server_name_string = config.server_name;
        if server_name_string.len() >= server_name.len() {
            return Err(ConfigError::ServerNameTooLong);
        }
        for (n, v) in server_name_string.as_bytes().iter().enumerate() {
            server_name[n] = *v;
        }
        Ok(Self{ server_address, network_interface, network_address, server_name })
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

    pub fn get_network_interface(&self) -> &str {
        &self.network_interface
    }

    pub fn get_sys_volume_path(&self) -> String {
        "/nfs/rink/nwserver/sys".to_string()
    }
}
