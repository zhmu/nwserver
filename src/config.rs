/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::types::*;
use crate::consts;
use serde::Deserialize;
use std::collections::BTreeMap;

use pnet::util::MacAddr;

#[derive(Debug)]
pub enum ConfigError {
    IoError(std::io::Error),
    TomlError(toml::de::Error),
    StringTooLong(String),
    InvalidCharacter(char),
    NoVolumeConfiguration,
    TooManyVolumes,
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

pub struct Volume {
    pub number: u8,
    pub name: BoundedString< { consts::VOLUME_NAME_LENGTH }>,
    pub path: String,
}

pub struct Configuration {
    toml: TomlConfig,
    // The unique server address, i.e. <internal_ipx_network>.000000000001
    server_address: IpxAddr,
    // The address of the server on the network, i.e. <ipx network>.<mac addr>
    network_address: IpxAddr,
    server_name: BoundedString<{ consts::SERVER_NAME_LENGTH }>,
    volumes: Vec<Volume>,
}

#[derive(Deserialize)]
struct TomlConfig {
    server_name: String,
    network: TomlNetwork,
    users: BTreeMap<String, TomlUser>,
    groups: BTreeMap<String, TomlGroup>,
    volumes: BTreeMap<String, TomlVolume>,
}

#[derive(Deserialize)]
struct TomlNetwork {
    ipx_network: u32,
    internal_ipx_network: u32,
    interface: String,
}

#[derive(Deserialize)]
pub struct TomlUser {
    pub initial_password: Option<String>,
}

#[derive(Deserialize)]
pub struct TomlGroup {
    pub members: Vec<String>,
}

#[derive(Deserialize)]
pub struct TomlVolume {
    pub path: String,
}

fn verify_and_convert_string<const MAX_LENGTH: usize>(input: &str) -> Result<BoundedString<{ MAX_LENGTH }>, ConfigError> {
    if input.len() >= MAX_LENGTH {
        return Err(ConfigError::StringTooLong(input.to_string()))
    }

    let input_uc = input.to_string().to_uppercase();
    for ch in input_uc.chars() {
        match ch {
            'A'..='Z' | '_' => { },
            _ => {
                return Err(ConfigError::InvalidCharacter(ch));
            }
        }
    }
    Ok(BoundedString::from_str(input_uc.as_str()))
}

fn process_volumes(config: &TomlConfig) -> Result<Vec<Volume>, ConfigError> {
    let mut volumes: Vec<Volume> = Vec::new();
    for (name, value) in &config.volumes {
        let name = verify_and_convert_string(&name)?;
        let number = volumes.len() as u8;
        volumes.push(Volume{ number, name, path: value.path.to_string() })
    }
    if volumes.is_empty() {
        return Err(ConfigError::NoVolumeConfiguration)
    }
    if volumes.len() >= consts::MAX_VOLUMES {
        return Err(ConfigError::TooManyVolumes)
    }
    Ok(volumes)
}

impl Configuration {
    pub fn new(content: &str) -> Result<Self, ConfigError> {
        let toml: TomlConfig = toml::from_str(&content)?;

        let server_address = IpxAddr::new(toml.network.internal_ipx_network, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0);
        let network_address = IpxAddr::new(toml.network.ipx_network, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0);
        let server_name = verify_and_convert_string(&toml.server_name)?;

        let volumes = process_volumes(&toml)?;
        Ok(Self{ toml, server_address, network_address, server_name, volumes })
    }

    pub fn set_mac_address(&mut self, mac: &MacAddr) {
        self.network_address.set_host(mac);
    }

    pub fn get_server_name(&self) -> &BoundedString<{ consts::SERVER_NAME_LENGTH }> {
        &self.server_name
    }

    pub fn get_server_address(&self) -> IpxAddr {
        self.server_address
    }

    pub fn get_network_address(&self) -> IpxAddr {
        self.network_address
    }

    pub fn get_network_interface(&self) -> &str {
        &self.toml.network.interface
    }

    pub fn get_volumes(&self) -> &Vec<Volume> {
        &self.volumes
    }

    pub fn get_users(&self) -> &BTreeMap<String, TomlUser> {
        &self.toml.users
    }

    pub fn get_groups(&self) -> &BTreeMap<String, TomlGroup> {
        &self.toml.groups
    }
}
