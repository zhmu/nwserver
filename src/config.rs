/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::types::*;
use crate::consts;
use serde::Deserialize;
use toml::Value;

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

#[derive(Debug)]
pub struct User {
    pub name: String,
    pub initial_password: String,
}

pub struct Configuration {
    network_interface: String,
    // The unique server address, i.e. <internal_ipx_network>.000000000001
    server_address: IpxAddr,
    // The address of the server on the network, i.e. <ipx network>.<mac addr>
    network_address: IpxAddr,
    server_name: BoundedString<{ consts::SERVER_NAME_LENGTH }>,
    volumes: Vec<Volume>,
    users: Vec<User>,
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

fn parse_volumes(config: &toml::Value) -> Result<Vec<Volume>, ConfigError> {
    return if let Value::Table(t) = &config["volumes"] {
        let mut volumes: Vec<Volume> = Vec::new();
        for (name, value) in t {
            let name = verify_and_convert_string(&name)?;
            if let Value::Table(t) = value {
                if let Some(path) = t["path"].as_str() {
                    let number = volumes.len() as u8;
                    volumes.push(Volume{ number, name, path: path.to_string() })
                }
            } else {
                return Err(ConfigError::NoVolumeConfiguration)
            }
        }
        if volumes.len() >= consts::MAX_VOLUMES {
            return Err(ConfigError::TooManyVolumes)
        }
        Ok(volumes)
    } else {
        Err(ConfigError::NoVolumeConfiguration)
    }
}

fn parse_users(config: &toml::Value) -> Result<Vec<User>, ConfigError> {
    let mut users: Vec<User> = Vec::new();
    if let Value::Table(t) = &config["users"] {
        for (name, value) in t {
            let name = name.to_uppercase();
            let mut initial_password = "";
            if let Value::Table(t) = value {
                if let Some(password) = t.get("initial_password") {
                    if let Some(password) = password.as_str() {
                        initial_password = password;
                    }
                }
            }
            users.push(User{ name, initial_password: initial_password.to_string() });
        }
    }
    Ok(users)
}

impl Configuration {
    pub fn new(content: &str) -> Result<Self, ConfigError> {
        let config: TomlConfig = toml::from_str(&content)?;

        let network_interface = config.network.interface;
        let server_address = IpxAddr::new(config.network.internal_ipx_network, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0);
        let network_address = IpxAddr::new(config.network.ipx_network, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0);
        let server_name = verify_and_convert_string(&config.server_name)?;

        let config: Value = toml::from_str(&content)?;
        let volumes = parse_volumes(&config)?;
        let users = parse_users(&config)?;
        Ok(Self{ server_address, network_interface, network_address, server_name, volumes, users })
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
        &self.network_interface
    }

    pub fn get_volumes(&self) -> &Vec<Volume> {
        &self.volumes
    }

    pub fn get_users(&self) -> &Vec<User> {
        &self.users
    }
}
