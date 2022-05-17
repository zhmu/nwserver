pub const IPX_SOCKET_NCP: u16 = 0x451;
pub const IPX_SOCKET_SAP: u16 = 0x452;
pub const IPX_SOCKET_RIP: u16 = 0x453;

pub const MAX_CONNECTIONS: usize = 10;
pub const MAX_VOLUMES: usize = 64;
pub const VOLUME_NAME_LENGTH : usize = 16;

pub const SERVER_NAME_LENGTH: usize = 48;

// Limits per connection
pub const MAX_SEARCH_HANDLES: usize = 16;
pub const MAX_DIR_HANDLES: usize = 32;
pub const MAX_OPEN_FILES: usize = 16;
