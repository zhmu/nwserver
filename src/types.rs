/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use crate::error::NetWareError;
use crate::consts;
use pnet::util::MacAddr;
use std::fmt;
use rand::Rng;

use std::convert::TryInto;
use std::io::Read;
use byteorder::{ByteOrder, ReadBytesExt, BigEndian};
use pnet::packet::PrimitiveValues;

pub type LeU32 = u32;

#[derive(PartialEq, Eq, Clone, Copy, Default, Hash, Ord, PartialOrd)]
pub struct IpxAddr(pub u32, pub MacAddr, pub u16);

impl IpxAddr {
    pub fn new(a: u32, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u16) -> Self {
        Self(a, MacAddr(b, c, d, e, f, g), h)
    }

    pub const fn zero() -> Self {
        Self(0, MacAddr(0, 0, 0, 0, 0, 0), 0)
    }

    pub fn network(&self) -> u32 {
        self.0
    }

    pub fn host(&self) -> MacAddr {
        self.1
    }

    pub fn socket(&self) -> u16 {
        self.2
    }

    pub fn set_network(&mut self, network: u32) {
        self.0 = network;
    }

    pub fn set_host(&mut self, host: &MacAddr) {
        self.1 = *host;
    }

    pub fn set_socket(&mut self, socket: u16) {
        self.2 = socket;
    }

    pub fn is_zero(&self) -> bool {
        self.0 == 0 && self.1 == MacAddr::zero() && self.2 == 0
    }

    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Option<Self> {
        let net = rdr.read_u32::<BigEndian>().ok()?;
        let mut mac = [ 0u8; 6 ];
        rdr.read_exact(&mut mac).ok()?;
        let socket = rdr.read_u16::<BigEndian>().ok()?;
        Some(Self(net, MacAddr::from(mac), socket))
    }

    pub fn to(&self, buffer: &mut [u8]) {
        BigEndian::write_u32(&mut buffer[0..], self.network());
        buffer[4..10].copy_from_slice(&self.host().octets());
        BigEndian::write_u16(&mut buffer[10..], self.socket());
    }
}

impl fmt::Display for IpxAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{:04x}.{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.{:02}",
            self.0, self.1.0, self.1.1, self.1.2, self.1.3, self.1.4, self.1.5, self.2)
    }
}

impl fmt::Debug for IpxAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl PrimitiveValues for IpxAddr {
    type T = (u32, u8, u8, u8, u8, u8, u8, u16);
    fn to_primitive_values(&self) -> (u32, u8, u8, u8, u8, u8, u8, u16) {
        (self.0, self.1.0, self.1.1, self.1.2, self.1.3, self.1.4, self.1.5, self.2)
    }
}

pub trait DataStreamer {
    fn add_u8(&mut self, value: u8);
    fn add_u16(&mut self, value: u16);
    fn add_u32(&mut self, value: u32);
    fn add_data(&mut self, code: &[u8]);
    fn fill_u8(&mut self, amount: usize, value: u8);
}

#[derive(Copy,Clone,Debug)]
pub struct BoundedString<const MAX_SIZE: usize> {
    data: [ u8; MAX_SIZE ],
    length: usize,
}

impl<const MAX_SIZE: usize> BoundedString<MAX_SIZE> {
    pub const fn empty() -> Self {
        let data = [ 0u8; MAX_SIZE ];
        Self{ data, length: 0 }
    }

    pub fn buffer(&self) -> &[u8] {
        &self.data
    }

    pub fn data(&self) -> &[u8] {
        &self.data[0..self.length]
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data[0..self.length]).unwrap()
    }

    pub fn from_str(string: &str) -> Self {
        assert!(string.len() <= MAX_SIZE);
        let mut s = Self::empty();
        s.length = string.len();
        s.data[0..s.length].copy_from_slice(string.as_bytes());
        s
    }

    pub fn from_slice(data: &[u8]) -> Self {
        assert!(data.len() < MAX_SIZE);
        let mut s = Self::empty();
        s.length = data.len();
        s.data[0..s.length].copy_from_slice(data);
        s
    }

    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let length: usize = rdr.read_u8()?.into();
        if length >= MAX_SIZE { return Err(NetWareError::StringTooLong) }
        let mut data = [ 0u8; MAX_SIZE ];
        let length = rdr.read(&mut data[0..length])?;
        Ok(Self{ data, length })
    }

    pub fn to<T: DataStreamer>(&self, out: &mut T) -> Option<()> {
        let length: u8 = self.length.try_into().ok()?;
        out.add_u8(length);
        out.add_data(&self.data[0..self.length]);
        Some(())
    }

    pub fn to_raw<T: DataStreamer>(&self, out: &mut T) -> Option<()> {
        out.add_data(&self.data);
        Some(())
    }

    pub fn append_str(&mut self, s: &str) {
        let new_length = self.length + s.len();
        assert!(new_length < MAX_SIZE);
        self.data[self.length..new_length].copy_from_slice(s.as_bytes());
        self.length = new_length;

    }

    pub fn append(&mut self, s: &BoundedString<MAX_SIZE>) {
        let new_length = self.length + s.length;
        assert!(new_length < MAX_SIZE);
        self.data[self.length..new_length].copy_from_slice(&s.data[0..s.length]);
        self.length = new_length;

    }

    pub fn equals<const OTHER_SIZE: usize>(&self, other: BoundedString<OTHER_SIZE>) -> bool {
        if self.length == other.length {
            self.data[0..self.length] == other.data[0..self.length]
        } else {
            false
        }
    }
}
    
impl<const MAX_SIZE: usize> fmt::Display for BoundedString<MAX_SIZE> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let data = &self.data[0..self.length];
        let s = std::str::from_utf8(data);
        if let Ok(s) = s {
            fmt.write_str(s)
        } else {
            write!(fmt, "{:?}", data)
        }
    }
}

pub type MaxBoundedString = BoundedString<256>;

// https://en.wikipedia.org/wiki/8.3_filename
fn is_valid_dos_char(ch: u8) -> bool {
    let ch = ch as char;
    matches!(ch,
        'A'..='Z' |
        '0'..='9' |
        '!' | '#' | '$' | '%' | '&' | '\'' | '(' | ')' | '-' | '@' | '^' | '_' | '`' | '{' | '}' | '~')
}

#[derive(Copy,Clone)]
pub struct DosFileName {
    data: [ u8; 12 ],
}

// Stores a DOS-style 8.3 filename
impl DosFileName {
    pub fn empty() -> Self {
        let data = [ 0u8; 12 ];
        Self{ data }
    }

    pub fn from_str(f: &str) -> Option<Self> {
        let mut data = [ 0u8; 12 ];
        let mut n: usize = 0;
        let mut got_dot = false;
        let mut chars_left: i32 = 8;
        for ch in f.bytes() {
            if ch == b'.' {
                // Dot is special, we accept only one
                if got_dot { return None; }
                got_dot = true;

                // Must have a filename before the dot
                if n == 0 { return None; }

                data[n] = ch;
                n += 1;

                chars_left = 3;
                continue;
            } else if !is_valid_dos_char(ch) {
                return None;
            }

            data[n] = ch;
            n += 1;

            chars_left -= 1;
            if chars_left < 0 { return None; }

        }

        // If we end on a dot, get rid of it
        if n > 0 && data[n - 1] == b'.' {
            data[n - 1] = 0;
        }
        Some(Self{ data })
    }

    pub fn to<T: DataStreamer>(&self, out: &mut T) {
        out.add_data(&self.data);
        out.add_u16(0);

    }

    pub fn matches(&self, pattern: &[u8]) -> bool {
        let mut m: usize = 0;
        for (n, ch) in pattern.iter().enumerate() {
            let ch = *ch;
            match ch {
                0xbf | 0x3f => {
                    // single char wildcard
                    if self.data[m] == 0 || self.data[m] == b'.' {
                        return false
                    }
                    m += 1;
                },
                0xaa | 0x2a => {
                    // asterisk
                    let stop_at = if n + 1 < pattern.len() {
                        pattern[n + 1]
                    } else {
                        0
                    };
                    while m < self.data.len() && self.data[m] != 0 && self.data[m] != b'.' {
                        if stop_at != 0 && self.data[m] == stop_at { break; }
                        m += 1;
                    }
                },
                0xae | 0x2e => {
                    // dot
                    if self.data[m] != b'.' {
                        if self.data[m] == 0 {
                            // We have matched the part before the dot, but
                            // there is no extension. FOO.?? and FOO.* are
                            // supposed to match FOO as well - see if there
                            // are only wildcards left, as this is supposed
                            // to match
                            let mut n = n + 1;
                            while n < pattern.len() {
                                match pattern[n] {
                                    0xbf | 0x3f | 0xaa | 0x2a => { },
                                    _ => { return false; }
                                }
                                n += 1;
                            }
                            return true;
                        }
                        return false
                    }
                    m += 1;
                },
                0 => {
                    // Never match zeroes
                    return false
                },
                _ => {
                    if self.data[m] != ch {
                        return false
                    }
                    m += 1;
                }
            }
        }
        m == self.data.len() || self.data[m] == 0
    }
}

impl fmt::Display for DosFileName {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut s = String::new();
        let mut n: usize = 0;
        while n < self.data.len() && self.data[n] != 0 {
            s.push(self.data[n] as char);
            n += 1;
        }
        fmt.write_str(&s)
    }
}

impl fmt::Debug for DosFileName {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

pub struct NcpFileHandle(pub u16);

impl NcpFileHandle {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn new(handle: usize) -> Self {
        Self(handle as u16)
    }

    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let a = rdr.read_u16::<BigEndian>()?;
        let b = rdr.read_u32::<BigEndian>()?;
        if b != 0 { return Err(NetWareError::InvalidFileHandle) }
        Ok(Self(a))
    }

    pub fn to<T: DataStreamer>(&self, out: &mut T) -> Option<()> {
        out.add_u16(self.0);
        out.add_u32(0);
        Some(())
    }

    pub fn get_value(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for NcpFileHandle {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!( fmt, "{}", self.0)
    }
}

impl fmt::Debug for NcpFileHandle {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

pub struct LoginKey(pub [ u8; 8 ]);

impl LoginKey {
    pub const fn empty() -> Self {
        Self([ 0u8; 8 ])
    }

    pub fn data(&self) -> &[u8; 8] {
        &self.0
    }

    pub fn generate() -> Self {
        let mut values = [ 0u8; 8 ];

        let mut rng = rand::thread_rng();
        for n in &mut values {
            *n = rng.gen::<u8>();
        }
        Self(values)
    }

    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let mut result = LoginKey::empty();
        rdr.read_exact(&mut result.0)?;
        Ok(result)
    }

    pub fn to<T: DataStreamer>(&self, out: &mut T) -> Option<()> {
        out.add_data(&self.0);
        Some(())
    }
}

impl fmt::Display for LoginKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!( fmt, "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3],
            self.0[4], self.0[5], self.0[6], self.0[7],
        )
    }
}

impl fmt::Debug for LoginKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

pub struct PropertyValue(pub [ u8; consts::PROPERTY_SEGMENT_LENGTH ]);

impl PropertyValue {
    pub const fn empty() -> Self {
        Self([ 0u8; consts::PROPERTY_SEGMENT_LENGTH ])
    }

    pub fn data(&self) -> &[u8; consts::PROPERTY_SEGMENT_LENGTH ] {
        &self.0
    }

    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let mut result = PropertyValue::empty();
        rdr.read_exact(&mut result.0)?;
        Ok(result)
    }

    pub fn to<T: DataStreamer>(&self, out: &mut T) -> Option<()> {
        out.add_data(&self.0);
        Some(())
    }
}

impl fmt::Display for PropertyValue {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "...")
    }
}

impl fmt::Debug for PropertyValue {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

#[derive(Copy,Clone,Debug)]
pub struct MaxBoundedBuffer {
    data: [ u8; 65535 ],
    length: usize,
}

impl MaxBoundedBuffer {
    pub const fn empty() -> Self {
        let data = [ 0u8; 65535 ];
        Self{ data, length: 0 }
    }

    pub fn data(&self) -> &[u8] {
        &self.data[0..self.length]
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {
        let mut buf = Self::empty();
        buf.length = rdr.read_u16::<BigEndian>()?.into();
        rdr.read_exact(&mut buf.data[0..buf.length])?;
        Ok(buf)
    }

}

impl fmt::Display for MaxBoundedBuffer {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let data = &self.data[0..self.length];
        write!(fmt, "{:?}", data)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::DosFileName;

    #[test]
    fn dosfilename_from_should_fail() {
        assert!(DosFileName::from_str("a").is_none());
        assert!(DosFileName::from_str("a.b").is_none());
        assert!(DosFileName::from_str("a.abcd").is_none());
        assert!(DosFileName::from_str(".abc").is_none());
        assert!(DosFileName::from_str("123456789").is_none());
        assert!(DosFileName::from_str(".").is_none());
        assert!(DosFileName::from_str(".a").is_none());
        assert!(DosFileName::from_str("..").is_none());
        assert!(DosFileName::from_str("a..").is_none());
        assert!(DosFileName::from_str("a..b").is_none());
    }

    #[test]
    fn dosfilename_from_should_succeed() {
        assert_eq!(&DosFileName::from_str("A").unwrap().data, &[ 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]);
        assert_eq!(&DosFileName::from_str("HELLO").unwrap().data, &[ 72, 69, 76, 76, 79, 0, 0, 0, 0, 0, 0, 0 ]);
        assert_eq!(&DosFileName::from_str("A.B").unwrap().data, &[ 65, 46, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]);
        assert_eq!(&DosFileName::from_str("A.").unwrap().data, &[ 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]);
        assert_eq!(&DosFileName::from_str("12345678").unwrap().data, &[ 49, 50, 51, 52, 53, 54, 55, 56, 0, 0, 0, 0 ]);
        assert_eq!(&DosFileName::from_str("12345678.").unwrap().data, &[ 49, 50, 51, 52, 53, 54, 55, 56, 0, 0, 0, 0 ]);
        assert_eq!(&DosFileName::from_str("12345678.ABC").unwrap().data, &[ 49, 50, 51, 52, 53, 54, 55, 56, 46, 65, 66, 67 ]);
    }

    #[test]
    fn dosfilename_matches_should_match() {
        let filename = DosFileName::from_str("12345678.ABC").unwrap();
        assert!(filename.matches(b"12345678.ABC"));
        assert!(filename.matches(b"????????.ABC"));
        assert!(filename.matches(b"?2345678.ABC"));
        assert!(filename.matches(b"*.ABC"));
        assert!(filename.matches(b"1*.ABC"));
        assert!(filename.matches(b"*.*"));
        assert!(filename.matches(b"1*8.ABC"));
        assert!(filename.matches(b"1?3*78.ABC"));
        assert!(filename.matches(b"1?3*78.A??"));
        let filename = DosFileName::from_str("123").unwrap();
        assert!(filename.matches(b"*"));
        assert!(filename.matches(b"???"));
        assert!(filename.matches(b"1??"));
        assert!(filename.matches(b"12?"));
        assert!(filename.matches(b"?23"));
        assert!(filename.matches(b"???.???"));
    }

    #[test]
    fn dosfilename_matches_should_not_match() {
        let filename = DosFileName::from_str("12345678.ABC").unwrap();
        assert!(!filename.matches(b"1234567.ABC"));
        assert!(!filename.matches(b"12345678?ABC"));
        assert!(!filename.matches(b"12345678"));
        assert!(!filename.matches(b"12345678."));
        assert!(!filename.matches(b"12345678.A"));
        assert!(!filename.matches(b"12345678.AB"));
        assert!(!filename.matches(b"1?3*78.A?"));
    }
}
