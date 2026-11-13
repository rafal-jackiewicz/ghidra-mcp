// Copyright 2026 Rafał Jackiewicz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Fare rules of the Styx Ferry Company.
//!
//! Reconstructed from the stripped binaries `libobol.so` and `obol.dll` with Ghidra.
//! Every rule below names the place in the original where it was read.

pub mod ffi;

/// Interface version; `obol_abi()` returned the constant 3.
pub const ABI: u16 = 3;

/// The five kinds of soul. The numeric values are the indices into the base-fare table
/// found at `base_fare_by_class` (bytes `02 01 00 05 0d`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SoulClass {
    Mortal = 0,
    Hero = 1,
    Poet = 2,
    King = 3,
    Publican = 4,
}

impl SoulClass {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Mortal),
            1 => Some(Self::Hero),
            2 => Some(Self::Poet),
            3 => Some(Self::King),
            4 => Some(Self::Publican),
            _ => None,
        }
    }

    pub fn base_fare(self) -> u32 {
        match self {
            Self::Mortal => 2,
            Self::Hero => 1,
            Self::Poet => 0,
            Self::King => 5,
            Self::Publican => 13,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Mortal => "mortal",
            Self::Hero => "hero",
            Self::Poet => "poet",
            Self::King => "king",
            Self::Publican => "publican",
        }
    }
}

/// Bits of `Passenger::flags`.
pub mod flag {
    pub const UNBURIED: u8 = 1;
    pub const PRIORITY: u8 = 2;
    pub const RETURN_TICKET: u8 = 4;
}

/// Why a passenger is turned away. The numbers are the original return codes of `obol_fare`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Nobody = 1,
    UnknownClass = 2,
    Unburied = 3,
    Counterfeit = 4,
    Overweight = 5,
}

impl Refusal {
    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn message(self) -> &'static str {
        strerror(self.code())
    }
}

/// Text for a return code, from the pointer table `error_messages`.
pub fn strerror(code: i32) -> &'static str {
    match code {
        0 => "ok",
        1 => "nobody there",
        2 => "unknown kind of soul",
        3 => "unburied: come back in a hundred years",
        4 => "coin is counterfeit",
        5 => "too many sins for one boat",
        _ => "unknown error",
    }
}

/// One passenger: 32 bytes in memory and on disk, little-endian.
///
/// | offset | size | field       |
/// |--------|------|-------------|
/// | 0x00   | 24   | name, NUL terminated |
/// | 0x18   | 2    | sins        |
/// | 0x1a   | 1    | soul class  |
/// | 0x1b   | 1    | flags       |
/// | 0x1c   | 4    | coin        |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Passenger {
    pub name: [u8; 24],
    pub sins: u16,
    pub soul_class: u8,
    pub flags: u8,
    pub coin: u32,
}

const _: () = assert!(std::mem::size_of::<Passenger>() == Passenger::SIZE);

impl Passenger {
    pub const SIZE: usize = 32;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..24].copy_from_slice(&self.name);
        out[24..26].copy_from_slice(&self.sins.to_le_bytes());
        out[26] = self.soul_class;
        out[27] = self.flags;
        out[28..32].copy_from_slice(&self.coin.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut name = [0u8; 24];
        name.copy_from_slice(&bytes[..24]);
        Self {
            name,
            sins: u16::from_le_bytes([bytes[24], bytes[25]]),
            soul_class: bytes[26],
            flags: bytes[27],
            coin: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
        }
    }

    /// The name up to its terminating NUL.
    pub fn name_bytes(&self) -> &[u8] {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        &self.name[..end]
    }
}

/// FNV-1a (32 bit) with one extra folding step at the end (`obol_checksum`).
pub fn checksum(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for &byte in data {
        h = (h ^ u32::from(byte)).wrapping_mul(0x0100_0193);
    }
    h ^ (h >> 15)
}

/// A coin is `serial << 8 | check`; it is genuine when the serial is not zero and
/// `check == (serial * 31 + 7) % 251` (`obol_coin_valid`).
pub fn coin_valid(coin: u32) -> bool {
    let serial = coin >> 8;
    serial != 0 && (serial * 31 + 7) % 251 == coin & 0xFF
}

/// The fare in oboli, or the reason for refusal (`obol_fare`).
///
/// The checks run in the order of the original, which matters when several apply.
pub fn fare(p: &Passenger) -> Result<u32, Refusal> {
    let class = SoulClass::from_code(p.soul_class).ok_or(Refusal::UnknownClass)?;
    if p.flags & flag::UNBURIED != 0 {
        return Err(Refusal::Unburied);
    }
    if !coin_valid(p.coin) {
        return Err(Refusal::Counterfeit);
    }
    if p.sins > 9000 {
        return Err(Refusal::Overweight);
    }
    if class == SoulClass::Poet && p.sins < 100 {
        return Ok(0); // regardless of flags
    }
    let surcharge = u32::from(p.sins / 250).min(20);
    let mut fare = class.base_fare() + surcharge;
    if p.flags & flag::PRIORITY != 0 {
        fare = fare * 2 + 1;
    }
    if p.flags & flag::RETURN_TICKET != 0 {
        fare *= 3;
    }
    Ok(fare)
}

/// XORs `buf` with a keystream: the top byte of `state = state * 1664525 + 1013904223`.
/// Sealing twice with the same key restores the data (`obol_seal`).
pub fn seal(buf: &mut [u8], key: u32) {
    let mut state = key;
    for byte in buf {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte ^= (state >> 24) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passenger(class: u8, sins: u16, flags: u8) -> Passenger {
        Passenger { name: [0; 24], sins, soul_class: class, flags, coin: 0x0A11_C37A }
    }

    #[test]
    fn coin_rule() {
        assert!(coin_valid(0x0A11_C37A));
        assert!(!coin_valid(0x00BE_EF42));
        assert!(!coin_valid(0x0000_0007)); // serial 0 is never valid, even with a matching check
    }

    #[test]
    fn refusals_in_original_order() {
        assert_eq!(fare(&passenger(9, 0, 1)), Err(Refusal::UnknownClass));
        assert_eq!(fare(&passenger(0, 9999, 1)), Err(Refusal::Unburied));
        let mut fake = passenger(0, 9999, 0);
        fake.coin = 0x00BE_EF42;
        assert_eq!(fare(&fake), Err(Refusal::Counterfeit));
        assert_eq!(fare(&passenger(0, 9001, 0)), Err(Refusal::Overweight));
        assert!(fare(&passenger(0, 9000, 0)).is_ok());
    }

    #[test]
    fn fares_at_the_boundaries() {
        assert_eq!(fare(&passenger(0, 249, 0)), Ok(2));
        assert_eq!(fare(&passenger(0, 250, 0)), Ok(3));
        assert_eq!(fare(&passenger(0, 5000, 0)), Ok(22));
        assert_eq!(fare(&passenger(0, 9000, 0)), Ok(22)); // surcharge is capped at 20
        assert_eq!(fare(&passenger(2, 99, 6)), Ok(0)); // poets with few sins travel free
        assert_eq!(fare(&passenger(2, 100, 0)), Ok(0));
        assert_eq!(fare(&passenger(3, 3100, 2)), Ok(35)); // Midas, priority
        assert_eq!(fare(&passenger(0, 12, 6)), Ok(15)); // Eurydice, priority and return
    }

    #[test]
    fn seal_is_its_own_inverse() {
        let original = *b"what is sealed can be unsealed";
        let mut data = original;
        seal(&mut data, 0x5859_5453);
        assert_ne!(data, original);
        seal(&mut data, 0x5859_5453);
        assert_eq!(data, original);
    }

    #[test]
    fn checksum_of_nothing_is_the_folded_offset_basis() {
        assert_eq!(checksum(b""), 0x811C_9DC5 ^ (0x811C_9DC5 >> 15));
    }
}
