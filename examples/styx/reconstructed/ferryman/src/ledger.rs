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

//! The ledger file.
//!
//! ```text
//! offset  size  field
//! 0x00    4     magic "STYX"
//! 0x04    2     version (the library's ABI number, 3)
//! 0x06    2     count of records
//! 0x08    4     total of all fares
//! 0x0c    4     checksum of the sealed payload
//! 0x10    36*n  records, sealed with key = total ^ 0x58595453
//! ```
//! A record is a 32-byte passenger followed by the 32-bit fare. All numbers are little-endian.

use std::fmt;

use obol::Passenger;

const MAGIC: &[u8; 4] = b"STYX";
const HEADER_SIZE: usize = 16;
const RECORD_SIZE: usize = Passenger::SIZE + 4;
/// "STYX" read as a little-endian number; XORed with the total to make the sealing key.
const KEY: u32 = 0x5859_5453;
const MAX_RECORDS: usize = 64;

pub struct Record {
    pub passenger: Passenger,
    pub fare: u32,
}

/// What can be wrong with a ledger; `Display` gives the original messages.
#[derive(Debug, PartialEq, Eq)]
pub enum Problem {
    NotALedger,
    AnotherEra(u16),
    Truncated,
    Tampered,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotALedger => write!(f, "not a Styx ledger"),
            Self::AnotherEra(version) => write!(f, "ledger from another era (version {version})"),
            Self::Truncated => write!(f, "ledger is truncated"),
            Self::Tampered => write!(f, "ledger has been tampered with"),
        }
    }
}

pub fn encode(records: &[Record], total: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(records.len() * RECORD_SIZE);
    for record in records {
        payload.extend_from_slice(&record.passenger.to_bytes());
        payload.extend_from_slice(&record.fare.to_le_bytes());
    }
    obol::seal(&mut payload, total ^ KEY);

    let mut file = Vec::with_capacity(HEADER_SIZE + payload.len());
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&obol::ABI.to_le_bytes());
    file.extend_from_slice(&(records.len() as u16).to_le_bytes());
    file.extend_from_slice(&total.to_le_bytes());
    file.extend_from_slice(&obol::checksum(&payload).to_le_bytes());
    file.extend_from_slice(&payload);
    file
}

/// Returns the records and the total stated in the header.
/// The checks run in the order of the original program.
pub fn decode(bytes: &[u8]) -> Result<(Vec<Record>, u32), Problem> {
    if bytes.len() < HEADER_SIZE || &bytes[..4] != MAGIC {
        return Err(Problem::NotALedger);
    }
    let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);

    let version = u16_at(4);
    if version != obol::ABI {
        return Err(Problem::AnotherEra(version));
    }
    let count = usize::from(u16_at(6));
    let total = u32_at(8);
    let stated_checksum = u32_at(12);

    let size = count * RECORD_SIZE;
    if count > MAX_RECORDS || bytes.len() < HEADER_SIZE + size {
        return Err(Problem::Truncated);
    }
    let mut payload = bytes[HEADER_SIZE..HEADER_SIZE + size].to_vec();
    if obol::checksum(&payload) != stated_checksum {
        return Err(Problem::Tampered);
    }
    obol::seal(&mut payload, total ^ KEY);

    let records = payload
        .chunks_exact(RECORD_SIZE)
        .map(|chunk| {
            let (head, tail) = chunk.split_at(Passenger::SIZE);
            Record {
                passenger: Passenger::from_bytes(head.try_into().expect("32 bytes")),
                fare: u32::from_le_bytes(tail.try_into().expect("4 bytes")),
            }
        })
        .collect();
    Ok((records, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Record> {
        let mut name = [0u8; 24];
        name[..8].copy_from_slice(b"Achilles");
        vec![Record {
            passenger: Passenger { name, sins: 1200, soul_class: 1, flags: 0, coin: 0x0A11_C37A },
            fare: 5,
        }]
    }

    #[test]
    fn round_trip() {
        let file = encode(&sample(), 5);
        assert_eq!(file.len(), 16 + 36);
        let (records, total) = decode(&file).unwrap();
        assert_eq!(total, 5);
        assert_eq!(records[0].passenger.name_bytes(), b"Achilles");
        assert_eq!(records[0].fare, 5);
    }

    #[test]
    fn a_flipped_bit_is_noticed() {
        let mut file = encode(&sample(), 5);
        file[20] ^= 1;
        assert_eq!(decode(&file).err(), Some(Problem::Tampered));
    }

    #[test]
    fn checks_run_in_the_original_order() {
        assert_eq!(decode(b"STY").err(), Some(Problem::NotALedger));
        let mut file = encode(&sample(), 5);
        file[4] = 2;
        assert_eq!(decode(&file).err(), Some(Problem::AnotherEra(2)));
        let file = encode(&sample(), 5);
        assert_eq!(decode(&file[..30]).err(), Some(Problem::Truncated));
    }
}
