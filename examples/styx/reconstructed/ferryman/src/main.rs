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

//! Boarding and ledger tool of the Styx Ferry Company.
//!
//! Reconstructed from the stripped binaries `ferryman` (ELF) and `ferryman.exe` (PE) with
//! Ghidra. The original keeps all of this in one function; here it is split by purpose.

mod ledger;
mod manifest;
mod textmode;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use ledger::Record;

/// The boat takes 64 passengers (`boarded == 0x40` in the original).
const BOAT_CAPACITY: usize = 64;

/// Exit codes of the original program.
mod exit {
    pub const USAGE: u8 = 1;
    pub const IO: u8 = 2;
    pub const BAD_LEDGER: u8 = 3;
    pub const TAMPERED: u8 = 4;
}

/// Left-justifies `text` in a field of `width` bytes, like `%-24s` (never truncates).
fn pad(out: &mut Vec<u8>, text: &[u8], width: usize) {
    out.extend_from_slice(text);
    for _ in text.len()..width {
        out.push(b' ');
    }
}

/// `"%-24s %-8s %5u\n"`
fn passenger_line(name: &[u8], kind: &str, fare: u32) -> Vec<u8> {
    let mut line = Vec::with_capacity(48);
    pad(&mut line, name, 24);
    line.push(b' ');
    pad(&mut line, kind.as_bytes(), 8);
    line.extend_from_slice(format!(" {fare:>5}\n").as_bytes());
    line
}

/// `"%-24s REFUSED  %s\n"`
fn refusal_line(name: &[u8], reason: &str) -> Vec<u8> {
    let mut line = Vec::with_capacity(72);
    pad(&mut line, name, 24);
    line.extend_from_slice(format!(" REFUSED  {reason}\n").as_bytes());
    line
}

/// The contents of a file, or `None` where the original's `fopen` fails. On Linux `fopen`
/// succeeds on a directory and every read from it fails, so a directory counts as an empty
/// file there; on Windows it cannot be opened at all.
fn read_as_fopen(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(_) if cfg!(unix) && path.is_dir() => Some(Vec::new()),
        Err(_) => None,
    }
}

fn board(manifest_path: &Path, ledger_path: &Path) -> io::Result<u8> {
    let text = match read_as_fopen(manifest_path) {
        Some(text) => text,
        None => {
            textmode::complain(&format!("ferryman: cannot read manifest {}", manifest_path.display()));
            return Ok(exit::IO);
        }
    };
    let text = textmode::input(text); // the original opens the manifest in text mode

    let mut out = textmode::Stdout::new();
    let mut records: Vec<Record> = Vec::new();
    let mut refused = 0u32;
    let mut total = 0u32;

    for (number, line) in manifest::lines(&text) {
        if manifest::is_skipped(line) {
            continue;
        }
        let Some(passenger) = manifest::parse(line) else {
            out.flush()?;
            textmode::complain(&format!("line {number}: unreadable, skipped"));
            continue;
        };
        let name = passenger.name_bytes();
        match obol::fare(&passenger) {
            Err(refusal) => {
                out.write_all(&refusal_line(name, refusal.message()))?;
                refused += 1;
            }
            Ok(_) if records.len() == BOAT_CAPACITY => {
                out.write_all(&refusal_line(name, "the boat is full"))?;
                refused += 1;
            }
            Ok(fare) => {
                // A fare was granted, so the class is one of the five known ones.
                let kind = obol::SoulClass::from_code(passenger.soul_class).map_or("?", |c| c.name());
                out.write_all(&passenger_line(name, kind, fare))?;
                records.push(Record { passenger, fare });
                total = total.wrapping_add(fare);
            }
        }
    }

    if std::fs::write(ledger_path, ledger::encode(&records, total)).is_err() {
        out.flush()?;
        textmode::complain(&format!("ferryman: cannot write ledger {}", ledger_path.display()));
        return Ok(exit::IO);
    }
    writeln!(out, "{} boarded, {refused} refused, {total} oboli collected", records.len())?;
    Ok(0)
}

fn audit(ledger_path: &Path) -> io::Result<u8> {
    let Some(bytes) = read_as_fopen(ledger_path) else {
        textmode::complain(&format!("ferryman: cannot read ledger {}", ledger_path.display()));
        return Ok(exit::IO);
    };
    let (records, total) = match ledger::decode(&bytes) {
        Ok(contents) => contents,
        Err(problem) => {
            textmode::complain(&format!("ferryman: {problem}"));
            return Ok(match problem {
                ledger::Problem::Tampered => exit::TAMPERED,
                _ => exit::BAD_LEDGER,
            });
        }
    };

    let mut out = textmode::Stdout::new();
    let mut sum = 0u32;
    for record in &records {
        let p = &record.passenger;
        let kind = obol::SoulClass::from_code(p.soul_class).map_or("?", |c| c.name());
        out.write_all(&passenger_line(p.name_bytes(), kind, record.fare))?;
        sum = sum.wrapping_add(record.fare);
    }
    if sum != total {
        out.flush()?;
        textmode::complain("ferryman: totals do not agree, someone is skimming");
        return Ok(exit::TAMPERED);
    }
    writeln!(out, "{} souls, {sum} oboli", records.len())?;
    Ok(0)
}

fn usage() -> io::Result<u8> {
    let mut out = textmode::Stdout::new();
    writeln!(out, "usage: ferryman board MANIFEST LEDGER")?;
    writeln!(out, "       ferryman audit LEDGER")?;
    Ok(exit::USAGE)
}

fn main() -> ExitCode {
    // File names are taken as the system gives them; they need not be valid UTF-8.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [command, manifest, ledger] if command == "board" => board(Path::new(manifest), Path::new(ledger)),
        [command, ledger] if command == "audit" => audit(Path::new(ledger)),
        _ => usage(),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            textmode::complain(&format!("ferryman: {error}"));
            ExitCode::from(exit::IO)
        }
    }
}
