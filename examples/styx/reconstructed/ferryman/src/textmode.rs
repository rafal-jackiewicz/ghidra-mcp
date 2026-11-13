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

//! What "text mode" means on Windows.
//!
//! The original is a C program that opens the manifest with `fopen(path, "r")` and prints
//! with `printf`. On Linux that reads and writes bytes unchanged. On Windows the C runtime
//! translates: when reading, a carriage return in front of a line feed is dropped and the
//! byte 0x1A (Ctrl-Z) ends the file; when writing, every line feed becomes carriage return
//! plus line feed. None of this is visible in the decompiled code, because it happens inside
//! the runtime. It was found by running both programs on a real Windows machine: the first
//! Windows build of this reconstruction differed from the original in every one of 779 cases,
//! by exactly these bytes.

use std::io::{self, Write};

/// The manifest as the original sees it after its runtime has had its way with it.
pub fn input(bytes: Vec<u8>) -> Vec<u8> {
    if cfg!(windows) {
        translate_input(&bytes)
    } else {
        bytes
    }
}

fn translate_input(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let [first, tail @ ..] = rest {
        match (*first, tail.first()) {
            (0x1A, _) => break,          // Ctrl-Z: end of file
            (b'\r', Some(b'\n')) => {}   // CR LF becomes LF
            (byte, _) => out.push(byte), // a lone CR stays
        }
        rest = tail;
    }
    out
}

fn translate_output(bytes: &[u8], out: &mut Vec<u8>) {
    for &byte in bytes {
        if byte == b'\n' {
            out.push(b'\r');
        }
        out.push(byte);
    }
}

/// Standard output with the line ends of the platform's C runtime.
pub struct Stdout {
    inner: io::StdoutLock<'static>,
    scratch: Vec<u8>,
}

impl Stdout {
    pub fn new() -> Self {
        Self { inner: io::stdout().lock(), scratch: Vec::new() }
    }
}

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if cfg!(windows) {
            self.scratch.clear();
            translate_output(buf, &mut self.scratch);
            self.inner.write_all(&self.scratch)?;
        } else {
            self.inner.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// One line on standard error, as `fprintf(stderr, "...\n")` writes it.
pub fn complain(message: &str) {
    let mut line = Vec::with_capacity(message.len() + 2);
    if cfg!(windows) {
        translate_output(message.as_bytes(), &mut line);
        line.extend_from_slice(b"\r\n");
    } else {
        line.extend_from_slice(message.as_bytes());
        line.push(b'\n');
    }
    let _ = io::stderr().lock().write_all(&line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_drops_cr_before_lf_and_stops_at_ctrl_z() {
        assert_eq!(translate_input(b"a\r\nb\rc\n"), b"a\nb\rc\n");
        assert_eq!(translate_input(b"one\ntwo\x1athree\n"), b"one\ntwo");
    }

    #[test]
    fn writing_turns_lf_into_cr_lf() {
        let mut out = Vec::new();
        translate_output(b"x\ny\n", &mut out);
        assert_eq!(out, b"x\r\ny\r\n");
    }
}
