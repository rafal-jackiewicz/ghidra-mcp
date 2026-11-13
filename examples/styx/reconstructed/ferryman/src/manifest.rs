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

//! The passenger manifest: text, one passenger per line, `name;class;sins;coin;flags`.
//!
//! The original reads it with `fgets(line, 160, file)` and
//! `sscanf(line, " %23[^;];%c;%u;%x;%u", ...)`. Those two calls *are* the file format:
//! what they accept, the format accepts. This module therefore follows them step by step
//! instead of using a tidy split-and-parse, which was tried first and differed from the
//! original on 263 of 304 test manifests.

use obol::Passenger;

/// Size of the original line buffer; `fgets` reads at most one byte less.
const LINE_BUFFER: usize = 160;

/// Splits the file the way repeated `fgets` calls do: a piece ends after a line feed or
/// after 159 bytes, whichever comes first. Pieces are numbered from 1.
pub fn lines(text: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let mut rest = text;
    let mut number = 0;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let limit = rest.len().min(LINE_BUFFER - 1);
        let end = rest[..limit].iter().position(|&b| b == b'\n').map_or(limit, |at| at + 1);
        let (piece, tail) = rest.split_at(end);
        rest = tail;
        number += 1;
        Some((number, piece))
    })
}

/// Lines whose FIRST byte is `#`, line feed or carriage return are skipped silently.
/// (The original tests this with a bit mask, `0x800002400 >> c & 1`: bits 10, 13 and 35.)
pub fn is_skipped(line: &[u8]) -> bool {
    matches!(line.first(), None | Some(b'#' | b'\n' | b'\r'))
}

/// The switch in the original, applied after `toupper`.
fn class_code(letter: u8) -> u8 {
    match letter.to_ascii_uppercase() {
        b'M' => 0,
        b'H' => 1,
        b'P' => 2,
        b'K' => 3,
        b'T' => 4,
        _ => 255, // obol_fare refuses it as an unknown kind of soul
    }
}

/// A cursor over one line, with the conversions `sscanf` performs.
struct Scanner<'a> {
    rest: &'a [u8],
}

impl<'a> Scanner<'a> {
    /// What C's `isspace` accepts in the default locale.
    fn skip_whitespace(&mut self) {
        while let [b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c, tail @ ..] = self.rest {
            self.rest = tail;
        }
    }

    /// A literal character in the format: it must be next.
    fn expect(&mut self, byte: u8) -> Option<()> {
        match self.rest {
            [first, tail @ ..] if *first == byte => {
                self.rest = tail;
                Some(())
            }
            _ => None,
        }
    }

    /// `%23[^;]`: one to 23 bytes that are not a semicolon.
    fn name(&mut self) -> Option<&'a [u8]> {
        let length = self.rest.iter().take(23).take_while(|&&b| b != b';').count();
        if length == 0 {
            return None;
        }
        let (name, tail) = self.rest.split_at(length);
        self.rest = tail;
        Some(name)
    }

    /// `%c`: exactly one byte, whatever it is.
    fn character(&mut self) -> Option<u8> {
        let (&first, tail) = self.rest.split_first()?;
        self.rest = tail;
        Some(first)
    }

    /// `%u` (radix 10) and `%x` (radix 16): leading white space, an optional sign, for
    /// hexadecimal an optional `0x`, then at least one digit. A minus sign negates modulo
    /// 2^32, so "-1" becomes 4294967295; scanning stops at the first byte that is no digit.
    fn unsigned(&mut self, radix: u32) -> Option<u32> {
        self.skip_whitespace();
        let negative = match self.rest {
            [b'-', tail @ ..] => {
                self.rest = tail;
                true
            }
            [b'+', tail @ ..] => {
                self.rest = tail;
                false
            }
            _ => false,
        };
        if radix == 16 {
            if let [b'0', b'x' | b'X', digit, ..] = self.rest {
                if digit.is_ascii_hexdigit() {
                    self.rest = &self.rest[2..];
                }
            }
        }
        let mut value: u64 = 0;
        let mut digits = 0;
        while let Some(digit) = self.rest.first().and_then(|&b| (b as char).to_digit(radix)) {
            value = value.saturating_mul(u64::from(radix)).saturating_add(u64::from(digit));
            self.rest = &self.rest[1..];
            digits += 1;
        }
        if digits == 0 {
            return None;
        }
        let value = if negative { value.wrapping_neg() } else { value };
        Some(value as u32) // the original stores the low 32 bits
    }
}

/// One manifest line, or `None` where the original reports "unreadable".
/// Whatever follows the fifth field is ignored, as `sscanf` ignores it.
pub fn parse(line: &[u8]) -> Option<Passenger> {
    let mut scan = Scanner { rest: line };
    scan.skip_whitespace();
    let name_field = scan.name()?;
    scan.expect(b';')?;
    let class_letter = scan.character()?;
    scan.expect(b';')?;
    let sins = scan.unsigned(10)?;
    scan.expect(b';')?;
    let coin = scan.unsigned(16)?;
    scan.expect(b';')?;
    let flags = scan.unsigned(10)?;

    let mut name = [0u8; 24];
    name[..name_field.len()].copy_from_slice(name_field);
    Some(Passenger {
        name,
        sins: sins.min(65535) as u16, // values above 65535 are clamped, not wrapped
        soul_class: class_code(class_letter),
        flags: flags as u8, // only the low byte is kept
        coin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_line() {
        let p = parse(b"Achilles;H;1200;a11c37a;0\n").unwrap();
        assert_eq!(p.name_bytes(), b"Achilles");
        assert_eq!((p.soul_class, p.sins, p.coin, p.flags), (1, 1200, 0x0A11_C37A, 0));
    }

    #[test]
    fn what_sscanf_tolerates() {
        assert_eq!(parse(b"   Leading;m;+12; 0xA11C37A;2 and more").unwrap().sins, 12);
        assert_eq!(parse(b"Saint;M;-1;a11c37a;0").unwrap().sins, 65535);
        assert_eq!(parse(b"Flags;M;1;a11c37a;258").unwrap().flags, 2);
        assert_eq!(parse(b"Two Words ;M;1;a11c37a;0").unwrap().name_bytes(), b"Two Words ");
    }

    #[test]
    fn what_sscanf_rejects() {
        assert!(parse(b"ExactlyTwentyFourCharsXX;M;10;a11c37a;0").is_none());
        assert!(parse(b";M;10;a11c37a;0").is_none());
        assert!(parse(b"Junk;M;10abc;a11c37a;0").is_none());
        assert!(parse(b"TwoLetters;MM;10;a11c37a;0").is_none());
        assert!(parse(b"NoFlags;M;10;a11c37a").is_none());
    }

    #[test]
    fn long_lines_are_read_in_pieces() {
        let text = [b"x".repeat(200), b"\nshort\n".to_vec()].concat();
        let pieces: Vec<usize> = lines(&text).map(|(_, piece)| piece.len()).collect();
        assert_eq!(pieces, [159, 42, 6]);
    }

    #[test]
    fn only_the_first_column_makes_a_comment() {
        assert!(is_skipped(b"# comment\n"));
        assert!(is_skipped(b"\r\n"));
        assert!(!is_skipped(b" # not a comment\n"));
    }
}
