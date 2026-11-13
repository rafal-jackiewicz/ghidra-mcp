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

//! The original C interface, so that this crate can replace `libobol.so` / `obol.dll`
//! under the original `ferryman` executable.

use std::ffi::{c_char, c_int};

use crate::Passenger;

#[no_mangle]
pub extern "C" fn obol_abi() -> c_int {
    c_int::from(crate::ABI)
}

/// # Safety
/// `data` must point to `len` readable bytes (it may be dangling when `len` is 0).
#[no_mangle]
pub unsafe extern "C" fn obol_checksum(data: *const u8, len: usize) -> u32 {
    if len == 0 {
        return crate::checksum(&[]);
    }
    crate::checksum(std::slice::from_raw_parts(data, len))
}

#[no_mangle]
pub extern "C" fn obol_coin_valid(coin: u32) -> c_int {
    c_int::from(crate::coin_valid(coin))
}

/// # Safety
/// `p` and `fare` must each be null or point to a valid object.
#[no_mangle]
pub unsafe extern "C" fn obol_fare(p: *const Passenger, fare: *mut u32) -> c_int {
    if p.is_null() || fare.is_null() {
        return crate::Refusal::Nobody.code();
    }
    match crate::fare(&*p) {
        Ok(value) => {
            *fare = value;
            0
        }
        Err(refusal) => refusal.code(),
    }
}

/// # Safety
/// `buf` must point to `len` writable bytes (it may be dangling when `len` is 0).
#[no_mangle]
pub unsafe extern "C" fn obol_seal(buf: *mut u8, len: usize, key: u32) {
    if len != 0 {
        crate::seal(std::slice::from_raw_parts_mut(buf, len), key);
    }
}

#[no_mangle]
pub extern "C" fn obol_strerror(code: c_int) -> *const c_char {
    let text: &'static std::ffi::CStr = match code {
        0 => c"ok",
        1 => c"nobody there",
        2 => c"unknown kind of soul",
        3 => c"unburied: come back in a hundred years",
        4 => c"coin is counterfeit",
        5 => c"too many sins for one boat",
        _ => c"unknown error",
    };
    text.as_ptr()
}
