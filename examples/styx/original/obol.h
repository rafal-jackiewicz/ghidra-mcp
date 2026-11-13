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

/* libobol: fare rules of the Styx Ferry Company.
 * In the story told by the book this header is lost; it is here as the answer key. */
#ifndef OBOL_H
#define OBOL_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(OBOL_BUILD)
#    define OBOL_API __declspec(dllexport)
#  else
#    define OBOL_API __declspec(dllimport)
#  endif
#else
#  define OBOL_API __attribute__((visibility("default")))
#endif

#define OBOL_ABI 3

typedef struct {
    char name[24];       /* NUL terminated */
    uint16_t sins;
    uint8_t soul_class;  /* 0 mortal, 1 hero, 2 poet, 3 king, 4 publican */
    uint8_t flags;       /* bit 0 unburied, bit 1 priority, bit 2 return ticket */
    uint32_t coin;       /* serial number of the obol */
} Passenger;

enum {
    OBOL_OK = 0,
    OBOL_E_NULL = 1,
    OBOL_E_CLASS = 2,
    OBOL_E_UNBURIED = 3,
    OBOL_E_COIN = 4,
    OBOL_E_OVERWEIGHT = 5
};

OBOL_API int obol_abi(void);
OBOL_API uint32_t obol_checksum(const void *data, size_t len);
OBOL_API int obol_coin_valid(uint32_t coin);
OBOL_API int obol_fare(const Passenger *p, uint32_t *fare);
OBOL_API void obol_seal(uint8_t *buf, size_t len, uint32_t key);
OBOL_API const char *obol_strerror(int code);

#endif
