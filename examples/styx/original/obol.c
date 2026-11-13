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

/* libobol: fare rules of the Styx Ferry Company (original C implementation). */
#define OBOL_BUILD
#include "obol.h"

static const uint8_t base_fare[5] = {2, 1, 0, 5, 13};

static const char *const messages[] = {
    "ok",
    "nobody there",
    "unknown kind of soul",
    "unburied: come back in a hundred years",
    "coin is counterfeit",
    "too many sins for one boat",
};

int obol_abi(void) { return OBOL_ABI; }

uint32_t obol_checksum(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 0x811C9DC5u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x01000193u;
    }
    return h ^ (h >> 15);
}

int obol_coin_valid(uint32_t coin) {
    uint32_t serial = coin >> 8;
    if (serial == 0) return 0;
    return (serial * 31u + 7u) % 251u == (coin & 0xFFu);
}

int obol_fare(const Passenger *p, uint32_t *fare) {
    if (!p || !fare) return OBOL_E_NULL;
    if (p->soul_class > 4) return OBOL_E_CLASS;
    if (p->flags & 1) return OBOL_E_UNBURIED;
    if (!obol_coin_valid(p->coin)) return OBOL_E_COIN;
    if (p->sins > 9000) return OBOL_E_OVERWEIGHT;

    if (p->soul_class == 2 && p->sins < 100) { /* poets rarely have money anyway */
        *fare = 0;
        return OBOL_OK;
    }
    uint32_t surcharge = p->sins / 250u;
    if (surcharge > 20) surcharge = 20;
    uint32_t f = base_fare[p->soul_class] + surcharge;
    if (p->flags & 2) f = f * 2 + 1; /* priority boarding */
    if (p->flags & 4) f *= 3;        /* return ticket: rare, and priced accordingly */
    *fare = f;
    return OBOL_OK;
}

void obol_seal(uint8_t *buf, size_t len, uint32_t key) {
    uint32_t state = key;
    for (size_t i = 0; i < len; i++) {
        state = state * 1664525u + 1013904223u;
        buf[i] ^= (uint8_t)(state >> 24);
    }
}

const char *obol_strerror(int code) {
    if (code < 0 || code > 5) return "unknown error";
    return messages[code];
}
