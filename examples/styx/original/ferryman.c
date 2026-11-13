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

/* ferryman: boarding and ledger tool of the Styx Ferry Company (original C implementation). */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "obol.h"

#define BOAT_CAPACITY 64
#define LEDGER_KEY 0x58595453u /* "STYX" */

typedef struct {
    Passenger p;
    uint32_t fare;
} Record; /* 36 bytes */

typedef struct {
    char magic[4];
    uint16_t version;
    uint16_t count;
    uint32_t total;
    uint32_t checksum;
} LedgerHeader; /* 16 bytes */

static const char *const class_names[] = {"mortal", "hero", "poet", "king", "publican"};

static int class_from_letter(char c) {
    switch (toupper((unsigned char)c)) {
        case 'M': return 0;
        case 'H': return 1;
        case 'P': return 2;
        case 'K': return 3;
        case 'T': return 4;
        default: return 255;
    }
}

static int board(const char *manifest, const char *ledger) {
    static Record records[BOAT_CAPACITY];
    FILE *in = fopen(manifest, "r");
    if (!in) {
        fprintf(stderr, "ferryman: cannot read manifest %s\n", manifest);
        return 2;
    }
    char line[160];
    unsigned count = 0, refused = 0, total = 0;
    int lineno = 0;
    while (fgets(line, sizeof line, in)) {
        char name[24], cls;
        unsigned sins, coin, flags;
        lineno++;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (sscanf(line, " %23[^;];%c;%u;%x;%u", name, &cls, &sins, &coin, &flags) != 5) {
            fprintf(stderr, "line %d: unreadable, skipped\n", lineno);
            continue;
        }
        Passenger p;
        memset(&p, 0, sizeof p);
        strncpy(p.name, name, sizeof p.name - 1);
        p.soul_class = (uint8_t)class_from_letter(cls);
        p.sins = (uint16_t)(sins > 65535 ? 65535 : sins);
        p.coin = coin;
        p.flags = (uint8_t)flags;

        uint32_t fare = 0;
        int rc = obol_fare(&p, &fare);
        if (rc != OBOL_OK) {
            printf("%-24s REFUSED  %s\n", p.name, obol_strerror(rc));
            refused++;
            continue;
        }
        if (count == BOAT_CAPACITY) {
            printf("%-24s REFUSED  the boat is full\n", p.name);
            refused++;
            continue;
        }
        printf("%-24s %-8s %5u\n", p.name, class_names[p.soul_class], (unsigned)fare);
        records[count].p = p;
        records[count].fare = fare;
        count++;
        total += fare;
    }
    fclose(in);

    LedgerHeader h;
    size_t size = count * sizeof(Record);
    memcpy(h.magic, "STYX", 4);
    h.version = (uint16_t)obol_abi();
    h.count = (uint16_t)count;
    h.total = total;
    obol_seal((uint8_t *)records, size, total ^ LEDGER_KEY);
    h.checksum = obol_checksum(records, size);

    FILE *out = fopen(ledger, "wb");
    if (!out || fwrite(&h, sizeof h, 1, out) != 1 ||
        (count && fwrite(records, sizeof(Record), count, out) != count)) {
        fprintf(stderr, "ferryman: cannot write ledger %s\n", ledger);
        if (out) fclose(out);
        return 2;
    }
    fclose(out);
    printf("%u boarded, %u refused, %u oboli collected\n", count, refused, total);
    return 0;
}

static int audit(const char *ledger) {
    static Record records[BOAT_CAPACITY];
    LedgerHeader h;
    FILE *in = fopen(ledger, "rb");
    if (!in) {
        fprintf(stderr, "ferryman: cannot read ledger %s\n", ledger);
        return 2;
    }
    if (fread(&h, sizeof h, 1, in) != 1 || memcmp(h.magic, "STYX", 4) != 0) {
        fprintf(stderr, "ferryman: not a Styx ledger\n");
        fclose(in);
        return 3;
    }
    if (h.version != obol_abi()) {
        fprintf(stderr, "ferryman: ledger from another era (version %u)\n", (unsigned)h.version);
        fclose(in);
        return 3;
    }
    if (h.count > BOAT_CAPACITY || fread(records, sizeof(Record), h.count, in) != h.count) {
        fprintf(stderr, "ferryman: ledger is truncated\n");
        fclose(in);
        return 3;
    }
    fclose(in);
    size_t size = h.count * sizeof(Record);
    if (obol_checksum(records, size) != h.checksum) {
        fprintf(stderr, "ferryman: ledger has been tampered with\n");
        return 4;
    }
    obol_seal((uint8_t *)records, size, h.total ^ LEDGER_KEY);
    unsigned sum = 0;
    for (unsigned i = 0; i < h.count; i++) {
        const Record *r = &records[i];
        const char *kind = r->p.soul_class < 5 ? class_names[r->p.soul_class] : "?";
        printf("%-24.24s %-8s %5u\n", r->p.name, kind, (unsigned)r->fare);
        sum += r->fare;
    }
    if (sum != h.total) {
        fprintf(stderr, "ferryman: totals do not agree, someone is skimming\n");
        return 4;
    }
    printf("%u souls, %u oboli\n", (unsigned)h.count, sum);
    return 0;
}

int main(int argc, char **argv) {
    if (obol_abi() != OBOL_ABI) {
        fprintf(stderr, "ferryman: libobol speaks ABI %d, expected %d\n", obol_abi(), OBOL_ABI);
        return 5;
    }
    if (argc == 4 && strcmp(argv[1], "board") == 0) return board(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "audit") == 0) return audit(argv[2]);
    puts("usage: ferryman board MANIFEST LEDGER");
    puts("       ferryman audit LEDGER");
    return 1;
}
