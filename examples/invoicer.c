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

/* Sample 2: a small "legacy" Windows billing tool with undocumented business rules.
 * Built as a stripped PE with MinGW and used in the documentation as the program whose
 * behaviour is recovered without source code. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef struct {
    char sku[16];
    int qty;
    double unit_price;
} OrderLine;

static int license_ok(const char *key) {
    /* INV-AAAA-NNNN: NNNN must equal (sum of the letters AAAA * 7) mod 10000 */
    if (strlen(key) != 13 || strncmp(key, "INV-", 4) != 0 || key[8] != '-') return 0;
    int sum = 0;
    for (int i = 4; i < 8; i++) sum += (unsigned char)key[i];
    return (sum * 7) % 10000 == atoi(key + 9);
}

static double discount_rate(double subtotal, int customer_class) {
    double rate = 0.0;
    if (subtotal >= 10000.0) rate = 0.10;
    else if (subtotal >= 5000.0) rate = 0.05;
    if (customer_class == 2) rate += 0.03; /* wholesale */
    return rate;
}

static double vat_rate(const char *country) {
    if (strcmp(country, "PL") == 0) return 0.23;
    if (strcmp(country, "DE") == 0) return 0.19;
    if (strcmp(country, "FR") == 0) return 0.20;
    return 0.0; /* export */
}

static int load_order(const char *path, OrderLine *lines, int max_lines) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char row[128];
    int n = 0;
    while (n < max_lines && fgets(row, sizeof row, f)) {
        if (row[0] == '#') continue;
        if (sscanf(row, "%15[^;];%d;%lf", lines[n].sku, &lines[n].qty, &lines[n].unit_price) == 3)
            n++;
    }
    fclose(f);
    return n;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        puts("usage: invoicer ORDER.CSV COUNTRY CLASS LICENSE");
        return 2;
    }
    if (!license_ok(argv[4])) {
        puts("License key rejected");
        return 3;
    }
    int max_lines = (int)GetPrivateProfileIntA("limits", "max_lines", 100, ".\\invoicer.ini");
    OrderLine *lines = calloc((size_t)max_lines, sizeof *lines);
    int n = load_order(argv[1], lines, max_lines);
    if (n < 0) {
        printf("Cannot open order file %s\n", argv[1]);
        return 4;
    }
    double subtotal = 0.0;
    for (int i = 0; i < n; i++) subtotal += lines[i].qty * lines[i].unit_price;
    double discount = subtotal * discount_rate(subtotal, atoi(argv[3]));
    double net = subtotal - discount;
    double vat = net * vat_rate(argv[2]);
    FILE *out = fopen("invoice.txt", "w");
    if (!out) return 5;
    fprintf(out, "LINES=%d\nSUBTOTAL=%.2f\nDISCOUNT=%.2f\nNET=%.2f\nVAT=%.2f\nTOTAL=%.2f\n", n,
            subtotal, discount, net, vat, net + vat);
    fclose(out);
    printf("Invoice written: %d lines, total %.2f\n", n, net + vat);
    return 0;
}
