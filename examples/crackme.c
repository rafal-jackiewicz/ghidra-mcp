/* Sample 1: a tiny Linux program with a hidden rule. Used in the documentation. */
#include <stdio.h>
#include <string.h>

int check_key(const char *key, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) sum += key[i] * (i + 1);
    return sum == 4242;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        puts("usage: crackme KEY");
        return 2;
    }
    if (check_key(argv[1], (int)strlen(argv[1])))
        puts("Access granted");
    else
        puts("Access denied");
    return 0;
}
