#include <stdio.h>
#include "frame.h"
int main(void)
{
    const char a[] = {1, 2, 3, 4};
    const char b[] = {(char)0xFF, (char)0x80, 0x01};
    char big[300];
    int i;
    if (frame_checksum(a, 4) != 10) { printf("FAIL small\n"); return 1; }
    if (frame_checksum(b, 3) != 0x0180) { printf("FAIL high bytes: %#x\n", frame_checksum(b, 3)); return 1; }
    for (i = 0; i < 300; i++) big[i] = (char)0xFF;
    if (frame_checksum(big, 300) != (unsigned short)(300 * 255)) { printf("FAIL long\n"); return 1; }
    printf("ok\n");
    return 0;
}
