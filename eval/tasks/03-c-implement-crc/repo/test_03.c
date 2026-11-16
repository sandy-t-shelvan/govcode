#include <stdio.h>
#include "crc.h"
int main(void)
{
    const unsigned char v[] = "123456789";
    unsigned short c = crc16_ccitt(v, 9);
    if (c != 0x29B1) { printf("FAIL check value %#06x, want 0x29b1\n", c); return 1; }
    printf("ok\n");
    return 0;
}
