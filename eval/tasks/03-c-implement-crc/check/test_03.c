#include <stdio.h>
#include "crc.h"
int main(void)
{
    const unsigned char v[] = "123456789";
    const unsigned char z[1] = {0};
    if (crc16_ccitt(v, 9) != 0x29B1) { printf("FAIL check value\n"); return 1; }
    if (crc16_ccitt(v, 0) != 0xFFFF) { printf("FAIL empty\n"); return 1; }
    if (crc16_ccitt(z, 1) != 0xE1F0) { printf("FAIL zero byte %#x\n", crc16_ccitt(z,1)); return 1; }
    printf("ok\n");
    return 0;
}
