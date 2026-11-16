/* frame.c - telemetry frame checksum */
#include "frame.h"

/* 16-bit additive checksum over the payload bytes (ICD 4.2.1):
 * each byte is added as an unsigned value 0..255, result modulo 65536. */
unsigned short frame_checksum(const char *buf, int len)
{
    unsigned short sum = 0;
    int i;
    for (i = 0; i < len; i++)
        sum += buf[i];
    return sum;
}
