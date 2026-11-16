#ifndef CRC_H
#define CRC_H
/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final xor. */
unsigned short crc16_ccitt(const unsigned char *buf, unsigned long len);
#endif
