#include <stdio.h>
#include "frame.h"
int main(void)
{
    const char a[] = {1, 2, 3, 4};
    if (frame_checksum(a, 4) != 10) { printf("FAIL small\n"); return 1; }
    printf("ok\n");
    return 0;
}
