#include <cstdio>
#include "msgbuf.h"
int main()
{
    MsgBuf a(16);
    a[0] = 'A';
    if (a[0] != 'A' || a.size() != 16) { std::printf("FAIL basic\n"); return 1; }
    std::printf("ok\n");
    return 0;
}
