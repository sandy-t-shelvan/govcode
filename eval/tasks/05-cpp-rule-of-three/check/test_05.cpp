#include <cstdio>
#include "msgbuf.h"
int main()
{
    MsgBuf a(16);
    a[0] = 'A';
    MsgBuf b(a);
    b[0] = 'B';
    if (a[0] != 'A') { std::printf("FAIL copy ctor is shallow\n"); return 1; }
    MsgBuf c(4);
    c = a;
    c[0] = 'C';
    if (a[0] != 'A' || c.size() != 16) { std::printf("FAIL assignment\n"); return 1; }
    c = c;
    if (c[0] != 'C') { std::printf("FAIL self-assign\n"); return 1; }
    std::printf("ok\n");
    return 0;
}
