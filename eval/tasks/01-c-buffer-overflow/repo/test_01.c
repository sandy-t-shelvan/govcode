#include <stdio.h>
#include <string.h>
#include "track.h"
int main(void)
{
    struct track t;
    track_init(&t, 7, "HAWK");
    if (strcmp(t.callsign, "HAWK") != 0) { printf("FAIL short callsign\n"); return 1; }
    printf("ok\n");
    return 0;
}
