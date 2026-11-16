#include <stdio.h>
#include <string.h>
#include "track.h"
int main(void)
{
    struct track t;
    track_init(&t, 7, "HAWK");
    if (strcmp(t.callsign, "HAWK") != 0) { printf("FAIL short callsign\n"); return 1; }
    track_init(&t, 9, "LONGCALLSIGN99");
    if (t.guard != TRACK_GUARD) { printf("FAIL guard overwritten\n"); return 1; }
    if (strcmp(t.callsign, "LONGCAL") != 0) { printf("FAIL truncation: '%.8s'\n", t.callsign); return 1; }
    printf("ok\n");
    return 0;
}
