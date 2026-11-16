/* track.c - track record handling (legacy, 1994) */
#include <string.h>
#include "track.h"

void track_init(struct track *t, int id, const char *callsign)
{
    t->id = id;
    strcpy(t->callsign, callsign);
    t->guard = TRACK_GUARD;
}
