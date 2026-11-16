#ifndef TRACK_H
#define TRACK_H
#define CALLSIGN_LEN 8          /* 7 chars + NUL */
#define TRACK_GUARD  0x5AA5
struct track {
    int  id;
    char callsign[CALLSIGN_LEN];
    unsigned short guard;
};
void track_init(struct track *t, int id, const char *callsign);
#endif
