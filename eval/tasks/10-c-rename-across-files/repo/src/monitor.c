#include "sensor.h"

int monitor_max(int nchan)
{
    int i, m = getTemp(0);
    for (i = 1; i < nchan; i++)
        if (getTemp(i) > m)
            m = getTemp(i);
    return m;
}
