#include <stdio.h>
#include "sensor.h"

void log_temp(int channel)
{
    printf("ch%d=%d\n", channel, getTemp(channel));
}
