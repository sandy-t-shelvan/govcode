#include <stdio.h>
#include "sensor.h"
int main(void)
{
    if (sensor_read_temp(1) != 21 || monitor_max(3) != 22) { printf("FAIL\n"); return 1; }
    log_temp(2);
    printf("ok\n");
    return 0;
}
