#ifndef SENSOR_H
#define SENSOR_H
/* Read temperature (deg C) on a channel. */
int getTemp(int channel);
int monitor_max(int nchan);
void log_temp(int channel);
#endif
