#include <cstdio>
#include "sensor_bus.h"
struct Fixed : Sensor { int v; explicit Fixed(int x) : v(x) {} int read() const { return v; } };
int main()
{
    SensorBus bus;
    bus.attach(new Fixed(3));
    bus.attach(new Fixed(4));
    if (bus.poll_all() != 7) { std::printf("FAIL poll\n"); return 1; }
    std::printf("ok\n");
    return 0;
}
