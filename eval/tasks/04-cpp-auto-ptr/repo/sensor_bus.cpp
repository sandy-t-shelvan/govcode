// sensor_bus.cpp - sensor registry (C++98)
#include "sensor_bus.h"

SensorBus::SensorBus() : count_(0) {}

void SensorBus::attach(Sensor* s)
{
    if (count_ < kMax) {
        std::auto_ptr<Sensor> p(s);
        slots_[count_++] = p;
    } else {
        delete s;
    }
}

int SensorBus::poll_all() const
{
    int total = 0;
    for (int i = 0; i < count_; ++i)
        total += slots_[i]->read();
    return total;
}
