#ifndef SENSOR_BUS_H
#define SENSOR_BUS_H
#include <memory>

class Sensor {
public:
    virtual ~Sensor() {}
    virtual int read() const = 0;
};

class SensorBus {
public:
    static const int kMax = 8;
    SensorBus();
    void attach(Sensor* s);      // takes ownership
    int poll_all() const;
    int count() const { return count_; }
private:
    std::auto_ptr<Sensor> slots_[kMax];
    int count_;
};
#endif
