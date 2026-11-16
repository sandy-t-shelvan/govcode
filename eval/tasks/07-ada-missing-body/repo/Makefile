test: test_sensors
	./test_sensors

test_sensors: *.ads *.adb
	gnatmake -q -gnata -gnatwa test_sensors.adb -o test_sensors

clean:
	rm -f *.o *.ali test_sensors

.PHONY: test clean
