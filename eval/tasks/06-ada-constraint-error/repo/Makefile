test: test_nav
	./test_nav

test_nav: *.ads *.adb
	gnatmake -q -gnata -gnatwa test_nav.adb -o test_nav

clean:
	rm -f *.o *.ali test_nav

.PHONY: test clean
