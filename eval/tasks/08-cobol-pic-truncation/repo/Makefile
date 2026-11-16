test: intcalc
	./intcalc > out.txt; cat out.txt; grep -q 'INTEREST=    525.00' out.txt

intcalc: INTCALC.cbl
	cobc -x -std=default -o intcalc INTCALC.cbl

.PHONY: test
