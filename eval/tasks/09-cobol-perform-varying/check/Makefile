test: annual
	./annual > out.txt; cat out.txt; grep -q 'ANNUAL=   7800.00' out.txt

annual: ANNUAL.cbl
	cobc -x -std=default -o annual ANNUAL.cbl

.PHONY: test
