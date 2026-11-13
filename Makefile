PYTHON ?= python3
JOBS ?= 8

.PHONY: all test matrix floor assets paper clean

all: test matrix floor assets paper

test:
	cd experiments && $(PYTHON) -m unittest -q test_simulator.py

matrix:
	cd experiments && $(PYTHON) simulator.py --all --seeds 10 --jobs $(JOBS) --out results/main.csv

floor:
	cd experiments && $(PYTHON) floor_sensitivity.py

assets:
	cd experiments && $(PYTHON) make_paper_assets.py

paper:
	cd paper && $(MAKE) pdf

clean:
	cd paper && $(MAKE) clean
