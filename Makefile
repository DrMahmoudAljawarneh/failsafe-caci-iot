PYTHON ?= python3
JOBS ?= 8

.PHONY: all test matrix floor assets clean

all: test matrix floor assets

test:
	cd experiments && $(PYTHON) -m unittest -q test_simulator.py

matrix:
	cd experiments && $(PYTHON) simulator.py --all --seeds 10 --jobs $(JOBS) --out results/main.csv

floor:
	cd experiments && $(PYTHON) floor_sensitivity.py

assets:
	cd experiments && $(PYTHON) make_paper_assets.py

clean:
	rm -rf experiments/__pycache__ experiments/.pytest_cache paper/tables paper/figures
