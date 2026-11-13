# Experiments

This directory contains the simulator and the frozen results used by the
manuscript. See the root [`README.md`](../README.md) for the full reproduction
procedure. The manuscript source itself is not distributed in this repository.

## Files

- `simulator.py` — discrete-time simulator, belief filter, invariants, policies,
  and analytical cost model. Run `python3 simulator.py --help` for options.
- `trace_calibration.py` — fits the IoT-23 network-intensity contrast and writes
  `results/trace_priors.json`. Captures are downloaded to `data/` (gitignored)
  and verified by SHA-256.
- `floor_sensitivity.py` — repeats the Full policy under four I1 floors and
  writes `results/floor_sensitivity.{json,csv}`.
- `make_paper_assets.py` — regenerates every table, figure and
  `results/summary.json` from the frozen CSVs. Tables and figures are written
  to a gitignored `paper/` directory; never edit them by hand.
- `test_simulator.py` — 23 unit tests. Includes exhaustive checks that the
  structural mask matches an independent restatement of I1/I2 for all 243
  actions, that the belief-conditional mask is a subset for a grid of risk
  levels, and that the PEP/fallback paths never emit a below-floor action.
- `results/main.csv` — 800 rows: 10 seeds x 8 scenarios x 10 policies. Paired by
  `(seed, scenario)`.
- `results/summary.json` — authoritative aggregates used to cross-check prose.

## Quick run

```bash
python3 -m unittest -q test_simulator.py
python3 simulator.py --all --seeds 10 --jobs 8 --out results/main.csv
python3 floor_sensitivity.py
python3 make_paper_assets.py
```

The repository root `Makefile` wraps these steps (`make test`, `make matrix`,
`make floor`, `make assets`).

## Determinism

The simulation is deterministic given the seeds. For each `(seed, scenario)` the
observation and request stream is generated once and replayed identically to
every policy, so the policy comparison is paired. The trace bootstrap is seeded
(20261112).

## Data note

The IoT-23 `conn.log.labeled` captures are not redistributed. Their public URLs
and SHA-256 digests are recorded in `results/trace_priors.json`; run
`python3 trace_calibration.py` to fetch and refit. Absolute honeypot rates are
not comparable to per-node application telemetry, so only the benign-to-attack
mean-log-rate contrast is calibrated.
