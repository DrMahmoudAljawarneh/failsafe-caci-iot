# Fail-Safe Context-Adaptive Access Control for Cyber-Physical IoT

Simulator, frozen experiment matrix, and manuscript source for:

> **Fail-Safe Context-Adaptive Access Control with Continuous Risk Belief Updates
> and Hard Safety Invariants for Cyber-Physical IoT**
> Mahmoud Aljawarneh, Applied Science Private University

The paper argues that context adaptation in access control should be allowed to
choose *among* safe actions but must not be allowed to choose *whether* an action
is safe. It formalises four invariants (I1 actuation envelope, I2 safety envelope,
I3 belief-conditional restriction, I4 per-operation fail-safe semantics), a
forward Bayesian belief with cross-modal trust weights, and a node-side PEP
re-check. The evaluation is a paired 24-node discrete-time simulation with eight
scenarios, ten policies and ten seeds, plus a trace-derived calibration of one
network-intensity prior against public IoT-23 captures.

The compiled manuscript is [`paper/main.pdf`](paper/main.pdf) (51 pages).

## Repository layout

| Path | Contents |
|---|---|
| `experiments/simulator.py` | Discrete-time simulator, belief filter, invariants, policies, and analytical cost model |
| `experiments/trace_calibration.py` | Fits the IoT-23 benign/malicious network-intensity contrast |
| `experiments/floor_sensitivity.py` | Repeats the Full policy under four I1 floors |
| `experiments/make_paper_assets.py` | Sole generator of every table, figure and `summary.json` |
| `experiments/test_simulator.py` | 23 unit tests, including the exhaustive I1/I2 mask checks |
| `experiments/results/` | Frozen `main.csv` (800 runs), summaries, floor sweep, trace priors |
| `paper/` | Elsevier `elsarticle` source, sections, generated tables and figures |
| `literature/` | Search log, screening, synthesis matrix, abstracts |

## Reproduce

Requires Python 3.11+ (developed on 3.14), NumPy, SciPy, Matplotlib, and a LaTeX
installation with `latexmk` and `elsarticle`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r experiments/requirements.txt

make test     # 23 unit tests
make all      # matrix -> floor sweep -> tables/figures -> PDF
```

`make all` takes about one to two minutes on eight cores. To change the
parallelism, use `make matrix JOBS=4`. The individual steps are:

```bash
make test
make matrix   # experiments/results/main.csv, 10 seeds x 8 scenarios x 10 policies
make floor    # experiments/results/floor_sensitivity.json
make assets   # paper/tables/*.tex, paper/figures/*, experiments/results/summary.json
make paper    # paper/main.pdf
```

The trace priors used by the simulator are committed as
`experiments/results/trace_priors.json`, so no network access is needed for
`make all`. To refit them from the public captures:

```bash
cd experiments
python3 trace_calibration.py          # downloads if needed, verifies SHA-256
python3 trace_calibration.py --no-download
```

The three IoT-23 `conn.log.labeled` files are **not redistributed**; the script
downloads them from the public CTU mirror into `experiments/data/` (gitignored)
and records their URLs and SHA-256 digests in `trace_priors.json`.

## Determinism

Every run is seeded. For a given `(seed, scenario)`, the observation and request
stream is generated once and replayed byte-identically to every policy, so all
policy comparisons are paired. The matrix is deterministic given the seeds; the
only stochastic post-processing is the trace bootstrap, which is seeded.

## Headline results (from `experiments/results/summary.json`)

- Invariant violations per 1,000 decisions: **0** for every policy that enforces
  I1/I2 in all eight scenarios, versus **327.41** for unconstrained Risk-Only and
  **393.31** for Static-Low.
- Mean attack-scenario utility: **0.120** for Full, **0.084** for Static-High,
  **0.077** for Threshold-CAAC.
- Residual malicious-grant rate: **0.177** for Full, **0.127** for Static-High.
  The gap is concentrated in the out-of-model `tee` scenario, where the node TEE
  is subverted (0.473 malicious grants, Brier 0.437, poisoning AUROC 0.273).
- In-model downgrade (network/security spoofed, attested anchor retained):
  Brier **0.003**, belief AUROC **1.000**.

These numbers are generated from `main.csv`; the manuscript contains no
hand-typed experimental values in its tables and figures.

## Scope and caveats

- This is a **simulation study**, not a deployment. Latency, energy and footprint
  are analytical model outputs from datasheet-level operation costs.
- The generator and the defender share emission parameters, so calibration and
  detection are an **oracle-model upper bound**, not a misspecified-defender
  estimate. This is stated in the paper.
- The `tee` scenario is deliberately out of the stated threat model: it asks what
  happens when the attestation anchor itself is subverted. The invariant
  guarantee survives; belief quality does not.
- Safety requests in the simulator are legitimate, so the reported safety-denial
  rate is a mechanism false-positive floor, not an adversarial denial-of-safety
  test.
- No multivariate or learned detector baseline is evaluated; Threshold is a
  univariate point estimate raised to the structural floor.

## Citation

```bibtex
@misc{aljawarneh2026failsafe,
  author       = {Aljawarneh, Mahmoud},
  title        = {Fail-Safe Context-Adaptive Access Control with Continuous Risk
                  Belief Updates and Hard Safety Invariants for Cyber-Physical IoT},
  year         = {2026},
  note         = {Preprint and reproducibility artifact},
  howpublished = {\url{https://github.com/DrMahmoudAljawarneh/failsafe-caci-iot}}
}
```

A `CITATION.cff` is included for GitHub's citation widget.

## License

The code in `experiments/` is released under the MIT License (see `LICENSE`).
The manuscript source, figures and compiled PDF in `paper/` are © Mahmoud
Aljawarneh and are provided for inspection and reproducibility; please cite the
paper if you use them. The IoT-23 captures remain subject to their original
terms and are downloaded, not redistributed.
