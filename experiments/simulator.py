#!/usr/bin/env python3
"""Fail-safe context-adaptive access control (CAAC) simulator.

This is the *parameterized discrete-time simulation* used in the paper. It is not a
replay of an IoT dataset: it generates a synthetic 24-node cyber-physical deployment,
with a latent threat state, four context modalities, adaptive context poisoning, and
per-request access decisions. Flow statistics from the public IoT-23 capture are used
only to calibrate the benign/malicious traffic-intensity priors (see
experiments/trace_calibration.py and experiments/results/trace_priors.json).

Everything is seeded: for a given (seed, scenario), the observation and request stream
is generated once and replayed to every policy, so policy comparisons are paired.

Usage
-----
    python3 simulator.py --all --seeds 10 --jobs 8 --out results/main.csv
    python3 simulator.py --scenario downgrade --policy full --seed 1 --trace results/trace.csv
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import math
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field

import numpy as np

# --------------------------------------------------------------------------------------
# Latent threat states and context features
# --------------------------------------------------------------------------------------

THETA = ["benign", "recon", "dos", "byzantine", "compromised"]
N_THETA = len(THETA)

FEATURES = [
    "battery",      # 0
    "cpu",          # 1
    "temp",         # 2
    "log_pkt",      # 3  log1p(packets/s)
    "loss",         # 4
    "log_rtt",      # 5  log(ms)
    "anomaly",      # 6
    "failed_auth",  # 7
    "dispersion",   # 8  cross-node IQR (Byzantine signal)
]
N_FEAT = len(FEATURES)

# Per-state emission means and standard deviations. These are the defender's model of
# what each context modality looks like under each threat state. They are deliberately
# overlapping: the classes are not separable with certainty.
#
# The network-intensity column (log_pkt) is anchored on the IoT-23 trace calibration:
# the benign mean is a design baseline (absolute rates in a sparse honeypot capture are
# not comparable to per-node application telemetry), while the DoS mean is set to
# 4.20 + 1.689, the measured within-capture benign->malicious mean-log-rate
# contrast (per-capture values 1.131 and 2.570; experiments/results/trace_priors.json).
MU = np.array([
    # battery  cpu   temp  log_pkt loss  log_rtt anomaly failed disp
    [0.72,   0.30, 39.0,  4.20,  0.05,  3.00,   0.07,   0.4,   0.065],  # benign
    [0.70,   0.34, 40.0,  4.45,  0.07,  3.10,   0.30,   2.8,   0.064],  # recon
    [0.55,   0.72, 52.0,  5.889, 0.35,  5.00,   0.62,   1.2,   0.065],  # dos
    [0.72,   0.32, 39.5,  4.30,  0.06,  3.05,   0.10,   0.6,   0.135],  # byzantine
    [0.45,   0.55, 47.0,  4.80,  0.12,  3.40,   0.45,   1.5,   0.065],  # compromised
])
SD = np.array([
    [0.12,   0.12,  4.0,  0.50,  0.06,  0.40,   0.07,   0.7,   0.012],
    [0.12,   0.12,  4.0,  0.55,  0.06,  0.42,   0.14,   1.5,   0.012],
    [0.15,   0.13,  5.0,  0.55,  0.10,  0.55,   0.15,   1.2,   0.012],
    [0.12,   0.12,  4.0,  0.50,  0.06,  0.40,   0.10,   1.2,   0.045],
    [0.15,   0.14,  5.0,  0.55,  0.08,  0.45,   0.16,   1.4,   0.012],
])

MODALITIES = {
    "dev": [0, 1, 2],
    "net": [3, 4, 5],
    "sec": [6, 7],
    "cross": [8],
}

# Per-node measurement noise (used to build the reports the gateway aggregates).
NODE_SD = np.array([0.05, 0.06, 1.2, 0.25, 0.03, 0.20, 0.04, 0.70, 0.000])

# Threat-state transition matrix: rows = from, columns = to. Persistent states.
T = np.full((N_THETA, N_THETA), 0.045)
np.fill_diagonal(T, 0.82)
T /= T.sum(axis=1, keepdims=True)

# --------------------------------------------------------------------------------------
# Action space: auth x crypto x ids x rate x freshness
# --------------------------------------------------------------------------------------

AUTH = [("token", 1, 0.60, 0.020), ("mutual", 2, 1.40, 0.050), ("attest", 3, 2.60, 0.120)]
CRYPTO = [("none", 0, 0.00, 0.000), ("aes-gcm", 2, 0.90, 0.350), ("ascon", 2, 0.45, 0.120)]
IDS = [("off", 0, 0.00, 0.000), ("header", 1, 0.50, 0.100), ("deep", 2, 1.80, 0.600)]
RATE = [("unlimited", 0, 0.00, 0.000), ("bucket50", 1, 0.20, 0.020), ("bucket10", 2, 0.60, 0.050)]
TTL = [("300s", 0, 0.00, 0.010), ("60s", 1, 0.10, 0.010), ("10s", 2, 0.25, 0.010)]

ACTIONS = list(itertools.product(range(3), range(3), range(3), range(3), range(3)))
N_ACTION = len(ACTIONS)  # 243
DENY = N_ACTION

ACTION_LEVELS = np.array([[AUTH[a][1], CRYPTO[c][1], IDS[i][1], RATE[r][1], TTL[t][1]]
                          for a, c, i, r, t in ACTIONS], dtype=float)
ACTION_SEC = ACTION_LEVELS.sum(axis=1)  # 0..13 ordinal, used only for hysteresis
ACTION_LAT = np.array([AUTH[a][2] + CRYPTO[c][2] + IDS[i][2] + RATE[r][2] + TTL[t][2] + 0.30
                       for a, c, i, r, t in ACTIONS])
ACTION_ENERGY = np.array([AUTH[a][3] + CRYPTO[c][3] + IDS[i][3] + RATE[r][3] + TTL[t][3] + 0.03
                          for a, c, i, r, t in ACTIONS])

# Detection probability of a malicious (credential-holding) request, per layer.
P_AUTH_DETECT = np.array([0.02, 0.18, 0.45])   # token, mutual, attest
P_IDS_DETECT = np.array([0.00, 0.45, 0.70])    # off, header, deep
P_RATE_DETECT = np.array([0.00, 0.15, 0.40])   # unlimited, 50/s, 10/s
P_BASE_DETECT = 0.05                            # request validation present in every policy

# False-positive / friction probabilities for legitimate requests.
P_AUTH_FAIL = np.array([0.003, 0.008, 0.020])
P_IDS_FP = np.array([0.000, 0.005, 0.020])
P_RATE_DROP = np.array([0.000, 0.010, 0.050])

# State-dependent multipliers on IDS/rate detection.
DET_MULT = {
    "recon": (0.8, 0.5),
    "dos": (1.0, 1.0),
    "byzantine": (0.6, 0.4),
    "compromised": (0.5, 0.5),
}


def _detect_table():
    """p_detect[theta, action] for malicious requests (theta 0 is unused)."""
    table = np.zeros((N_THETA, N_ACTION))
    for k in range(N_ACTION):
        a, c, i, r, t = ACTIONS[k]
        for th in range(1, N_THETA):
            m_ids, m_rate = DET_MULT[THETA[th]]
            p_miss = (1.0 - P_BASE_DETECT)
            p_miss *= (1.0 - P_AUTH_DETECT[a])
            p_miss *= (1.0 - min(0.99, P_IDS_DETECT[i] * m_ids))
            p_miss *= (1.0 - min(0.99, P_RATE_DETECT[r] * m_rate))
            table[th, k] = 1.0 - p_miss
    return table


P_DETECT = _detect_table()
P_FALSE_DENY = np.array([
    1.0 - (1.0 - P_AUTH_FAIL[a]) * (1.0 - P_IDS_FP[i]) * (1.0 - P_RATE_DROP[r])
    for a, c, i, r, t in ACTIONS
])

# Utility parameters (value units; normalised by V_MAX for reporting).
VALUE = {"read": 0.2, "write": 0.6, "actuate": 1.0, "safety": 4.0}
DENY_COST = {"read": 0.05, "write": 0.20, "actuate": 1.5, "safety": 5.0}
DAMAGE = {"read": 0.3, "write": 1.5, "actuate": 8.0, "safety": 12.0}
V_MAX = 4.0
P_MALICIOUS = 0.35
SAFETY_PENALTY = 6.0   # utility cost of executing an invariant-violating action

# Cost weights in the objective.
LAMBDA_ENERGY = 0.15
LAMBDA_LATENCY = 0.02
GAMMA_SWITCH = 0.05
SWITCH_MARGIN = 0.06   # utility margin required for a lateral/de-escalating change

# Invariant thresholds.
TAU_RISK = 0.55       # above this, require IDS>=header and rate<=50/s (non-safety)
TAU_HIGH = 0.90       # above this, require mutual auth + AEAD + inspection (non-safety)
TAU_UP = 0.60         # hysteresis escalation threshold
TAU_DOWN = 0.30       # hysteresis de-escalation threshold
DWELL = 25            # epochs of low risk before de-escalation

N_NODES = 24
N_COMPROMISED = 10    # f < N/2
NODE_NOISE = NODE_SD

# Hardware tier multipliers: Class-1 MCU, Class-2 MCU, edge gateway.
TIER_MULT = np.array([1.00, 0.60, 0.35])
TIER_PROB = np.array([0.55, 0.30, 0.15])


# --------------------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------------------

@dataclass
class Request:
    op: str
    malicious: bool
    node: int
    tier: int
    u_detect: float
    u_fp: float


@dataclass
class Epoch:
    t: int
    theta: int
    x_med: np.ndarray
    x_mean: np.ndarray
    requests: list[Request]
    poisoned: bool
    byzantine: bool


@dataclass
class Result:
    policy: str
    run: int
    scenario: str
    decisions: int = 0
    inv_violations: int = 0
    malicious_total: int = 0
    malicious_granted: int = 0
    benign_total: int = 0
    benign_denied: int = 0
    benign_granted: int = 0
    safety_total: int = 0
    safety_denied: int = 0
    utility_sum: float = 0.0
    switches: int = 0
    latencies: list[float] = field(default_factory=list)
    energies: list[float] = field(default_factory=list)
    brier_sum: float = 0.0
    brier_n: int = 0
    ece_bins: np.ndarray = field(default_factory=lambda: np.zeros((10, 3)))
    det_scores: list[float] = field(default_factory=list)
    det_labels: list[int] = field(default_factory=list)
    inv_by_op: dict = field(default_factory=lambda: {"read": 0, "write": 0,
                                                     "actuate": 0, "safety": 0})
    decisions_by_op: dict = field(default_factory=lambda: {"read": 0, "write": 0,
                                                           "actuate": 0, "safety": 0})

    def row(self):
        n = max(1, self.decisions)
        brier = self.brier_sum / self.brier_n if self.brier_n else float("nan")
        lat = np.array(self.latencies) if self.latencies else np.array([0.0])
        eng = np.array(self.energies) if self.energies else np.array([0.0])
        return {
            "policy": self.policy,
            "run": self.run,
            "scenario": self.scenario,
            "decisions": self.decisions,
            "ivr_per_1k": 1000.0 * self.inv_violations / n,
            "ivr_readwrite_per_1k": 1000.0 * (self.inv_by_op["read"] + self.inv_by_op["write"])
                                    / max(1, self.decisions_by_op["read"] + self.decisions_by_op["write"]),
            "ivr_actuate_per_1k": 1000.0 * self.inv_by_op["actuate"]
                                  / max(1, self.decisions_by_op["actuate"]),
            "ivr_safety_per_1k": 1000.0 * self.inv_by_op["safety"]
                                 / max(1, self.decisions_by_op["safety"]),
            "unsafe_grant": self.malicious_granted / max(1, self.malicious_total),
            "false_deny": self.benign_denied / max(1, self.benign_total),
            "legit_grant": self.benign_granted / max(1, self.benign_total),
            "safety_denied": self.safety_denied / max(1, self.safety_total),
            "utility": self.utility_sum / n / V_MAX,
            "brier": brier,
            "ece": float("nan"),
            "poison_auroc": 0.0,   # filled by metrics()
            "poison_tpr1": 0.0,
            "belief_auroc": 0.0,
            "belief_tpr1": 0.0,
            "switches_per_1k": 1000.0 * self.switches / n,
            "p50_ms": float(np.percentile(lat, 50)),
            "p99_ms": float(np.percentile(lat, 99)),
            "energy_mj": float(eng.mean()),
            "sram_kb": 0.0,
            "flash_kb": 0.0,
        }


# --------------------------------------------------------------------------------------
# Stream generation (policy independent)
# --------------------------------------------------------------------------------------

def _windows(rng, epochs, n_windows=3, lo=250, hi=350):
    """Non-overlapping attack windows, returned as (start, end) pairs.

    The defaults are sized for the 2,000-epoch runs used in the paper. Shorter
    streams (used by the unit tests) get proportionally shorter windows.
    """
    if epochs < 900:
        n_windows = max(1, min(n_windows, epochs // 300))
        length = max(20, min(hi, (epochs - 80) // (n_windows + 1)))
        starts = []
        for _ in range(n_windows):
            s = int(rng.integers(5, max(6, epochs - length - 5)))
            for _try in range(50):
                if all(abs(s - x) > length + 10 for x in starts):
                    break
                s = int(rng.integers(5, max(6, epochs - length - 5)))
            starts.append(s)
        return [(s, s + length) for s in sorted(starts)]

    length = int(rng.integers(lo, hi))
    starts = []
    for _ in range(n_windows):
        s = int(rng.integers(150, epochs - length - 50))
        for _try in range(50):
            if all(abs(s - x) > length + 60 for x in starts):
                break
            s = int(rng.integers(150, epochs - length - 50))
        starts.append(s)
    return [(s, s + length) for s in sorted(starts)]


def _in_window(t, windows):
    return any(a <= t < b for a, b in windows)


def _sample_x(rng, theta):
    x = rng.normal(MU[theta], SD[theta])
    x[0] = np.clip(x[0], 0.02, 1.0)
    x[1] = np.clip(x[1], 0.01, 1.0)
    x[4] = np.clip(x[4], 0.0, 1.0)
    x[6] = np.clip(x[6], 0.0, 1.0)
    x[7] = max(0.0, x[7])
    x[8] = max(0.005, x[8])
    return x


def _observe(rng, theta, byzantine):
    """Generate node reports, return (median aggregate, mean aggregate, dispersion)."""
    true = _sample_x(rng, theta)
    reports = true[None, :] + rng.normal(0.0, NODE_NOISE, (N_NODES, N_FEAT))
    if byzantine:
        fake = _sample_x(rng, 0)
        reports[:N_COMPROMISED] = fake[None, :] + rng.normal(
            0.0, NODE_NOISE * 0.5, (N_COMPROMISED, N_FEAT))
    x_med = np.median(reports, axis=0)
    x_mean = reports.mean(axis=0)
    disp = float(np.mean([
        np.percentile(reports[:, 0], 75) - np.percentile(reports[:, 0], 25),
        (np.percentile(reports[:, 3], 75) - np.percentile(reports[:, 3], 25)) / 4.0,
        np.percentile(reports[:, 6], 75) - np.percentile(reports[:, 6], 25),
    ]))
    x_med[8] = disp
    x_mean[8] = disp
    return x_med, x_mean


def _blend_to_benign(x, strength):
    return (1.0 - strength) * x + strength * MU[0]


def _poison(x, kind, t, rng, rng_replay, epoch_store):
    if kind == "downgrade":
        # In-model downgrade: the network and security modalities are spoofed, but
        # the attested device modality and cross-node dispersion are retained.
        y = x.copy()
        idx = [3, 4, 5, 6, 7]
        y[idx] = (1.0 - 0.92) * x[idx] + 0.92 * MU[0, idx]
        y[6] = min(y[6], 0.12)
        y[7] = min(y[7], 0.8)
        return y
    if kind == "tee":
        # Explicit TEE-compromise stress test: even the attested anchor is spoofed.
        y = _blend_to_benign(x, 0.92)
        y[6] = min(y[6], 0.12)
        y[7] = min(y[7], 0.8)
        return y
    if kind == "energy":
        y = x.copy()
        y[6] = max(y[6], 0.80)
        y[7] = max(y[7], 6.8)
        y[3] = max(y[3], 5.4)
        y[4] = max(y[4], 0.55)
        return y
    if kind == "replay":
        return epoch_store[max(0, t - 300)].copy()
    return x


def _op_for_node(rng, node):
    role = "sensor" if node < 8 else ("actuator" if node < 16 else "mixed")
    if role == "sensor":
        p = [0.80, 0.15, 0.05, 0.00]
    elif role == "actuator":
        p = [0.10, 0.20, 0.55, 0.15]
    else:
        p = [0.40, 0.30, 0.20, 0.10]
    return rng.choice(["read", "write", "actuate", "safety"], p=p)


def generate_stream(seed, scenario, epochs):
    """Generate the observation/request stream for one (seed, scenario)."""
    rng = np.random.default_rng(seed * 100_000 + SCENARIOS.index(scenario))
    windows = _windows(rng, epochs)
    stream = []
    benign_history = []

    for t in range(epochs):
        in_win = _in_window(t, windows)
        poisoned = False
        byzantine = False
        poison_kind = None

        if scenario == "none":
            theta = 1 if rng.random() < 0.01 else 0
        elif scenario == "dos":
            theta = 2 if in_win else (1 if rng.random() < 0.01 else 0)
        elif scenario == "downgrade":
            theta = 2 if in_win else (1 if rng.random() < 0.01 else 0)
            poisoned = in_win
            poison_kind = "downgrade"
        elif scenario == "tee":
            # The compromised latent state, with the attestation anchor subverted.
            theta = 4 if in_win else (1 if rng.random() < 0.01 else 0)
            poisoned = in_win
            poison_kind = "tee"
        elif scenario == "energy":
            theta = 0
            poisoned = in_win
            poison_kind = "energy"
        elif scenario == "byzantine":
            theta = 3 if in_win else 0
            byzantine = in_win
            poisoned = in_win
        elif scenario == "resonant":
            theta = 2 if in_win else 0
            poisoned = in_win
            poison_kind = "resonant"  # resolved below
        elif scenario == "adaptive":
            theta = 2 if in_win else 0
            poisoned = in_win
            poison_kind = "adaptive"
        else:
            raise ValueError("unknown scenario " + scenario)

        x_med, x_mean = _observe(rng, theta, byzantine)
        benign_history.append(x_med.copy())

        if poisoned and poison_kind:
            if poison_kind == "resonant":
                kind = "downgrade" if (t // DWELL) % 2 == 0 else "energy"
                x_med = _poison(x_med, kind, t, rng, rng, benign_history)
                x_mean = _poison(x_mean, kind, t, rng, rng, benign_history)
            elif poison_kind == "adaptive":
                elapsed = t - min(a for a, b in windows if a <= t < b) if in_win else 0
                # Progressive spoof, then hold the anomaly just below the public
                # point-estimate threshold (0.55). The attacker does not solve the
                # defender's POMDP, but it does evade the threshold baseline.
                strength = min(0.95, 0.30 + 0.65 * min(1.0, elapsed / 600.0))
                x_med = _blend_to_benign(x_med, strength)
                x_mean = _blend_to_benign(x_mean, strength)
                x_med[6] = min(x_med[6], 0.54)
                x_mean[6] = min(x_mean[6], 0.54)
            else:
                x_med = _poison(x_med, poison_kind, t, rng, rng, benign_history)
                x_mean = _poison(x_mean, poison_kind, t, rng, rng, benign_history)

        n_req = rng.poisson(2.2)
        requests = []
        for _ in range(n_req):
            node = int(rng.integers(0, N_NODES))
            op = _op_for_node(rng, node)
            malicious = False
            if scenario in ("dos", "downgrade", "tee", "byzantine", "resonant",
                            "adaptive") and in_win:
                if op != "safety" and rng.random() < P_MALICIOUS:
                    malicious = True
                    op = "actuate" if rng.random() < 0.7 else "write"
            requests.append(Request(op=op, malicious=malicious, node=node,
                                     tier=int(rng.choice(3, p=TIER_PROB)),
                                     u_detect=float(rng.random()), u_fp=float(rng.random())))

        stream.append(Epoch(t=t, theta=theta, x_med=x_med, x_mean=x_mean,
                            requests=requests, poisoned=poisoned, byzantine=byzantine))
    return stream


# --------------------------------------------------------------------------------------
# Belief and trust
# --------------------------------------------------------------------------------------

def _loglik(x):
    """(n_modalities, n_states) log-likelihood of one observation."""
    ll = np.zeros((len(MODALITIES), N_THETA))
    for m, idxs in enumerate(MODALITIES.values()):
        for j in idxs:
            ll[m] += -0.5 * ((x[j] - MU[:, j]) / SD[:, j]) ** 2 - np.log(SD[:, j])
    return ll


def _softmax(logits):
    z = logits - logits.max()
    e = np.exp(z)
    return e / e.sum()


def _posterior(ll, prior):
    """Per-modality posterior over latent states; ll has shape (..., N_THETA)."""
    z = np.log(prior + 1e-12) + ll
    z = z - z.max(axis=-1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=-1, keepdims=True)


# Trust calibration: a modality whose posterior is within TV_DIST of the device
# anchor is trusted; beyond TV_SPAN it is effectively discarded. The benign 95th
# percentile of the anchor distance is ~0.18 (see trace_prior diagnostics).
TV_DIST = 0.25
TV_SPAN = 0.06
# Dispersion calibration: benign cross-node IQR is ~0.065 (95th pct ~0.08).
DISP_LO = 0.09
DISP_SPAN = 0.16


def precompute_beliefs(stream):
    """Return the belief sequences used by the policies (all policy independent).

    The fused belief is a forward HMM filter whose per-modality log-likelihoods are
    weighted by how far each modality's posterior has drifted from the device
    (attestation-anchor) posterior. Cross-node dispersion is kept at full weight and
    is also exposed as a standalone consistency score.
    """
    n = len(stream)
    b_full = np.zeros((n, N_THETA))
    b_equal = np.zeros((n, N_THETA))
    trust = np.zeros((n, len(MODALITIES)))
    det_score = np.zeros(n)

    prior0 = np.array([0.85, 0.03, 0.05, 0.04, 0.03])
    b_prev = prior0.copy()
    b_eq_prev = prior0.copy()
    w_prev = np.ones(len(MODALITIES))
    for i, ep in enumerate(stream):
        ll_med = _loglik(ep.x_med)
        q = _posterior(ll_med, prior0)
        # Total-variation distance of each modality posterior from the device anchor.
        tv = 0.5 * np.abs(q - q[0]).sum(axis=1)
        w_now = 1.0 / (1.0 + np.exp((tv - TV_DIST) / TV_SPAN))
        w_now[0] = 1.0   # device telemetry is the attestation anchor
        w_now[3] = 1.0   # cross-node dispersion is always retained
        # Distrust quickly, restore slowly (asymmetric trust update).
        w = np.where(w_now < w_prev, 0.2 * w_prev + 0.8 * w_now,
                     0.9 * w_prev + 0.1 * w_now)
        w = np.clip(w, 0.0, 1.0)
        w_prev = w
        trust[i] = w

        disp_score = float(np.clip((ep.x_med[8] - DISP_LO) / DISP_SPAN, 0.0, 1.0))
        det_score[i] = float(min(1.0, max(float(tv.max()), disp_score)))

        prior = T.T @ b_prev
        wlog = (w[:, None] * ll_med).sum(axis=0)
        b_full[i] = _softmax(np.log(prior + 1e-12) + wlog)

        prior_e = T.T @ b_eq_prev
        b_equal[i] = _softmax(np.log(prior_e + 1e-12) + ll_med.sum(axis=0))
        b_prev = b_full[i]
        b_eq_prev = b_equal[i]

    return b_full, b_equal, trust, det_score


# --------------------------------------------------------------------------------------
# Decision policies
# --------------------------------------------------------------------------------------

STATIC_HIGH = next(k for k, v in enumerate(ACTIONS) if v == (2, 2, 2, 2, 2))
STATIC_MED = next(k for k, v in enumerate(ACTIONS) if v == (1, 1, 1, 1, 1))
STATIC_LOW = next(k for k, v in enumerate(ACTIONS) if v == (0, 0, 0, 0, 0))
THRESH_HIGH = STATIC_HIGH

# Precomputed utility by op: u[op] shape (N_THETA, N_ACTION)
U_TABLE = {}
for op in VALUE:
    u = np.zeros((N_THETA, N_ACTION))
    for th in range(N_THETA):
        pmal = P_MALICIOUS if th != 0 else 0.0
        if op == "safety":
            pmal = 0.0
        for k in range(N_ACTION):
            pdet = P_DETECT[th, k] if th != 0 else 0.0
            pf = P_FALSE_DENY[k]
            u[th, k] = (pmal * (-(1.0 - pdet) * DAMAGE[op])
                        + (1.0 - pmal) * (VALUE[op] * (1.0 - pf) - DENY_COST[op] * pf))
    U_TABLE[op] = u


def _cost_vector(op):
    # Latency and energy are converted to utility units; the tier mix is averaged.
    mult = float(TIER_PROB @ TIER_MULT)
    return LAMBDA_LATENCY * ACTION_LAT * mult + LAMBDA_ENERGY * ACTION_ENERGY * mult


COST = {op: _cost_vector(op) for op in VALUE}


def _structural_mask(op):
    """Unconditional invariants I1/I2 (independent of the belief)."""
    fl = floor_levels(op)
    return np.all(ACTION_LEVELS >= fl[None, :], axis=1)


def _attack_prob(b):
    """Probability of a serious attack state (DoS, Byzantine, compromised)."""
    return float(b[2] + b[3] + b[4])


def _invariant_mask(op, b_attack):
    """Admissible set: unconditional invariants plus belief-conditional restriction I3."""
    auth = ACTION_LEVELS[:, 0]
    cry = ACTION_LEVELS[:, 1]
    ids = ACTION_LEVELS[:, 2]
    rate = ACTION_LEVELS[:, 3]
    ok = _structural_mask(op).copy()

    # I3: distrust restricts non-safety operations.
    if b_attack >= TAU_RISK and op != "safety":
        ok &= (ids >= 1) & (rate >= 1)
    # I3 (strong): above the high-risk threshold non-safety operations require
    # mutual authentication, AEAD, and inspection. They are not globally denied:
    # availability is preserved by escalating the posture, not by failing closed.
    if b_attack >= TAU_HIGH and op != "safety":
        ok &= (auth >= 2) & (cry >= 2) & (ids >= 1) & (rate >= 1)
    return ok


def _deny_allowed(op, b_attack):
    """Deny is admissible for non-safety traffic only; safety needs fail-safe-allow."""
    return op != "safety"


# Structural floor per operation class, as action-space indices
# (auth, crypto, ids, rate, ttl). These are the operational reading of I1/I2 and are
# the *minimum* posture; the controller may choose a stronger one. `floor_sensitivity.py`
# varies the actuation floor to measure the exposure/utility trade-off.
STRUCT_FLOOR = {
    "read":    (0, 0, 0, 0, 0),
    "write":   (0, 0, 0, 0, 0),
    "actuate": (1, 1, 1, 0, 1),
    "safety":  (1, 1, 2, 0, 1),
}
ACTION_INDEX = {v: k for k, v in enumerate(ACTIONS)}
A_MAX = ACTION_INDEX[(2, 2, 2, 2, 2)]
# I4: fail-closed for confidentiality/integrity, fail-safe-allow for safety.
SAFE_FALLBACK = {"read": DENY, "write": DENY, "actuate": DENY, "safety": A_MAX}
# Policies that install the node-side PEP re-check. The unconstrained baselines do
# not, so their violations measure what the PEP is worth.
PEP_POLICIES = {"threshold", "invariant_only", "full_no_hyst",
                "full_no_consistency", "full", "oracle"}


def floor_levels(op):
    """Invariant floor expressed as security levels (not action indices)."""
    return ACTION_LEVELS[ACTION_INDEX[STRUCT_FLOOR[op]]]


def _safe_static(op, level):
    """A static posture of the given strength, raised to the operation's floor.

    Used by the threshold baseline so that a well-intentioned CAAC is not a
    strawman: it may adapt, but it never selects a structurally unsafe action.
    """
    fl = STRUCT_FLOOR[op]
    idx = tuple(max(min(level, 2), f) for f in fl)
    return ACTION_INDEX[idx]


def _score_actions(op, b, prev_sec=None, mask=None, allow_deny=True,
                   prev_action=None, margin=0.0):
    if mask is not None and not mask.any():
        return SAFE_FALLBACK[op], -1e9
    scores = b @ U_TABLE[op] - COST[op]
    if prev_action is not None and 0 <= prev_action < N_ACTION:
        scores = scores - GAMMA_SWITCH * (np.arange(N_ACTION) != prev_action)
    if mask is not None:
        scores = np.where(mask, scores, -1e9)
    if prev_sec is not None:
        # Asymmetric hysteresis: never de-escalate below the current posture.
        scores = np.where(ACTION_SEC >= prev_sec, scores, -1e9)
    best = int(np.argmax(scores))
    best_score = float(scores[best])

    # Utility margin: a lateral move or a de-escalation must win by `margin`;
    # an escalation is taken immediately. This is the anti-thrashing control.
    if (margin > 0.0 and prev_action is not None and prev_action < N_ACTION
            and scores[prev_action] > -1e8
            and ACTION_SEC[best] <= ACTION_SEC[prev_action]
            and best_score < scores[prev_action] + margin):
        best = int(prev_action)
        best_score = float(scores[best])

    deny_score = -1e9
    if allow_deny:
        # Request-level probability of malice: the epoch may be under attack, but a
        # given request is malicious only with the base rate. Denying is therefore
        # costly whenever legitimate traffic is still arriving.
        p_mal_req = (1.0 - float(b[0])) * P_MALICIOUS
        deny_score = -(1.0 - p_mal_req) * DENY_COST[op]
    if deny_score > best_score:
        return DENY, deny_score
    return best, best_score


def decide(policy, ep, b, b_eq, trust, z_point, prev_sec, low_streak, prev_action):
    """Return (action_index, security_level) for each request in the epoch."""
    out = []
    if policy == "static_high":
        return [(STATIC_HIGH, ACTION_SEC[STATIC_HIGH]) for _ in ep.requests]
    if policy == "static_med":
        return [(_safe_static(q.op, 1), ACTION_SEC[_safe_static(q.op, 1)]) for q in ep.requests]
    if policy == "static_low":
        return [(STATIC_LOW, ACTION_SEC[STATIC_LOW]) for _ in ep.requests]
    if policy == "threshold":
        z = ep.x_mean[6]
        level = 2 if z > 0.55 else (1 if z > 0.30 else 0)
        for q in ep.requests:
            act = _safe_static(q.op, level)
            out.append((act, ACTION_SEC[act]))
        return out

    if policy == "risk_only":
        for q in ep.requests:
            a, _ = _score_actions(q.op, b, prev_action=prev_action.get(q.op))
            out.append((a, ACTION_SEC[a] if a != DENY else 0.0))
        return out

    if policy == "invariant_only":
        b_attack = float(z_point)
        beff = np.zeros(N_THETA)
        beff[0] = 1.0 - b_attack
        beff[2] = b_attack
        for q in ep.requests:
            mask = _invariant_mask(q.op, b_attack)
            a, _ = _score_actions(q.op, beff, prev_sec.get(q.op), mask,
                                  _deny_allowed(q.op, b_attack),
                                  prev_action.get(q.op))
            out.append((a, ACTION_SEC[a] if a != DENY else 0.0))
        return out

    # Full and ablations
    if policy == "oracle":
        beff = np.zeros(N_THETA)
        beff[ep.theta] = 1.0
        b_attack = _attack_prob(beff)
    else:
        if policy == "full_no_consistency":
            beff = b_eq
        else:
            beff = b
        b_attack = _attack_prob(beff)

    for q in ep.requests:
        mask = _invariant_mask(q.op, b_attack)
        # The dwell floor applies only while risk is decaying through the hysteresis
        # band. Once risk is clearly low, the posture may relax (subject to margin),
        # so the controller does not over-provision benign traffic after an attack.
        psec = None
        if (policy != "full_no_hyst" and low_streak < DWELL
                and TAU_DOWN <= b_attack < TAU_UP):
            psec = prev_sec.get(q.op)
        margin = 0.0 if policy == "full_no_hyst" else SWITCH_MARGIN
        a, _ = _score_actions(q.op, beff, psec, mask, _deny_allowed(q.op, b_attack),
                              prev_action.get(q.op), margin)
        out.append((a, ACTION_SEC[a] if a != DENY else 0.0))
    return out


# --------------------------------------------------------------------------------------
# Run one policy over one stream
# --------------------------------------------------------------------------------------

def _auc(scores, labels):
    """Rank-based AUC with mid-ranks for ties (ties contribute 0.5)."""
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels, dtype=int)
    pos, neg = scores[labels == 1], scores[labels == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    values = np.concatenate([pos, neg])
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values))
    sorted_vals = values[order]
    i = 0
    while i < len(values):
        j = i
        while j + 1 < len(values) and sorted_vals[j + 1] == sorted_vals[i]:
            j += 1
        ranks[order[i:j + 1]] = 0.5 * (i + j) + 1.0
        i = j + 1
    r_pos = ranks[:len(pos)].sum()
    return float((r_pos - len(pos) * (len(pos) + 1) / 2.0) / (len(pos) * len(neg)))


def _tpr_at_fpr(scores, labels, fpr=0.01):
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels, dtype=int)
    pos, neg = scores[labels == 1], scores[labels == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    thresh = np.percentile(neg, 100 * (1 - fpr))
    return float((pos >= thresh).mean())


def _pep_enforce(op, a):
    """Unconditional PEP re-check of I1/I2, with the I4 fallback."""
    if a == DENY:
        return a
    if _structural_mask(op)[a]:
        return a
    return SAFE_FALLBACK[op]


def run_policy(policy, stream, b_full, b_equal, trust, det_score, run_id, scenario):
    res = Result(policy=policy, run=run_id, scenario=scenario)
    prev_sec = {}
    prev_action = {}
    prev_epoch = {}
    low_streak = DWELL
    det_scores = []
    det_labels = []
    bel_scores = []
    bel_labels = []

    for i, ep in enumerate(stream):
        b = b_full[i]
        b_eq = b_equal[i]

        # The risk estimate each policy actually acts on (also used for calibration).
        if policy in ("full", "full_no_hyst", "risk_only"):
            p_pol = _attack_prob(b)
        elif policy == "full_no_consistency":
            p_pol = _attack_prob(b_eq)
        elif policy == "invariant_only":
            p_pol = float(np.clip(ep.x_mean[6], 0.0, 1.0))
        elif policy == "oracle":
            p_pol = 1.0 if ep.theta in (2, 3, 4) else 0.0
        else:
            p_pol = None

        b_attack = _attack_prob(b) if p_pol is None else p_pol
        if b_attack < TAU_DOWN:
            low_streak += 1
        else:
            low_streak = 0

        actions = decide(policy, ep, b, b_eq, trust[i], ep.x_mean[6], prev_sec,
                         low_streak, prev_action)
        # The PEP independently re-checks the unconditional floor. This is part of
        # the proposed architecture and of the structurally-raised Threshold
        # baseline; the deliberately unconstrained baselines (Static-Low,
        # Risk-Only) have no such layer, which is the point of the comparison.
        if policy in PEP_POLICIES:
            actions = [(_pep_enforce(q.op, a), sec) for q, (a, sec) in zip(ep.requests, actions)]

        # Calibration/detection, one observation per epoch. Static and threshold
        # policies have no belief, so their calibration metrics are undefined.
        y = 1.0 if ep.theta in (2, 3, 4) else 0.0
        if p_pol is not None:
            res.brier_sum += (p_pol - y) ** 2
            res.brier_n += 1
            bin_idx = min(9, int(p_pol * 10))
            res.ece_bins[bin_idx, 0] += p_pol
            res.ece_bins[bin_idx, 1] += 1
            res.ece_bins[bin_idx, 2] += y
            bel_scores.append(p_pol)
            bel_labels.append(1 if y else 0)

        det_scores.append(det_score[i])
        det_labels.append(1 if ep.poisoned else 0)

        for q, (a, sec) in zip(ep.requests, actions):
            res.decisions += 1
            res.decisions_by_op[q.op] += 1
            if a == DENY:
                granted = False
            elif q.malicious:
                granted = q.u_detect >= P_DETECT[ep.theta, a]
            else:
                granted = q.u_fp >= P_FALSE_DENY[a]

            below_floor = False
            if granted and a < N_ACTION:
                below_floor = not _structural_mask(q.op)[a]
                if below_floor:
                    res.inv_violations += 1
                    res.inv_by_op[q.op] += 1

            # Accounting
            if q.malicious:
                res.malicious_total += 1
                if granted:
                    res.malicious_granted += 1
                    u = -DAMAGE[q.op]
                else:
                    u = 0.0
            else:
                res.benign_total += 1
                if q.op == "safety":
                    res.safety_total += 1
                if granted:
                    res.benign_granted += 1
                    u = VALUE[q.op]
                else:
                    res.benign_denied += 1
                    if q.op == "safety":
                        res.safety_denied += 1
                    u = -DENY_COST[q.op]

            # Realised utility: mission value/damage/denial, minus the modelled
            # systems cost of the granted action, minus the safety-violation
            # penalty rho for any granted action below the structural floor.
            if granted and a < N_ACTION:
                lat = float(ACTION_LAT[a] * TIER_MULT[q.tier])
                eng = float(ACTION_ENERGY[a] * TIER_MULT[q.tier])
                u -= LAMBDA_LATENCY * lat + LAMBDA_ENERGY * eng
                res.latencies.append(lat)
                res.energies.append(eng)
                if below_floor:
                    u -= SAFETY_PENALTY
            res.utility_sum += u

            # Thrashing: count posture changes between epochs for the same operation class.
            if q.op in prev_sec and prev_epoch.get(q.op) != i:
                if prev_sec[q.op] != sec:
                    res.switches += 1
            prev_action[q.op] = a
            prev_epoch[q.op] = i
            prev_sec[q.op] = sec

    res.det_scores = det_scores
    res.det_labels = det_labels

    row = res.row()
    row["ece"] = _ece(res.ece_bins)
    row["poison_auroc"] = _auc(det_scores, det_labels)
    row["poison_tpr1"] = _tpr_at_fpr(det_scores, det_labels)
    row["belief_auroc"] = _auc(bel_scores, bel_labels)
    row["belief_tpr1"] = _tpr_at_fpr(bel_scores, bel_labels)
    row["sram_kb"], row["flash_kb"] = _footprint(policy)
    return row


def _ece(bins):
    total = bins[:, 1].sum()
    if total == 0:
        return float("nan")
    ece = 0.0
    for conf_sum, cnt, acc_sum in bins:
        if cnt:
            ece += cnt / total * abs(acc_sum / cnt - conf_sum / cnt)
    return float(ece)


def _footprint(policy):
    """Modelled SRAM / flash footprint (KB), not measured on silicon."""
    if policy in ("static_high", "static_low"):
        return 4.0, 28.0
    if policy == "threshold":
        return 6.0, 34.0
    if policy == "invariant_only":
        return 9.0, 58.0
    if policy in ("risk_only", "full_no_consistency"):
        return 12.0, 74.0
    return 14.0, 86.0


# --------------------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------------------

SCENARIOS = ["none", "dos", "downgrade", "tee", "energy", "byzantine", "resonant", "adaptive"]
POLICIES = ["static_high", "static_med", "static_low", "threshold", "risk_only",
            "invariant_only", "full_no_hyst", "full_no_consistency", "full", "oracle"]

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def run_one(args):
    seed, scenario, epochs = args
    stream = generate_stream(seed, scenario, epochs)
    b_full, b_equal, trust, det_score = precompute_beliefs(stream)
    rows = []
    for policy in POLICIES:
        rows.append(run_policy(policy, stream, b_full, b_equal, trust, det_score, seed, scenario))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--all", action="store_true", help="run all scenarios x policies x seeds")
    ap.add_argument("--scenario", choices=SCENARIOS)
    ap.add_argument("--policy", choices=POLICIES)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--epochs", type=int, default=2000)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--out", default=os.path.join(RESULTS_DIR, "main.csv"))
    ap.add_argument("--trace", help="dump per-epoch belief trace for one run")
    args = ap.parse_args()

    if args.all:
        tasks = [(s, sc, args.epochs) for s in range(1, args.seeds + 1) for sc in SCENARIOS]
        rows = []
        if args.jobs > 1:
            with ProcessPoolExecutor(max_workers=args.jobs) as ex:
                for chunk in ex.map(run_one, tasks):
                    rows.extend(chunk)
        else:
            for task in tasks:
                rows.extend(run_one(task))
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        fields = list(rows[0].keys())
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        print("wrote {} rows to {}".format(len(rows), args.out))
        return

    if not args.scenario or not args.policy:
        ap.error("give --all, or --scenario and --policy")

    stream = generate_stream(args.seed, args.scenario, args.epochs)
    b_full, b_equal, trust, det_score = precompute_beliefs(stream)
    row = run_policy(args.policy, stream, b_full, b_equal, trust, det_score,
                     args.seed, args.scenario)
    for k, v in row.items():
        print("{:>18s}: {}".format(k, v))

    if args.trace:
        with open(args.trace, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["epoch", "theta", "poisoned", "p_attack", "trust_min", "det_score",
                        "anomaly", "dispersion", "b_benign", "b_recon", "b_dos",
                        "b_byzantine", "b_compromised"])
            for i, ep in enumerate(stream):
                w.writerow([ep.t, THETA[ep.theta], int(ep.poisoned), float(1 - b_full[i][0]),
                            float(trust[i].min()), det_score[i],
                            ep.x_med[6], ep.x_med[8]] + [float(v) for v in b_full[i]])


if __name__ == "__main__":
    main()
