#!/usr/bin/env python3
"""Unit and property tests for the fail-safe CAAC simulator.

These tests check the properties the paper relies on, not just code coverage:

1. The unconditional invariant set I1/I2 is exactly the documented structural mask,
   for every one of the 243 actions and every operation class.
2. The belief-conditional admissible set is always a subset of the structural mask and
   is never empty, for a grid of risk levels (so the controller always has a legal move).
3. The static-threshold baseline never selects a structurally unsafe action.
4. The adaptive policies never emit a structurally unsafe action on a real stream.
5. Beliefs are proper probability vectors; the monitor down-weights a poisoned
   modality instead of following it.
6. AUC / TPR helpers are correct on hand-computable cases.
7. Runs are paired and deterministic: the same (seed, scenario) produces the same
   stream, and every policy sees that same stream.

Run with:  python3 -m unittest -v test_simulator.py
"""

from __future__ import annotations

import math
import unittest

import numpy as np

import simulator as s


def _structural_spec(op, auth, cry, ids, ttl):
    """Independent restatement of I1/I2 from the design section.

    Takes *levels* (as in ACTION_LEVELS), not action-space indices: the crypto
    dimension has two different AEAD constructions at the same level.
    """
    if op in ("actuate", "safety"):
        if auth < 2 or cry < 2 or ttl < 1 or ids < 1:
            return False
    if op == "safety":
        if auth < 2 or ttl < 1 or ids < 2:
            return False
    return True


class TestInvariantSets(unittest.TestCase):
    def test_structural_mask_is_exact_for_all_actions(self):
        self.assertEqual(s.N_ACTION, 243)
        for op in ("read", "write", "actuate", "safety"):
            mask = s._structural_mask(op)
            self.assertEqual(mask.shape, (s.N_ACTION,))
            for k, (a, c, i, r, t) in enumerate(s.ACTIONS):
                auth, cry, ids, _rate, ttl = s.ACTION_LEVELS[k]
                self.assertEqual(
                    bool(mask[k]), _structural_spec(op, auth, cry, ids, ttl),
                    "op=%s action=%s" % (op, (a, c, i, r, t)))

    def test_structural_set_nonempty_for_every_operation(self):
        for op in ("read", "write", "actuate", "safety"):
            self.assertTrue(s._structural_mask(op).any(), op)

    def test_invariant_mask_subset_of_structural_for_all_risk(self):
        grid = np.linspace(0.0, 1.0, 41)
        for op in ("read", "write", "actuate", "safety"):
            structural = s._structural_mask(op)
            for b in grid:
                allowed = s._invariant_mask(op, float(b))
                self.assertTrue(allowed.any(),
                                "empty admissible set: op=%s b=%.3f" % (op, b))
                self.assertFalse((allowed & ~structural).any(),
                                 "conditional mask weakens I1/I2: op=%s b=%.3f" % (op, b))

    def test_deny_forbidden_only_for_safety(self):
        for b in (0.0, 0.5, 0.9, 1.0):
            self.assertFalse(s._deny_allowed("safety", b))
            for op in ("read", "write", "actuate"):
                self.assertTrue(s._deny_allowed(op, b))

    def test_safe_static_never_violates(self):
        for op, floor in s.STRUCT_FLOOR.items():
            for level in (0, 1, 2):
                k = s._safe_static(op, level)
                self.assertTrue(s._structural_mask(op)[k],
                                "op=%s level=%d -> %s" % (op, level, s.ACTIONS[k]))
                a, c, i, r, t = s.ACTIONS[k]
                self.assertGreaterEqual(a, floor[0])
                self.assertGreaterEqual(c, floor[1])
                self.assertGreaterEqual(i, floor[2])
                self.assertGreaterEqual(t, floor[4])

    def test_adaptive_policies_never_emit_unsafe_action(self):
        stream = s.generate_stream(3, "byzantine", 250)
        b_full, b_equal, trust, det = s.precompute_beliefs(stream)
        for policy in ("invariant_only", "full", "full_no_hyst",
                       "full_no_consistency", "threshold", "oracle"):
            prev_sec, prev_action, low = {}, {}, s.DWELL
            for i, ep in enumerate(stream):
                b = b_full[i]
                p_pol = s._attack_prob(b)
                low = low + 1 if p_pol < s.TAU_DOWN else 0
                for q, (a, _) in zip(
                        ep.requests,
                        s.decide(policy, ep, b, b_equal[i], trust[i],
                                 ep.x_mean[6], prev_sec, low, prev_action)):
                    if a != s.DENY:
                        self.assertTrue(
                            s._structural_mask(q.op)[a],
                            "%s violated I1/I2 on %s with action %s"
                            % (policy, q.op, s.ACTIONS[a]))
                        prev_action[q.op] = a
                        prev_sec[q.op] = s.ACTION_SEC[a]


class TestBeliefs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = s.generate_stream(1, "energy", 400)
        cls.b_full, cls.b_equal, cls.trust, cls.det = s.precompute_beliefs(cls.stream)

    def test_beliefs_are_probability_vectors(self):
        for name, b in (("full", self.b_full), ("equal", self.b_equal)):
            self.assertEqual(b.shape, (len(self.stream), s.N_THETA))
            self.assertTrue(np.isfinite(b).all(), name)
            self.assertTrue((b >= 0).all(), name)
            np.testing.assert_allclose(b.sum(axis=1), 1.0, atol=1e-9,
                                       err_msg="belief does not normalise (%s)" % name)

    def test_trust_is_bounded_and_anchored(self):
        self.assertTrue(((self.trust >= 0) & (self.trust <= 1)).all())
        # Device telemetry and the dispersion modality are always retained.
        np.testing.assert_allclose(self.trust[:, 0], 1.0, atol=1e-12)
        np.testing.assert_allclose(self.trust[:, 3], 1.0, atol=1e-12)

    def test_monitor_downweights_poisoned_modality(self):
        # In the energy-spoof scenario the network and security modalities are moved
        # toward benign while the device is under attack. Their trust must fall.
        poisoned = [i for i, ep in enumerate(self.stream) if ep.poisoned]
        self.assertTrue(poisoned, "scenario produced no poisoned epochs")
        idx = poisoned[len(poisoned) // 2]
        self.assertLess(self.trust[idx, 1], 0.1, "net modality not down-weighted")
        self.assertLess(self.trust[idx, 2], 0.1, "sec modality not down-weighted")
        self.assertGreaterEqual(self.det[idx], 0.5, "consistency score missed poison")

    def test_det_score_in_unit_interval(self):
        self.assertTrue(((self.det >= 0) & (self.det <= 1)).all())


class TestMetrics(unittest.TestCase):
    def test_auc_hand_cases(self):
        self.assertEqual(s._auc([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1]), 1.0)
        self.assertEqual(s._auc([0.9, 0.8, 0.2, 0.1], [0, 0, 1, 1]), 0.0)
        self.assertEqual(s._auc([0.5, 0.5, 0.5, 0.5], [0, 0, 1, 1]), 0.5)
        self.assertTrue(math.isnan(s._auc([0.5, 0.5], [0, 0])))

    def test_tpr_at_fpr(self):
        scores = [0.1, 0.2, 0.8, 0.9]
        labels = [0, 0, 1, 1]
        self.assertEqual(s._tpr_at_fpr(scores, labels, fpr=0.5), 1.0)
        self.assertTrue(math.isnan(s._tpr_at_fpr([0.4, 0.6], [0, 0])))

    def test_ece_zero_when_perfectly_calibrated(self):
        bins = np.zeros((10, 3))
        bins[0] = [0.0, 100.0, 0.0]   # confidence 0, accuracy 0
        bins[9] = [100.0, 100.0, 100.0]  # confidence 1, accuracy 1
        self.assertAlmostEqual(s._ece(bins), 0.0, places=12)

    def test_result_row_ranges(self):
        stream = s.generate_stream(2, "adaptive", 150)
        bf, be, tr, det = s.precompute_beliefs(stream)
        row = s.run_policy("full", stream, bf, be, tr, det, 2, "adaptive")
        for key in ("ivr_per_1k", "unsafe_grant", "false_deny", "legit_grant",
                    "safety_denied", "brier", "ece"):
            self.assertTrue(0.0 <= row[key] <= 1.0 or math.isnan(row[key]), key)
        self.assertGreater(row["p50_ms"], 0.0)
        self.assertGreaterEqual(row["p99_ms"], row["p50_ms"])


class TestDeterminism(unittest.TestCase):
    def test_same_seed_same_stream(self):
        a = s.generate_stream(7, "resonant", 120)
        b = s.generate_stream(7, "resonant", 120)
        self.assertEqual(len(a), len(b))
        for ea, eb in zip(a, b):
            self.assertEqual(ea.theta, eb.theta)
            self.assertEqual(ea.poisoned, eb.poisoned)
            np.testing.assert_array_equal(ea.x_med, eb.x_med)
            self.assertEqual([(q.op, q.malicious) for q in ea.requests],
                             [(q.op, q.malicious) for q in eb.requests])

    def test_different_seeds_differ(self):
        a = s.generate_stream(1, "byzantine", 100)
        b = s.generate_stream(2, "byzantine", 100)
        self.assertFalse(np.array_equal(a[0].x_med, b[0].x_med))

    def test_policies_are_paired(self):
        rows1 = s.run_one((4, "dos", 120))
        rows2 = s.run_one((4, "dos", 120))
        self.assertEqual(len(rows1), len(s.POLICIES))
        for r1, r2 in zip(rows1, rows2):
            self.assertEqual(r1["policy"], r2["policy"])
            for key in ("decisions", "ivr_per_1k", "utility", "unsafe_grant"):
                self.assertEqual(r1[key], r2[key], key)

    def test_every_policy_sees_same_decision_count(self):
        rows = s.run_one((5, "none", 100))
        counts = {r["decisions"] for r in rows}
        self.assertEqual(len(counts), 1, "policies saw different request streams")


class TestFailSafe(unittest.TestCase):
    def test_pep_fails_closed_for_actuation_and_allows_safety(self):
        low = s.STATIC_LOW
        self.assertFalse(s._structural_mask("actuate")[low])
        self.assertEqual(s._pep_enforce("actuate", low), s.DENY)
        self.assertEqual(s._pep_enforce("safety", low), s.A_MAX)
        # A safe action is passed through unchanged.
        safe = s.ACTION_INDEX[(2, 2, 2, 2, 2)]
        self.assertEqual(s._pep_enforce("actuate", safe), safe)

    def test_empty_admissible_set_uses_fallback(self):
        empty = np.zeros(s.N_ACTION, dtype=bool)
        a, _ = s._score_actions("actuate", np.eye(s.N_THETA)[0], mask=empty)
        self.assertEqual(a, s.DENY)
        a, _ = s._score_actions("safety", np.eye(s.N_THETA)[0], mask=empty)
        self.assertEqual(a, s.A_MAX)

    def test_per_operation_ivr_fields_are_reported(self):
        rows = s.run_one((2, "tee", 120))
        for r in rows:
            for key in ("ivr_readwrite_per_1k", "ivr_actuate_per_1k",
                        "ivr_safety_per_1k"):
                self.assertIn(key, r)
                self.assertGreaterEqual(r[key], 0.0)

    def test_utility_charges_systems_cost(self):
        # A granted action always has a positive modelled cost, so the realised
        # utility cannot exceed the raw value for a stream of benign requests.
        stream = s.generate_stream(2, "none", 80)
        bf, be, tr, ds = s.precompute_beliefs(stream)
        r = s.run_policy("full", stream, bf, be, tr, ds, 2, "none")
        self.assertLessEqual(r["utility"], 1.0)
        self.assertGreaterEqual(r["utility"], -3.0)


class TestTraceCalibration(unittest.TestCase):
    def test_priors_are_consistent(self):
        import json
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "results", "trace_priors.json")
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        self.assertIn("IoT-23", d["dataset"])
        contrast = d["pooled"]["log_rate_contrast"]
        lo, hi = contrast["ci95"]
        self.assertLessEqual(lo, contrast["point"])
        self.assertLessEqual(contrast["point"], hi)
        # The simulator's DoS network mean is calibrated to 4.20 + this contrast.
        self.assertAlmostEqual(s.MU[2, 3], 4.20 + contrast["point"], places=2)
        self.assertAlmostEqual(s.MU[0, 3], 4.20, places=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
