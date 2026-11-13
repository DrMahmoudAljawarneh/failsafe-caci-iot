# Literature Screening

Search log: `literature/search_log.json` (20 queries, all with `--save`, run 2026-11-12).
Engines: OpenAlex, Crossref, arXiv (Semantic Scholar omitted: keyless rate limits made
it non-reproducible on the day of the search).

## Search strategy

Three query families, each run with `lit_search.py`:

1. **Problem terms** — context-aware / risk-based / continuous access control in IoT;
   zero-trust IIoT; access-control surveys.
2. **Method terms** — MAPE-K, self-adaptive security, runtime enforcement, shield
   synthesis, simplex/runtime assurance, Bayesian filtering, Byzantine fusion.
3. **Evaluation terms** — IoT intrusion-detection datasets (Edge-IIoTset, CIC-IoT-2023,
   TON_IoT, Bot-IoT), denial-of-sleep, false data injection, lightweight AEAD.

Queries (verbatim, from the log):
`context-aware access control internet of things` ·
`risk-based access control continuous authentication internet of things` ·
`MAPE-K self-adaptive security cyber-physical systems` ·
`Byzantine resilient context fusion IoT telemetry` ·
`usage control UCON authorization model` ·
`zero trust architecture industrial IoT access control` ·
`runtime enforcement safety invariants cyber-physical systems` ·
`ASCON lightweight authenticated encryption IoT` ·
`role-based access control Sandhu` ·
`false data injection attacks cyber-physical systems` ·
`denial of sleep attacks wireless sensor networks` ·
`Edge-IIoTset dataset intrusion detection` ·
`CIC IoT 2023 dataset` ·
`risk adaptable access control RAdAC` ·
`runtime assurance simplex architecture` ·
`sensor spoofing attacks cyber-physical systems` ·
`access control survey internet of things` ·
`TON_IoT dataset new distributed architecture evaluating AI security applications` ·
`using simplicity to control complexity` ·
`calibration of modern neural networks`

## Screening criteria

**Include** if all hold:
- Peer-reviewed article, conference paper, or standard from a recognised venue/publisher
  (foundational pre-2000 classics allowed).
- English, full text or abstract available.
- Directly informs at least one of: IoT/CPS access-control decision making, adaptive
  security architecture, runtime safety enforcement, adversarial context manipulation,
  or the evaluation datasets/metrics used here.
- Resolvable identifier (DOI or arXiv ID) that `refs.py verify` matches.

**Exclude** if any hold:
- Duplicate record already captured under another DOI/preprint.
- Preprint superseded by a published version (the published version was used).
- Generic IoT survey with no access-control or adaptation content.
- Opinion/editorial without a method or evidence.
- Domain outside cyber-physical/IoT systems (e.g., pure organisational policy).

## Counts

| Stage | Count |
|---|---|
| Unique records after multi-engine merge | 362 |
| Records with a resolvable DOI | 310 |
| Title/abstract screened | 362 |
| Full-text or abstract assessed | ~60 |
| Included in `references.bib` | 51 |
| Cited in the manuscript | see final bibliography |

## Decisions (representative)

| Record | Decision | Reason |
|---|---|---|
| Sandhu et al. 1996, RBAC | include | Baseline access-control model the paper contrasts with |
| Park & Sandhu 2004, UCON | include | Continuous-authorization ancestor of this work |
| NIST SP 800-162 (ABAC) / 800-207 (ZTA) | include | Definitions and the zero-trust framing |
| Atlam et al. 2017; Rath & Colin 2017 | include | Risk-aware IoT access control, closest static-adaptive baselines |
| Arfaoui et al. 2019; Genç et al. 2019 | include | Context-aware authentication/authorization; no invariant analysis |
| Al-Naji & Zagrouba 2022; Merlec & In 2024 | include | Continuous authentication / context-aware AC; different trust assumptions |
| Stodt et al. 2025 | include | Most recent dynamic ZTA for IIoT; motivates the comparison |
| Kephart & Chess 2003; Cheng et al. 2009 | include | MAPE-K / self-adaptive systems foundations |
| Wu et al. 2017, 2019; Mehmood et al. 2022; Sha 2001 | include | Runtime safety enforcement / simplicity, the fail-safe lineage |
| Ferrag et al. 2022; Neto et al. 2023; Moustafa 2021 | include | Public IoT security datasets used for trace calibration |
| Brownfield et al. 2005; Raymond et al. 2009 | include | Denial-of-sleep attack model |
| Ye et al. 2020; Li et al. 2019 | include | False-data-injection detection, the sensor-integrity threat |
| Dobraunig et al. 2021; Cagua et al. 2025 | include | Lightweight AEAD used in the action space |
| Non-IoT risk-adaptable access control (e.g., cloud) | exclude | Threat model and constraints differ; kept as context only |
| Preprints superseded by journal versions | exclude | Published version preferred |
| Blockchain-only access-control proposals | exclude unless context-aware | Trust/consensus assumptions out of scope |

## Notes on evidence quality

- 51 entries were machine-verified against Crossref/arXiv (`refs.py verify`), with the
  three mismatches repaired (HTML in a title, a malformed author string in a Crossref
  record, and a truncated Crossref title) or removed.
- Dataset papers are cited for **what the datasets contain**, not for numbers reused in
  this paper. The trace calibration in `experiments/trace_calibration.py` documents the
  exact capture and preprocessing; if a capture cannot be downloaded reproducibly, the
  paper reports that and falls back to published priors.
