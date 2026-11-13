# Synthesis Matrix

Each row records what the work actually provides, at the level of its abstract/paper,
and the specific gap this paper addresses. "Headline" is deliberately qualitative: no
number is copied from a paper into this project unless it is used in the manuscript and
traceable to that paper.

## A. Access-control foundations

| Work | Problem | Approach | Context signals | Threat model | Evaluation | Headline (qualitative) | Limitation for this paper |
|---|---|---|---|---|---|---|---|
| Sandhu et al. 1996, RBAC | Administration of permissions at scale | Roles, role hierarchies, constraints | None (identity/role only) | Insiders, misassignment | Model + case studies | Establishes role-based access control as an administrative model | Static: no runtime context, no risk, no failure semantics |
| Park & Sandhu 2004, UCON_ABC | Access decisions must continue after a request | Authorizations, obligations, conditions; continuity and mutability | Ongoing conditions | Policy violations during use | Formal model | Generalises access control to continuous usage decisions | Conditions are predicates, not beliefs; no notion of an unsafe action set |
| Hu et al. 2014, NIST SP 800-162 | Enterprise ABAC deployment | Attribute-based policies, PDP/PEP separation | Subject/resource/action/environment attributes | Misconfiguration, attribute spoofing | Guidance/standard | Defines the ABAC vocabulary and reference architecture | Environment attributes are trusted inputs; no adaptation or adversarial context model |
| Rose et al. 2020, NIST SP 800-207 | Perimeter erosion | Zero-trust architecture, per-request evaluation | Device/user/network posture | Assume-breach | Architecture/standard | Codifies continuous, least-privilege evaluation | Architectural, not an algorithm; no invariants, no belief, no evaluation under poisoning |

## B. Risk-aware and context-aware IoT access control

| Work | Problem | Approach | Context signals | Threat model | Evaluation | Headline (qualitative) | Limitation for this paper |
|---|---|---|---|---|---|---|---|
| Atlam et al. 2017 | How to estimate risk for IoT access requests | Survey/classification of risk-estimation techniques | Device, network, user behaviour (surveyed) | Not formalised | Literature synthesis | Shows risk estimation is the open problem in risk-based AC | No decision algorithm; no safety floor |
| Rath & Colin 2017 | Static AC ignores agent profile and behaviour | Adaptive risk-aware AC integrated into an existing model | Agent profile, behaviour, resource sensitivity | Malicious requester | Model + scenario | Risk-adaptive decisions for sensitive IoT (e.g., health devices) | Risk is a score, not a belief; adaptation may lower security; no adversarial context |
| Arfaoui et al. 2019 | Context changes faster than static policy | Context-aware adaptive authentication and authorization | Device/network context, user activity | Unauthorised access | Simulation/use case | Demonstrates adaptive auth selection in IoT settings | Policy choice is rule/optimisation based; no invariant or uncertainty analysis |
| Genç et al. 2019 | Fixed policies cannot express thing-to-thing interaction | Operation-based context-aware AC | Operation, entity interaction context | Malicious attempts | Prototype | Context-aware operation-level decisions | Context is assumed truthful; no poisoning or Byzantine model |
| Al-Naji & Zagrouba 2022, CAB-IoT | Session hijacking after login | Blockchain-backed continuous authentication via fog nodes | Behavioural/identity signals | Session takeover | Architecture + evaluation | Continuous, non-intrusive authentication for IoT | Authenticates identity, not whether the *policy* is safe; blockchain trust assumptions |
| Merlec & In 2024, SC-CAAC | Context-dependent sharing in blockchain-IoT | Smart-contract context-aware AC | Context predicates on-chain | Malicious tenants/contracts | Implementation + evaluation | Automates context-aware policy enforcement on-chain | On-chain trust/consensus; no hard safety invariant or fail-safe fallback |
| Stodt et al. 2025 | Static security ignores segment criticality | Dynamic ZTA with threat assessment + fuzzy state management | Device status, network conditions, user behaviour | Escalating IIoT threats | Framework + evaluation | Continuously adjusts trust and access in IIoT | No formal invariant that adaptation cannot cross; no context-poisoning evaluation |
| Krishnasrija et al. 2025 | Roles and capabilities must react to context | Dynamic context-aware role-capability AC | Context conditions, capabilities | Unauthorised access | Model + prototype | Combines roles, capabilities and context | No risk belief; no adversarial or safety analysis |

## C. Self-adaptive and runtime-enforcement systems

| Work | Problem | Approach | Context signals | Threat model | Evaluation | Headline (qualitative) | Limitation for this paper |
|---|---|---|---|---|---|---|---|
| Kephart & Chess 2003 | Managing complex systems | Autonomic computing, MAPE-K | Monitored state | Not security-specific | Vision/architecture | Establishes the MAPE-K control loop | Loop assumes trustworthy sensors; no security invariant |
| Cheng et al. 2009 | Engineering self-adaptive systems | Research roadmap for feedback loops | Runtime models | Not adversarial | Roadmap | Frames adaptation, requirements and assurance | Does not address adversarial context or access decisions |
| Elgendi et al. 2019 | CPS under advanced cyber threats | Learned MAPE-K model for self-adaptive protection | CPS telemetry | Network and controller attacks | Learned model evaluation | Uses a learned MAPE-K loop to support CPS protection | Focus is detection/response, not access-control decisions or invariants |
| Wu et al. 2017, Safety Guard | CPS must remain fail-operational | Synthesised runtime enforcer (safety guard) | System outputs | Faults and malicious inputs | Synthesis + case study | Runtime component corrects unsafe outputs | Safety property is given; the guard does not decide *access* under uncertain risk |
| Wu et al. 2019, Shield synthesis | Boolean shields do not handle real-valued CPS | Shield synthesis for real-valued signals | Continuous signals | Property violations | Synthesis + experiments | Instantaneous correction to enforce safety | Assumes a specified property and a trusted observation of the system state |
| Mehmood et al. 2022, Black-box simplex | Assurance for autonomous CPS | Simplex architecture with black-box components | Controller/plant state | Component failure | Case studies | Runtime assurance around unverified controllers | Control-level assurance, not policy selection; no adversarial context belief |
| Sha 2001 | Complexity undermines assurance | "Use simplicity to control complexity" / forward recovery | — | Faults | Position + examples | Argues a simple trusted core should supervise a complex system | Architectural principle, not an access-control mechanism |

## D. Adversarial context and evaluation data

| Work | Problem | Approach | Context signals | Threat model | Evaluation | Headline (qualitative) | Limitation for this paper |
|---|---|---|---|---|---|---|---|
| Brownfield et al. 2005; Raymond et al. 2009 | Denial-of-sleep drains sensor lifetime | Classify attacks by MAC knowledge; defences | Radio duty cycle, energy | Energy-targeted attacker | Analysis + simulation | Shows sleep-deprivation can reduce lifetime from years to days | Not framed as an access-control downgrade or belief-manipulation problem |
| Ye et al. 2020; Li et al. 2019 | Stealthy false data injection | Summation detector; stealthy attack design | Sensor measurements | White-box FDI | Detection theory + simulations | Detects attacks designed to evade chi-square tests | Detection only; no policy decision, no hard invariant, no fail-safe action |
| Ferrag et al. 2022, Edge-IIoTset | Realistic IoT/IIoT security data | Testbed dataset, centralised and federated use | Network/flow features | Labeled attacks | Dataset benchmark | Provides a large realistic IoT/IIoT attack dataset | IDS-oriented; no access-control decisions or context-belief ground truth |
| Neto et al. 2023, CICIoT2023 | Large-scale real-time IoT attacks | Dataset + benchmark | Flow features | Many attack classes | Benchmark | Provides a large attack benchmark for IoT | Same: detection labels, not policy-risk labels |
| Moustafa 2021, TON_IoT | Heterogeneous IoT telemetry | Distributed edge/fog/cloud testbed datasets | Telemetry, OS, network | Labeled attacks | Dataset | Provides telemetry+network datasets | Not an access-control trace; no invariant labels |
| Dobraunig et al. 2021, Ascon; Cagua et al. 2025 | AEAD on constrained devices | Lightweight AEAD specification and IoT implementation study | — | Cryptographic | Specification + benchmarks | Ascon is efficient on constrained IoT hardware | Provides a primitive, not a policy or adaptation mechanism |

## Gap statement

The literature contains three mature but separate lines:

1. **Access control** (RBAC/ABAC/UCON, risk-aware and context-aware IoT variants) decides
   *who may do what* and increasingly *under which context*, but risk enters as a score
   or a rule antecedent. Adaptation is not required to preserve a formal safety
   invariant, uncertainty over the threat state is not represented, and failure
   semantics are unspecified.
2. **Self-adaptive and runtime-assurance systems** (MAPE-K, simplex, shields, safety
   guards) provide strong guarantees *given a trustworthy observation and a specified
   property*, but they do not decide access, and they assume the monitor's inputs are
   not adversarially chosen.
3. **IoT security datasets and attack models** (denial-of-sleep, FDI, poisoning) show
   that context telemetry is both attackable and noisy, yet access-control evaluations
   rarely expose the controller to an adaptive adversary that targets the adaptation
   loop itself.

**Gap.** There is no decision-level formulation in which (i) access policy is chosen
against a *continuous belief* over latent threat states, (ii) the admissible action set
is filtered by *hard safety invariants that utility cannot trade away*, and (iii) the
failure mode is a *precomputed safe action with per-operation semantics*. Consequently
there is also no evaluation that measures the price of such a guarantee under
context-poisoning, Byzantine telemetry, and resonant thrashing attacks.

This paper fills exactly that gap and evaluates it against static, threshold, and
unconstrained risk-adaptive policies, with a white-box adaptive attacker as a stress
test.
