# Summary

[Introduction](introduction.md)

---

# Part I: Concepts

- [Proof-Carrying Data](concepts/pcd.md)
- [Core Ideas](concepts/core.md)
- [Structured Vectors](concepts/structured_vectors.md)

---

# Part II: User Guide

- [Getting Started](guide/getting_started.md)
- [Writing Circuits](guide/writing_circuits.md)
- [Gadgets](guide/gadgets/index.md)
  - [Simple Gadgets](guide/gadgets/simple.md)
  - [The GadgetKind Trait](guide/gadgets/gadgetkind.md)
  - [The Kind! Macro](guide/gadgets/kind.md)
- [Routines](guide/routines.md)
- [Drivers](guide/drivers.md)
- [Configuration](guide/configuration.md)

---

# Part III: Protocol Specification

- [Protocol Overview](protocol/index.md)
- [Preliminaries](protocol/prelim/index.md)
  - [Notation](protocol/prelim/notation.md)
  - [Constraint Systems](protocol/prelim/cs.md)
  - [Building Blocks](protocol/prelim/building_blocks.md)
- [Core Construction](protocol/core/index.md)
  - [Arithmetization](protocol/core/arithmetization.md)
  - [NARK](protocol/core/nark.md)
  - [Split-Accumulation Schemes](protocol/core/accumulation/index.md)
    - [PCS Batched Evaluation](protocol/core/accumulation/pcs.md)
    - [Wiring Consistency](protocol/core/accumulation/wiring.md)
    - [Revdot Product](protocol/core/accumulation/revdot.md)
- [Extensions](protocol/extensions/index.md)
  - [Mesh Polynomial](protocol/extensions/mesh.md)
  - [Staging](protocol/extensions/staging.md)
  - [PCD Construction](protocol/extensions/pcd.md)
- [Analysis](protocol/analysis.md)

---

# Part IV: Implementation & Design

- [Architecture Overview](implementation/arch.md)
- [Circuits](implementation/circuits.md)
- [Polynomial Management](implementation/polynomials.md)
- [PCD Step and Proofs](implementation/proofs.md)
- [Staging](implementation/staging.md)
- [Drivers](implementation/drivers/index.md)
  - [Emulator](implementation/drivers/emulator.md)
  - [Writing Custom Drivers](implementation/drivers/custom.md)

---

# Appendices

- [Cryptography Background](appendix/math.md)
- [Related Work](appendix/related.md)
