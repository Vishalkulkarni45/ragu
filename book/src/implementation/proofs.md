# PCD Proofs

The proof structure in Ragu represents the cryptographic evidence that a
computation was performed correctly. Proofs are _recursive_ and each proof can
verify previous proofs while simultaneously attesting to a new computation.
This enables construction of arbitrarily deep proof trees where each node
carries evidence of its entire computational history.

## The `Pcd` Type

The primary type that applications interact with is `Pcd` (Proof-Carrying Data):

```rust
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    pub proof: Proof<C, R>,
    pub data: H::Data<'source>,
}
```

A `Pcd` bundles two components:

* **`proof`**: The cryptographic proof object containing all data necessary
  for verification.
* **`data`**: Application-defined data described by a `Header`
  representing the current state of the computation.

The type parameters configure the proof system:

* **`C: Cycle`**: The elliptic curve cycle used for recursion (e.g., Pasta).
* **`R: Rank`**: The circuit capacity as a power of two (e.g., `R<13>` for
  2^13 constraints).
* **`H: Header`**: The header type describing what data this proof carries.

## The `Step` Trait

A `Step` defines a single computation in the PCD graph. Every
step takes two input proofs (which may be trivial) and produces a new proof:

```rust
pub trait Step<C: Cycle>: Sized + Send + Sync {
    const INDEX: Index;

    type Witness<'source>: Send;
    type Aux<'source>: Send;
    type Left: Header<C::CircuitField>;
    type Right: Header<C::CircuitField>;
    type Output: Header<C::CircuitField>;

    fn witness<...>(...) -> Result<(Encoded outputs, Aux)>;
}
```

The associated types define the step's interface:

* **`INDEX`**: Unique identifier for this step within the application.
* **`Witness`**: Private data provided by the prover (not visible to verifiers).
* **`Aux`**: Auxiliary output returned after proving, often used to construct
  the output header data.
* **`Left`, `Right`**: The header types of the two input proofs.
* **`Output`**: The header type of the resulting proof.

## Creating Proofs

The `Application` provides two methods for creating proofs:

### `seed`

Creates a new proof from witness data alone, without requiring input proofs.
This is the entry point for leaf nodes in a PCD tree:

```rust
let (proof, aux) = app.seed(&mut rng, MyLeafStep { ... }, witness)?;
let pcd = proof.carry(aux);
```

Internally, `seed` fuses the step with trivial proofs. Steps used with `seed`
must have `Left = ()` and `Right = ()`.

### `fuse`

Combines two existing proofs using a step's logic:

```rust
let (proof, aux) = app.fuse(&mut rng, MyCombineStep { ... }, (), left_pcd, right_pcd)?;
let pcd = proof.carry::<OutputHeader>(aux);
```

Within the step's `witness` function, calling `.encode()` on the input encoders
verifies those proofs in-circuit, this is where recursive verification occurs.

## The `carry` Method

The `carry` method converts a raw `Proof` into a `Pcd` by
attaching header data:

```rust
let pcd: Pcd<'_, _, _, MyHeader> = proof.carry(header_data);
```

This separation allows the proving methods to return auxiliary data that
applications use to construct the final header.

## Verification

Proofs are verified using `verify`:

```rust
let valid: bool = app.verify(&pcd, &mut rng)?;
```

Verification confirms the entire recursive proof structure is sound, including
all accumulated claims from previous steps.

## Rerandomization

The `rerandomize` method produces a new proof that
verifies identically but reveals nothing about the original proof's randomness:

```rust
let fresh_pcd = app.rerandomize(pcd, &mut rng)?;
```

This is useful for privacy-preserving applications where proof linkability
must be prevented.

## Unified Accumulator Structure

Ragu uses an _accumulation scheme_ (similar to [Halo]) to achieve efficient
recursion. Rather than fully verifying each child proof inside the circuit,
proofs are _folded_ together deferring expensive verification work while
accumulating claims that will eventually be checked.

The `Proof` type serves as a **unified accumulator** that
carries both:

* The current computation's witness and commitments
* Accumulated claims from all previous proofs in the tree

This design means a single proof structure handles the entire recursive
history, regardless of tree depth. 

[Halo]: https://eprint.iacr.org/2019/1021

## Compressed vs. Uncompressed Proofs

Proofs in Ragu can exist in two forms, reflecting a fundamental tradeoff
between proof size and generation cost. During recursive computation, proofs
remain in an expanded form optimized for folding. Only at final output when
bandwidth or storage matters are proofs compressed into a succinct form.

### Uncompressed (Split-Accumulation Form)

* **Size**: Scales with circuit size (non-succinct)
* **Generation**: Fast—just polynomial arithmetic and commitments
* **Use case**: Intermediate computation during recursion
* **Folding**: Efficiently combined using accumulation

This is the natural operating mode during recursive proving. When calling
`seed()` or `fuse()`, the resulting proof is in uncompressed form.

### Compressed (IPA-Based Succinct Form)

* **Size**: Logarithmic in circuit size (succinct)
* **Generation**: Expensive—requires inner product argument (IPA)
* **Use case**: Final proof for transmission/storage
* **Verification**: Dominated by multi-scalar multiplication

Compression is applied at _boundary points_ for example, before broadcasting
a proof onchain where bandwidth matters.

```admonish tip title="When to Compress"
Keep proofs uncompressed during intermediate recursion steps. Only compress
when you need to transmit or store the final result. Compressed proofs can
be decompressed back to accumulation form if further folding is needed.
```

For deeper background, see
[Proof-Carrying Data](../concepts/pcd.md#the-cost-model-compression-vs-folding).

## Internal Proof Structure

The `Proof` type contains the cryptographic data required for
verification, organized into stages that mirror the protocol. Each stage
captures polynomials, blinding factors, and commitments on both the host and
nested curves.

| Stage | Purpose |
|-------|---------|
| Application | Binds proof to a specific step circuit; holds witness polynomial and header commitments |
| Preamble | Initial transcript setup; bridges native and nested curve layers |
| SPrime | Mesh polynomial evaluations at challenge points |
| ErrorM | First layer of revdot claim reduction (multiple M-sized reductions) |
| ErrorN | Second layer of revdot claim reduction (single N-sized reduction) |
| AB | Accumulation folding polynomials and revdot product |
| Query | Polynomial query stage with mesh evaluations |
| F | Batched verification polynomial |
| Eval | Evaluation stage commitments |
| P | Final batch proof: $p(X)$ and evaluation $v = p(u)$ |
| Challenges | Fiat-Shamir challenges derived during proving |
| InternalCircuits | Hash and collapse circuit witness commitments |

### Trivial Proofs

A _trivial proof_ is a special base case proof containing zero polynomials
and deterministic blinding factors. It serves as a placeholder input to
`seed()` for steps that don't require input proofs.

Trivial proofs are not meant to verify independently, they exist to bootstrap
the recursive structure.
