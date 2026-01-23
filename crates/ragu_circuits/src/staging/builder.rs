//! Multi-stage circuit witness computation with staged wire allocation.
//!
//! The staging system separates witness computation into two types of stages:
//! **normal stages** that can be committed independently, and a **final stage**
//! that enforces relationships between them. This enables the prover to commit
//! to portions of the witness (like public inputs or intermediate computations)
//! before computing the full circuit.
//!
//! ## Two-Phase Builder Pattern
//!
//! The [`StageBuilder`] uses a two-phase protocol:
//!
//! 1. **Wire reservation** - Each normal stage reserves non-overlapping wire
//!    positions in the witness polynomial without computing values yet. This
//!    ensures all provers agree on which wires belong to which stage.
//!
//! 2. **Witness computation** - All stages (normal + final) compute their actual
//!    witness values. Normal stage outputs are injected into their reserved wires,
//!    and the final stage enforces relationships between them.
//!
//! This separation is necessary because the verifier must know the exact wire
//! positions for each stage polynomial before seeing any witness values.
//!
//! ## Example
//!
//! A circuit with two normal stages plus the implicit final stage:
//!
//! ```rust
//! use ragu_circuits::staging::{Stage, StageBuilder, MultiStageCircuit};
//! # use ragu_circuits::polynomials::Rank;
//! # use ragu_core::gadgets::{Kind, GadgetKind};
//! # use ragu_core::{drivers::{Driver, DriverValue}, maybe::Maybe, Result};
//! # use ragu_primitives::{vec::{FixedVec, ConstLen, CollectFixed}, Element, Point};
//! # use arithmetic::CurveAffine;
//! # use ff::Field;
//!
//! // Stage 1: 100 field elements (no internal constraints)
//! #[derive(Default)]
//! struct StageOne;
//! impl<F: Field, R: Rank> Stage<F, R> for StageOne {
//!     type Parent = ();
//!     type Witness<'source> = [F; 100];
//!     type OutputKind = Kind![F; FixedVec<Element<'_, _>, ConstLen<100>>];
//!
//!     fn values() -> usize { 100 }
//!     fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
//!         &self,
//!         dr: &mut D,
//!         witness: DriverValue<D, Self::Witness<'source>>,
//!     ) -> Result<<Self::OutputKind as GadgetKind<F>>::Rebind<'dr, D>>
//!     where
//!         Self: 'dr,
//!     {
//!         (0..100)
//!             .map(|i| Element::alloc(dr, witness.view().map(|w| w[i])))
//!             .try_collect_fixed()
//!     }
//! }
//!
//! // Stage 2: Curve point (enforces curve equation)
//! #[derive(Default)]
//! struct StageTwo<C: CurveAffine>(core::marker::PhantomData<C>);
//!
//! impl<F: Field, R: Rank, C: CurveAffine<Base = F>> Stage<F, R> for StageTwo<C> {
//!     type Parent = StageOne;
//!     type Witness<'source> = C;
//!     type OutputKind = Kind![F; Point<'_, _, C>];
//!
//!     fn values() -> usize { 2 }
//!     fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
//!         &self,
//!         dr: &mut D,
//!         witness: DriverValue<D, Self::Witness<'source>>,
//!     ) -> Result<<Self::OutputKind as GadgetKind<F>>::Rebind<'dr, D>>
//!     where
//!         Self: 'dr,
//!     {
//!         Point::alloc(dr, witness)
//!     }
//! }
//!
//! // Multi-stage circuit that consumes the two stages above
//! #[derive(Clone)]
//! struct MyCircuit<C: CurveAffine>(core::marker::PhantomData<C>);
//!
//! impl<F: Field, R: Rank, C: CurveAffine<Base = F>> MultiStageCircuit<F, R> for MyCircuit<C> {
//!     type Last = StageTwo<C>;
//!     type Instance<'source> = ();
//!     type Witness<'source> = ([F; 100], C);
//!     type Output = Kind![F; Element<'_, _>];
//!     type Aux<'source> = ();
//!
//!     fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
//!         &self,
//!         _dr: &mut D,
//!         _instance: DriverValue<D, Self::Instance<'source>>,
//!     ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>
//!     where
//!         Self: 'dr,
//!     {
//!         unimplemented!("not needed for this example")
//!     }
//!
//!     fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
//!         &self,
//!         builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
//!         witness: DriverValue<D, Self::Witness<'source>>,
//!     ) -> Result<(
//!         <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
//!         DriverValue<D, Self::Aux<'source>>,
//!     )>
//!     where
//!         Self: 'dr,
//!     {
//!         // Phase 1: Reserve wire positions for each stage
//!         let (stage1_guard, builder) = builder.add_stage::<StageOne>()?;
//!         let (stage2_guard, builder) = builder.add_stage::<StageTwo<C>>()?;
//!         let dr = builder.finish();
//!
//!         // Phase 2: Populate reserved wires and compute final stage
//!
//!         // StageOne: just Elements, no constraints - use unenforced()
//!         let stage1_output = stage1_guard.unenforced(
//!             dr,
//!             witness.view().map(|w| w.0),
//!         )?;
//!
//!         // StageTwo: Point has curve equation - use enforced()
//!         let stage2_output = stage2_guard.enforced(
//!             dr,
//!             witness.view().map(|w| w.1),
//!         )?;
//!
//!         // Final stage: consume normal stage outputs, enforce relationships
//!         let doubled_point = stage2_output.double(dr)?;
//!         let point_x_value = doubled_point.value().view().map(|p| {
//!             *p.coordinates().unwrap().x()
//!         });
//!         let point_x = Element::alloc(dr, point_x_value)?;
//!
//!         let mut sum = Element::zero(dr);
//!         for elem in stage1_output.iter() {
//!             sum = sum.add(dr, elem);
//!         }
//!
//!         let result = sum.add(dr, &point_x);
//!
//!         Ok((result, D::just(|| ())))
//!     }
//! }
//! ```
//!
//! ## How The Builder Works
//!
//! ### Phase 1: Wire Reservation for Normal Stages
//!
//! Call `builder.add_stage::<S>()` for each normal stage. This:
//!
//! 1. Counts how many wires the stage needs (using a counter emulator)
//! 2. Reserves non-overlapping wire positions with placeholder values
//! 3. Returns a [`StageGuard`] holding the reserved positions
//!
//! After all normal stages are added, call `builder.finish()` to get the driver
//! for the final stage. At this point, the witness polynomial has a fixed structure:
//!
//! ```text
//! r(X) = [Stage 1: wires 0-99] + [Stage 2: wires 100-101] + [Final: wires 102+]
//! ```
//!
//! ### Phase 2: Witness Computation for All Stages
//!
//! Now compute witness values for both normal and final stages:
//!
//! 1. **Normal stages** - Consume each [`StageGuard`] with `unenforced()` or
//!    `enforced()` to populate its reserved wires
//! 2. **Final stage** - Write your circuit logic that consumes the normal stage
//!    outputs. This is where relationships between stages are enforced.
//!
//! The methods for populating normal stage wires:
//!
//! #### `unenforced()` - For Constraint-Free Outputs
//!
//! Use when the normal stage outputs only field elements with no internal
//! constraints (e.g., `Element<F>`). Computes values with a wireless emulator
//! and directly injects them into the reserved wires:
//!
//! ```rust,ignore
//! let output = guard.unenforced(dr, witness)?;
//! ```
//!
//! **What happens**:
//! ```text
//! Reserved wires:    [w100, w101, w102, ...]  (from Phase 1)
//! Computed values:   [v0, v1, v2, ...]        (wireless emulation)
//! Result:            w100 := v0, w101 := v1   (direct injection)
//! Cost:              Zero - no extra wires or constraints
//! ```
//!
//! #### `enforced()` - For Outputs With Internal Constraints
//!
//! Use when the normal stage output has internal constraints (e.g., `Point`
//! enforces curve equations). Runs the full witness computation on the real
//! driver, then connects the resulting "live wires" to the reserved stage wires
//! via equality constraints:
//!
//! ```rust,ignore
//! let output = guard.enforced(dr, witness)?;
//! ```
//!
//! **What happens** (for a `Point` with curve equation `x³ + b = y²`):
//! ```text
//! Reserved wires:        [w100, w101]              (x, y positions from Phase 1)
//! Live computation:      [w102, w103, w104, ...]   (x, x², x³, y, y²)
//! Internal constraints:  w104 = w102·w103          (x³ = x·x²)
//!                        w104 + b = w105           (curve LHS = RHS)
//! Equality glue:         w102 = w100, w105 = w101  (connect to reserved positions)
//! Returned gadget:       Point { x: w100, y: w101 }
//! Cost:                  Extra wires for internal computation + equality constraints
//! ```
//!
//! The final stage can now use the returned `Point` gadget, which references
//! the reserved stage wires but has its internal constraints already enforced.
//!
//! ## Why Stage Witnesses This Way?
//!
//! Ragu's protocol requires committing to stage polynomials independently:
//! `r(X) = a(X) + b(X) + ... + f(X)`. The verifier needs to know which wires
//! belong to which stage polynomial before seeing witness values.
//!
//! **Benefits**:
//! - Commit to partial witnesses before computing the full circuit
//! - Deterministic wire positions across all provers
//! - Can compute stages out-of-order or conditionally
//! - Use any gadget in a stage without rewriting it (via `enforced()`)
//!
//! **Cost**: `enforced()` adds overhead proportional to gadget complexity
//!
//! ## Choosing Between `enforced()` and `unenforced()`
//!
//! Use `unenforced()` when the output contains only field elements:
//! - `Element`, `Scalar`, `FixedVec<Element>`, etc.
//! - Hash outputs, linear combinations, field arithmetic
//!
//! Use `enforced()` when the output has internal constraints:
//! - `Point` (curve equation: `x³ + b = y²`)
//! - `Boolean` (bit constraint: `a·(1-a) = 0`)
//! - `Endoscalar` (contains `Boolean` fields)
//! - Custom gadgets with gates, range checks, etc.

use arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue, FromDriver,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Gadget, GadgetKind},
    maybe::Empty,
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{Stage, StageExt};
use crate::polynomials::Rank;

/// Builder object for synthesizing a multi-stage circuit witness.
pub struct StageBuilder<
    'a,
    'dr,
    D: Driver<'dr>,
    R: Rank,
    Current: Stage<D::F, R>,
    Target: Stage<D::F, R>,
> {
    driver: &'a mut D,
    _marker: PhantomData<(&'dr (), R, Current, Target)>,
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, (), Target>
{
    /// Creates a new `StageBuilder` given an underlying `driver`.
    pub fn new(driver: &'a mut D) -> Self {
        StageBuilder {
            driver,
            _marker: PhantomData,
        }
    }
}

/// Injects pre-allocated stage wires into a gadget, and enforces equality
/// between live wires and stage wires.
struct EnforcingInjector<'a, 'dr, D: Driver<'dr>> {
    driver: &'a mut D,
    stage_wires: core::slice::Iter<'a, D::Wire>,
}

impl<'dr, D: Driver<'dr>> FromDriver<'dr, 'dr, D> for EnforcingInjector<'_, 'dr, D> {
    type NewDriver = D;

    fn convert_wire(&mut self, live_wire: &D::Wire) -> Result<D::Wire> {
        let stage_wire = self
            .stage_wires
            .next()
            .ok_or_else(|| ragu_core::Error::InvalidWitness("not enough stage wires".into()))?;

        self.driver.enforce_equal(live_wire, stage_wire)?;

        Ok(stage_wire.clone())
    }
}

/// Injects pre-allocated stage wires into a gadget, without enforcing constraints.
struct StageWireInjector<'a, 'dr, D: Driver<'dr>> {
    stage_wires: core::slice::Iter<'a, D::Wire>,
    _marker: PhantomData<&'dr ()>,
}

impl<'dr, D: Driver<'dr>> FromDriver<'_, 'dr, Emulator<Wireless<D::MaybeKind, D::F>>>
    for StageWireInjector<'_, 'dr, D>
{
    type NewDriver = D;

    fn convert_wire(&mut self, _: &()) -> Result<D::Wire> {
        self.stage_wires
            .next()
            .cloned()
            .ok_or_else(|| ragu_core::Error::InvalidWitness("not enough stage wires".into()))
    }
}

/// Guard type returned by `add_stage` that holds pre-allocated stage wires.
///
/// The stage wires are allocated at the correct positions, but the actual
/// witness computation is deferred until one of the consuming methods is called:
///
/// - [`enforced`](Self::enforced) - run witness and enforce constraints
/// - [`unenforced`](Self::unenforced) - run witness without constraints
///
/// To skip a stage without producing a gadget, use [`StageBuilder::skip_stage`]
/// instead of `add_stage`.
#[must_use = "StageGuard must be consumed via `enforced` or `unenforced`"]
pub struct StageGuard<'dr, D: Driver<'dr>, R: Rank, S: Stage<D::F, R>> {
    stage: S,
    stage_wires: Vec<D::Wire>,
    _marker: PhantomData<(&'dr (), R, S)>,
}

impl<'dr, D: Driver<'dr>, R: Rank, S: Stage<D::F, R> + 'dr> StageGuard<'dr, D, R, S> {
    /// Enforce constraints and inject stage wires.
    ///
    /// Runs the stage's witness method on the real driver (enforcing all
    /// internal constraints), then enforces equality between the computed
    /// wires and the pre-allocated stage wires.
    pub fn enforced<'a, 'source: 'dr>(
        self,
        driver: &'a mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<<S::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>> {
        // Run witness on the real driver, enforcing all constraints.
        let computed_gadget = self.stage.witness(driver, witness)?;

        // Map the computed gadget, enforcing equality and substituting stage wires.
        let mut injector = EnforcingInjector {
            driver,
            stage_wires: self.stage_wires.iter(),
        };

        computed_gadget.map(&mut injector)
    }

    /// Inject stage wires without enforcing constraints.
    ///
    /// Runs the stage's witness method on a wireless emulator (not on the
    /// underlying driver), then substitutes the pre-allocated stage wires
    /// into the resulting gadget.
    pub fn unenforced<'source: 'dr>(
        self,
        _dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<<S::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, D::F>> = Emulator::wireless();
        let computed_gadget = self.stage.witness(&mut emulator, witness)?;

        let mut injector = StageWireInjector::<D> {
            stage_wires: self.stage_wires.iter(),
            _marker: PhantomData,
        };

        computed_gadget.map(&mut injector)
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Current: Stage<D::F, R>, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Current, Target>
{
    /// Add the next stage to the builder, allocating stage wire positions.
    ///
    /// This method allocates the stage wires at the correct positions but does
    /// not compute the witness. Call [`StageGuard::unenforced`] or
    /// [`StageGuard::enforced`] on the returned guard to provide the witness
    /// and obtain the output gadget.
    pub fn configure_stage<Next: Stage<D::F, R, Parent = Current> + 'dr>(
        self,
        stage: Next,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )> {
        // Invoke wireless emulator with dummy witness to get gadget structure.
        // The emulator never actually reads the witness values.
        let mut emulator = Emulator::counter();
        let num_wires = stage.witness(&mut emulator, Empty)?.num_wires();

        // Check bounds
        if num_wires > Next::values() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded(
                Next::num_multiplications(),
            ));
        }

        // Collect stage wires
        let mut wires = Vec::with_capacity(num_wires);
        for _ in 0..num_wires {
            wires.push(self.driver.alloc(|| Ok(Coeff::Zero))?);
        }

        Ok((
            StageGuard {
                stage,
                stage_wires: wires,
                _marker: PhantomData,
            },
            StageBuilder {
                driver: self.driver,
                _marker: PhantomData,
            },
        ))
    }

    /// Add the next stage to the builder using [`Self::configure_stage`]
    /// assuming the stage implements [`Default`].
    pub fn add_stage<Next>(
        self,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )>
    where
        Next: Stage<D::F, R, Parent = Current> + Default + 'dr,
    {
        self.configure_stage(Next::default())
    }

    /// Skip the next stage without producing a gadget.
    ///
    /// This allocates the stage wire positions but does not return a guard,
    /// so it's used when you need to reserve the wire positions for a stage
    /// but don't need to compute its witness or produce its output gadget.
    pub fn skip_stage<Next: Stage<D::F, R, Parent = Current> + Default + 'dr>(
        self,
    ) -> Result<StageBuilder<'a, 'dr, D, R, Next, Target>> {
        let (_, builder) = self.add_stage::<Next>()?;
        Ok(builder)
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Finished: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Finished, Finished>
{
    /// Obtain the underlying driver after finishing the last stage.
    pub fn finish(self) -> &'a mut D {
        self.driver
    }
}
