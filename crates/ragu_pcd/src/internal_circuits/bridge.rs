//! Bridge circuit for soundness between preamble and application circuit.
//!
//! This circuit ensures that the headers stored in `ApplicationProof` match
//! the output headers committed in the preamble. The circuit outputs the
//! preamble's output headers, and k(y) verification ensures the instance
//! (from `ApplicationProof`) matches the committed output.

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    io::Write,
    vec::{ConstLen, FixedVec},
};

use core::marker::PhantomData;

use super::stages::native::{
    error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
};
use crate::components::{fold_revdot, suffix::Suffix};

pub use crate::internal_circuits::InternalCircuitIndex::BridgeCircuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::BridgeStaged as STAGED_ID;

/// Output gadget for the bridge circuit: left and right headers.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, const HEADER_SIZE: usize> {
    #[ragu(gadget)]
    pub left_header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>,
    #[ragu(gadget)]
    pub right_header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>,
}

pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    pub fn new() -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> Default
    for Circuit<C, R, HEADER_SIZE, FP>
{
    fn default() -> Self {
        Circuit {
            _marker: PhantomData,
        }
    }
}

/// Witness for the bridge circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Preamble witness providing access to output headers from child proofs.
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
}

/// Instance for the bridge circuit: (left_header, right_header).
pub type Instance<'source, F, const HEADER_SIZE: usize> = (
    &'source FixedVec<F, ConstLen<HEADER_SIZE>>,
    &'source FixedVec<F, ConstLen<HEADER_SIZE>>,
);

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    StagedCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = Instance<'source, C::CircuitField, HEADER_SIZE>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
    type Output = Kind![C::CircuitField; Suffix<'_, _, Output<'_, _, HEADER_SIZE>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        // Add preamble stage but use unenforced (constraints are enforced by hashes_1)
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;

        // Skip error_m and error_n stages (allocate wire positions but no witness)
        let builder = builder.skip_stage::<native_error_m::Stage<C, R, HEADER_SIZE, FP>>()?;
        let builder = builder.skip_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;

        let dr = builder.finish();

        // Load preamble unenforced - just inject wire values
        let preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;

        // Output the preamble's committed headers directly.
        // k(y) verification ensures instance headers (from ApplicationProof)
        // match these committed headers.
        Ok((
            Suffix::new(
                Output {
                    left_header: preamble.left.output_header,
                    right_header: preamble.right.output_header,
                },
                Element::zero(dr),
            ),
            D::just(|| ()),
        ))
    }
}
