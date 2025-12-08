use alloc::vec::Vec;
use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{ConstLen, FixedVec},
};

use core::marker::PhantomData;

pub const STAGING_ID: usize = crate::internal_circuits::NATIVE_PREAMBLE_STAGING_ID;

type Header<'dr, D, const HEADER_SIZE: usize> = FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>;

/// Headers from a single proof's k(Y) polynomial.
pub struct ProofHeaders<F, const HEADER_SIZE: usize> {
    pub right_header: [F; HEADER_SIZE],
    pub left_header: [F; HEADER_SIZE],
    pub output_header: [F; HEADER_SIZE],
}

/// Witness for the native preamble stage.
pub struct Witness<F, const HEADER_SIZE: usize> {
    pub left: ProofHeaders<F, HEADER_SIZE>,
    pub right: ProofHeaders<F, HEADER_SIZE>,
}

/// Output of the native preamble stage.
pub type Output<'dr, D, const HEADER_SIZE: usize> = (
    (
        Header<'dr, D, HEADER_SIZE>,
        (Header<'dr, D, HEADER_SIZE>, Header<'dr, D, HEADER_SIZE>),
    ),
    (
        Header<'dr, D, HEADER_SIZE>,
        (Header<'dr, D, HEADER_SIZE>, Header<'dr, D, HEADER_SIZE>),
    ),
);

pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = ();
    type Witness<'source> = &'source Witness<C::CircuitField, HEADER_SIZE>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, HEADER_SIZE>];

    fn values() -> usize {
        2 * 3 * HEADER_SIZE
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        fn alloc_header<'dr, D: Driver<'dr>, const HEADER_SIZE: usize>(
            dr: &mut D,
            data: DriverValue<D, &[D::F; HEADER_SIZE]>,
        ) -> Result<FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>> {
            let mut v = Vec::with_capacity(HEADER_SIZE);
            for i in 0..HEADER_SIZE {
                v.push(Element::alloc(dr, data.view().map(|d| d[i]))?);
            }
            Ok(FixedVec::new(v).expect("length"))
        }

        // Allocation following adapter's reversed k(Y): right, left, output
        let left_right = alloc_header(dr, witness.view().map(|w| &w.left.right_header))?;
        let left_left = alloc_header(dr, witness.view().map(|w| &w.left.left_header))?;
        let left_output = alloc_header(dr, witness.view().map(|w| &w.left.output_header))?;

        let right_right = alloc_header(dr, witness.view().map(|w| &w.right.right_header))?;
        let right_left = alloc_header(dr, witness.view().map(|w| &w.right.left_header))?;
        let right_output = alloc_header(dr, witness.view().map(|w| &w.right.output_header))?;

        Ok((
            (left_right, (left_left, left_output)),
            (right_right, (right_left, right_output)),
        ))
    }
}
