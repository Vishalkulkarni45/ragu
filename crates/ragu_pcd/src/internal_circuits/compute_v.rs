use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, txz::Evaluate},
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};
use ragu_primitives::GadgetExt;

use core::marker::PhantomData;

use super::{
    stages::native::{eval as native_eval, preamble as native_preamble, query as native_query},
    unified::{self, OutputBuilder},
};
use crate::components::horner::Horner;

pub use crate::internal_circuits::InternalCircuitIndex::ComputeVCircuit as CIRCUIT_ID;

pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Circuit<C, R, HEADER_SIZE> {
    pub fn new() -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    pub unified_instance: &'a unified::Instance<C>,
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub query_witness: &'a native_query::Witness<C>,
    pub eval_witness: &'a native_eval::Witness<'a, C, R>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> StagedCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE>
{
    type Final = native_eval::Stage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
    type Output = unified::InternalOutputKind<C>;
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
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;

        // TODO: these are unenforced for now, because query/eval stages aren't
        // supposed to contain anything (yet) besides Elements, which require no
        // enforcement logic. Re-evaluate this in the future.
        let _query = query.unenforced(dr, witness.view().map(|w| w.query_witness))?;
        let eval = eval.unenforced(dr, witness.view().map(|w| w.eval_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        let x = unified_output.x.get(dr, unified_instance)?;
        let z = unified_output.z.get(dr, unified_instance)?;
        let alpha = unified_output.alpha.get(dr, unified_instance)?;
        let u = unified_output.u.get(dr, unified_instance)?;
        let beta = unified_output.beta.get(dr, unified_instance)?;

        let _txz = dr.routine(Evaluate::new(R::RANK), (x, z))?;

        {
            // Inversions for denominators (u - x_i)
            let denominator_left_u = u.sub(dr, &preamble.left.unified.u).invert(dr)?;
            let denominator_right_u = u.sub(dr, &preamble.right.unified.u).invert(dr)?;

            // Quotient data: (p(u), v, 1/(u - x_i))
            // Proves p(x_i) = v_i
            let quotients = [
                (
                    &eval.left.p_poly,
                    &preamble.left.unified.v,
                    &denominator_left_u,
                ),
                (
                    &eval.right.p_poly,
                    &preamble.right.unified.v,
                    &denominator_right_u,
                ),
            ];

            let mut horner = Horner::new(dr, &alpha);
            for (pu, v, denominator) in quotients {
                pu.sub(dr, v).mul(dr, denominator)?.write(dr, &mut horner)?;
            }
            let fu = horner.finish();
            let mut horner = Horner::new(dr, &beta);
            fu.write(dr, &mut horner)?;
            eval.write(dr, &mut horner)?;
            let computed_v = horner.finish();
            let witnessed_v = unified_output.v.get(dr, unified_instance)?;

            // When NOT in base case, enforce witnessed_v == computed_v.
            // In base case (both children trivial), prover may witness any v value.
            preamble
                .is_base_case(dr)?
                .not(dr)
                .conditional_enforce_equal(dr, &witnessed_v, &computed_v)?;
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
