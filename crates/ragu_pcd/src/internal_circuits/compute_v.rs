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
use ragu_primitives::{Element, GadgetExt};

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
        let query = query.unenforced(dr, witness.view().map(|w| w.query_witness))?;
        let eval = eval.unenforced(dr, witness.view().map(|w| w.eval_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        let w = unified_output.w.get(dr, unified_instance)?;
        let y = unified_output.y.get(dr, unified_instance)?;
        let z = unified_output.z.get(dr, unified_instance)?;
        let x = unified_output.x.get(dr, unified_instance)?;

        let _txz = dr.routine(Evaluate::new(R::RANK), (x.clone(), z))?;

        // Enforce the claimed value `v` in the unified instance is correctly
        // computed based on committed evaluation claims and verifier
        // challenges.
        {
            // Compute expected f(u)
            let fu = {
                let alpha = unified_output.alpha.get(dr, unified_instance)?;
                let u = unified_output.u.get(dr, unified_instance)?;
                let denominators = Denominators::new(dr, &u, &w, &x, &y, &preamble)?;
                let mut horner = Horner::new(dr, &alpha);
                for (pu, v, denominator) in poly_queries(&eval, &query, &preamble, &denominators) {
                    pu.sub(dr, v).mul(dr, denominator)?.write(dr, &mut horner)?;
                }
                horner.finish()
            };

            // Compute expected v = p(u)
            let computed_v = {
                let beta = unified_output.beta.get(dr, unified_instance)?;
                let mut horner = Horner::new(dr, &beta);
                fu.write(dr, &mut horner)?;
                eval.write(dr, &mut horner)?;
                horner.finish()
            };

            // When NOT in base case, enforce witnessed_v == computed_v.
            // In base case (both children trivial), prover may witness any v value.
            let witnessed_v = unified_output.v.get(dr, unified_instance)?;
            preamble
                .is_base_case(dr)?
                .not(dr)
                .conditional_enforce_equal(dr, &witnessed_v, &computed_v)?;
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}

/// Denominator component of all quotient polynomial evaluations.
///
/// Each represents some $(u - x_i)^{-1}$.
struct Denominators<'dr, D: Driver<'dr>> {
    left_u: Element<'dr, D>,
    right_u: Element<'dr, D>,
    w: Element<'dr, D>,
    old_y0: Element<'dr, D>,
    old_y1: Element<'dr, D>,
    y: Element<'dr, D>,
    old_x0: Element<'dr, D>,
    old_x1: Element<'dr, D>,
    x: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Denominators<'dr, D> {
    #[rustfmt::skip]
    fn new<C: Cycle, const HEADER_SIZE: usize>(
        dr: &mut D,
        u: &Element<'dr, D>,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        preamble: &native_preamble::Output<'dr, D, C, HEADER_SIZE>,
    ) -> Result<Self> {
        Ok(Denominators {
            left_u:  u.sub(dr, &preamble.left.unified.u).invert(dr)?,
            right_u: u.sub(dr, &preamble.right.unified.u).invert(dr)?,
            w:       u.sub(dr, w).invert(dr)?,
            old_y0:  u.sub(dr, &preamble.left.unified.y).invert(dr)?,
            old_y1:  u.sub(dr, &preamble.right.unified.y).invert(dr)?,
            y:       u.sub(dr, y).invert(dr)?,
            old_x0:  u.sub(dr, &preamble.left.unified.x).invert(dr)?,
            old_x1:  u.sub(dr, &preamble.right.unified.x).invert(dr)?,
            x:       u.sub(dr, x).invert(dr)?,
        })
    }
}

/// Returns an iterator over the queries.
///
/// Each yielded element represents $(p(u), v, (u - x_i)^{-1})$ where $v = p(x_i)$
/// is the prover's claim for that query.
#[rustfmt::skip]
fn poly_queries<'a, 'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize>(
    eval: &'a native_eval::Output<'dr, D>,
    query: &'a native_query::Output<'dr, D>,
    preamble: &'a native_preamble::Output<'dr, D, C, HEADER_SIZE>,
    d: &'a Denominators<'dr, D>,
) -> impl Iterator<Item = (&'a Element<'dr, D>, &'a Element<'dr, D>, &'a Element<'dr, D>)> {
    [
        // Check p(X) accumulator
        (&eval.left.p_poly,        &preamble.left.unified.v,          &d.left_u),
        (&eval.right.p_poly,       &preamble.right.unified.v,         &d.right_u),
        // Consistency checks for mesh polynomials
        (&eval.left.mesh_xy_poly,  &query.left.old_mesh_xy_at_new_w,  &d.w),
        (&eval.right.mesh_xy_poly, &query.right.old_mesh_xy_at_new_w, &d.w),
        (&eval.mesh_wx0,           &query.left.old_mesh_xy_at_new_w,  &d.old_y0),
        (&eval.mesh_wx1,           &query.right.old_mesh_xy_at_new_w, &d.old_y1),
        (&eval.mesh_wx0,           &query.left.new_mesh_wy_at_old_x,  &d.y),
        (&eval.mesh_wx1,           &query.right.new_mesh_wy_at_old_x, &d.y),
        (&eval.mesh_wy,            &query.left.new_mesh_wy_at_old_x,  &d.old_x0),
        (&eval.mesh_wy,            &query.right.new_mesh_wy_at_old_x, &d.old_x1),
        (&eval.mesh_wy,            &query.mesh_wxy,                   &d.x),
        (&eval.mesh_xy,            &query.mesh_wxy,                   &d.w),
    ]
    .into_iter()
}
