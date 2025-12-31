//! Eval stage for fuse operations.

use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, io::Write};

use core::marker::PhantomData;

use crate::proof::{ABProof, ErrorMProof, Proof, QueryProof, SPrimeProof};

pub use crate::internal_circuits::InternalCircuitIndex::EvalStage as STAGING_ID;

/// Witness for the eval stage.
pub struct Witness<'a, C: Cycle, R: Rank> {
    pub u: C::CircuitField,
    pub left: &'a Proof<C, R>,
    pub right: &'a Proof<C, R>,
    pub s_prime: &'a SPrimeProof<C, R>,
    pub error_m: &'a ErrorMProof<C, R>,
    pub ab: &'a ABProof<C, R>,
    pub query: &'a QueryProof<C, R>,
}

/// The number of elements inside of a `ChildEvaluations` gadget, representing
/// the number of evaluations at `u` per child proof.
const NUM_EVALS_PER_CHILD_PROOF: usize = 15;

/// The number of evaluations at `u` for the current fuse step's polynomials.
const NUM_EVALS_FOR_CURRENT_STEP: usize = 6;

/// Output gadget for a single child proof's polynomial evaluations at `u`.
#[derive(Gadget, Write)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub application: Element<'dr, D>,
    #[ragu(gadget)]
    pub preamble: Element<'dr, D>,
    #[ragu(gadget)]
    pub error_m: Element<'dr, D>,
    #[ragu(gadget)]
    pub error_n: Element<'dr, D>,
    #[ragu(gadget)]
    pub a_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub query: Element<'dr, D>,
    #[ragu(gadget)]
    pub mesh_xy_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub eval: Element<'dr, D>,
    #[ragu(gadget)]
    pub p_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub hashes_1: Element<'dr, D>,
    #[ragu(gadget)]
    pub hashes_2: Element<'dr, D>,
    #[ragu(gadget)]
    pub partial_collapse: Element<'dr, D>,
    #[ragu(gadget)]
    pub full_collapse: Element<'dr, D>,
    #[ragu(gadget)]
    pub compute_v: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> ChildEvaluations<'dr, D> {
    pub fn alloc<C: Cycle, R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, (&Proof<C, R>, C::CircuitField)>,
    ) -> Result<Self>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        Ok(ChildEvaluations {
            application: Element::alloc(dr, proof.view().map(|(p, u)| p.application.rx.eval(*u)))?,
            preamble: Element::alloc(dr, proof.view().map(|(p, u)| p.preamble.stage_rx.eval(*u)))?,
            error_m: Element::alloc(dr, proof.view().map(|(p, u)| p.error_m.stage_rx.eval(*u)))?,
            error_n: Element::alloc(dr, proof.view().map(|(p, u)| p.error_n.stage_rx.eval(*u)))?,
            a_poly: Element::alloc(dr, proof.view().map(|(p, u)| p.ab.a_poly.eval(*u)))?,
            b_poly: Element::alloc(dr, proof.view().map(|(p, u)| p.ab.b_poly.eval(*u)))?,
            query: Element::alloc(dr, proof.view().map(|(p, u)| p.query.stage_rx.eval(*u)))?,
            mesh_xy_poly: Element::alloc(
                dr,
                proof.view().map(|(p, u)| p.query.mesh_xy_poly.eval(*u)),
            )?,
            eval: Element::alloc(dr, proof.view().map(|(p, u)| p.eval.stage_rx.eval(*u)))?,
            p_poly: Element::alloc(dr, proof.view().map(|(p, u)| p.p.poly.eval(*u)))?,
            hashes_1: Element::alloc(
                dr,
                proof.view().map(|(p, u)| p.circuits.hashes_1_rx.eval(*u)),
            )?,
            hashes_2: Element::alloc(
                dr,
                proof.view().map(|(p, u)| p.circuits.hashes_2_rx.eval(*u)),
            )?,
            partial_collapse: Element::alloc(
                dr,
                proof
                    .view()
                    .map(|(p, u)| p.circuits.partial_collapse_rx.eval(*u)),
            )?,
            full_collapse: Element::alloc(
                dr,
                proof
                    .view()
                    .map(|(p, u)| p.circuits.full_collapse_rx.eval(*u)),
            )?,
            compute_v: Element::alloc(
                dr,
                proof.view().map(|(p, u)| p.circuits.compute_v_rx.eval(*u)),
            )?,
        })
    }
}

/// Output gadget for the eval stage.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub left: ChildEvaluations<'dr, D>,
    #[ragu(gadget)]
    pub right: ChildEvaluations<'dr, D>,
    #[ragu(gadget)]
    pub mesh_wx0: Element<'dr, D>,
    #[ragu(gadget)]
    pub mesh_wx1: Element<'dr, D>,
    #[ragu(gadget)]
    pub mesh_wy: Element<'dr, D>,
    #[ragu(gadget)]
    pub a_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub mesh_xy: Element<'dr, D>,
}

/// The eval stage of the fuse witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = super::query::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source Witness<'source, C, R>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _>];

    fn values() -> usize {
        NUM_EVALS_PER_CHILD_PROOF * 2 + NUM_EVALS_FOR_CURRENT_STEP
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let left = ChildEvaluations::alloc(dr, witness.view().map(|w| (w.left, w.u)))?;
        let right = ChildEvaluations::alloc(dr, witness.view().map(|w| (w.right, w.u)))?;

        let mesh_wx0 = Element::alloc(
            dr,
            witness.view().map(|w| w.s_prime.mesh_wx0_poly.eval(w.u)),
        )?;
        let mesh_wx1 = Element::alloc(
            dr,
            witness.view().map(|w| w.s_prime.mesh_wx1_poly.eval(w.u)),
        )?;
        let mesh_wy = Element::alloc(dr, witness.view().map(|w| w.error_m.mesh_wy_poly.eval(w.u)))?;
        let a_poly = Element::alloc(dr, witness.view().map(|w| w.ab.a_poly.eval(w.u)))?;
        let b_poly = Element::alloc(dr, witness.view().map(|w| w.ab.b_poly.eval(w.u)))?;
        let mesh_xy = Element::alloc(dr, witness.view().map(|w| w.query.mesh_xy_poly.eval(w.u)))?;

        Ok(Output {
            left,
            right,
            mesh_wx0,
            mesh_wx1,
            mesh_wy,
            a_poly,
            b_poly,
            mesh_xy,
        })
    }
}
