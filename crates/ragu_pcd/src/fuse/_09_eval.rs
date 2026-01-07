//! Commit to the evaluations of every queried polynomial at $u$.
//!
//! This creates the [`proof::Eval`] component of the proof, which contains
//! evaluations of every committed or accumulated polynomial (thus far) at the
//! point $u$, except $f(u)$ which is _derived_ from said evaluations.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::Rng;

use crate::{
    Application, Proof,
    circuits::stages::{self, native::eval},
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_eval<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
    ) -> Result<(proof::Eval<C, R>, eval::Witness<C::CircuitField>)>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let u = *u.value().take();

        let eval_witness = eval::Witness {
            left: eval::ChildEvaluationsWitness::from_proof(left, u),
            right: eval::ChildEvaluationsWitness::from_proof(right, u),
            current: eval::CurrentStepWitness {
                // TODO: the mesh evaluations here could _theoretically_ be more
                // efficient if they're computed simultaneously with assistance
                // from the mesh itself, rather than individually evaluated for
                // each of these restrictions.
                mesh_wx0: s_prime.mesh_wx0_poly.eval(u),
                mesh_wx1: s_prime.mesh_wx1_poly.eval(u),
                mesh_wy: error_m.mesh_wy_poly.eval(u),
                a_poly: ab.a_poly.eval(u),
                b_poly: ab.b_poly.eval(u),
                mesh_xy: query.mesh_xy_poly.eval(u),
            },
        };
        let stage_rx = eval::Stage::<C, R, HEADER_SIZE>::rx(&eval_witness)?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        let nested_eval_witness = stages::nested::eval::Witness {
            native_eval: stage_commitment,
        };
        let nested_rx = stages::nested::eval::Stage::<C::HostCurve, R>::rx(&nested_eval_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::Eval {
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            eval_witness,
        ))
    }
}
