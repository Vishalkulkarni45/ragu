//! Evaluate $p(X)$.
//!
//! This creates the [`proof::P`] component of the proof, which contains the
//! accumulated polynomial $p(X)$ and its claimed evaluation $p(u) = v$.
//!
//! The commitment and blinding factor are derived as linear combinations of
//! the child proof commitments/blinds using the additive homomorphism of
//! Pedersen commitments: `commit(Σ β^j * p_j, Σ β^j * r_j) = Σ β^j * C_j`.
//!
//! The commitment is computed via a single MSM over all accumulated terms.

use alloc::vec::Vec;
use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;

use crate::{Application, Proof, proof};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_p<'dr, D>(
        &self,
        beta: &Element<'dr, D>,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
    ) -> Result<proof::P<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let mut poly = f.poly.clone();
        let mut blind = f.blind;

        // Collect MSM terms: (scalar, base) pairs for commitment computation.
        // The commitment is Σ β^j * C_j, computed via a single MSM at the end.
        let mut msm_scalars: Vec<C::CircuitField> = Vec::new();
        let mut msm_bases: Vec<C::HostCurve> = Vec::new();

        // The orderings in this code must match the corresponding struct
        // definition ordering of `stages::native::eval::Output`.
        //
        // We accumulate polynomial and blind in lock-step, while collecting
        // MSM terms for the commitment computation.
        {
            let beta = *beta.value().take();

            // Current power of beta, starting at β^0 for the last term added.
            // We'll compute the final scalars by multiplying accumulated powers.
            let mut beta_power = C::CircuitField::ONE;

            // Accumulate structured polynomial with corresponding blind,
            // and collect MSM term for commitment.
            let acc_s = |p: &mut ragu_circuits::polynomials::unstructured::Polynomial<_, _>,
                         b: &mut C::CircuitField,
                         scalars: &mut Vec<C::CircuitField>,
                         bases: &mut Vec<C::HostCurve>,
                         beta_pow: &mut C::CircuitField,
                         term_poly,
                         term_blind,
                         term_commitment: C::HostCurve| {
                p.scale(beta);
                p.add_structured(term_poly);
                *b = beta * *b + term_blind;
                // Push the term; we'll fix up scalars at the end.
                scalars.push(*beta_pow);
                bases.push(term_commitment);
                *beta_pow *= beta;
            };

            // Accumulate unstructured polynomial with corresponding blind,
            // and collect MSM term for commitment.
            let acc_u = |p: &mut ragu_circuits::polynomials::unstructured::Polynomial<_, _>,
                         b: &mut C::CircuitField,
                         scalars: &mut Vec<C::CircuitField>,
                         bases: &mut Vec<C::HostCurve>,
                         beta_pow: &mut C::CircuitField,
                         term_poly,
                         term_blind,
                         term_commitment: C::HostCurve| {
                p.scale(beta);
                p.add_assign(term_poly);
                *b = beta * *b + term_blind;
                // Push the term; we'll fix up scalars at the end.
                scalars.push(*beta_pow);
                bases.push(term_commitment);
                *beta_pow *= beta;
            };

            for proof in [left, right] {
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.application.rx,
                    proof.application.blind,
                    proof.application.commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.preamble.stage_rx,
                    proof.preamble.stage_blind,
                    proof.preamble.stage_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.error_n.stage_rx,
                    proof.error_n.stage_blind,
                    proof.error_n.stage_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.error_m.stage_rx,
                    proof.error_m.stage_blind,
                    proof.error_m.stage_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.ab.a_poly,
                    proof.ab.a_blind,
                    proof.ab.a_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.ab.b_poly,
                    proof.ab.b_blind,
                    proof.ab.b_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.query.stage_rx,
                    proof.query.stage_blind,
                    proof.query.stage_commitment,
                );
                acc_u(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.query.mesh_xy_poly,
                    proof.query.mesh_xy_blind,
                    proof.query.mesh_xy_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.eval.stage_rx,
                    proof.eval.stage_blind,
                    proof.eval.stage_commitment,
                );
                acc_u(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.p.poly,
                    proof.p.blind,
                    proof.p.commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.circuits.hashes_1_rx,
                    proof.circuits.hashes_1_blind,
                    proof.circuits.hashes_1_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.circuits.hashes_2_rx,
                    proof.circuits.hashes_2_blind,
                    proof.circuits.hashes_2_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.circuits.partial_collapse_rx,
                    proof.circuits.partial_collapse_blind,
                    proof.circuits.partial_collapse_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.circuits.full_collapse_rx,
                    proof.circuits.full_collapse_blind,
                    proof.circuits.full_collapse_commitment,
                );
                acc_s(
                    &mut poly,
                    &mut blind,
                    &mut msm_scalars,
                    &mut msm_bases,
                    &mut beta_power,
                    &proof.circuits.compute_v_rx,
                    proof.circuits.compute_v_blind,
                    proof.circuits.compute_v_commitment,
                );
            }

            acc_u(
                &mut poly,
                &mut blind,
                &mut msm_scalars,
                &mut msm_bases,
                &mut beta_power,
                &s_prime.mesh_wx0_poly,
                s_prime.mesh_wx0_blind,
                s_prime.mesh_wx0_commitment,
            );
            acc_u(
                &mut poly,
                &mut blind,
                &mut msm_scalars,
                &mut msm_bases,
                &mut beta_power,
                &s_prime.mesh_wx1_poly,
                s_prime.mesh_wx1_blind,
                s_prime.mesh_wx1_commitment,
            );
            acc_s(
                &mut poly,
                &mut blind,
                &mut msm_scalars,
                &mut msm_bases,
                &mut beta_power,
                &error_m.mesh_wy_poly,
                error_m.mesh_wy_blind,
                error_m.mesh_wy_commitment,
            );
            acc_s(
                &mut poly,
                &mut blind,
                &mut msm_scalars,
                &mut msm_bases,
                &mut beta_power,
                &ab.a_poly,
                ab.a_blind,
                ab.a_commitment,
            );
            acc_s(
                &mut poly,
                &mut blind,
                &mut msm_scalars,
                &mut msm_bases,
                &mut beta_power,
                &ab.b_poly,
                ab.b_blind,
                ab.b_commitment,
            );
            acc_u(
                &mut poly,
                &mut blind,
                &mut msm_scalars,
                &mut msm_bases,
                &mut beta_power,
                &query.mesh_xy_poly,
                query.mesh_xy_blind,
                query.mesh_xy_commitment,
            );

            // Add f's commitment with the final beta power.
            msm_scalars.push(beta_power);
            msm_bases.push(f.commitment);
        }

        let n = msm_scalars.len() - 1;
        msm_scalars[..n].reverse();

        // Compute commitment via MSM: Σ scalar_i * base_i
        let commitment = arithmetic::mul(msm_scalars.iter(), msm_bases.iter());

        let v = poly.eval(*u.value().take());

        Ok(proof::P {
            poly,
            blind,
            commitment: commitment.into(),
            v,
        })
    }
}
