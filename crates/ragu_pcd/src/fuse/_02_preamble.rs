//! Commit to the preamble.
//!
//! This creates the [`proof::Preamble`] component of the proof, which commits
//! to the public inputs and witness polynomials used in the fuse step.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use rand::Rng;

use crate::{
    Application, Proof,
    circuits::stages::{self, native::preamble as native_preamble},
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_preamble<'a, RNG: Rng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        application: &proof::Application<C, R>,
    ) -> Result<(
        proof::Preamble<C, R>,
        native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    )> {
        let preamble_witness = native_preamble::Witness::new(
            left,
            right,
            &application.left_header,
            &application.right_header,
        )?;

        let stage_rx = native_preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        let nested_preamble_witness = stages::nested::preamble::Witness {
            native_preamble: stage_commitment,
            left_application: left.application.commitment,
            right_application: right.application.commitment,
            left_hashes_1: left.circuits.hashes_1_commitment,
            right_hashes_1: right.circuits.hashes_1_commitment,
            left_hashes_2: left.circuits.hashes_2_commitment,
            right_hashes_2: right.circuits.hashes_2_commitment,
            left_partial_collapse: left.circuits.partial_collapse_commitment,
            right_partial_collapse: right.circuits.partial_collapse_commitment,
            left_full_collapse: left.circuits.full_collapse_commitment,
            right_full_collapse: right.circuits.full_collapse_commitment,
            left_compute_v: left.circuits.compute_v_commitment,
            right_compute_v: right.circuits.compute_v_commitment,
        };

        let nested_rx =
            stages::nested::preamble::Stage::<C::HostCurve, R>::rx(&nested_preamble_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::Preamble {
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            preamble_witness,
        ))
    }
}
