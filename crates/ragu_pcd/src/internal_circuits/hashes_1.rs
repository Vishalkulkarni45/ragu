//! First hash circuit for Fiat-Shamir derivations (claim-side challenges).
//!
//! This circuit derives the first set of Fiat-Shamir challenges from public commitments:
//! - `w = H(nested_preamble_commitment)`
//! - `(y, z) = H(w, nested_s_prime_commitment)`
//! - `(mu, nu) = H(nested_error_m_commitment)` (bound to z)
//! - `(mu_prime, nu_prime) = H(nested_error_n_commitment)` (bound to nu)

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};

use core::marker::PhantomData;

use super::unified::{self, OutputBuilder};
use crate::components::transcript;

pub use crate::internal_circuits::InternalCircuitIndex::Hashes1Circuit as CIRCUIT_ID;

pub struct Circuit<'params, C: Cycle> {
    params: &'params C,
    _marker: PhantomData<C>,
}

impl<'params, C: Cycle> Circuit<'params, C> {
    pub fn new(params: &'params C) -> Self {
        Circuit {
            params,
            _marker: PhantomData,
        }
    }
}

pub struct Witness<'a, C: Cycle> {
    pub unified_instance: &'a unified::Instance<C>,
}

impl<C: Cycle> ragu_circuits::Circuit<C::CircuitField> for Circuit<'_, C> {
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        OutputBuilder::new().finish(dr, &instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Derive w = H(nested_preamble_commitment)
        let w = {
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance)?;
            transcript::derive_w::<_, C>(dr, &nested_preamble_commitment, self.params)?
        };
        unified_output.w.set(w.clone());

        // Derive (y, z) = H(w, nested_s_prime_commitment)
        let (y, z) = {
            let nested_s_prime_commitment = unified_output
                .nested_s_prime_commitment
                .get(dr, unified_instance)?;
            transcript::derive_y_z::<_, C>(dr, &w, &nested_s_prime_commitment, self.params)?
        };
        unified_output.y.set(y);
        unified_output.z.set(z);

        // Derive (mu, nu) = H(nested_error_m_commitment)
        let (mu, nu) = {
            let nested_error_m_commitment = unified_output
                .nested_error_m_commitment
                .get(dr, unified_instance)?;
            transcript::derive_mu_nu::<_, C>(dr, &nested_error_m_commitment, self.params)?
        };
        unified_output.mu.set(mu);
        unified_output.nu.set(nu);

        // Derive (mu_prime, nu_prime) = H(nested_error_n_commitment)
        let (mu_prime, nu_prime) = {
            let nested_error_n_commitment = unified_output
                .nested_error_n_commitment
                .get(dr, unified_instance)?;
            transcript::derive_mu_nu::<_, C>(dr, &nested_error_n_commitment, self.params)?
        };
        unified_output.mu_prime.set(mu_prime);
        unified_output.nu_prime.set(nu_prime);

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
