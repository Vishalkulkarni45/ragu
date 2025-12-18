//! Second hash circuit for Fiat-Shamir derivations (verification-side challenges).
//!
//! This circuit derives the second set of Fiat-Shamir challenges from public commitments:
//! - `x = H(nu_prime, nested_ab_commitment)` (nu_prime from unified instance)
//! - `alpha = H(nested_query_commitment)`
//! - `u = H(alpha, nested_f_commitment)`
//! - `beta = H(nested_eval_commitment)`

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

pub use crate::internal_circuits::InternalCircuitIndex::Hashes2Circuit as CIRCUIT_ID;

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

        // Get nu_prime from unified instance (derived by hashes_1 circuit)
        let nu_prime = unified_output.nu_prime.get(dr, unified_instance)?;

        // Derive x = H(nu_prime, nested_ab_commitment)
        let x = {
            let nested_ab_commitment = unified_output
                .nested_ab_commitment
                .get(dr, unified_instance)?;
            transcript::derive_x::<_, C>(dr, &nu_prime, &nested_ab_commitment, self.params)?
        };
        unified_output.x.set(x);

        // Derive alpha = H(nested_query_commitment)
        let alpha = {
            let nested_query_commitment = unified_output
                .nested_query_commitment
                .get(dr, unified_instance)?;
            transcript::derive_alpha::<_, C>(dr, &nested_query_commitment, self.params)?
        };
        unified_output.alpha.set(alpha.clone());

        // Derive u = H(alpha, nested_f_commitment)
        let u = {
            let nested_f_commitment = unified_output
                .nested_f_commitment
                .get(dr, unified_instance)?;
            transcript::derive_u::<_, C>(dr, &alpha, &nested_f_commitment, self.params)?
        };
        unified_output.u.set(u);

        // Derive beta = H(nested_eval_commitment)
        let beta = {
            let nested_eval_commitment = unified_output
                .nested_eval_commitment
                .get(dr, unified_instance)?;
            transcript::derive_beta::<_, C>(dr, &nested_eval_commitment, self.params)?
        };
        unified_output.beta.set(beta);

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
