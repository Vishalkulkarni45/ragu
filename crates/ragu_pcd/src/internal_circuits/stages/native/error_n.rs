//! Error stage (layer 2) for fuse operations.
//!
//! This stage handles the final N-sized revdot claim reduction.

use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    poseidon::{PoseidonStateLen, SpongeState},
    vec::{CollectFixed, FixedVec, Len},
};

use core::marker::PhantomData;

pub use crate::internal_circuits::InternalCircuitIndex::ErrorNStage as STAGING_ID;

use crate::components::fold_revdot::{self, ErrorTermsLen};

/// $k(Y)$ evaluation values computed during fuse operation.
pub struct KyValues<F> {
    pub left_application: F,
    pub right_application: F,
    pub left_unified: F,
    pub right_unified: F,
    pub left_unified_bridge: F,
    pub right_unified_bridge: F,
}

/// Witness data for the error_n stage (layer 2).
///
/// Contains $N^2 - N$ error terms for the second layer of reduction, plus the
/// $N$ collapsed values from layer 1 folding, and the saved sponge state for
/// bridging the transcript between hashes_1 and hashes_2.
pub struct Witness<C: Cycle, FP: fold_revdot::Parameters> {
    /// Error term elements for layer 2.
    pub error_terms: FixedVec<C::CircuitField, ErrorTermsLen<FP::N>>,

    /// Collapsed values from layer 1 folding ($N$ values). These are the
    /// outputs of $N$ individual size-$M$ revdot reductions.
    pub collapsed: FixedVec<C::CircuitField, FP::N>,

    /// $k(y)$ evaluation values.
    pub ky: KyValues<C::CircuitField>,

    /// Sponge state elements saved after absorbing nested_error_m_commitment.
    /// Used to bridge the Fiat-Shamir transcript between hashes_1 and hashes_2.
    pub sponge_state_elements:
        FixedVec<C::CircuitField, PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>>,
}

/// Output gadget for the error_n stage.
#[derive(Gadget)]
pub struct Output<
    'dr,
    D: Driver<'dr>,
    FP: fold_revdot::Parameters,
    Poseidon: arithmetic::PoseidonPermutation<D::F>,
> {
    /// Error term elements for layer 2.
    #[ragu(gadget)]
    pub error_terms: FixedVec<Element<'dr, D>, ErrorTermsLen<FP::N>>,
    /// Collapsed values from layer 1 folding (N values).
    #[ragu(gadget)]
    pub collapsed: FixedVec<Element<'dr, D>, FP::N>,
    /// k(y) for left application circuit.
    #[ragu(gadget)]
    pub left_application_ky: Element<'dr, D>,
    /// k(y) for right application circuit.
    #[ragu(gadget)]
    pub right_application_ky: Element<'dr, D>,
    /// k(y) for left unified circuit.
    #[ragu(gadget)]
    pub left_unified_ky: Element<'dr, D>,
    /// k(y) for right unified circuit.
    #[ragu(gadget)]
    pub right_unified_ky: Element<'dr, D>,
    /// k(y) for left child's header-unified binding.
    #[ragu(gadget)]
    pub left_unified_bridge_ky: Element<'dr, D>,
    /// k(y) for right child's header-unified binding.
    #[ragu(gadget)]
    pub right_unified_bridge_ky: Element<'dr, D>,
    /// Sponge state saved after absorbing nested_error_m_commitment.
    /// Used to bridge the Fiat-Shamir transcript between hashes_1 and hashes_2.
    #[ragu(gadget)]
    pub sponge_state: SpongeState<'dr, D, Poseidon>,
}

/// The error_n stage (layer 2) of the fuse witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    staging::Stage<C::CircuitField, R> for Stage<C, R, HEADER_SIZE, FP>
{
    type Parent = super::error_m::Stage<C, R, HEADER_SIZE, FP>;
    type Witness<'source> = &'source Witness<C, FP>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, FP, C::CircuitPoseidon>];

    fn values() -> usize {
        // N² - N error terms + N collapsed values + 6 ky values + sponge state elements
        ErrorTermsLen::<FP::N>::len()
            + FP::N::len()
            + 6
            + PoseidonStateLen::<C::CircuitField, C::CircuitPoseidon>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let error_terms = ErrorTermsLen::<FP::N>::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.error_terms[i])))
            .try_collect_fixed()?;
        let collapsed = FP::N::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.collapsed[i])))
            .try_collect_fixed()?;
        let left_application_ky =
            Element::alloc(dr, witness.view().map(|w| w.ky.left_application))?;
        let right_application_ky =
            Element::alloc(dr, witness.view().map(|w| w.ky.right_application))?;
        let left_unified_ky = Element::alloc(dr, witness.view().map(|w| w.ky.left_unified))?;
        let right_unified_ky = Element::alloc(dr, witness.view().map(|w| w.ky.right_unified))?;
        let left_unified_bridge_ky =
            Element::alloc(dr, witness.view().map(|w| w.ky.left_unified_bridge))?;
        let right_unified_bridge_ky =
            Element::alloc(dr, witness.view().map(|w| w.ky.right_unified_bridge))?;
        let sponge_state = SpongeState::from_elements(FixedVec::try_from_fn(|i| {
            Element::alloc(dr, witness.view().map(|w| w.sponge_state_elements[i]))
        })?);

        Ok(Output {
            error_terms,
            collapsed,
            left_application_ky,
            right_application_ky,
            left_unified_ky,
            right_unified_ky,
            left_unified_bridge_ky,
            right_unified_bridge_ky,
            sponge_state,
        })
    }
}
