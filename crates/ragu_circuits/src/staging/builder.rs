use core::marker::PhantomData;

use ragu_core::{
    Result,
    drivers::{Coeff, Driver, DriverTypes, FromDriver, Witness},
    gadgets::{Gadget, GadgetKind},
};

use super::{Stage, StageExt};
use crate::polynomials::Rank;

/// Builder object for synthesizing a staged circuit witness.
pub struct StageBuilder<
    'a,
    'dr,
    D: Driver<'dr>,
    R: Rank,
    Current: Stage<D::F, R>,
    Target: Stage<D::F, R>,
> {
    driver: &'a mut D,
    _marker: PhantomData<(&'dr (), R, Current, Target)>,
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, (), Target>
{
    /// Creates a new `StageBuilder` given an underlying `driver`.
    pub fn new(driver: &'a mut D) -> Self {
        StageBuilder {
            driver,
            _marker: PhantomData,
        }
    }
}

struct GhostDriver<'a, 'dr, D: Driver<'dr>> {
    underlying: &'a mut D,
    alloc_count: usize,
    _marker: core::marker::PhantomData<(&'dr (), D)>,
}

impl<'dr, D: Driver<'dr>> DriverTypes for GhostDriver<'_, 'dr, D> {
    type ImplField = D::F;
    type ImplWire = ();
    type MaybeKind = D::MaybeKind;
    type LCadd = ();
    type LCenforce = ();
}

impl<'dr, D: Driver<'dr>> Driver<'dr> for GhostDriver<'_, 'dr, D> {
    type F = D::F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        Ok(())
    }

    fn constant(&mut self, _: Coeff<Self::F>) -> Self::Wire {}

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }
}

impl<'a, 'dr, D: Driver<'dr>> FromDriver<'dr, 'dr, GhostDriver<'a, 'dr, D>>
    for GhostDriver<'a, 'dr, D>
{
    type NewDriver = D;

    fn convert_wire(&mut self, _: &()) -> Result<<Self::NewDriver as Driver<'dr>>::Wire> {
        // For every wire conversion, allocate a zero on the underlying driver
        self.alloc_count += 1;
        self.underlying.alloc(|| Ok(Coeff::Zero))
    }
}

impl<
    'a,
    'dr,
    'source: 'dr,
    D: Driver<'dr>,
    R: Rank,
    Current: Stage<D::F, R>,
    Target: Stage<D::F, R>,
> StageBuilder<'a, 'dr, D, R, Current, Target>
{
    /// Add the next stage to the builder, given its `witness`, returning its
    /// output.
    pub fn add_stage<Next: Stage<D::F, R, Parent = Current> + 'dr>(
        self,
        witness: Witness<D, Next::Witness<'source>>,
    ) -> Result<(
        <Next::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )> {
        Ok((
            {
                let mut dr = GhostDriver::<'_, '_, D> {
                    underlying: self.driver,
                    alloc_count: 0,
                    _marker: core::marker::PhantomData,
                };
                let gadget = Next::witness(&mut dr, witness)?.map_gadget(&mut dr)?;

                while dr.alloc_count < Next::values() {
                    dr.convert_wire(&())?;
                }

                // Pad to ensure an even number of allocations, ensuring we
                // round up to the next multiplication gate.
                if dr.alloc_count % 2 == 1 {
                    dr.convert_wire(&())?;
                }
                assert_eq!(dr.alloc_count / 2, Next::num_multiplications());

                gadget
            },
            StageBuilder {
                driver: self.driver,
                _marker: PhantomData,
            },
        ))
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Finished: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Finished, Finished>
{
    /// Obtain the underlying driver after finishing the last stage.
    pub fn finish(self) -> &'a mut D {
        self.driver
    }
}
