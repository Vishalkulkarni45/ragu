use ragu_core::{
    Result,
    drivers::{Coeff, Driver, DriverTypes, FromDriver},
    gadgets::{Gadget, GadgetKind},
    maybe::Empty,
};

use alloc::vec::Vec;

/// A driver for extracting a gadget's wire values into a vector for inspection.
struct WireExtractor<'dr, D: Driver<'dr>> {
    wires: Vec<D::Wire>,
    _marker: core::marker::PhantomData<(&'dr (), D)>,
}

impl<'dr, D: Driver<'dr>> WireExtractor<'dr, D> {
    /// Creates a new wire extractor.
    fn new() -> Self {
        Self {
            wires: Vec::new(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<'dr, D: Driver<'dr>> DriverTypes for WireExtractor<'dr, D> {
    type ImplField = D::F;
    type ImplWire = ();
    type MaybeKind = Empty;
    type LCadd = ();
    type LCenforce = ();
}

impl<'dr, D: Driver<'dr>> Driver<'dr> for WireExtractor<'dr, D> {
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

impl<'dr, D: Driver<'dr>> FromDriver<'dr, 'dr, D> for WireExtractor<'dr, D> {
    type NewDriver = Self;

    fn convert_wire(&mut self, wire: &D::Wire) -> Result<<Self::NewDriver as Driver<'dr>>::Wire> {
        self.wires.push(wire.clone());
        Ok(())
    }
}

pub fn wires<'dr, D: Driver<'dr>, G: Gadget<'dr, D>>(gadget: &G) -> Result<Vec<D::Wire>> {
    let mut collector: WireExtractor<'_, D> = WireExtractor::new();
    <G::Kind as GadgetKind<D::F>>::map(gadget, &mut collector)?;
    Ok(collector.wires)
}
