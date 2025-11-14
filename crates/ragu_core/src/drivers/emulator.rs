//! TODO(ebfull): Emulator documentation.

use core::marker::PhantomData;
use ff::Field;

use alloc::vec::Vec;

use crate::{
    Result,
    drivers::{Coeff, DirectSum, Driver, DriverTypes, FromDriver, LinearExpression},
    gadgets::{Gadget, GadgetKind},
    maybe::{Always, Empty, Maybe, MaybeKind},
    routines::{Prediction, Routine},
};

/// Mode that an emulator may be running in; usually either [`Wired`] or
/// [`Wireless`].
pub trait Mode {
    /// The resulting [`Emulator`]'s [`DriverTypes::MaybeKind`].
    type MaybeKind: MaybeKind;

    /// The resulting [`Emulator`]'s [`DriverTypes::ImplField`].
    type F: Field;

    /// The resulting [`Emulator`]'s [`DriverTypes::ImplWire`].
    type Wire: Clone;

    /// The resulting [`Emulator`]'s [`DriverTypes::LCadd`].
    type LCadd: LinearExpression<Self::Wire, Self::F>;

    /// The resulting [`Emulator`]'s [`DriverTypes::LCenforce`].
    type LCenforce: LinearExpression<Self::Wire, Self::F>;
}

/// Mode for an [`Emulator`] that tracks wire assignments.
pub struct Wired<M: MaybeKind, F: Field>(PhantomData<(M, F)>);

/// Container for a [`Field`] element representing a wire assignment that may or
/// may not be known depending on the parameterized [`MaybeKind`].
pub enum MaybeWired<M: MaybeKind, F: Field> {
    /// The special wire representing the constant one.
    One,

    /// A wire with an arbitrary assignment.
    Arbitrary(M::Rebind<F>),
}

impl<F: Field> MaybeWired<Always<()>, F> {
    /// Retrieves the underlying wire value.
    pub fn value(self) -> F {
        match self {
            MaybeWired::One => F::ONE,
            MaybeWired::Arbitrary(value) => value.take(),
        }
    }
}

impl<M: MaybeKind, F: Field> Clone for MaybeWired<M, F> {
    fn clone(&self) -> Self {
        match self {
            MaybeWired::One => MaybeWired::One,
            MaybeWired::Arbitrary(value) => MaybeWired::Arbitrary(value.clone()),
        }
    }
}

/// Implementation of [`LinearExpression`] for a [`DirectSum`] that may or may
/// not have a known value depending on the parameterized [`MaybeKind`].
pub struct MaybeDirectSum<M: MaybeKind, F: Field>(M::Rebind<DirectSum<F>>);

impl<M: MaybeKind, F: Field> LinearExpression<MaybeWired<M, F>, F> for MaybeDirectSum<M, F> {
    fn add_term(self, wire: &MaybeWired<M, F>, coeff: Coeff<F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| {
            let wire = match wire {
                MaybeWired::One => &F::ONE,
                MaybeWired::Arbitrary(wire) => wire.snag(),
            };
            sum.add_term(wire, coeff)
        }))
    }

    fn gain(self, coeff: Coeff<F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| sum.gain(coeff)))
    }

    fn extend(self, with: impl IntoIterator<Item = (MaybeWired<M, F>, Coeff<F>)>) -> Self {
        MaybeDirectSum(self.0.map(|sum| {
            sum.extend(with.into_iter().map(|(wire, coeff)| {
                let wire = match wire {
                    MaybeWired::One => F::ONE,
                    MaybeWired::Arbitrary(wire) => wire.take(),
                };
                (wire, coeff)
            }))
        }))
    }

    fn add(self, wire: &MaybeWired<M, F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| {
            let wire = match wire {
                MaybeWired::One => &F::ONE,
                MaybeWired::Arbitrary(wire) => wire.snag(),
            };
            sum.add(wire)
        }))
    }

    fn sub(self, wire: &MaybeWired<M, F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| {
            let wire = match wire {
                MaybeWired::One => &F::ONE,
                MaybeWired::Arbitrary(wire) => wire.snag(),
            };
            sum.sub(wire)
        }))
    }
}

impl<M: MaybeKind, F: Field> Mode for Wired<M, F> {
    type MaybeKind = M;
    type F = F;
    type Wire = MaybeWired<M, F>;
    type LCadd = MaybeDirectSum<M, F>;
    type LCenforce = MaybeDirectSum<M, F>;
}

/// Mode for an [`Emulator`] that does not track wire assignments.
pub struct Wireless<M: MaybeKind, F: Field>(PhantomData<(M, F)>);

impl<M: MaybeKind, F: Field> Mode for Wireless<M, F> {
    type MaybeKind = M;
    type F = F;
    type Wire = ();
    type LCadd = ();
    type LCenforce = ();
}

/// A driver used to execute circuit synthesis code and obtain the result of a
/// computation without enforcing constraints or collecting a witness. Useful
/// for obtaining the result of a computation that is later executed with
/// another driver.
pub struct Emulator<M: Mode>(PhantomData<M>);

impl<M: MaybeKind, F: Field> Emulator<Wireless<M, F>> {
    /// Creates a new `Emulator` driver in wireless mode, parameterized on the
    /// existence of a witness.
    pub fn wireless() -> Self {
        Emulator(PhantomData)
    }
}

impl<F: Field> Emulator<Wireless<Always<()>, F>> {
    /// Creates a new `Emulator` driver in wireless mode, specifically for
    /// executing with a known witness.
    pub fn execute() -> Self {
        Self::wireless()
    }
}

impl<F: Field> Emulator<Wired<Always<()>, F>> {
    /// Creates a new `Emulator` while tracking wire assignments, specifically
    /// for extracting the wire values afterward.
    pub fn extractor() -> Self {
        Emulator(PhantomData)
    }

    /// Extract the raw wire values from a gadget.
    pub fn wires<'dr, G: Gadget<'dr, Self>>(&self, gadget: &G) -> Result<Vec<F>> {
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

            fn enforce_zero(
                &mut self,
                _: impl Fn(Self::LCenforce) -> Self::LCenforce,
            ) -> Result<()> {
                Ok(())
            }
        }

        impl<'dr, D: Driver<'dr>> FromDriver<'dr, 'dr, D> for WireExtractor<'dr, D> {
            type NewDriver = Self;

            fn convert_wire(
                &mut self,
                wire: &D::Wire,
            ) -> Result<<Self::NewDriver as Driver<'dr>>::Wire> {
                self.wires.push(wire.clone());
                Ok(())
            }
        }

        let mut collector: WireExtractor<'_, Self> = WireExtractor::new();
        <G::Kind as GadgetKind<F>>::map_gadget(gadget, &mut collector)?;
        Ok(collector.wires.into_iter().map(|w| w.value()).collect())
    }
}

impl<M: Mode<F = F>, F: Field> Emulator<M> {
    /// Executes a closure with this driver, returning its output.
    pub fn just<R, W: Send>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R> {
        f(self)
    }

    /// Executes a closure with this driver, passing a witness value into the
    /// closure and returning its output.
    pub fn with<R, W: Send>(
        &mut self,
        witness: W,
        f: impl FnOnce(&mut Self, <M::MaybeKind as MaybeKind>::Rebind<W>) -> Result<R>,
    ) -> Result<R> {
        f(self, M::MaybeKind::maybe_just(|| witness))
    }
}

impl<M: Mode> DriverTypes for Emulator<M> {
    type ImplField = M::F;
    type ImplWire = M::Wire;
    type MaybeKind = M::MaybeKind;
    type LCadd = M::LCadd;
    type LCenforce = M::LCenforce;
}

impl<'dr, M: MaybeKind, F: Field> Driver<'dr> for Emulator<Wireless<M, F>> {
    type F = F;
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

    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: <R::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<R::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        // Emulator will short-circuit execution if the routine can predict its
        // output, as the emulator is not involved in enforcing any constraints.
        match routine.predict(self, &input)? {
            Prediction::Known(output, _) => Ok(output),
            Prediction::Unknown(aux) => routine.execute(self, input, aux),
        }
    }
}

impl<'dr, M: MaybeKind, F: Field> Driver<'dr> for Emulator<Wired<M, F>> {
    type F = F;
    type Wire = MaybeWired<M, F>;
    const ONE: Self::Wire = MaybeWired::One;

    fn alloc(&mut self, f: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        f().map(|coeff| MaybeWired::Arbitrary(M::maybe_just(|| coeff.value())))
    }

    fn constant(&mut self, coeff: Coeff<Self::F>) -> Self::Wire {
        MaybeWired::Arbitrary(M::maybe_just(|| coeff.value()))
    }

    fn mul(
        &mut self,
        f: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let (a, b, c) = f()?;

        // Despite wires existing, the emulator does not enforce multiplication
        // constraints.

        Ok((
            MaybeWired::Arbitrary(M::maybe_just(|| a.value())),
            MaybeWired::Arbitrary(M::maybe_just(|| b.value())),
            MaybeWired::Arbitrary(M::maybe_just(|| c.value())),
        ))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let lc = lc(MaybeDirectSum(M::maybe_just(|| DirectSum::default())));
        MaybeWired::Arbitrary(lc.0.map(|sum| sum.value))
    }

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        // Despite wires existing, the emulator does not enforce linear
        // constraints.

        Ok(())
    }

    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: <R::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<R::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        // Emulator will short-circuit execution if the routine can predict its
        // output, as the emulator is not involved in enforcing any constraints.
        match routine.predict(self, &input)? {
            Prediction::Known(output, _) => Ok(output),
            Prediction::Unknown(aux) => routine.execute(self, input, aux),
        }
    }
}

impl<'dr, D: Driver<'dr>> FromDriver<'dr, '_, D> for Emulator<Wireless<D::MaybeKind, D::F>> {
    type NewDriver = Self;

    fn convert_wire(&mut self, _: &D::Wire) -> Result<()> {
        Ok(())
    }
}
