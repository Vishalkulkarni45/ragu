//! Emulation for executing circuit synthesis code without unnecessary
//! constraint enforcement or wire tracking.
//!
//! ## Usage
//!
//! This module provides the [`Emulator`] driver, which can be used to execute
//! circuit synthesis code _directly_ rather than for assembling a witness or
//! polynomial reductions.
//!
//! The [`Emulator`] can be instantiated in [`Wired`] or [`Wireless`] mode,
//! through the use of the respective constructors [`Emulator::wired()`] or
//! [`Emulator::wireless()`]:
//! * In [`Wired`] mode, circuit synthesis is performed while tracking wire
//!   assignments; wire assignments have values depending on if there is a
//!   witness present, as determined by the parameterized [`MaybeKind`].
//!   [`Emulator::extractor()`] is a shorthand for creating a [`Wired`] emulator
//!   with a known witness.
//! * [`Wireless`] mode is equivalent, except that it doesn't track wire values
//!   at all. [`Emulator::execute()`] is shorthand for creating a [`Wireless`]
//!   emulator with a known witness.
//!
//! Emulators never enforce multiplication or linear constraints, and will also
//! use [Routine prediction](Routine::predict) to short-circuit execution of
//! routines.
//!
//! ### Extracting Wire Values
//!
//! In [`Wired`] mode, the wire assignments can be extracted from a gadget using
//! [`Emulator::wires()`]. If a witness always exists (such as in the
//! [`Emulator::extractor()`] case) then [`Emulator::always_wires()`] can be
//! used to extract the raw wire assignments.

use core::marker::PhantomData;
use ff::Field;

use alloc::vec::Vec;

use crate::{
    Result,
    drivers::{Coeff, DirectSum, Driver, DriverTypes, FromDriver, LinearExpression},
    gadgets::{Gadget, GadgetKind},
    maybe::{Always, Maybe, MaybeKind},
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

impl<M: MaybeKind, F: Field> MaybeWired<M, F> {
    /// Retrieves the underlying wire value.
    pub fn value(self) -> F {
        match self {
            MaybeWired::One => F::ONE,
            MaybeWired::Arbitrary(value) => value.take(),
        }
    }

    /// Retrieves a reference to the underlying wire value.
    pub fn snag<'a>(&'a self, one: &'a F) -> &'a F {
        match self {
            MaybeWired::One => one,
            MaybeWired::Arbitrary(value) => value.snag(),
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
        MaybeDirectSum(self.0.map(|sum| sum.add_term(wire.snag(&F::ONE), coeff)))
    }

    fn gain(self, coeff: Coeff<F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| sum.gain(coeff)))
    }

    fn extend(self, with: impl IntoIterator<Item = (MaybeWired<M, F>, Coeff<F>)>) -> Self {
        MaybeDirectSum(
            self.0
                .map(|sum| sum.extend(with.into_iter().map(|(wire, coeff)| (wire.value(), coeff)))),
        )
    }

    fn add(self, wire: &MaybeWired<M, F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| sum.add(wire.snag(&F::ONE))))
    }

    fn sub(self, wire: &MaybeWired<M, F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| sum.sub(wire.snag(&F::ONE))))
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

impl<M: MaybeKind, F: Field> Emulator<Wired<M, F>> {
    /// Creates a new `Emulator` driver in wired mode, parameterized on the
    /// existence of a witness.
    ///
    /// This driver does not enforce any constraints.
    pub fn wired() -> Self {
        Emulator(PhantomData)
    }

    /// Extract the raw wire values from a gadget.
    pub fn wires<'dr, G: Gadget<'dr, Self>>(&self, gadget: &G) -> Result<Vec<MaybeWired<M, F>>> {
        /// A conversion utility for extracting wire values.
        struct WireExtractor<M: MaybeKind, F: Field> {
            wires: Vec<MaybeWired<M, F>>,
        }

        impl<M: MaybeKind, F: Field> FromDriver<'_, '_, Emulator<Wired<M, F>>> for WireExtractor<M, F> {
            type NewDriver = PhantomData<F>;

            fn convert_wire(
                &mut self,
                wire: &MaybeWired<M, F>,
            ) -> Result<<Self::NewDriver as Driver<'_>>::Wire> {
                self.wires.push(wire.clone());
                Ok(())
            }
        }

        let mut collector = WireExtractor { wires: Vec::new() };
        <G::Kind as GadgetKind<F>>::map_gadget(gadget, &mut collector)?;
        Ok(collector.wires)
    }
}

impl<M: MaybeKind, F: Field> Emulator<Wireless<M, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode, parameterized on the
    /// existence of a witness.
    ///
    /// This driver does not enforce any constraints or track wire assignments.
    pub fn wireless() -> Self {
        Emulator(PhantomData)
    }
}

impl<F: Field> Emulator<Wireless<Always<()>, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode, specifically for
    /// executing with a known witness.
    ///
    /// This driver does not enforce any constraints or track wire assignments.
    pub fn execute() -> Self {
        Self::wireless()
    }

    /// Execute the provided closure with a fresh [`Emulator`] driver in
    /// [`Wireless`] mode.
    pub fn emulate_wireless<R, W: Send>(
        witness: W,
        f: impl FnOnce(&mut Self, Always<W>) -> Result<R>,
    ) -> Result<R> {
        let mut dr = Self::execute();
        dr.with(witness, f)
    }
}

impl<F: Field> Emulator<Wired<Always<()>, F>> {
    /// Extract the raw wire values from a gadget.
    ///
    /// This is a proxy for [`Emulator::wires`] that assumes a witness always
    /// exists.
    pub fn always_wires<'dr, G: Gadget<'dr, Self>>(&self, gadget: &G) -> Result<Vec<F>> {
        Ok(self.wires(gadget)?.into_iter().map(|w| w.value()).collect())
    }

    /// Creates a new `Emulator` while tracking wire assignments, specifically
    /// for extracting the wire values afterward.
    ///
    /// This driver tracks all wire assignments and is only used in contexts
    /// when a witness always exists. The [`Emulator::wires()`] method can be
    /// used to extract the raw wire values from a gadget constructed using this
    /// driver.
    pub fn extractor() -> Self {
        Emulator(PhantomData)
    }

    /// Execute the provided closure with a fresh [`Emulator`] driver in
    /// [`Wired`] mode.
    pub fn emulate_wired<R, W: Send>(
        witness: W,
        f: impl FnOnce(&mut Self, Always<W>) -> Result<R>,
    ) -> Result<R> {
        let mut dr = Self::extractor();
        dr.with(witness, f)
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
        let lc = lc(MaybeDirectSum(M::maybe_just(DirectSum::default)));
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
