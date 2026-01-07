use ff::PrimeField;
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::GadgetKind,
};
use ragu_primitives::{
    Element, GadgetExt,
    io::Pipe,
    vec::{ConstLen, FixedVec},
};

use alloc::vec::Vec;

use super::{Header, internal::padded};

/// A helper passed to step synthesis that provides access to the header data
/// for an input, along with methods to encode it into a header gadget.
pub struct Encoder<'dr, 'source: 'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    witness: DriverValue<D, H::Data<'source>>,
}

impl<'dr, 'source: 'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize>
    Encoder<'dr, 'source, D, H, HEADER_SIZE>
{
    /// Creates a new encoder for some header data.
    pub(crate) fn new(witness: DriverValue<D, H::Data<'source>>) -> Self {
        Encoder { witness }
    }
}

enum EncodedInner<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> {
    Gadget(<H::Output as GadgetKind<D::F>>::Rebind<'dr, D>),
    Raw(FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>),
}

/// The result of encoding a header within a step.
pub struct Encoded<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize>(
    EncodedInner<'dr, D, H, HEADER_SIZE>,
);

impl<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> Clone
    for EncodedInner<'dr, D, H, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        match self {
            EncodedInner::Gadget(gadget) => EncodedInner::Gadget(gadget.clone()),
            EncodedInner::Raw(raw) => EncodedInner::Raw(raw.clone()),
        }
    }
}

impl<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> Clone
    for Encoded<'dr, D, H, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        Encoded(self.0.clone())
    }
}

impl<'dr, D: Driver<'dr, F: PrimeField>, H: Header<D::F>, const HEADER_SIZE: usize>
    Encoded<'dr, D, H, HEADER_SIZE>
{
    /// Create an encoded header from a gadget value.
    pub fn from_gadget(gadget: <H::Output as GadgetKind<D::F>>::Rebind<'dr, D>) -> Self {
        Encoded(EncodedInner::Gadget(gadget))
    }

    /// Returns a reference to the underlying gadget.
    pub fn as_gadget(&self) -> &<H::Output as GadgetKind<D::F>>::Rebind<'dr, D> {
        match &self.0 {
            EncodedInner::Gadget(g) => g,
            EncodedInner::Raw(_) => unreachable!(),
        }
    }

    pub(crate) fn write(self, dr: &mut D, buf: &mut Vec<Element<'dr, D>>) -> Result<()> {
        match self.0 {
            EncodedInner::Gadget(gadget) => {
                padded::for_header::<H, HEADER_SIZE, _>(dr, gadget)?.write(dr, buf)?
            }
            EncodedInner::Raw(raw) => {
                buf.extend(raw.into_inner());
            }
        }
        Ok(())
    }
}

impl<'dr, 'source: 'dr, D: Driver<'dr, F: PrimeField>, H: Header<D::F>, const HEADER_SIZE: usize>
    Encoder<'dr, 'source, D, H, HEADER_SIZE>
{
    /// Proxy for [`Header::encode`] applied to the [`Header::Data`] held by
    /// this encoder.
    pub fn encode(self, dr: &mut D) -> Result<Encoded<'dr, D, H, HEADER_SIZE>> {
        Ok(Encoded::from_gadget(H::encode(dr, self.witness)?))
    }

    /// This witnesses the Header's gadget as its serialized encoding (via
    /// [`Write`](ragu_primitives::io::Write)) directly, rather than witnessing
    /// the gadget and then performing serialization. This step (if successful)
    /// will always synthesize the same circuit regardless of the concrete
    /// header.
    pub(crate) fn raw_encode(self, dr: &mut D) -> Result<Encoded<'dr, D, H, HEADER_SIZE>> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, _>> = Emulator::wireless();
        let gadget = H::encode(&mut emulator, self.witness)?;
        let gadget = padded::for_header::<H, HEADER_SIZE, _>(&mut emulator, gadget)?;

        let mut raw = Vec::with_capacity(HEADER_SIZE);
        gadget.write(&mut emulator, &mut Pipe::new(dr, &mut raw))?;

        Ok(Encoded(EncodedInner::Raw(FixedVec::try_from(raw)?)))
    }
}
