use arithmetic::Coeff;
use ff::{Field, PrimeField};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Gadget, Kind},
    maybe::Maybe,
};

use alloc::{vec, vec::Vec};

use crate::{
    Element, GadgetExt,
    io::{Buffer, Write},
    promotion::{Demoted, Promotion},
    util::InternalMaybe,
};

/// Represents a wire that is constrained to be zero or one, along with its
/// corresponding [`bool`] value.
#[derive(Gadget)]
pub struct Boolean<'dr, D: Driver<'dr>> {
    /// The wire that has a value of either `0` or `1`.
    #[ragu(wire)]
    wire: D::Wire,

    /// The witness value for the value of this boolean.
    #[ragu(value)]
    value: DriverValue<D, bool>,
}

impl<'dr, D: Driver<'dr>> Boolean<'dr, D> {
    /// Allocates a boolean with the provided witness value.
    ///
    /// This costs one multiplication constraint and two linear constraints.
    pub fn alloc(dr: &mut D, value: DriverValue<D, bool>) -> Result<Self> {
        let (a, b, c) = dr.mul(|| {
            let value = value.coeff().take();
            Ok((value, value, value))
        })?;

        // enforces a = b  =>  c = a^2
        dr.enforce_equal(&a, &b)?;

        // enforces a = c  =>  a = a^2
        //                 =>  (a - 0) * (a - 1) = 0
        //                 =>  (a = 0) OR (a = 1)
        dr.enforce_equal(&a, &c)?;

        // NB: We can take any of the three wires we want.
        Ok(Boolean { value, wire: c })
    }

    /// Computes the NOT of this boolean. This is "free" in the circuit model.
    pub fn not(&self, dr: &mut D) -> Self {
        // The wire w is transformed into 1 - w, its logical NOT.
        let wire = dr.add(|lc| lc.add(&D::ONE).sub(self.wire()));
        let value = D::just(|| !self.value.snag());
        Boolean { wire, value }
    }

    /// Computes the AND of two booleans. This costs one multiplication
    /// constraint and two linear constraints.
    pub fn and(&self, dr: &mut D, other: &Self) -> Result<Self> {
        let result = D::just(|| self.value.snag() & other.value.snag());
        let (a, b, c) = dr.mul(|| {
            let a = self.value.coeff().take();
            let b = other.value.coeff().take();
            let c = result.coeff().take();
            Ok((a, b, c))
        })?;

        dr.enforce_equal(&a, self.wire())?;
        dr.enforce_equal(&b, other.wire())?;

        Ok(Boolean {
            value: result,
            wire: c,
        })
    }

    /// Returns the witness value of this boolean.
    pub fn value(&self) -> DriverValue<D, bool> {
        self.value.clone()
    }

    /// Returns the wire associated with this boolean.
    pub fn wire(&self) -> &D::Wire {
        &self.wire
    }

    /// Compares two elements and returns a boolean indicating whether they are equal.
    /// Uses the standard "inverse trick" for equality checking in arithmetic circuits.
    pub fn is_equal(dr: &mut D, a: &Element<'dr, D>, b: &Element<'dr, D>) -> Result<Self> {
        let diff = a.sub(dr, b);

        let is_equal_witness = D::just(|| *diff.value().take() == D::F::ZERO);
        let diff_inv = D::just(|| diff.value().take().invert().unwrap_or(D::F::ZERO));

        let is_equal_fe = is_equal_witness.fe::<D::F>();
        let diff_coeff = || Coeff::Arbitrary(*diff.value().take());

        // Constraint: diff * inv = 1 - is_eq.
        let (diff_wire, _, one_minus_is_equal) = dr.mul(|| {
            Ok((
                diff_coeff(),
                Coeff::Arbitrary(*diff_inv.snag()),
                Coeff::Arbitrary(D::F::ONE - *is_equal_fe.snag()),
            ))
        })?;
        dr.enforce_equal(&diff_wire, diff.wire())?;
        let is_equal_wire = dr.add(|lc| lc.add(&D::ONE).sub(&one_minus_is_equal));

        // Constraint: diff * is_eq = 0.
        let (diff_wire, is_equal_wire_2, zero_product) = dr.mul(|| {
            Ok((
                diff_coeff(),
                Coeff::Arbitrary(*is_equal_fe.snag()),
                Coeff::Zero,
            ))
        })?;
        dr.enforce_equal(&diff_wire, diff.wire())?;
        dr.enforce_equal(&is_equal_wire_2, &is_equal_wire)?;
        dr.enforce_zero(|lc| lc.add(&zero_product))?;

        Ok(Boolean {
            wire: is_equal_wire,
            value: is_equal_witness,
        })
    }

    /// Compares an element against the constant ONE and returns a boolean gadget.
    pub fn is_one(dr: &mut D, a: &Element<'dr, D>) -> Result<Self> {
        Self::is_equal(dr, a, &Element::one())
    }

    /// Converts this boolean into an [`Element`].
    pub fn element(&self) -> Element<'dr, D> {
        Element::promote(self.wire.clone(), self.value().fe())
    }
}

impl<F: Field> Write<F> for Kind![F; @Boolean<'_, _>] {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Boolean<'dr, D>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        this.element().write(dr, buf)
    }
}

impl<F: Field> Promotion<F> for Kind![F; @Boolean<'_, _>] {
    type Value = bool;

    fn promote<'dr, D: Driver<'dr, F = F>>(
        demoted: &Demoted<'dr, D, Boolean<'dr, D>>,
        witness: DriverValue<D, bool>,
    ) -> Boolean<'dr, D> {
        Boolean {
            wire: demoted.wire.clone(),
            value: witness,
        }
    }
}

/// Packs boolean slices into values depending on the capacity of the prime
/// field to store data.
pub fn multipack<'dr, D: Driver<'dr, F: ff::PrimeField>>(
    dr: &mut D,
    bits: &[Boolean<'dr, D>],
) -> Result<Vec<Element<'dr, D>>> {
    let mut v = vec![];
    for chunk in bits.chunks(D::F::CAPACITY as usize) {
        let value = D::just(|| {
            let mut value = D::F::ZERO;
            let mut gain = D::F::ONE;
            for bit in chunk.iter() {
                if bit.value().take() {
                    value += gain;
                }
                gain = gain.double();
            }
            value
        });

        let wire = dr.add(|mut lc| {
            for bit in chunk.iter() {
                lc = lc.add(bit.wire());
                lc = lc.gain(Coeff::Two);
            }
            lc
        });

        v.push(Element::promote(wire, value));
    }

    Ok(v)
}

#[test]
fn test_boolean_alloc() -> Result<()> {
    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let alloc = |bit: bool| {
        let sim = Simulator::simulate(bit, |dr, bit| {
            let allocated_bit = Boolean::alloc(dr, bit.clone())?;

            assert_eq!(allocated_bit.value().take(), bit.clone().take());
            assert_eq!(*allocated_bit.wire(), bit.fe().take());

            Ok(())
        })?;

        assert_eq!(sim.num_allocations(), 0);
        assert_eq!(sim.num_multiplications(), 1);
        assert_eq!(sim.num_linear_constraints(), 2);
        Ok(())
    };

    alloc(false)?;
    alloc(true)?;

    Ok(())
}

#[test]
fn test_multipack() -> Result<()> {
    use alloc::vec::Vec;

    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let bits = (0..1000).map(|i| i % 2 == 0).collect::<Vec<_>>();

    Simulator::simulate(bits, |dr, bits| {
        let bits = (0..1000)
            .map(|i| Boolean::alloc(dr, bits.view().map(|b| b[i])))
            .collect::<Result<Vec<_>>>()?;

        let vals = multipack(dr, &bits)?;
        assert_eq!(vals.len(), 4);

        for val in vals {
            assert_eq!(val.value().take(), val.wire());
        }

        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_multipack_vector() -> Result<()> {
    use alloc::vec::Vec;

    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let bits = vec![false, true, true, false, true]; // 0b10110 = 22
    Simulator::simulate(bits, |dr, bits| {
        let bits = (0..5)
            .map(|i| Boolean::alloc(dr, bits.view().map(|b| b[i])))
            .collect::<Result<Vec<_>>>()?;

        let vals = multipack(dr, &bits)?;
        assert_eq!(vals.len(), 1);
        assert_eq!(*vals[0].value().take(), F::from(22));
        assert_eq!(*vals[0].wire(), F::from(22));

        Ok(())
    })?;

    Ok(())
}
