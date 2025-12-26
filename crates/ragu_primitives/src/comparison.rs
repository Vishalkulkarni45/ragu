//! Comparison gadget for field elements.
//!
//! This module re-exports comparison functions from [`Boolean`].

use ragu_core::{Result, drivers::Driver};

use crate::{Boolean, Element};

/// Convenience method that compares two elements and returns a boolean
/// indicating whether they are equal.
pub fn is_equal<'dr, D: Driver<'dr>>(
    dr: &mut D,
    a: &Element<'dr, D>,
    b: &Element<'dr, D>,
) -> Result<Boolean<'dr, D>> {
    Boolean::is_equal(dr, a, b)
}

/// Convenience method that compares an element against the constant ONE
/// and returns a boolean gadget.
pub fn is_one<'dr, D: Driver<'dr>>(dr: &mut D, a: &Element<'dr, D>) -> Result<Boolean<'dr, D>> {
    Boolean::is_one(dr, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_core::maybe::Maybe;

    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    #[test]
    fn test_is_equal_same() -> Result<()> {
        let sim = Simulator::simulate((F::from(123u64), F::from(123u64)), |dr, witness| {
            let (a_val, b_val) = witness.cast();
            let a = Element::alloc(dr, a_val)?;
            let b = Element::alloc(dr, b_val)?;

            dr.reset();
            let eq = is_equal(dr, &a, &b)?;

            assert!(eq.value().take(), "Expected a == b");
            Ok(())
        })?;

        assert_eq!(sim.num_multiplications(), 2);
        assert_eq!(sim.num_linear_constraints(), 4);

        Ok(())
    }

    #[test]
    fn test_is_not_equal() -> Result<()> {
        Simulator::simulate((F::from(1u64), F::from(123u64)), |dr, witness| {
            let (a_val, b_val) = witness.cast();
            let a = Element::alloc(dr, a_val)?;
            let b = Element::alloc(dr, b_val)?;

            dr.reset();
            let eq = is_equal(dr, &a, &b)?;

            assert!(!eq.value().take(), "Expected a != b");
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_is_equal_one() -> Result<()> {
        Simulator::simulate(F::ONE, |dr, witness| {
            let a = Element::alloc(dr, witness)?;

            dr.reset();
            let eq = is_one(dr, &a)?;

            assert!(eq.value().take(), "Expected a == ONE");
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_is_equal_zero() -> Result<()> {
        Simulator::simulate((F::ZERO, F::ZERO), |dr, witness| {
            let (a_val, b_val) = witness.cast();
            let a = Element::alloc(dr, a_val)?;
            let b = Element::alloc(dr, b_val)?;

            dr.reset();
            let eq = is_equal(dr, &a, &b)?;

            assert!(eq.value().take(), "Expected 0 == 0");
            Ok(())
        })?;

        Ok(())
    }
}
