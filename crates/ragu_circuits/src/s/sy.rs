//! Evaluates $s(X, y)$ at fixed $y$.
//!
//! # Design
//!
//! Unlike [`sx`][super::sx] which can build coefficients incrementally, $s(X, y)$
//! coefficients cannot be computed in a strictly streaming order during synthesis.
//! The coefficient of $X^j$ depends on wiring matrix terms like
//! $\sum_{j=0}^{q-1} \sum_{i=0}^{n-1} U_{j, i} \cdot X^{2n-1-i}$
//! (and similarly for the $V$, $W$ matrices), which essentially require evaluating
//! a row of the $U$ (or $V$, $W$) matrix. These rows are undetermined until
//! all $q$ linear constraints have been processed.
//!
//! We use **virtual wires** to defer coefficient computation. Virtual wires are
//! symbolic linear combinations that accumulate references to other wires
//! (virtual or allocated). They use manual reference counting to track usage.
//! When a virtual wire's refcount reaches zero, it resolves by distributing its
//! value to constituent terms, eventually reaching allocated wires (A, B, C) where
//! values are written to the polynomial via the backward view.

use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::GadgetKind,
    maybe::Empty,
    routines::{Prediction, Routine},
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};
use core::cell::RefCell;

use crate::{
    Circuit,
    polynomials::{Rank, structured},
};

#[derive(Copy, Clone)]
enum WireIndex {
    A(usize),
    B(usize),
    C(usize),
    Virtual(usize),
}

/// A uniform type for allocated and virtual wires.
///
/// A virtual wire carries a virtual table pointer (`table: Some(_)`).
struct Wire<'table, 'sy, F: Field, R: Rank> {
    index: WireIndex,
    table: Option<&'table RefCell<VirtualTable<'sy, F, R>>>,
}

impl<'table, 'sy, F: Field, R: Rank> Wire<'table, 'sy, F, R> {
    fn new(index: WireIndex, table: &'table RefCell<VirtualTable<'sy, F, R>>) -> Self {
        Wire {
            index,
            table: Some(table),
        }
    }

    /// Increments the refcount for this wire to register storing a reference.
    ///
    /// This is used when storing a wire reference in a term vector (e.g., in a
    /// virtual wire's linear combination). The refcount will be decremented when
    /// the virtual wire is freed and its terms are resolved.
    ///
    /// For non-virtual wires (A, B, C), this is a no-op.
    fn increment_refcount(&self) {
        if let WireIndex::Virtual(index) = self.index {
            self.table.unwrap().borrow_mut().wires[index].refcount += 1;
        }
    }
}

impl<F: Field, R: Rank> Clone for Wire<'_, '_, F, R> {
    fn clone(&self) -> Self {
        if let WireIndex::Virtual(index) = self.index {
            self.table.unwrap().borrow_mut().wires[index].refcount += 1;
        }

        Wire {
            index: self.index,
            table: self.table,
        }
    }
}

impl<F: Field, R: Rank> Drop for Wire<'_, '_, F, R> {
    fn drop(&mut self) {
        if let WireIndex::Virtual(_) = self.index {
            self.table.as_ref().unwrap().borrow_mut().free(self.index);
        }
    }
}

/// A virtual wire representing a linear combination of allocated wires.
///
/// Virtual wires accumulate references to other wires (virtual or allocated)
/// in their `terms` vector. The reference count tracks:
/// 1. Owned `Wire` handles that reference this virtual wire
/// 2. References stored in other virtual wires' `terms` vectors
///
/// When the refcount reaches zero, the virtual wire is **resolved**,
/// see [`VirtualTable::free`].
struct VirtualWire<F: Field> {
    /// Reference count: number of owned Wire handles + stored references
    refcount: usize,
    /// Terms accumulated in this virtual wire's linear combination.
    /// Each stored wire reference contributes +1 to that wire's refcount.
    terms: Vec<(WireIndex, Coeff<F>)>,
    /// Current accumulated value for this virtual wire
    value: Coeff<F>,
}

/// The virtual table maintains a list of virtual wires, a free list for
/// reusing virtual wire slots, and a backward view into the structured polynomial
/// $s(X, y)$.
///
/// See [`Self::free`] for details on the reference counting and resolution.
///
/// # Backward View
///
/// Ultimately, $\langle\langle r(X), s(X, y) \rangle\rangle = k(y)$ enforces
/// correct circuit wiring. Expressed in revdot product, the LHS becomes:
/// $\langle [0 \mid a.\text{rev} \mid b \mid c.\text{rev}], s_{\text{coeff}} \rangle$
///
/// The backward view of $s(X, y)$ gives direct access to the coefficients for
/// the $a$, $b$, and $c$ wires in the correct order, instead of building a flat
/// coefficient vector for $s(X, y)$ then re-interpreting it.
struct VirtualTable<'sy, F: Field, R: Rank> {
    wires: Vec<VirtualWire<F>>,
    free: Vec<usize>,
    sy: structured::View<'sy, F, R, structured::Backward>,
}

impl<F: Field, R: Rank> VirtualTable<'_, F, R> {
    fn add(&mut self, index: WireIndex, value: Coeff<F>) {
        *match index {
            WireIndex::A(i) => &mut self.sy.a[i],
            WireIndex::B(i) => &mut self.sy.b[i],
            WireIndex::C(i) => &mut self.sy.c[i],
            WireIndex::Virtual(i) => {
                self.wires[i].value = self.wires[i].value + value;
                return;
            }
        } += value.value();
    }

    /// Decrements the refcount of a virtual wire and **resolves** it (by adding
    /// to the `self.free` vector) if the count reaches zero.
    ///
    /// Resolved virtual wires distribute their accumulated value to all
    /// constituent terms, which are then recursively freed. This cascading
    /// resolution eventually reaches allocated wires (A, B, C) where the values
    /// are written to the polynomial.
    fn free(&mut self, index: WireIndex) {
        if let WireIndex::Virtual(index) = index {
            assert!(self.wires[index].refcount > 0);
            self.wires[index].refcount -= 1;

            if self.wires[index].refcount == 0 {
                let mut terms = vec![];
                core::mem::swap(&mut terms, &mut self.wires[index].terms);
                let value = self.wires[index].value;
                for (wire, coeff) in terms.drain(..) {
                    self.add(wire, value * coeff);
                    self.free(wire);
                }
                self.wires[index].value = Coeff::Zero;
                self.free.push(index);
            }
        }
    }

    /// Updates the terms of a virtual wire.
    fn update(&mut self, index: WireIndex, terms: Vec<(WireIndex, Coeff<F>)>) {
        match index {
            WireIndex::Virtual(index) => {
                self.wires[index].terms = terms;
            }
            _ => unreachable!(),
        }
    }

    /// Allocates a new virtual wire.
    fn alloc(&mut self) -> WireIndex {
        match self.free.pop() {
            Some(index) => {
                assert_eq!(self.wires[index].refcount, 0);
                assert!(self.wires[index].value.is_zero());
                assert!(self.wires[index].terms.is_empty());

                self.wires[index].refcount = 1;
                WireIndex::Virtual(index)
            }
            None => {
                let index = self.wires.len();
                self.wires.push(VirtualWire {
                    refcount: 1,
                    terms: vec![],
                    value: Coeff::Zero,
                });
                WireIndex::Virtual(index)
            }
        }
    }
}

/// Driver that computes $s(X, y)$ at a fixed $y$.
struct Evaluator<'table, 'sy, F: Field, R: Rank> {
    multiplication_constraints: usize,
    linear_constraints: usize,
    y_inv: F,
    current_y: F,
    virtual_table: &'table RefCell<VirtualTable<'sy, F, R>>,
    available_b: Option<Wire<'table, 'sy, F, R>>,
    _marker: core::marker::PhantomData<R>,
}

/// Collects terms for a linear combination of wires.
struct TermCollector<F: Field> {
    terms: Vec<(WireIndex, Coeff<F>)>,
    gain: Coeff<F>,
}

impl<F: Field> TermCollector<F> {
    fn new() -> Self {
        TermCollector {
            terms: vec![],
            gain: Coeff::One,
        }
    }
}

impl<'table, 'sy, F: Field, R: Rank> LinearExpression<Wire<'table, 'sy, F, R>, F>
    for TermCollector<F>
{
    fn add_term(mut self, wire: &Wire<'table, 'sy, F, R>, coeff: Coeff<F>) -> Self {
        wire.increment_refcount();
        self.terms.push((wire.index, coeff * self.gain));
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}

/// Enforces a linear combination to zero by adding terms to the virtual table.
struct TermEnforcer<'table, 'sy, F: Field, R: Rank>(
    &'table RefCell<VirtualTable<'sy, F, R>>,
    Coeff<F>,
);
impl<'table, 'sy, F: Field, R: Rank> LinearExpression<Wire<'table, 'sy, F, R>, F>
    for TermEnforcer<'table, 'sy, F, R>
{
    fn add_term(self, wire: &Wire<'table, 'sy, F, R>, coeff: Coeff<F>) -> Self {
        self.0.borrow_mut().add(wire.index, coeff * self.1);
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.1 = self.1 * coeff;
        self
    }
}

impl<'table, 'sy, F: Field, R: Rank> DriverTypes for Evaluator<'table, 'sy, F, R> {
    type MaybeKind = Empty;
    type LCadd = TermCollector<F>;
    type LCenforce = TermEnforcer<'table, 'sy, F, R>;
    type ImplField = F;
    type ImplWire = Wire<'table, 'sy, F, R>;
}

impl<'table, 'sy, F: Field, R: Rank> Driver<'table> for Evaluator<'table, 'sy, F, R> {
    type F = F;
    type Wire = Wire<'table, 'sy, F, R>;

    const ONE: Self::Wire = Wire {
        index: WireIndex::C(0),
        table: None,
    };

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.available_b.take() {
            Ok(wire)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.available_b = Some(b);

            Ok(a)
        }
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let index = self.multiplication_constraints;
        if index == R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }
        self.multiplication_constraints += 1;

        {
            let mut table = self.virtual_table.borrow_mut();
            table.sy.a.push(F::ZERO);
            table.sy.b.push(F::ZERO);
            table.sy.c.push(F::ZERO);
        }

        let a = Wire::new(WireIndex::A(index), self.virtual_table);
        let b = Wire::new(WireIndex::B(index), self.virtual_table);
        let c = Wire::new(WireIndex::C(index), self.virtual_table);

        Ok((a, b, c))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let wire = self.virtual_table.borrow_mut().alloc();
        let terms = lc(TermCollector::new()).terms;
        self.virtual_table.borrow_mut().update(wire, terms);

        Wire {
            index: wire,
            table: Some(self.virtual_table),
        }
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.linear_constraints;
        if q == R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.linear_constraints += 1;

        lc(TermEnforcer(
            self.virtual_table,
            Coeff::Arbitrary(self.current_y),
        ));

        self.current_y *= self.y_inv;

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'table>(
        &mut self,
        routine: Ro,
        input: <Ro::Input as GadgetKind<Self::F>>::Rebind<'table, Self>,
    ) -> Result<<Ro::Output as GadgetKind<Self::F>>::Rebind<'table, Self>> {
        // Temporarily store currently `available_b` to reset the allocation
        // logic within the routine.
        let tmp = self.available_b.take();
        let mut dummy = Emulator::wireless();
        let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
        let result = match routine.predict(&mut dummy, &dummy_input)? {
            Prediction::Known(_, aux) | Prediction::Unknown(aux) => {
                routine.execute(self, input, aux)?
            }
        };
        // Restore the allocation logic state, discarding the state from within
        // the routine.
        self.available_b = tmp;
        Ok(result)
    }
}

/// Evaluates the wiring polynomial $s(X, y)$ at a fixed $y$, with mesh key `key`.
///
/// The mesh key augments the original `circuit` with one additional `key`-related
/// linear constraint, binding the circuit to an outer [`Mesh`][crate::mesh::Mesh] context.
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    y: F,
    key: F,
    num_linear_constraints: usize,
) -> Result<structured::Polynomial<F, R>> {
    let mut sy = structured::Polynomial::<F, R>::new();

    if y == F::ZERO {
        // If y is zero, the only linear constraint enforces the 'one' wire for
        // the public inputs.
        sy.backward().c.push(F::ONE);
        return Ok(sy);
    }

    {
        let virtual_table = RefCell::new(VirtualTable::<F, R> {
            wires: vec![],
            free: vec![],
            sy: sy.backward(),
        });
        {
            let mut evaluator = Evaluator::<'_, '_, F, R> {
                multiplication_constraints: 0,
                linear_constraints: 0,
                y_inv: y.invert().expect("y is not zero"),
                current_y: y.pow_vartime([(num_linear_constraints - 1) as u64]),
                virtual_table: &virtual_table,
                available_b: None,
                _marker: core::marker::PhantomData,
            };

            let (key_wire, _, one) = evaluator.mul(|| unreachable!())?;

            // Enforce linear constraint key_wire = key to randomize non-trivial
            // evaluations of this wiring polynomial.
            evaluator.enforce_zero(|lc| {
                lc.add(&key_wire)
                    .add_term(&one, Coeff::NegativeArbitrary(key))
            })?;

            let mut outputs = vec![];
            let (io, _) = circuit.witness(&mut evaluator, Empty)?;
            io.write(&mut evaluator, &mut outputs)?;

            for output in outputs {
                evaluator.enforce_zero(|lc| lc.add(output.wire()))?;
            }
            evaluator.enforce_zero(|lc| lc.add(&one))?;
            assert_eq!(evaluator.linear_constraints, num_linear_constraints);
        }

        // We should have ended up freeing all the wires; otherwise, there's
        // unexpected behavior during synthesis that could indicate a bug in the
        // circuit.
        let virtual_table = virtual_table.into_inner();
        assert_eq!(virtual_table.free.len(), virtual_table.wires.len());
    }

    Ok(sy)
}
