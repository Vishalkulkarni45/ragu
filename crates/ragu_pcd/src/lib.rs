//! # `ragu_pcd`

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]

extern crate alloc;

use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{Mesh, MeshBuilder},
    polynomials::Rank,
};
use ragu_core::{Error, Result};

use alloc::collections::BTreeMap;
use core::{any::TypeId, marker::PhantomData};

use header::Header;
use step::{Step, adapter::Adapter};

pub mod header;
pub mod step;

/// Builder for an [`Application`](crate::Application) for proof-carrying data.
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    circuit_mesh: MeshBuilder<'params, C::CircuitField, R>,
    num_application_steps: usize,
    header_map: BTreeMap<header::Prefix, TypeId>,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Default
    for ApplicationBuilder<'_, C, R, HEADER_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>
    ApplicationBuilder<'params, C, R, HEADER_SIZE>
{
    /// Create an empty [`ApplicationBuilder`] for proof-carrying data.
    pub fn new() -> Self {
        ApplicationBuilder {
            circuit_mesh: MeshBuilder::new(),
            num_application_steps: 0,
            header_map: BTreeMap::new(),
            _marker: PhantomData,
        }
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) should be the next sequential
    /// index that has not been inserted yet.
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        // NB: all internal steps are registered after application steps, and so
        // we can pass 0 to this function.
        if S::INDEX.circuit_index(0) != self.num_application_steps {
            return Err(Error::Initialization(
                "steps must be registered in sequential order".into(),
            ));
        }

        match self
            .header_map
            .get(&<S::Output as Header<C::CircuitField>>::PREFIX)
        {
            Some(ty) => {
                if *ty != TypeId::of::<S::Output>() {
                    return Err(Error::Initialization(
                        "two different Header implementations using the same prefix".into(),
                    ));
                }
            }
            None => {
                self.header_map.insert(
                    <S::Output as Header<C::CircuitField>>::PREFIX,
                    TypeId::of::<S::Output>(),
                );
            }
        }

        self.circuit_mesh = self
            .circuit_mesh
            .register_circuit(Adapter::<C, S, R, HEADER_SIZE>::new(step))?;
        self.num_application_steps += 1;

        Ok(self)
    }

    /// Perform finalization and optimization steps to produce the
    /// [`Application`].
    pub fn finalize(self, params: &C) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        Ok(Application {
            circuit_mesh: self.circuit_mesh.finalize(params.circuit_poseidon())?,
            num_application_steps: self.num_application_steps,
            _marker: PhantomData,
        })
    }
}

/// The recursion context that is used to create and verify proof-carrying data.
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    circuit_mesh: Mesh<'params, C::CircuitField, R>,
    num_application_steps: usize,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}
