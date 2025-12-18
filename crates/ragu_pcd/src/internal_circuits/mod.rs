use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::StageExt,
};
use ragu_core::Result;

pub mod c;
pub mod dummy;
pub mod hashes_1;
pub mod hashes_2;
pub mod stages;
pub mod unified;
pub mod v;

pub use crate::components::fold_revdot::NativeParameters;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum InternalCircuitIndex {
    DummyCircuit = 0,
    Hashes1Circuit = 1,
    Hashes2Circuit = 2,
    ClaimStaged = 3,
    ClaimCircuit = 4,
    VStaged = 5,
    VCircuit = 6,
    PreambleStage = 7,
    ErrorMStage = 8,
    ErrorNStage = 9,
    QueryStage = 10,
    EvalStage = 11,
}

/// The number of internal circuits registered by [`register_all`],
/// and the number of variants in [`InternalCircuitIndex`].
pub const NUM_INTERNAL_CIRCUITS: usize = 12;

impl InternalCircuitIndex {
    pub fn circuit_index(self, num_application_steps: usize) -> CircuitIndex {
        CircuitIndex::new(num_application_steps + super::step::NUM_INTERNAL_STEPS + self as usize)
    }
}

pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mesh: MeshBuilder<'params, C::CircuitField, R>,
    params: &'params C,
    log2_circuits: u32,
) -> Result<MeshBuilder<'params, C::CircuitField, R>> {
    let initial_num_circuits = mesh.num_circuits();

    let mesh = mesh.register_circuit(dummy::Circuit)?;
    let mesh = mesh.register_circuit(hashes_1::Circuit::<C>::new(params))?;
    let mesh = mesh.register_circuit(hashes_2::Circuit::<C>::new(params))?;
    let mesh = {
        let c = c::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params, log2_circuits);
        mesh.register_circuit_object(c.final_into_object()?)?
            .register_circuit(c)?
    };
    let mesh = {
        let v = v::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params);
        mesh.register_circuit_object(v.final_into_object()?)?
            .register_circuit(v)?
    };

    let mesh = mesh.register_circuit_object(
        stages::native::preamble::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    let mesh = mesh.register_circuit_object(stages::native::error_m::Stage::<
        C,
        R,
        HEADER_SIZE,
        NativeParameters,
    >::into_object()?)?;
    let mesh = mesh.register_circuit_object(stages::native::error_n::Stage::<
        C,
        R,
        HEADER_SIZE,
        NativeParameters,
    >::into_object()?)?;
    let mesh = mesh.register_circuit_object(
        stages::native::query::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    let mesh = mesh.register_circuit_object(
        stages::native::eval::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;

    // Verify we registered the expected number of circuits.
    assert_eq!(
        mesh.num_circuits(),
        initial_num_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(mesh)
}
