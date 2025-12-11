use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::StageExt,
};
use ragu_core::Result;

pub mod c;
pub mod dummy;
pub mod stages;
pub mod unified;

// TODO: Placeholder value for the number of revdot claims.
pub const NUM_REVDOT_CLAIMS: usize = 3;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum InternalCircuitIndex {
    DummyCircuit = 0,
    ClaimStage = 1,
    ClaimCircuit = 2,
    PreambleStage = 3,
}

impl InternalCircuitIndex {
    pub fn circuit_index(self, num_application_steps: usize) -> CircuitIndex {
        CircuitIndex::new(num_application_steps + super::step::NUM_INTERNAL_STEPS + self as usize)
    }
}

pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mesh: MeshBuilder<'params, C::CircuitField, R>,
    params: &'params C,
) -> Result<MeshBuilder<'params, C::CircuitField, R>> {
    let mesh = mesh.register_circuit(dummy::Circuit)?;
    let mesh = {
        let c = c::Circuit::<C, R, HEADER_SIZE, NUM_REVDOT_CLAIMS>::new(params);
        mesh.register_circuit_object(c.final_into_object()?)?
            .register_circuit(c)?
    };

    let mesh = mesh.register_circuit_object(
        stages::native::preamble::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    Ok(mesh)
}
