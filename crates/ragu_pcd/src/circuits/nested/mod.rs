use arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::Result;
use ragu_primitives::vec::Len;

use crate::components::endoscalar::{EndoscalarStage, EndoscalingStep, NumStepsLen, PointsStage};
use crate::proof::NUM_P_COMMITMENTS;

/// Index of internal nested circuits registered into the mesh.
///
/// These correspond to the circuit objects registered in [`register_all`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum InternalCircuitIndex {
    /// `EndoscalarStage` stage object (index 0)
    EndoscalarStage,
    /// `PointsStage` stage object (index 1)
    PointsStage,
    /// `PointsStage` final staged object (index 2)
    PointsFinalStaged,
    /// `EndoscalingStep` circuit at given step (indices 3+)
    EndoscalingStep(usize),
}

impl InternalCircuitIndex {
    /// Convert to a [`CircuitIndex`] for mesh lookup.
    pub(crate) fn circuit_index(self) -> CircuitIndex {
        let idx = match self {
            Self::EndoscalarStage => 0,
            Self::PointsStage => 1,
            Self::PointsFinalStaged => 2,
            Self::EndoscalingStep(step) => 3 + step,
        };
        CircuitIndex::new(idx)
    }
}

pub mod stages;

/// Register internal nested circuits into the provided mesh.
pub(crate) fn register_all<'params, C: Cycle, R: Rank>(
    mut mesh: MeshBuilder<'params, C::ScalarField, R>,
) -> Result<MeshBuilder<'params, C::ScalarField, R>> {
    mesh = mesh.register_circuit_object(EndoscalarStage::into_object()?)?;

    mesh = mesh
        .register_circuit_object(PointsStage::<C::HostCurve, NUM_P_COMMITMENTS>::into_object()?)?;

    mesh = mesh.register_circuit_object(
        PointsStage::<C::HostCurve, NUM_P_COMMITMENTS>::final_into_object()?,
    )?;

    let num_steps = NumStepsLen::<NUM_P_COMMITMENTS>::len();
    for step in 0..num_steps {
        let step_circuit = EndoscalingStep::<C::HostCurve, R, NUM_P_COMMITMENTS>::new(step);
        let staged = Staged::new(step_circuit);
        mesh = mesh.register_circuit_object(staged.into_object()?)?;
    }
    Ok(mesh)
}
