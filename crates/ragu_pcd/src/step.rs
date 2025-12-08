//! Merging operations defined for the proof-carrying data computational graph.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use super::header::Header;
pub use encoder::{Encoded, Encoder};

pub(crate) mod adapter;
mod encoder;
pub(crate) mod padded;
pub(crate) mod rerandomize;

#[repr(usize)]
pub(crate) enum InternalStepIndex {
    Rerandomize = 0,
}

/// The number of internal steps used by Ragu for things like rerandomization or
/// proof decompression.
///
/// * `0` is used for the rerandomization step (see [`rerandomize`]).
pub(crate) const NUM_INTERNAL_STEPS: usize = 1;

/// The index of a [`Step`] in an application, distinguishing internal vs.
/// application steps.
///
/// All steps added to an application have a unique index and must be inserted
/// sequentially so that their location (and other metadata) can be identified
/// during proof generation and at other times.
pub enum StepIndex {
    /// Identifies an application-defined step.
    Application(usize),
    /// Identifies an internal step defined by Ragu.
    #[allow(private_interfaces)]
    Internal(InternalStepIndex),
}

impl StepIndex {
    /// Creates a new application-defined [`Step`] index.
    pub const fn new(value: usize) -> Self {
        StepIndex::Application(value)
    }

    /// Returns the circuit index for this step.
    ///
    /// Pass the known number of application steps to validate and compute the
    /// final index of this step. Returns an error if an application step index
    /// exceeds the number of registered steps.
    pub(crate) fn circuit_index(self, num_application_steps: usize) -> Result<usize> {
        match self {
            StepIndex::Internal(i) => Ok(num_application_steps + (i as usize)),
            StepIndex::Application(i) => {
                if i >= num_application_steps {
                    return Err(ragu_core::Error::Initialization(
                            "attempted to use application Step index that exceeds Application registered steps".into(),
                        ));
                }

                Ok(i)
            }
        }
    }

    /// Called during application step registration to assert the appropriate
    /// next sequential index.
    ///
    /// ## Panics
    ///
    /// Panics if called on an internal step.
    pub(crate) fn assert_index(self, expect_id: usize) -> Result<()> {
        match self {
            StepIndex::Application(i) => {
                if i != expect_id {
                    return Err(ragu_core::Error::Initialization(
                        "steps must be registered in sequential order".into(),
                    ));
                }

                Ok(())
            }
            StepIndex::Internal(_) => panic!("step should be application-defined"),
        }
    }
}

#[test]
fn test_index_map() -> Result<()> {
    let num_application_steps = 10;

    assert_eq!(
        StepIndex::Internal(InternalStepIndex::Rerandomize).circuit_index(num_application_steps)?,
        10
    );
    assert_eq!(StepIndex::new(0).circuit_index(num_application_steps)?, 0);
    assert_eq!(StepIndex::new(1).circuit_index(num_application_steps)?, 1);
    StepIndex::new(999).assert_index(999)?;
    assert!(
        StepIndex::new(10)
            .circuit_index(num_application_steps)
            .is_err()
    );

    Ok(())
}

/// Represents a node in the computational graph (or the proof-carrying data
/// tree) that represents the merging of two pieces of proof-carrying data.
pub trait Step<C: Cycle>: Sized + Send + Sync {
    /// Each unique [`Step`] implementation within a provided context must have
    /// a unique index.
    const INDEX: StepIndex;

    /// The witness data needed to construct a proof for this step.
    type Witness<'source>: Send;

    /// Auxiliary information produced during circuit synthesis. This may be
    /// necessary to construct the [`Header::Data`] for the resulting proof.
    type Aux<'source>: Send;

    /// The "left" header expected during this step.
    type Left: Header<C::CircuitField>;

    /// The "right" header expected during this step.
    type Right: Header<C::CircuitField>;

    /// The header produced during this step.
    type Output: Header<C::CircuitField>;

    /// The main synthesis method that checks the validity of this merging step.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr;
}
