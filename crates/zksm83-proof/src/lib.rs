#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Halo2 constraints and proof generation for validated SM83 traces.

mod address;
mod alu;
mod authentication;
mod backend;
mod bus;
mod circuit;
mod control;
mod data;
mod decode;
mod expressions;
mod flags;
mod frame;
mod log;
mod merkle;
mod opcode;
mod public;
mod shape;
mod state;
mod word_alu;

pub use backend::{ProofArtifact, ProofError, VerifiedProof, prove, recommended_k, verify};
pub use public::{
    MACHINE_PROFILE_ID, PUBLIC_INSTANCE_COUNT, PublicInputError, PublicInputs, VM_VERSION_ID,
};
pub use shape::{BusEventKind, ExecutionShape, ShapeError, StepShape};
