//! Canonical length-prefixed descriptor helpers.

use super::UniformError;

pub(crate) fn push_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), UniformError> {
    let value = u64::try_from(value).map_err(|_| UniformError::Shape)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(crate) fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), UniformError> {
    push_usize(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}
