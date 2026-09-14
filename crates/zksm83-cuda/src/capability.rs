use core::fmt::{self, Display, Formatter};

use thiserror::Error;

/// The oldest compute capability accepted by the experimental CUDA backend.
pub const MINIMUM_COMPUTE_CAPABILITY: ComputeCapability = ComputeCapability { major: 7, minor: 0 };

/// A validated NVIDIA CUDA compute capability.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ComputeCapability {
    major: u32,
    minor: u32,
}

/// The field-kernel implementation selected for a CUDA device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldKernelVariant {
    /// Portable SIMT arithmetic using only the basic Volta-and-newer surface.
    PortableSimt,
}

/// The validated device target used to choose CUDA kernels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelTarget {
    capability: ComputeCapability,
    field_kernel: FieldKernelVariant,
}

/// Invalid or unsupported CUDA compute capability.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityError {
    /// The CUDA driver returned a negative or otherwise invalid component.
    #[error("CUDA driver returned invalid compute capability {major}.{minor}")]
    InvalidDriverValue {
        /// Driver-reported major component.
        major: i32,
        /// Driver-reported minor component.
        minor: i32,
    },
    /// A program supplied an impossible CUDA capability component.
    #[error("invalid CUDA compute capability {major}.{minor}")]
    InvalidComponents {
        /// Requested major component.
        major: u32,
        /// Requested minor component.
        minor: u32,
    },
    /// The device predates the backend's portable SIMT floor.
    #[error("CUDA compute capability {detected} is unsupported; minimum capability is {minimum}")]
    Unsupported {
        /// Capability reported by the selected device.
        detected: ComputeCapability,
        /// Oldest capability implemented by this backend.
        minimum: ComputeCapability,
    },
}

impl ComputeCapability {
    /// Constructs a capability from CUDA major and minor components.
    pub const fn new(major: u32, minor: u32) -> Result<Self, CapabilityError> {
        if major == 0 || minor > 9 {
            return Err(CapabilityError::InvalidComponents { major, minor });
        }
        Ok(Self { major, minor })
    }

    /// Converts the signed components returned by the CUDA driver.
    pub fn from_driver(major: i32, minor: i32) -> Result<Self, CapabilityError> {
        let Ok(converted_major) = u32::try_from(major) else {
            return Err(CapabilityError::InvalidDriverValue { major, minor });
        };
        let Ok(converted_minor) = u32::try_from(minor) else {
            return Err(CapabilityError::InvalidDriverValue { major, minor });
        };
        Self::new(converted_major, converted_minor)
    }

    /// Returns the compute-capability major component.
    #[must_use]
    pub const fn major(self) -> u32 {
        self.major
    }

    /// Returns the compute-capability minor component.
    #[must_use]
    pub const fn minor(self) -> u32 {
        self.minor
    }

    /// Returns whether the portable CUDA field kernel supports this device.
    #[must_use]
    pub const fn supports_portable_field_kernel(self) -> bool {
        self.major >= MINIMUM_COMPUTE_CAPABILITY.major
    }
}

impl Display for ComputeCapability {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "sm_{}{}", self.major, self.minor)
    }
}

impl KernelTarget {
    /// Selects kernels for the exact capability reported by a CUDA device.
    pub const fn for_device(capability: ComputeCapability) -> Result<Self, CapabilityError> {
        if !capability.supports_portable_field_kernel() {
            return Err(CapabilityError::Unsupported {
                detected: capability,
                minimum: MINIMUM_COMPUTE_CAPABILITY,
            });
        }
        Ok(Self {
            capability,
            field_kernel: FieldKernelVariant::PortableSimt,
        })
    }

    /// Returns the exact device capability retained by this target.
    #[must_use]
    pub const fn capability(self) -> ComputeCapability {
        self.capability
    }

    /// Returns the field kernel selected for the device.
    #[must_use]
    pub const fn field_kernel(self) -> FieldKernelVariant {
        self.field_kernel
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityError, ComputeCapability, FieldKernelVariant, KernelTarget,
        MINIMUM_COMPUTE_CAPABILITY,
    };

    #[test]
    fn target_preserves_each_supported_device_capability() -> Result<(), CapabilityError> {
        for capability in [
            ComputeCapability::new(7, 0)?,
            ComputeCapability::new(7, 5)?,
            ComputeCapability::new(8, 0)?,
            ComputeCapability::new(8, 9)?,
            ComputeCapability::new(9, 0)?,
            ComputeCapability::new(12, 0)?,
        ] {
            let target = KernelTarget::for_device(capability)?;
            assert_eq!(target.capability(), capability);
            assert_eq!(target.field_kernel(), FieldKernelVariant::PortableSimt);
        }
        Ok(())
    }

    #[test]
    fn target_rejects_devices_below_the_portable_floor() -> Result<(), CapabilityError> {
        let detected = ComputeCapability::new(6, 1)?;
        assert_eq!(
            KernelTarget::for_device(detected),
            Err(CapabilityError::Unsupported {
                detected,
                minimum: MINIMUM_COMPUTE_CAPABILITY,
            })
        );
        Ok(())
    }

    #[test]
    fn driver_conversion_rejects_negative_components() {
        assert!(matches!(
            ComputeCapability::from_driver(-1, 0),
            Err(CapabilityError::InvalidDriverValue {
                major: -1,
                minor: 0,
            })
        ));
        assert!(matches!(
            ComputeCapability::from_driver(8, -1),
            Err(CapabilityError::InvalidDriverValue {
                major: 8,
                minor: -1,
            })
        ));
    }

    #[test]
    fn constructor_rejects_impossible_components() {
        assert_eq!(
            ComputeCapability::new(0, 0),
            Err(CapabilityError::InvalidComponents { major: 0, minor: 0 })
        );
        assert_eq!(
            ComputeCapability::new(8, 10),
            Err(CapabilityError::InvalidComponents {
                major: 8,
                minor: 10,
            })
        );
    }
}
