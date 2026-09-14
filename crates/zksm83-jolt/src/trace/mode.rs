//! Stable one-hot mode model shared by trace encoding and CPU relations.

use zksm83_core::StepKind;

/// Canonical v2 transition-mode position in the native trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceMode {
    Instruction,
    HaltIdle,
    HaltUntilVBlank,
    HaltWake,
    Interrupt,
    DmaByte,
    HaltUntilSerial,
    HaltUntilTimer,
    Padding,
}

impl TraceMode {
    pub(crate) const COUNT: usize = 9;

    pub(crate) const fn for_step(kind: StepKind) -> Self {
        match kind {
            StepKind::Instruction => Self::Instruction,
            StepKind::HaltIdle => Self::HaltIdle,
            StepKind::HaltUntilVBlank => Self::HaltUntilVBlank,
            StepKind::HaltUntilSerial => Self::HaltUntilSerial,
            StepKind::HaltUntilTimer => Self::HaltUntilTimer,
            StepKind::HaltWake => Self::HaltWake,
            StepKind::InterruptDispatch(_) => Self::Interrupt,
            StepKind::DmaByte => Self::DmaByte,
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Instruction => 0,
            Self::HaltIdle => 1,
            Self::HaltUntilVBlank => 2,
            Self::HaltWake => 3,
            Self::Interrupt => 4,
            Self::DmaByte => 5,
            Self::HaltUntilSerial => 6,
            Self::HaltUntilTimer => 7,
            Self::Padding => 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use zksm83_core::DmgInterrupt;

    use super::*;

    #[test]
    fn every_step_kind_has_one_stable_v2_mode() {
        let cases = [
            (StepKind::Instruction, TraceMode::Instruction),
            (StepKind::HaltIdle, TraceMode::HaltIdle),
            (StepKind::HaltUntilVBlank, TraceMode::HaltUntilVBlank),
            (StepKind::HaltUntilSerial, TraceMode::HaltUntilSerial),
            (StepKind::HaltUntilTimer, TraceMode::HaltUntilTimer),
            (StepKind::HaltWake, TraceMode::HaltWake),
            (
                StepKind::InterruptDispatch(DmgInterrupt::Timer),
                TraceMode::Interrupt,
            ),
            (StepKind::DmaByte, TraceMode::DmaByte),
        ];
        for (kind, expected) in cases {
            assert_eq!(TraceMode::for_step(kind), expected);
        }
        assert_eq!(TraceMode::Padding.index() + 1, TraceMode::COUNT);
    }
}
