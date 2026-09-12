use super::{PcsBatchGateMode, PcsBatchTamperReport, deterministic_columns};

#[test]
fn deterministic_fixture_has_requested_group_shape() {
    let groups = deterministic_columns(4);
    assert_eq!(groups.len(), 4);
    assert!(groups.iter().all(|group| group.len() == 128));
    assert!(groups.iter().flatten().all(|column| column.len() == 512));
}

#[test]
fn tamper_report_requires_every_rejection() {
    let complete = PcsBatchTamperReport {
        swapped_groups_rejected: true,
        changed_commitment_rejected: true,
        changed_value_rejected: true,
        changed_point_rejected: true,
        changed_schedule_rejected: true,
    };
    assert!(complete.all_rejected());
    assert!(
        !PcsBatchTamperReport {
            changed_point_rejected: false,
            ..complete
        }
        .all_rejected()
    );
    assert_ne!(PcsBatchGateMode::Independent, PcsBatchGateMode::Batched);
}
