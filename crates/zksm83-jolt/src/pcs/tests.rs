use std::sync::Arc;

use super::{
    AkitaScheduleLookupKey, PcsLayout, PolynomialGroupLayout, context_slot,
    root_commit_requirements, scheme, validate_schedule,
};

const DOMAIN: &[u8] = b"zksm83/pcs-prewarm-test/v1";
const ROM_FILE: &[u8] = include_bytes!("../../protocol/akita/fp128_dense_bounded_nv20_p1.aks");
const ROM_SCHEDULE: &[u8] = ROM_FILE.split_at(ROM_FILE.len() - 1).0;
const MEMORY_FILE: &[u8] = include_bytes!("../../protocol/akita/fp128_dense_bounded_nv17_p1.aks");
const MEMORY_SCHEDULE: &[u8] = MEMORY_FILE.split_at(MEMORY_FILE.len() - 1).0;
const LOG_FILE: &[u8] = include_bytes!("../../protocol/akita/fp128_dense_bounded_nv17_p128.aks");
const LOG_SCHEDULE: &[u8] = LOG_FILE.split_at(LOG_FILE.len() - 1).0;

#[test]
fn every_pinned_layout_has_explicit_root_commit_prewarm_requirements()
-> Result<(), Box<dyn std::error::Error>> {
    for layout in layouts() {
        let scheme = scheme(layout)?;
        let group = PolynomialGroupLayout::new(layout.num_variables, layout.group_columns);
        let key = AkitaScheduleLookupKey::single(group);
        let schedule = scheme.schedules().resolve_key(&key)?.schedule();
        assert!(!root_commit_requirements(schedule)?.entries().is_empty());
    }
    Ok(())
}

#[test]
fn live_layouts_share_one_initialization_slot() -> Result<(), Box<dyn std::error::Error>> {
    let rom_layout = layout(20, 1, ROM_FILE);
    let first = context_slot(rom_layout)?;
    let second = context_slot(rom_layout)?;
    let different = context_slot(layout(17, 1, MEMORY_FILE))?;
    assert!(Arc::ptr_eq(&first, &second));
    assert!(!Arc::ptr_eq(&first, &different));
    assert!(first.get().is_none());
    Ok(())
}

#[test]
fn paired_trace_schedule_has_one_exact_precommitment() -> Result<(), Box<dyn std::error::Error>> {
    let layout = PcsLayout::paired(
        14,
        128,
        include_bytes!("../../protocol/akita/fp128_dense_bounded_nv14_p128_pair.aks"),
        DOMAIN,
        DOMAIN,
    );
    let scheme = scheme(layout)?;
    let (_, precommitted) = validate_schedule(layout, &scheme)?;
    assert_eq!(layout.groups_per_opening(), 2);
    assert_eq!(precommitted.len(), 1);
    assert_eq!(
        precommitted.first().map(|profile| profile.group),
        Some(PolynomialGroupLayout::new(14, 128))
    );
    Ok(())
}

#[test]
fn paired_layout_maps_twenty_six_groups_to_thirteen_openings() {
    let layout = PcsLayout::paired(14, 128, b"unused", DOMAIN, DOMAIN);
    assert!(matches!(layout.opening_count(26), Ok(13)));
    assert!(matches!(layout.opening_count(2), Ok(1)));
    assert!(layout.opening_count(25).is_err());
    assert!(layout.opening_count(0).is_err());
}

fn layouts() -> [PcsLayout; 6] {
    [
        layout(
            14,
            128,
            include_bytes!("../../protocol/akita/fp128_dense_bounded_nv14_p128.aks"),
        ),
        layout(
            9,
            128,
            include_bytes!("../../protocol/akita/fp128_dense_bounded_nv9_p128.aks"),
        ),
        layout(20, 1, ROM_SCHEDULE),
        layout(17, 1, MEMORY_SCHEDULE),
        layout(17, 128, LOG_SCHEDULE),
        layout(
            14,
            1,
            include_bytes!("../../protocol/akita/fp128_dense_bounded.aks"),
        ),
    ]
}

const fn layout(variables: usize, columns: usize, schedule: &'static [u8]) -> PcsLayout {
    PcsLayout::new(variables, columns, schedule, DOMAIN, DOMAIN)
}
