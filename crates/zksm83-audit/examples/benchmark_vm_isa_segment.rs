//! Measures the partial complete-state structural plus committed-ISA segment proof.

use std::{env, time::Instant};

use zksm83_audit::{CommittedVmIsaStructuralProof, IpaParameters};
use zksm83_memory::{MemoryImage, RomImage};
use zksm83_trace::TraceBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let steps = env::args()
        .nth(1)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(256);
    if steps == 0 || !steps.is_power_of_two() || steps > (u16::MAX as usize).saturating_add(1) {
        return Err("steps must be a power of two in 1..=65536".into());
    }

    let trace_started = Instant::now();
    let mut builder = TraceBuilder::new(
        RomImage::new(vec![0x18, 0xfe])?,
        MemoryImage::zeroed()?,
        Vec::new(),
    );
    let mut rows = Vec::with_capacity(steps);
    for _ in 0..steps {
        rows.push(builder.step()?);
    }
    let trace_ms = trace_started.elapsed().as_millis();
    let initial = rows.first().ok_or("missing initial row")?.before();
    let final_state = rows.last().ok_or("missing final row")?.after();

    let setup_started = Instant::now();
    let table_parameters = IpaParameters::new(512)?;
    let trace_parameters = IpaParameters::new(steps)?;
    let setup_ms = setup_started.elapsed().as_millis();

    let prove_started = Instant::now();
    let proof = CommittedVmIsaStructuralProof::prove(&table_parameters, &trace_parameters, &rows)?;
    let prove_ms = prove_started.elapsed().as_millis();

    let verify_started = Instant::now();
    proof.verify(&table_parameters, &trace_parameters, initial, final_state)?;
    let verify_ms = verify_started.elapsed().as_millis();
    let elements = proof.element_count();

    println!(
        "{{\"schema\":\"zksm83-vm-isa-structural-benchmark/v1\",\"steps\":{steps},\"trace_ms\":{trace_ms},\"setup_ms\":{setup_ms},\"prove_ms\":{prove_ms},\"verify_ms\":{verify_ms},\"curve_points\":{},\"field_elements\":{},\"scope\":\"structural-plus-isa-lookup-not-complete-sm83-semantics\"}}",
        elements.0, elements.1
    );
    Ok(())
}
