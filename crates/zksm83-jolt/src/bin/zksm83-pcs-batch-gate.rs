//! Hard-timeout controller for the isolated two-group PCS batching experiment.

use std::{
    ffi::OsStr,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zksm83_jolt::{
    PcsBatchGateMode, PcsBatchPathReport, PcsBatchTamperReport, run_pcs_batch_gate_worker,
};

const MAX_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const MAX_SCHEDULE_BYTES: u64 = 1024 * 1024;
const MAX_WORKER_REPORT_BYTES: usize = 64 * 1024;
const RSS_POLL_INTERVAL: Duration = Duration::from_millis(100);
const WORKER_ENVIRONMENT: &str = "ZKSM83_PCS_BATCH_GATE_CHILD";
const WORKER_ENVIRONMENT_VALUE: &str = "v1";

#[derive(Debug, Parser)]
#[command(about = "Bounded, non-protocol two-group Akita batching experiment")]
struct Arguments {
    /// Locally generated nv9/p128 + nv9/p128 Akita schedule artifact.
    #[arg(long)]
    candidate_schedule: PathBuf,
    /// Hard deadline for each child path; values above 30 are rejected.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS)]
    timeout_seconds: u64,
    /// Internal child-process mode; direct use is rejected.
    #[arg(long, value_enum, hide = true)]
    worker: Option<WorkerMode>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum WorkerMode {
    Independent,
    Batched,
}

impl WorkerMode {
    const fn gate_mode(self) -> PcsBatchGateMode {
        match self {
            Self::Independent => PcsBatchGateMode::Independent,
            Self::Batched => PcsBatchGateMode::Batched,
        }
    }

    const fn argument(self) -> &'static str {
        match self {
            Self::Independent => "independent",
            Self::Batched => "batched",
        }
    }
}

#[derive(Debug, Error)]
enum GateCliError {
    #[error("timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds")]
    InvalidTimeout,
    #[error("candidate schedule is larger than {MAX_SCHEDULE_BYTES} bytes")]
    ScheduleTooLarge,
    #[error("direct worker invocation is forbidden")]
    DirectWorker,
    #[error("PCS batch gate path {mode} exceeded its {seconds}-second deadline")]
    TimedOut { mode: &'static str, seconds: u64 },
    #[error("PCS batch gate child {mode} failed with status {status}")]
    WorkerFailed { mode: &'static str, status: String },
    #[error("PCS batch gate child report exceeded {MAX_WORKER_REPORT_BYTES} bytes")]
    WorkerReportTooLarge,
    #[error("PCS batch gate child reports disagree on candidate schedule identity")]
    CandidateMismatch,
    #[error("PCS batch gate IO failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCS batch gate JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("PCS batch gate execution failed: {0}")]
    Gate(#[from] zksm83_jolt::PcsBatchGateError),
}

#[derive(Debug, Deserialize, Serialize)]
struct MeasuredPath {
    report: PcsBatchPathReport,
    sampled_peak_rss_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AcceptanceCriteria {
    exact_claims_verified: bool,
    tamper_matrix_passed: bool,
    proof_bytes_reduced: bool,
    warm_opening_speedup_percent: Option<f64>,
    warm_opening_speedup_at_least_ten_percent: bool,
    sampled_peak_rss_increase_basis_points: Option<i64>,
    sampled_peak_rss_increase_at_most_twenty_five_percent: bool,
}

impl AcceptanceCriteria {
    const fn accepted(&self) -> bool {
        self.exact_claims_verified
            && self.tamper_matrix_passed
            && self.proof_bytes_reduced
            && self.warm_opening_speedup_at_least_ten_percent
            && self.sampled_peak_rss_increase_at_most_twenty_five_percent
    }
}

#[derive(Debug, Serialize)]
struct GateReport {
    schema: &'static str,
    protocol_status: &'static str,
    candidate_schedule_sha256: String,
    timeout_seconds_per_path: u64,
    independent: MeasuredPath,
    batched: MeasuredPath,
    criteria: AcceptanceCriteria,
    accepted_for_larger_candidate: bool,
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Arguments) -> Result<(), GateCliError> {
    validate_timeout(arguments.timeout_seconds)?;
    let schedule = read_schedule(&arguments.candidate_schedule)?;
    if let Some(worker) = arguments.worker {
        return run_worker(worker, &schedule);
    }
    let independent = run_bounded_child(
        WorkerMode::Independent,
        &arguments.candidate_schedule,
        arguments.timeout_seconds,
    )?;
    let batched = run_bounded_child(
        WorkerMode::Batched,
        &arguments.candidate_schedule,
        arguments.timeout_seconds,
    )?;
    if independent.report.candidate_schedule_sha256 != batched.report.candidate_schedule_sha256
        || independent.report.candidate_schedule_sha256 != hex_digest(&schedule)
    {
        return Err(GateCliError::CandidateMismatch);
    }
    let criteria = acceptance_criteria(&independent, &batched);
    let report = GateReport {
        schema: "zksm83-pcs-batch-gate/v1",
        protocol_status: "experiment_only_v1_unchanged",
        candidate_schedule_sha256: hex_digest(&schedule),
        timeout_seconds_per_path: arguments.timeout_seconds,
        accepted_for_larger_candidate: criteria.accepted(),
        independent,
        batched,
        criteria,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn validate_timeout(seconds: u64) -> Result<(), GateCliError> {
    if seconds == 0 || seconds > MAX_TIMEOUT_SECONDS {
        return Err(GateCliError::InvalidTimeout);
    }
    Ok(())
}

fn read_schedule(path: &Path) -> Result<Vec<u8>, GateCliError> {
    if fs::metadata(path)?.len() > MAX_SCHEDULE_BYTES {
        return Err(GateCliError::ScheduleTooLarge);
    }
    Ok(fs::read(path)?)
}

fn run_worker(worker: WorkerMode, schedule: &[u8]) -> Result<(), GateCliError> {
    if std::env::var_os(WORKER_ENVIRONMENT).as_deref() != Some(OsStr::new(WORKER_ENVIRONMENT_VALUE))
    {
        return Err(GateCliError::DirectWorker);
    }
    let report = run_pcs_batch_gate_worker(worker.gate_mode(), schedule)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn run_bounded_child(
    worker: WorkerMode,
    schedule: &Path,
    timeout_seconds: u64,
) -> Result<MeasuredPath, GateCliError> {
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .arg("--candidate-schedule")
        .arg(schedule)
        .arg("--timeout-seconds")
        .arg(timeout_seconds.to_string())
        .arg("--worker")
        .arg(worker.argument())
        .env(WORKER_ENVIRONMENT, WORKER_ENVIRONMENT_VALUE)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    supervise_child(&mut child, worker, timeout_seconds)
}

fn supervise_child(
    child: &mut Child,
    worker: WorkerMode,
    timeout_seconds: u64,
) -> Result<MeasuredPath, GateCliError> {
    let deadline = Duration::from_secs(timeout_seconds);
    let started = Instant::now();
    let mut sampled_peak_rss_bytes = None;
    loop {
        sampled_peak_rss_bytes =
            max_optional(sampled_peak_rss_bytes, sampled_resident_bytes(child.id()));
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(GateCliError::WorkerFailed {
                    mode: worker.argument(),
                    status: status.to_string(),
                });
            }
            let report = read_worker_report(child)?;
            return Ok(MeasuredPath {
                report,
                sampled_peak_rss_bytes,
            });
        }
        if started.elapsed() >= deadline {
            child.kill()?;
            let _status = child.wait()?;
            return Err(GateCliError::TimedOut {
                mode: worker.argument(),
                seconds: timeout_seconds,
            });
        }
        thread::sleep(RSS_POLL_INTERVAL);
    }
}

fn read_worker_report(child: &mut Child) -> Result<PcsBatchPathReport, GateCliError> {
    let mut bytes = Vec::new();
    let stdout = child
        .stdout
        .as_mut()
        .ok_or_else(|| std::io::Error::other("PCS batch gate child stdout was not captured"))?;
    stdout
        .take(
            u64::try_from(MAX_WORKER_REPORT_BYTES + 1)
                .map_err(|_| std::io::Error::other("worker report limit does not fit u64"))?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_WORKER_REPORT_BYTES {
        return Err(GateCliError::WorkerReportTooLarge);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn sampled_resident_bytes(process_id: u32) -> Option<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &process_id.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let kibibytes = std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    kibibytes.checked_mul(1024)
}

fn max_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn acceptance_criteria(independent: &MeasuredPath, batched: &MeasuredPath) -> AcceptanceCriteria {
    let exact_claims_verified = independent.report.verified
        && batched.report.verified
        && independent.report.opened_group_count == 2
        && batched.report.opened_group_count == 2;
    let tamper_matrix_passed = batched
        .report
        .tamper
        .is_some_and(PcsBatchTamperReport::all_rejected);
    let proof_bytes_reduced = batched.report.proof_bytes < independent.report.proof_bytes;
    let speedup = relative_change_percent(
        independent.report.opening_seconds,
        batched.report.opening_seconds,
    );
    let rss_increase = optional_relative_change_basis_points(
        independent.sampled_peak_rss_bytes,
        batched.sampled_peak_rss_bytes,
    );
    AcceptanceCriteria {
        exact_claims_verified,
        tamper_matrix_passed,
        proof_bytes_reduced,
        warm_opening_speedup_percent: speedup,
        warm_opening_speedup_at_least_ten_percent: speedup.is_some_and(|value| value >= 10.0),
        sampled_peak_rss_increase_basis_points: rss_increase,
        sampled_peak_rss_increase_at_most_twenty_five_percent: rss_increase
            .is_some_and(|value| value <= 2500),
    }
}

fn relative_change_percent(baseline: f64, candidate: f64) -> Option<f64> {
    if !baseline.is_finite() || !candidate.is_finite() || baseline <= 0.0 {
        return None;
    }
    Some((baseline - candidate) * 100.0 / baseline)
}

fn optional_relative_change_basis_points(
    baseline: Option<u64>,
    candidate: Option<u64>,
) -> Option<i64> {
    let baseline = i128::from(baseline?);
    let candidate = i128::from(candidate?);
    if baseline == 0 {
        return None;
    }
    i64::try_from((candidate - baseline) * 10_000 / baseline).ok()
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        MeasuredPath, PcsBatchGateMode, PcsBatchPathReport, PcsBatchTamperReport,
        acceptance_criteria, validate_timeout,
    };

    #[test]
    fn timeout_never_exceeds_thirty_seconds() {
        assert!(validate_timeout(0).is_err());
        assert!(validate_timeout(1).is_ok());
        assert!(validate_timeout(30).is_ok());
        assert!(validate_timeout(31).is_err());
    }

    #[test]
    fn acceptance_requires_every_measurement_gate() {
        let independent = measured(PcsBatchGateMode::Independent, 100, 10.0, 1000, None);
        let tamper = PcsBatchTamperReport {
            swapped_groups_rejected: true,
            changed_commitment_rejected: true,
            changed_value_rejected: true,
            changed_point_rejected: true,
            changed_schedule_rejected: true,
        };
        let batched = measured(PcsBatchGateMode::Batched, 90, 8.9, 1200, Some(tamper));
        let accepted = acceptance_criteria(&independent, &batched);
        assert!(accepted.accepted());

        let slow = measured(PcsBatchGateMode::Batched, 90, 9.5, 1200, Some(tamper));
        assert!(!acceptance_criteria(&independent, &slow).accepted());
        let large = measured(PcsBatchGateMode::Batched, 90, 8.9, 1300, Some(tamper));
        assert!(!acceptance_criteria(&independent, &large).accepted());
        let bigger = measured(PcsBatchGateMode::Batched, 101, 8.9, 1200, Some(tamper));
        assert!(!acceptance_criteria(&independent, &bigger).accepted());
    }

    fn measured(
        mode: PcsBatchGateMode,
        proof_bytes: usize,
        opening_seconds: f64,
        rss: u64,
        tamper: Option<PcsBatchTamperReport>,
    ) -> MeasuredPath {
        MeasuredPath {
            report: PcsBatchPathReport {
                schema: "test".to_owned(),
                mode,
                candidate_schedule_sha256: "00".repeat(32),
                cold_setup_seconds: 1.0,
                warm_setup_seconds: 1.0,
                commit_seconds: 1.0,
                opening_seconds,
                encode_seconds: 1.0,
                verify_seconds: 1.0,
                worker_seconds: 6.0,
                proof_bytes,
                opened_group_count: 2,
                verified: true,
                tamper,
            },
            sampled_peak_rss_bytes: Some(rss),
        }
    }
}
