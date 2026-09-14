use sha2::{Digest, Sha256};

use super::{LOG_LAYOUT, LOG_SCHEDULE_ARTIFACT, PROTOCOL_LOG_NUM_VARIABLES, ProtocolLogError};
use crate::{AKITA_LOG_SCHEDULE_SHA256, pcs::scheme};

#[test]
fn pinned_log_schedule_admits_exact_group_shape() -> Result<(), ProtocolLogError> {
    let scheme = scheme(LOG_LAYOUT)?;
    let admitted = scheme.schedules().catalog().rows().any(|row| {
        row.profiles().final_group.group.num_vars() == PROTOCOL_LOG_NUM_VARIABLES
            && row.profiles().final_group.group.num_polynomials() == 128
            && row.profiles().precommitteds.is_empty()
    });
    assert!(admitted);
    assert_eq!(
        format!("{:x}", Sha256::digest(LOG_SCHEDULE_ARTIFACT)),
        AKITA_LOG_SCHEDULE_SHA256
    );
    Ok(())
}
