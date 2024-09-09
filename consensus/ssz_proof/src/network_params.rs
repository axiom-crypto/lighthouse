use ethereum_consensus::deneb::{
    mainnet::{
        BYTES_PER_LOGS_BLOOM as MAINNET_BYTES_PER_LOGS_BLOOM,
        HISTORICAL_ROOTS_LIMIT as MAINNET_HISTORICAL_ROOTS_LIMIT,
        MAX_EXTRA_DATA_BYTES as MAINNET_MAX_EXTRA_DATA_BYTES,
        SLOTS_PER_HISTORICAL_ROOT as MAINNET_SLOTS_PER_HISTORICAL_ROOT,
    },
    minimal::{
        BYTES_PER_LOGS_BLOOM as MINIMAL_BYTES_PER_LOGS_BLOOM,
        HISTORICAL_ROOTS_LIMIT as MINIMAL_HISTORICAL_ROOTS_LIMIT,
        MAX_EXTRA_DATA_BYTES as MINIMAL_MAX_EXTRA_DATA_BYTES,
        SLOTS_PER_HISTORICAL_ROOT as MINIMAL_SLOTS_PER_HISTORICAL_ROOT,
    },
};

pub trait NetworkParams {
    const SLOTS_PER_HISTORICAL_ROOT: usize;
    const HISTORICAL_ROOTS_LIMIT: usize;
    const BYTES_PER_LOGS_BLOOM: usize;
    const MAX_EXTRA_DATA_BYTES: usize;
}

/// These parameters have not been changed in hardforks so far, so we only have different
/// params based on Mainnet/Minimal.
pub struct MainnetParams;
impl NetworkParams for MainnetParams {
    const SLOTS_PER_HISTORICAL_ROOT: usize = MAINNET_SLOTS_PER_HISTORICAL_ROOT;
    const HISTORICAL_ROOTS_LIMIT: usize = MAINNET_HISTORICAL_ROOTS_LIMIT;
    const BYTES_PER_LOGS_BLOOM: usize = MAINNET_BYTES_PER_LOGS_BLOOM;
    const MAX_EXTRA_DATA_BYTES: usize = MAINNET_MAX_EXTRA_DATA_BYTES;
}

pub struct MinimalParams;
impl NetworkParams for MinimalParams {
    const SLOTS_PER_HISTORICAL_ROOT: usize = MINIMAL_SLOTS_PER_HISTORICAL_ROOT;
    const HISTORICAL_ROOTS_LIMIT: usize = MINIMAL_HISTORICAL_ROOTS_LIMIT;
    const BYTES_PER_LOGS_BLOOM: usize = MINIMAL_BYTES_PER_LOGS_BLOOM;
    const MAX_EXTRA_DATA_BYTES: usize = MINIMAL_MAX_EXTRA_DATA_BYTES;
}
