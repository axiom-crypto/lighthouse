use beacon_state_summary::{encode_node, BeaconStateSummary};
use network_params::{MainnetParams, MinimalParams, NetworkParams};
use serde::{Deserialize, Serialize};
use ssz_rs::PathElement;
use types::{BeaconState, EthSpec, EthSpecId};
mod beacon_state_summary;
mod network_params;

use ssz_rs::Prove;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofWrapper {
    pub leaf: String,
    pub branch: Vec<String>,
    pub index: usize,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofAndWitness {
    proof: ProofWrapper,
    witness: [u8; 32],
}

fn generate_proof_and_witnes<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    state: BeaconStateSummary<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    path: &Vec<PathElement>,
) -> ProofAndWitness {
    let (proof, witness) = match state {
        BeaconStateSummary::Base(state) => state.prove(&path).unwrap(),
        BeaconStateSummary::Altair(state) => state.prove(&path).unwrap(),
        BeaconStateSummary::Bellatrix(state) => state.prove(&path).unwrap(),
        BeaconStateSummary::Capella(state) => state.prove(&path).unwrap(),
        BeaconStateSummary::Deneb(state) => state.prove(&path).unwrap(),
        BeaconStateSummary::Electra(_) => todo!(),
    };

    let proof_and_witness = ProofAndWitness {
        proof: ProofWrapper {
            leaf: encode_node(&proof.leaf),
            branch: proof.branch.iter().map(|n| encode_node(&n)).collect(),
            index: proof.index,
        },
        witness: *witness,
    };
    proof_and_witness
}

pub fn ssz_prove<E: EthSpec>(
    state: BeaconState<E>,
    spec_id: EthSpecId,
    path: Vec<String>,
) -> ProofAndWitness {
    let path: Vec<PathElement> = path.into_iter().map(PathElement::Field).collect();
    match spec_id {
        EthSpecId::Mainnet => {
            let state = BeaconStateSummary::<
                { MainnetParams::SLOTS_PER_HISTORICAL_ROOT },
                { MainnetParams::HISTORICAL_ROOTS_LIMIT },
                { MainnetParams::BYTES_PER_LOGS_BLOOM },
                { MainnetParams::MAX_EXTRA_DATA_BYTES },
            >::from(state);

            generate_proof_and_witnes(state, &path)
        }
        EthSpecId::Minimal => {
            let state = BeaconStateSummary::<
                { MinimalParams::SLOTS_PER_HISTORICAL_ROOT },
                { MinimalParams::HISTORICAL_ROOTS_LIMIT },
                { MinimalParams::BYTES_PER_LOGS_BLOOM },
                { MinimalParams::MAX_EXTRA_DATA_BYTES },
            >::from(state);
            generate_proof_and_witnes(state, &path)
        }
        EthSpecId::Gnosis => {
            todo!();
        }
    }
}
