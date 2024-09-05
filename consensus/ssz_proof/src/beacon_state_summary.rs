use derivative::Derivative;
use ethereum_consensus::{
    altair::Fork,
    bellatrix,
    capella::{self, HistoricalSummary},
    deneb::{self},
    phase0::{beacon_block::BeaconBlockHeader, U256},
    primitives::{Root, Slot},
    ssz::prelude::{List, Vector},
};
use hex::encode;
use metastruct::metastruct;
use ssz_rs::{
    Deserialize, GeneralizedIndexable, HashTreeRoot, MerkleizationError, Node, PathElement,
    Serialize,
};
use ssz_rs_derive::SimpleSerialize;
use superstruct::superstruct;
use tree_hash::TreeHash;
use types::{historical_summary, BeaconState, Error, EthSpec, ExecutionPayloadHeader};

pub fn encode_node(node: &Node) -> String {
    let mut buffer = Vec::new();
    node.serialize(&mut buffer).unwrap();
    encode(&buffer)
}

/// The state of the `BeaconChain` at some slot.
#[superstruct(
    variants(Base, Altair, Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(Derivative, Debug, PartialEq, SimpleSerialize),
        derivative(Clone)
    ),
    specific_variant_attributes(
        Base(metastruct(
            mappings(
                map_beacon_state_summary_base_fields(),
                map_beacon_state_summary_base_tree_list_fields(
                    mutable,
                    fallible,
                    groups(tree_lists)
                ),
                map_beacon_state_summary_base_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_summary_base_tree_list_fields(
                other_type = "BeaconStateSummaryBase",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Altair(metastruct(
            mappings(
                map_beacon_state_summary_altair_fields(),
                map_beacon_state_summary_altair_tree_list_fields(
                    mutable,
                    fallible,
                    groups(tree_lists)
                ),
                map_beacon_state_summary_altair_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_summary_altair_tree_list_fields(
                other_type = "BeaconStateSummaryAltair",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Bellatrix(metastruct(
            mappings(
                map_beacon_state_summary_bellatrix_fields(),
                map_beacon_state_summary_bellatrix_tree_list_fields(
                    mutable,
                    fallible,
                    groups(tree_lists)
                ),
                map_beacon_state_summary_bellatrix_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_summary_bellatrix_tree_list_fields(
                other_type = "BeaconStateSummaryBellatrix",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Capella(metastruct(
            mappings(
                map_beacon_state_summary_capella_fields(),
                map_beacon_state_summary_capella_tree_list_fields(
                    mutable,
                    fallible,
                    groups(tree_lists)
                ),
                map_beacon_state_summary_capella_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_summary_capella_tree_list_fields(
                other_type = "BeaconStateSummaryCapella",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Deneb(metastruct(
            mappings(
                map_beacon_state_summary_deneb_fields(),
                map_beacon_state_summary_deneb_tree_list_fields(
                    mutable,
                    fallible,
                    groups(tree_lists)
                ),
                map_beacon_state_summary_deneb_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_summary_deneb_tree_list_fields(
                other_type = "BeaconStateSummaryDeneb",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        )),
        Electra(metastruct(
            mappings(
                map_beacon_state_summary_electra_fields(),
                map_beacon_state_summary_electra_tree_list_fields(
                    mutable,
                    fallible,
                    groups(tree_lists)
                ),
                map_beacon_state_summary_electra_tree_list_fields_immutable(groups(tree_lists)),
            ),
            bimappings(bimap_beacon_state_summary_electra_tree_list_fields(
                other_type = "BeaconStateSummaryElectra",
                self_mutable,
                fallible,
                groups(tree_lists)
            )),
            num_fields(all()),
        ))
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    map_ref_mut_into(BeaconStateRef)
)]
#[derive(Debug, PartialEq, Clone)]
pub struct BeaconStateSummary<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
> {
    // Versioning
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub genesis_time: u64,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub genesis_validators_root: Root,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub slot: Slot,
    #[superstruct(getter())]
    #[metastruct(exclude_from(tree_lists))]
    pub fork: Fork,

    // History
    #[metastruct(exclude_from(tree_lists))]
    pub latest_block_header: BeaconBlockHeader,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub block_roots: Root,
    pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    // Frozen in Capella, replaced by historical_summaries
    pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,

    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub eth1_data: Root,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub eth1_data_votes: Root,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub eth1_deposit_index: u64,

    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub validators: Root,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub balances: Root,

    // Randomness
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub randao_mixes: Root,

    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub slashings: Root,

    // Attestations (genesis fork only)
    #[superstruct(only(Base))]
    #[metastruct(exclude_from(tree_lists))]
    pub previous_epoch_attestations: Root,
    #[superstruct(only(Base))]
    #[metastruct(exclude_from(tree_lists))]
    pub current_epoch_attestations: Root,

    // Participation (Altair and later)
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    #[metastruct(exclude_from(tree_lists))]
    pub previous_epoch_participation: Root,
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    #[metastruct(exclude_from(tree_lists))]
    pub current_epoch_participation: Root,

    // Finality
    #[metastruct(exclude_from(tree_lists))]
    pub justification_bits: Root,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub previous_justified_checkpoint: Root,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub current_justified_checkpoint: Root,
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub finalized_checkpoint: Root,

    // Inactivity
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    #[superstruct(getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub inactivity_scores: Root,

    // Light-client sync committees
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    #[metastruct(exclude_from(tree_lists))]
    pub current_sync_committee: Root,
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    #[metastruct(exclude_from(tree_lists))]
    pub next_sync_committee: Root,

    // Execution
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "latest_execution_payload_header_bellatrix")
    )]
    #[metastruct(exclude_from(tree_lists))]
    pub latest_execution_payload_header:
        bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    #[superstruct(
        only(Capella),
        partial_getter(rename = "latest_execution_payload_header_capella")
    )]
    #[metastruct(exclude_from(tree_lists))]
    pub latest_execution_payload_header:
        capella::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    #[superstruct(
        only(Deneb),
        partial_getter(rename = "latest_execution_payload_header_deneb")
    )]
    #[metastruct(exclude_from(tree_lists))]
    pub latest_execution_payload_header:
        deneb::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    // #[superstruct(
    //     only(Electra),
    //     partial_getter(rename = "latest_execution_payload_header_electra")
    // )]
    // #[metastruct(exclude_from(tree_lists))]
    // pub latest_execution_payload_header: ExecutionPayloadHeaderElectra<E>,

    // Capella
    #[superstruct(only(Capella, Deneb, Electra), partial_getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Capella, Deneb, Electra), partial_getter(copy))]
    #[metastruct(exclude_from(tree_lists))]
    pub next_withdrawal_validator_index: u64,
    // Deep history valid from Capella onwards.
    #[superstruct(only(Capella, Deneb, Electra))]
    pub historical_summaries: List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,
    // Electra
    // #[superstruct(only(Electra), partial_getter(copy))]
    // #[metastruct(exclude_from(tree_lists))]
    // #[serde(with = "serde_utils::quoted_u64")]
    // pub deposit_receipts_start_index: u64,
    // #[superstruct(only(Electra), partial_getter(copy))]
    // #[metastruct(exclude_from(tree_lists))]
    // #[serde(with = "serde_utils::quoted_u64")]
    // pub deposit_balance_to_consume: u64,
    // #[superstruct(only(Electra), partial_getter(copy))]
    // #[metastruct(exclude_from(tree_lists))]
    // #[serde(with = "serde_utils::quoted_u64")]
    // pub exit_balance_to_consume: u64,
    // #[superstruct(only(Electra), partial_getter(copy))]
    // #[metastruct(exclude_from(tree_lists))]
    // pub earliest_exit_epoch: Epoch,
    // #[superstruct(only(Electra), partial_getter(copy))]
    // #[metastruct(exclude_from(tree_lists))]
    // #[serde(with = "serde_utils::quoted_u64")]
    // pub consolidation_balance_to_consume: u64,
    // #[superstruct(only(Electra), partial_getter(copy))]
    // #[metastruct(exclude_from(tree_lists))]
    // pub earliest_consolidation_epoch: Epoch,
    // #[test_random(default)]
    // #[superstruct(only(Electra))]
    // pub pending_balance_deposits: List<PendingBalanceDeposit, E::PendingBalanceDepositsLimit>,
    // #[test_random(default)]
    // #[superstruct(only(Electra))]
    // pub pending_partial_withdrawals:
    //     List<PendingPartialWithdrawal, E::PendingPartialWithdrawalsLimit>,
    // #[test_random(default)]
    // #[superstruct(only(Electra))]
    // pub pending_consolidations: List<PendingConsolidation, E::PendingConsolidationsLimit>,
}

/// This is the list of common fields for BeaconStateSummary

pub struct BeaconStateSummaryCommonFields<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
> {
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
    pub slot: Slot,
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: Root,
    pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    // Frozen in Capella, replaced by historical_summaries
    pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,

    pub eth1_data: Root,
    pub eth1_data_votes: Root,
    pub eth1_deposit_index: u64,

    pub validators: Root,
    pub balances: Root,

    // Randomness
    pub randao_mixes: Root,
    pub slashings: Root,

    pub justification_bits: Root,
    pub previous_justified_checkpoint: Root,
    pub current_justified_checkpoint: Root,
    pub finalized_checkpoint: Root,
}

fn to_beacon_state_summary_common_fields<
    E: EthSpec,
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
>(
    state: &BeaconState<E>,
) -> BeaconStateSummaryCommonFields<SLOTS_PER_HISTORICAL_ROOT, HISTORICAL_ROOTS_LIMIT>
where
    E: EthSpec,
{
    let genesis_time = state.genesis_time();
    let genesis_validators_root = state.genesis_validators_root().0.into();
    let slot: Slot = state.slot().into();

    let fork = Fork {
        previous_version: state.fork().previous_version,
        current_version: state.fork().current_version,
        epoch: state.fork().epoch.into(),
    };

    let latest_block_header = BeaconBlockHeader {
        slot: state.latest_block_header().slot.into(),
        proposer_index: state.latest_block_header().proposer_index as usize,
        parent_root: state.latest_block_header().parent_root.0.into(),
        state_root: state.latest_block_header().state_root.0.into(),
        body_root: state.latest_block_header().body_root.0.into(),
    };

    let block_roots = state.block_roots().tree_hash_root().0.into();
    let state_roots = Vector::try_from(
        state
            .state_roots()
            .into_iter()
            .map(|x| x.0.into())
            .collect::<Vec<Root>>(),
    )
    .unwrap();
    let historical_roots = List::try_from(
        state
            .historical_roots()
            .into_iter()
            .map(|x| x.0.into())
            .collect::<Vec<Root>>(),
    )
    .unwrap();

    let eth1_data = state.eth1_data().tree_hash_root().0.into();
    let eth1_data_votes = state.eth1_data_votes().tree_hash_root().0.into();
    let eth1_deposit_index = state.eth1_deposit_index();
    let validators = state.validators().tree_hash_root().0.into();
    let balances = state.balances().tree_hash_root().0.into();
    let randao_mixes = state.randao_mixes().tree_hash_root().0.into();
    let slashings = state.slashings().tree_hash_root().0.into();
    let justification_bits = state.justification_bits().tree_hash_root().0.into();
    let previous_justified_checkpoint = state
        .previous_justified_checkpoint()
        .tree_hash_root()
        .0
        .into();
    let current_justified_checkpoint = state
        .current_justified_checkpoint()
        .tree_hash_root()
        .0
        .into();
    let finalized_checkpoint = state.finalized_checkpoint().tree_hash_root().0.into();

    BeaconStateSummaryCommonFields::<SLOTS_PER_HISTORICAL_ROOT, HISTORICAL_ROOTS_LIMIT> {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
    }
}

fn to_execution_payload_header_common_fields<
    E: EthSpec,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
>(
    header: &ExecutionPayloadHeader<E>,
) -> bellatrix::ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES> {
    bellatrix::ExecutionPayloadHeader {
        parent_hash: header.parent_hash().0 .0.as_slice().try_into().unwrap(),
        fee_recipient: header.fee_recipient().0.as_slice().try_into().unwrap(),
        state_root: header.state_root().0.as_slice().try_into().unwrap(),
        receipts_root: header.receipts_root().0.as_slice().try_into().unwrap(),
        logs_bloom: header.logs_bloom().as_ref().try_into().unwrap(),
        prev_randao: header.prev_randao().0.as_slice().try_into().unwrap(),
        block_number: header.block_number(),
        gas_limit: header.gas_limit(),
        gas_used: header.gas_used(),
        timestamp: header.timestamp(),
        extra_data: header.extra_data().as_ref().try_into().unwrap(),
        base_fee_per_gas: U256::from_limbs(header.base_fee_per_gas().0),
        block_hash: header.block_hash().0 .0.as_slice().try_into().unwrap(),
        transactions_root: header.transactions_root().0.as_slice().try_into().unwrap(),
    }
}

fn convert_historical_summaries<T: EthSpec, const HISTORICAL_ROOTS_LIMIT: usize>(
    historical_summaries: milhouse::List<
        historical_summary::HistoricalSummary,
        T::HistoricalRootsLimit,
    >,
) -> List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT> {
    List::try_from(
        historical_summaries
            .into_iter()
            .map(|x| HistoricalSummary {
                block_summary_root: x.block_summary_root.0.into(),
                state_summary_root: x.state_summary_root.0.into(),
            })
            .collect::<Vec<HistoricalSummary>>(),
    )
    .unwrap()
}

impl<
        E: EthSpec,
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
    > From<BeaconState<E>>
    for BeaconStateSummary<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >
{
    fn from(state: BeaconState<E>) -> Self {
        let BeaconStateSummaryCommonFields {
            genesis_time,
            genesis_validators_root,
            slot,
            fork,
            latest_block_header,
            block_roots,
            state_roots,
            historical_roots,
            eth1_data,
            eth1_data_votes,
            eth1_deposit_index,
            validators,
            balances,
            randao_mixes,
            slashings,
            justification_bits,
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
        } = to_beacon_state_summary_common_fields(&state);

        match state {
            BeaconState::Base(state) => BeaconStateSummary::Base(BeaconStateSummaryBase {
                genesis_time,
                genesis_validators_root,
                slot,
                fork,
                latest_block_header,
                block_roots,
                state_roots,
                historical_roots,
                eth1_data,
                eth1_data_votes,
                eth1_deposit_index,
                validators,
                balances,
                randao_mixes,
                slashings,
                justification_bits,
                previous_justified_checkpoint,
                current_justified_checkpoint,
                finalized_checkpoint,
                previous_epoch_attestations: state
                    .previous_epoch_attestations
                    .tree_hash_root()
                    .0
                    .into(),
                current_epoch_attestations: state
                    .current_epoch_attestations
                    .tree_hash_root()
                    .0
                    .into(),
            }),
            BeaconState::Altair(state) => BeaconStateSummary::Altair(BeaconStateSummaryAltair {
                genesis_time,
                genesis_validators_root,
                slot,
                fork,
                latest_block_header,
                block_roots,
                state_roots,
                historical_roots,
                eth1_data,
                eth1_data_votes,
                eth1_deposit_index,
                validators,
                balances,
                randao_mixes,
                slashings,
                justification_bits,
                previous_justified_checkpoint,
                current_justified_checkpoint,
                finalized_checkpoint,
                current_epoch_participation: state
                    .current_epoch_participation
                    .tree_hash_root()
                    .0
                    .into(),
                previous_epoch_participation: state
                    .previous_epoch_participation
                    .tree_hash_root()
                    .0
                    .into(),
                current_sync_committee: state.current_sync_committee.tree_hash_root().0.into(),
                next_sync_committee: state.next_sync_committee.tree_hash_root().0.into(),
                inactivity_scores: state.inactivity_scores.tree_hash_root().0.into(),
            }),
            BeaconState::Merge(state) => {
                let latest_execution_payload_header =
                    ExecutionPayloadHeader::Merge(state.latest_execution_payload_header);
                let latest_execution_payload_header =
                    to_execution_payload_header_common_fields(&latest_execution_payload_header);
                BeaconStateSummary::Bellatrix(BeaconStateSummaryBellatrix {
                    genesis_time,
                    genesis_validators_root,
                    slot,
                    fork,
                    latest_block_header,
                    block_roots,
                    state_roots,
                    historical_roots,
                    eth1_data,
                    eth1_data_votes,
                    eth1_deposit_index,
                    validators,
                    balances,
                    randao_mixes,
                    slashings,
                    justification_bits,
                    previous_justified_checkpoint,
                    current_justified_checkpoint,
                    finalized_checkpoint,
                    current_epoch_participation: state
                        .current_epoch_participation
                        .tree_hash_root()
                        .0
                        .into(),
                    previous_epoch_participation: state
                        .previous_epoch_participation
                        .tree_hash_root()
                        .0
                        .into(),
                    current_sync_committee: state.current_sync_committee.tree_hash_root().0.into(),
                    next_sync_committee: state.next_sync_committee.tree_hash_root().0.into(),
                    inactivity_scores: state.inactivity_scores.tree_hash_root().0.into(),
                    latest_execution_payload_header,
                })
            }
            BeaconState::Capella(state) => {
                let withdrawals_root: Root = state
                    .latest_execution_payload_header
                    .withdrawals_root
                    .0
                    .as_slice()
                    .try_into()
                    .unwrap();
                let latest_execution_payload_header =
                    ExecutionPayloadHeader::Capella(state.latest_execution_payload_header);
                let bellatrix::ExecutionPayloadHeader {
                    parent_hash,
                    fee_recipient,
                    state_root,
                    receipts_root,
                    logs_bloom,
                    prev_randao,
                    block_hash,
                    block_number,
                    gas_limit,
                    gas_used,
                    timestamp,
                    extra_data,
                    base_fee_per_gas,
                    transactions_root,
                } = to_execution_payload_header_common_fields(&latest_execution_payload_header);

                BeaconStateSummary::Capella(BeaconStateSummaryCapella {
                    genesis_time,
                    genesis_validators_root,
                    slot,
                    fork,
                    latest_block_header,
                    block_roots,
                    state_roots,
                    historical_roots,
                    eth1_data,
                    eth1_data_votes,
                    eth1_deposit_index,
                    validators,
                    balances,
                    randao_mixes,
                    slashings,
                    justification_bits,
                    previous_justified_checkpoint,
                    current_justified_checkpoint,
                    finalized_checkpoint,
                    current_epoch_participation: state
                        .current_epoch_participation
                        .tree_hash_root()
                        .0
                        .into(),
                    previous_epoch_participation: state
                        .previous_epoch_participation
                        .tree_hash_root()
                        .0
                        .into(),
                    current_sync_committee: state.current_sync_committee.tree_hash_root().0.into(),
                    next_sync_committee: state.next_sync_committee.tree_hash_root().0.into(),
                    inactivity_scores: state.inactivity_scores.tree_hash_root().0.into(),
                    latest_execution_payload_header: capella::ExecutionPayloadHeader {
                        parent_hash,
                        fee_recipient,
                        state_root,
                        receipts_root,
                        logs_bloom,
                        prev_randao,
                        block_hash,
                        block_number,
                        gas_limit,
                        gas_used,
                        timestamp,
                        extra_data,
                        base_fee_per_gas,
                        transactions_root,
                        withdrawals_root,
                    },
                    next_withdrawal_index: state.next_withdrawal_index,
                    next_withdrawal_validator_index: state.next_withdrawal_validator_index,
                    historical_summaries: convert_historical_summaries::<E, HISTORICAL_ROOTS_LIMIT>(
                        state.historical_summaries,
                    ),
                })
            }
            BeaconState::Deneb(state) => {
                let withdrawals_root: Root = state
                    .latest_execution_payload_header
                    .withdrawals_root
                    .0
                    .as_slice()
                    .try_into()
                    .unwrap();
                let blob_gas_used = state.latest_execution_payload_header.blob_gas_used;
                let excess_blob_gas = state.latest_execution_payload_header.excess_blob_gas;
                let latest_execution_payload_header =
                    ExecutionPayloadHeader::Deneb(state.latest_execution_payload_header);
                let bellatrix::ExecutionPayloadHeader {
                    parent_hash,
                    fee_recipient,
                    state_root,
                    receipts_root,
                    logs_bloom,
                    prev_randao,
                    block_hash,
                    block_number,
                    gas_limit,
                    gas_used,
                    timestamp,
                    extra_data,
                    base_fee_per_gas,
                    transactions_root,
                } = to_execution_payload_header_common_fields(&latest_execution_payload_header);

                BeaconStateSummary::Deneb(BeaconStateSummaryDeneb {
                    genesis_time,
                    genesis_validators_root,
                    slot,
                    fork,
                    latest_block_header,
                    block_roots,
                    state_roots,
                    historical_roots,
                    eth1_data,
                    eth1_data_votes,
                    eth1_deposit_index,
                    validators,
                    balances,
                    randao_mixes,
                    slashings,
                    justification_bits,
                    previous_justified_checkpoint,
                    current_justified_checkpoint,
                    finalized_checkpoint,
                    current_epoch_participation: state
                        .current_epoch_participation
                        .tree_hash_root()
                        .0
                        .into(),
                    previous_epoch_participation: state
                        .previous_epoch_participation
                        .tree_hash_root()
                        .0
                        .into(),
                    current_sync_committee: state.current_sync_committee.tree_hash_root().0.into(),
                    next_sync_committee: state.next_sync_committee.tree_hash_root().0.into(),
                    inactivity_scores: state.inactivity_scores.tree_hash_root().0.into(),
                    latest_execution_payload_header: deneb::ExecutionPayloadHeader {
                        parent_hash,
                        fee_recipient,
                        state_root,
                        receipts_root,
                        logs_bloom,
                        prev_randao,
                        block_hash,
                        block_number,
                        gas_limit,
                        gas_used,
                        timestamp,
                        extra_data,
                        base_fee_per_gas,
                        transactions_root,
                        withdrawals_root,
                        blob_gas_used,
                        excess_blob_gas,
                    },
                    next_withdrawal_index: state.next_withdrawal_index,
                    next_withdrawal_validator_index: state.next_withdrawal_validator_index,
                    historical_summaries: convert_historical_summaries::<E, HISTORICAL_ROOTS_LIMIT>(
                        state.historical_summaries,
                    ),
                })
            } // BeaconState::Electra(state) => todo!(),
        }
    }
}
