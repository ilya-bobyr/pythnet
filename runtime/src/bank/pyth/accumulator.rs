use {
    super::batch_publish,
    crate::{
        accounts_index::{IndexKey, ScanConfig, ScanError},
        bank::Bank,
    },
    borsh::BorshSerialize,
    byteorder::{LittleEndian, ReadBytesExt},
    itertools::Itertools,
    log::*,
    pyth_oracle::validator::AggregationError,
    pythnet_sdk::{
        accumulators::{merkle::MerkleAccumulator, Accumulator},
        hashers::keccak256_160::Keccak160,
        publisher_stake_caps::StakeCapParameters,
        wormhole::{AccumulatorSequenceTracker, MessageData, PostedMessageUnreliableData},
    },
    solana_measure::measure::Measure,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        borsh::try_from_slice_unchecked,
        feature_set,
        hash::hashv,
        pubkey::Pubkey,
    },
    std::{
        collections::HashMap,
        env::{self, VarError},
    },
};

pub const ACCUMULATOR_RING_SIZE: u32 = 10_000;

lazy_static! {
    pub static ref MESSAGE_BUFFER_PID: Pubkey = env_pubkey_or(
        "MESSAGE_BUFFER_PID",
        Pubkey::new_from_array(pythnet_sdk::MESSAGE_BUFFER_PID),
    );
    pub static ref ACCUMULATOR_EMITTER_ADDR: Pubkey = env_pubkey_or(
        "ACCUMULATOR_EMITTER_ADDR",
        Pubkey::new_from_array(pythnet_sdk::ACCUMULATOR_EMITTER_ADDRESS),
    );
    pub static ref ACCUMULATOR_SEQUENCE_ADDR: Pubkey = env_pubkey_or(
        "ACCUMULATOR_SEQUENCE_ADDR",
        Pubkey::new_from_array(pythnet_sdk::pythnet::ACCUMULATOR_SEQUENCE_ADDR),
    );
    pub static ref WORMHOLE_PID: Pubkey = env_pubkey_or(
        "WORMHOLE_PID",
        Pubkey::new_from_array(pythnet_sdk::pythnet::WORMHOLE_PID),
    );
    pub static ref ORACLE_PID: Pubkey = env_pubkey_or(
        "ORACLE_PID",
        "FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH"
            .parse()
            .unwrap(),
    );
    pub static ref STAKE_CAPS_PARAMETERS_ADDR: Pubkey = env_pubkey_or(
        "STAKE_CAPS_PARAMETERS_ADDR",
        "879ZVNagiWaAKsWDjGVf8pLq1wUBeBz7sREjUh3hrU36"
            .parse()
            .unwrap(),
    );
    pub static ref PRICE_STORE_PID: Pubkey = env_pubkey_or(
        "PRICE_STORE_PID",
        "3m6sv6HGqEbuyLV84mD7rJn4MAC9LhUa1y1AUNVqcPfr"
            .parse()
            .unwrap(),
    );
}

/// Accumulator specific error type. It would be nice to use `transaction::Error` but it does
/// not include any `Custom` style variant we can leverage, so we introduce our own.
#[derive(Debug, thiserror::Error)]
pub enum AccumulatorUpdateErrorV1 {
    #[error("get_program_accounts failed to return accounts: {0}")]
    GetProgramAccounts(#[from] ScanError),

    #[error("failed to serialize sequence account")]
    FailedSequenceSerialization,

    #[error("failed to serialize message account")]
    FailedMessageSerialization,

    #[error("io error")]
    Io(#[from] std::io::Error),

    #[error("could not parse Pubkey from environment")]
    InvalidEnvPubkey(#[from] solana_sdk::pubkey::ParsePubkeyError),
}

/// Updates the Accumulator Sysvar at the start of a new slot. See `update_clock` to see a similar
/// sysvar this is based on.
///
/// Note:
/// - Library imports are placed within this function to keep the diff against upstream small.
/// - This update will incur a performance hit on each slot, so must be kept efficient.
/// - Focused on Merkle for initial release but will generalise to more accumulators in future.
pub fn update_accumulator(bank: &Bank) {
    if !bank
        .feature_set
        .is_active(&feature_set::enable_accumulator_sysvar::id())
    {
        info!(
            "Accumulator: Skipping because the feature is disabled. Slot: {}",
            bank.slot()
        );
        return;
    }

    info!("Accumulator: Updating accumulator. Slot: {}", bank.slot());

    if let Err(e) = update_v2(bank) {
        error!("Error updating accumulator v2: {:?}", e);
    }
}

/// Read the pubkey from the environment variable `var` or return `default`
/// if the variable is not set.
fn env_pubkey_or(var: &str, default: Pubkey) -> Pubkey {
    match env::var(var) {
        Ok(value) => value.parse().unwrap_or_else(|err| {
            panic!(
                "failed to parse env var {}={:?} as pubkey: {}",
                var, value, err
            )
        }),
        Err(VarError::NotPresent) => default,
        Err(VarError::NotUnicode(value)) => {
            panic!("invalid value of env var {}={:?}: not unicode", var, value);
        }
    }
}

pub fn update_v1(
    bank: &Bank,
    v2_messages: &[Vec<u8>],
    use_message_buffers: bool,
) -> std::result::Result<(), AccumulatorUpdateErrorV1> {
    // Use the current Clock to determine the index into the accumulator ring buffer.
    let ring_index = (bank.slot() % 10_000) as u32;

    // Find all accounts owned by the Message Buffer program using get_program_accounts, and
    // extract the account data.

    let message_buffer_accounts;
    let v1_messages = if use_message_buffers {
        let mut measure = Measure::start("update_v1_load_program_accounts");

        assert!(
            bank.account_indexes_include_key(&*MESSAGE_BUFFER_PID),
            "MessageBuffer program account index missing"
        );
        message_buffer_accounts = bank
            .get_filtered_indexed_accounts(
                &IndexKey::ProgramId(*MESSAGE_BUFFER_PID),
                |account| account.owner() == &*MESSAGE_BUFFER_PID,
                &ScanConfig::new(true),
                None,
            )
            .map_err(AccumulatorUpdateErrorV1::GetProgramAccounts)?;

        measure.stop();
        debug!(
            "Accumulator: Loaded message buffer accounts in {}us",
            measure.as_us()
        );

        let mut measure = Measure::start("update_v1_extract_message_data");

        let preimage = b"account:MessageBuffer";
        let mut expected_sighash = [0u8; 8];
        expected_sighash.copy_from_slice(&hashv(&[preimage]).to_bytes()[..8]);

        // Filter accounts that don't match the Anchor sighash.
        let message_buffer_accounts = message_buffer_accounts.iter().filter(|(_, account)| {
            // Remove accounts that do not start with the expected Anchor sighash.
            let mut sighash = [0u8; 8];
            sighash.copy_from_slice(&account.data()[..8]);
            sighash == expected_sighash
        });

        // This code, using the offsets in each Account, extracts the various data versions from
        // the account. We deduplicate this result because the accumulator expects a set.
        let res = message_buffer_accounts
            .map(|(_, account)| {
                let data = account.data();
                let mut cursor = std::io::Cursor::new(&data);
                let _sighash = cursor.read_u64::<LittleEndian>()?;
                let _bump = cursor.read_u8()?;
                let _version = cursor.read_u8()?;
                let header_len = cursor.read_u16::<LittleEndian>()?;
                let mut header_begin = header_len;
                let mut inputs = Vec::new();
                let mut cur_end_offsets_idx: usize = 0;
                while let Ok(end) = cursor.read_u16::<LittleEndian>() {
                    if end == 0 || cur_end_offsets_idx == (u8::MAX as usize) {
                        break;
                    }

                    let end_offset = header_len + end;
                    if end_offset as usize > data.len() {
                        break;
                    }
                    let accumulator_input_data = &data[header_begin as usize..end_offset as usize];
                    inputs.push(accumulator_input_data);
                    header_begin = end_offset;
                    cur_end_offsets_idx += 1;
                }

                Ok(inputs)
            })
            .collect::<std::result::Result<Vec<_>, std::io::Error>>()?
            .into_iter()
            .flatten()
            .collect();

        measure.stop();
        debug!(
            "Accumulator: Extracted message data in {}us",
            measure.as_us()
        );

        res
    } else {
        Vec::new()
    };

    let mut measure = Measure::start("create_message_set");

    let mut messages = v1_messages;
    messages.extend(v2_messages.iter().map(|x| &**x));
    messages.sort_unstable();
    messages.dedup();

    // We now generate a Proof PDA (Owned by the System Program) to store the resulting Proof
    // Set. The derivation includes the ring buffer index to simulate a ring buffer in order
    // for RPC users to select the correct proof for an associated VAA.
    let (accumulator_account, _) = Pubkey::find_program_address(
        &[b"AccumulatorState", &ring_index.to_be_bytes()],
        &solana_sdk::system_program::id(),
    );

    let accumulator_data = {
        let mut data = vec![];
        let acc_state_magic = &mut b"PAS1".to_vec();
        let accounts_data = &mut BorshSerialize::try_to_vec(&messages)?;
        data.append(acc_state_magic);
        data.append(&mut BorshSerialize::try_to_vec(&bank.slot())?);
        data.append(&mut BorshSerialize::try_to_vec(&ACCUMULATOR_RING_SIZE)?);
        data.append(accounts_data);
        let owner = solana_sdk::system_program::id();
        let balance = bank.get_minimum_balance_for_rent_exemption(data.len());
        let mut account = AccountSharedData::new(balance, data.len(), &owner);
        account.set_data(data);
        account
    };

    measure.stop();
    debug!("Accumulator: Created message set in {}us", measure.as_us());

    // Generate a Message owned by Wormhole to be sent cross-chain. This short-circuits the
    // Wormhole message generation code that would normally be called, but the Guardian
    // set filters our messages so this does not pose a security risk.
    let mut measure = Measure::start("create_accumulator");

    let maybe_accumulator = MerkleAccumulator::<Keccak160>::from_set(messages.into_iter());

    measure.stop();
    debug!("Accumulator: Created accumulator in {}us", measure.as_us());

    if let Some(accumulator) = maybe_accumulator {
        let mut measure = Measure::start("post_accumulator_attestation");
        post_accumulator_attestation(bank, accumulator, ring_index)?;
        measure.stop();
        debug!(
            "Accumulator: Posted accumulator attestation in {}us",
            measure.as_us()
        );
    }

    // Write the Account Set into `accumulator_state` so that the hermes application can
    // request historical data to prove.
    info!(
        "Accumulator: Writing accumulator state to {:?}",
        accumulator_account
    );

    let mut measure = Measure::start("store_account_and_update_capitalization");
    bank.store_account_and_update_capitalization(&accumulator_account, &accumulator_data);
    measure.stop();
    debug!(
        "Accumulator: Stored accumulator state in {}us",
        measure.as_us()
    );

    Ok(())
}

/// TODO: Safe integer conversion checks if any are missed.
fn post_accumulator_attestation(
    bank: &Bank,
    acc: MerkleAccumulator<Keccak160>,
    ring_index: u32,
) -> std::result::Result<(), AccumulatorUpdateErrorV1> {
    // Wormhole uses a Sequence account that is incremented each time a message is posted. As
    // we aren't calling Wormhole we need to bump this ourselves. If it doesn't exist, we just
    // create it instead.
    let mut sequence: AccumulatorSequenceTracker = {
        let data = bank
            .get_account_with_fixed_root(&ACCUMULATOR_SEQUENCE_ADDR)
            .unwrap_or_default();
        let data = data.data();
        try_from_slice_unchecked(data).unwrap_or(AccumulatorSequenceTracker { sequence: 0 })
    };

    debug!("Accumulator: accumulator sequence: {:?}", sequence.sequence);

    // Generate the Message to emit via Wormhole.
    let message = PostedMessageUnreliableData {
        message: if !bank
            .feature_set
            .is_active(&feature_set::zero_wormhole_message_timestamps::id())
        {
            MessageData {
                vaa_version: 1,
                consistency_level: 1,
                vaa_time: 1u32,
                vaa_signature_account: Pubkey::default().to_bytes(),
                submission_time: bank.clock().unix_timestamp as u32,
                nonce: 0,
                sequence: sequence.sequence,
                emitter_chain: 26,
                emitter_address: ACCUMULATOR_EMITTER_ADDR.to_bytes(),
                payload: acc.serialize(bank.slot(), ACCUMULATOR_RING_SIZE),
            }
        } else {
            // Use Default::default() to ensure zeroed VAA fields.
            MessageData {
                vaa_version: 1,
                consistency_level: 1,
                submission_time: bank.clock().unix_timestamp as u32,
                sequence: sequence.sequence,
                emitter_chain: 26,
                emitter_address: ACCUMULATOR_EMITTER_ADDR.to_bytes(),
                payload: acc.serialize(bank.slot(), ACCUMULATOR_RING_SIZE),
                ..Default::default()
            }
        },
    };

    debug!("Accumulator: Wormhole message data: {:?}", message.message);
    // Now we can bump and write the Sequence account.
    sequence.sequence += 1;
    let sequence = BorshSerialize::try_to_vec(&sequence)
        .map_err(|_| AccumulatorUpdateErrorV1::FailedSequenceSerialization)?;
    let sequence_balance = bank.get_minimum_balance_for_rent_exemption(sequence.len());
    let sequence_account = {
        let owner = &WORMHOLE_PID;
        let mut account = AccountSharedData::new(sequence_balance, sequence.len(), owner);
        account.set_data(sequence);
        account
    };

    // Serialize into (and create if necessary) the message account.
    let message = BorshSerialize::try_to_vec(&message)
        .map_err(|_| AccumulatorUpdateErrorV1::FailedMessageSerialization)?;
    let message_balance = bank.get_minimum_balance_for_rent_exemption(message.len());
    let message_account = {
        let owner = &WORMHOLE_PID;
        let mut account = AccountSharedData::new(message_balance, message.len(), owner);
        account.set_data(message);
        account
    };

    // The message_pda derivation includes the ring buffer index to simulate a ring buffer in order
    // for RPC users to select the message for an associated VAA.
    let (message_pda, _) = Pubkey::find_program_address(
        &[b"AccumulatorMessage", &ring_index.to_be_bytes()],
        &WORMHOLE_PID,
    );

    bank.store_account_and_update_capitalization(&ACCUMULATOR_SEQUENCE_ADDR, &sequence_account);

    info!("Accumulator: Writing wormhole message to {:?}", message_pda);
    bank.store_account_and_update_capitalization(&message_pda, &message_account);

    Ok(())
}

pub fn update_v2(bank: &Bank) -> std::result::Result<(), AccumulatorUpdateErrorV1> {
    let mut measure = Measure::start("update_v2_load_program_accounts");

    assert!(
        bank.account_indexes_include_key(&*ORACLE_PID),
        "Oracle program account index missing"
    );

    let accounts = bank
        .get_filtered_indexed_accounts(
            &IndexKey::ProgramId(*ORACLE_PID),
            |account| account.owner() == &*ORACLE_PID,
            &ScanConfig::new(true),
            None,
        )
        .map_err(AccumulatorUpdateErrorV1::GetProgramAccounts)?;

    measure.stop();
    debug!(
        "Accumulator: Loaded oracle program accounts in {}us",
        measure.as_us()
    );

    let mut any_v1_aggregations = false;
    let mut v2_messages = Vec::new();

    if let Some(publisher_stake_caps_message) = compute_publisher_stake_caps(bank, &accounts) {
        info!("PublisherStakeCaps: Adding publisher stake caps to the accumulator");
        v2_messages.push(publisher_stake_caps_message);
    }

    let mut measure = Measure::start("extract_batch_publish_prices");
    let mut new_prices = batch_publish::extract_batch_publish_prices(bank).unwrap_or_else(|err| {
        warn!("extract_batch_publish_prices failed: {}", err);
        HashMap::new()
    });
    measure.stop();
    debug!("batch publish: loaded prices in {}us", measure.as_us());

    let mut measure = Measure::start("update_v2_aggregate_price");
    for (pubkey, mut account) in accounts {
        let mut price_account_data = account.data().to_owned();
        let price_account =
            match pyth_oracle::validator::checked_load_price_account_mut(&mut price_account_data) {
                Ok(data) => data,
                Err(_err) => {
                    continue;
                }
            };

        let mut need_save =
            batch_publish::apply_published_prices(price_account, &mut new_prices, bank.slot());

        // Perform Accumulation
        match pyth_oracle::validator::aggregate_price(
            bank.slot(),
            bank.clock().unix_timestamp,
            &pubkey.to_bytes().into(),
            price_account,
        ) {
            Ok(messages) => {
                need_save = true;
                v2_messages.extend(messages);
            }
            Err(err) => match err {
                AggregationError::NotPriceFeedAccount => {}
                AggregationError::V1AggregationMode | AggregationError::AlreadyAggregated => {
                    any_v1_aggregations = true;
                }
            },
        }
        if need_save {
            account.set_data(price_account_data);
            bank.store_account_and_update_capitalization(&pubkey, &account);
        }
    }
    if !new_prices.is_empty() {
        warn!(
            "pyth batch publish: missing price feed accounts for indexes: {}",
            new_prices.keys().join(", ")
        );
    }

    measure.stop();
    debug!(
        "Accumulator: Aggregated oracle prices in {}us and generated {} messages",
        measure.as_us(),
        v2_messages.len()
    );

    update_v1(bank, &v2_messages, any_v1_aggregations)
}

pub fn compute_publisher_stake_caps(
    bank: &Bank,
    accounts: &[(Pubkey, AccountSharedData)],
) -> Option<Vec<u8>> {
    let mut measure = Measure::start("compute_publisher_stake_caps");

    let parameters: StakeCapParameters = {
        let data = bank
            .get_account_with_fixed_root(&STAKE_CAPS_PARAMETERS_ADDR)
            .unwrap_or_default();
        let data = data.data();
        solana_sdk::borsh::try_from_slice_unchecked(data).unwrap_or_default()
    };

    let message = pyth_oracle::validator::compute_publisher_stake_caps(
        accounts.iter().map(|(_, account)| account.data()),
        bank.clock().unix_timestamp,
        parameters.m,
        parameters.z,
    );

    measure.stop();
    debug!(
        "PublisherStakeCaps: Computed publisher stake caps with m : {} and z : {} in {} us",
        parameters.m,
        parameters.z,
        measure.as_us()
    );

    if bank
        .feature_set
        .is_active(&feature_set::add_publisher_stake_caps_to_the_accumulator::id())
    {
        Some(message)
    } else {
        None
    }
}
