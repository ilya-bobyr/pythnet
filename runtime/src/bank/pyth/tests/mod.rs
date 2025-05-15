use {
    super::accumulator::{MESSAGE_BUFFER_PID, ORACLE_PID, PRICE_STORE_PID},
    crate::bank::Bank,
    solana_accounts_db::{
        accounts_db::AccountShrinkThreshold,
        accounts_index::{
            AccountIndex, AccountSecondaryIndexes, AccountSecondaryIndexesIncludeExclude,
        },
    },
    solana_sdk::{genesis_config::GenesisConfig, pubkey::Pubkey},
    std::sync::Arc,
};

mod accumulator_tests;
mod batch_publish_tests;

fn new_from_parent(parent: Arc<Bank>) -> Bank {
    let slot = parent.slot() + 1;
    Bank::new_from_parent(parent, &Pubkey::default(), slot)
}

fn create_new_bank_for_tests_with_index(genesis_config: &GenesisConfig) -> Bank {
    Bank::new_with_config_for_tests(
        genesis_config,
        AccountSecondaryIndexes {
            keys: Some(AccountSecondaryIndexesIncludeExclude {
                exclude: false,
                keys: [*ORACLE_PID, *MESSAGE_BUFFER_PID, *PRICE_STORE_PID]
                    .into_iter()
                    .collect(),
            }),
            indexes: [AccountIndex::ProgramId].into_iter().collect(),
        },
        AccountShrinkThreshold::default(),
    )
}
