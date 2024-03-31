//! Run an APT/BTC swap in the role of Alice.
//! Alice holds APT and wishes receive BTC.
use crate::env::Config;
use crate::protocol::Database;
use crate::{bitcoin, aptos};
use std::sync::Arc;
use uuid::Uuid;

pub use self::state::*;
pub use self::swap::{run, run_until};

pub mod state;
pub mod swap;

pub struct Swap {
    pub state: AliceState,
    pub bitcoin_wallet: Arc<bitcoin::Wallet>,
    pub aptos_wallet: Arc<aptos::Wallet>,
    pub env_config: Config,
    pub swap_id: Uuid,
    pub db: Arc<dyn Database + Send + Sync>,
}
