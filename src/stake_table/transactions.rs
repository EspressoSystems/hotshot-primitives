use super::{error::StakeTableError, EncodedPublicKey};
use ark_std::{string::ToString, vec::Vec};
use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
/// Batch transactions for stake table
pub struct BatchTransactions {
    txs: Vec<(EncodedPublicKey, i64)>,
    finalized: bool,
}

impl BatchTransactions {
    /// Creates a new [`BatchTransactions`].
    pub fn new() -> Self {
        Self {
            txs: Vec::new(),
            finalized: false,
        }
    }

    /// Transfer `amount` stakes from `from` to `to`
    pub fn transfer(
        &mut self,
        from: &EncodedPublicKey,
        to: &EncodedPublicKey,
        amount: u64,
    ) -> Result<(), StakeTableError> {
        if self.finalized {
            Err(StakeTableError::TransactionError(
                "This batch of transaction is already finalized.".to_string(),
            ))
        } else {
            self.txs.push((from.clone(), -(amount as i64)));
            self.txs.push((to.clone(), amount as i64));
            Ok(())
        }
    }

    /// Finalize this batch of transactions for stake table update
    pub fn finalize(&mut self) {
        self.finalized = true;
        todo!("Sort and aggregate transactions");
    }

    // TODO: iter for txs
}
