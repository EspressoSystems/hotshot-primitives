use displaydoc::Display;

#[derive(Debug, Display)]
pub enum StakeTableError {
    /// Internal error caused by Rescue
    RescueError,
    /// Key mismatched
    MismatchedKey,
    /// Key not found
    KeyNotFound,
    /// Key already exists
    ExistingKey,
    /// Update that will result in a negative amount of stake
    InsufficientFund,
}
