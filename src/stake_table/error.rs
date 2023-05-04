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
    /// Malformed Merkle proof
    MalformedProof,
    /// Verification Error
    VerificationError,
    /// Insufficient fund: the number of stake cannot be negative
    InsufficientFund,
    /// The number of stake exceed U256
    StakeOverflow,
}
