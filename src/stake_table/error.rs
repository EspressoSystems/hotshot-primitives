use ark_std::string::ToString;
use displaydoc::Display;
use jf_primitives::errors::PrimitivesError;

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
    /// The historical snapshot requested is not supported.
    SnapshotUnsupported,
}

impl ark_std::error::Error for StakeTableError {}

impl From<StakeTableError> for PrimitivesError {
    fn from(value: StakeTableError) -> Self {
        // FIXME: (alex) should we define a PrimitivesError::General()?
        Self::ParameterError(value.to_string())
    }
}
