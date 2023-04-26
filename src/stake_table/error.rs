use ark_std::string::String;

pub enum StakeTableError {
    KeyNotFound,
    MismatchedKey,
    RescueError,
    TransactionError(String),
}
