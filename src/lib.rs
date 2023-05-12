//! This crate provides various cryptography primitives required for the HotShot protocol. [TODO link to hotshot paper]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(warnings)]
// #![warn(missing_docs)] // TODO need rustdoc for stake_table

pub mod stake_table;
pub mod vdf;
pub mod vid;
