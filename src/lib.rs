//! This crate provides various cryptography primitives required for the HotShot protocol. [TODO link to hotshot paper]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(warnings)]
#![warn(missing_docs)]

pub mod vdf;
pub mod vid;
