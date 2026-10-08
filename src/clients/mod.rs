//! Thin clients for Microsoft admin APIs that Graph does not cover. Each borrows the `GraphClient`
//! for token acquisition (`Resource::*`) and returns `serde_json::Value`; the modules evaluate.

pub mod spo;
pub mod teams;
