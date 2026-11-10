//! The ledger as a separate process: messages, the ledger's side and a service's side.
//!
//! What the link gives: the ledger's memory is reachable only through typed requests, each one
//! run as the service that proved its key when it connected. What it does not give: secrecy or
//! integrity on an open network. Payloads are neither encrypted nor authenticated one by one;
//! the link is meant for a local socket that the operating system protects. Anything else needs
//! a secure channel underneath.

mod client;
mod host;
mod wire;

pub use client::{
    read_frame, write_frame, LedgerClient, LinkError, Loopback, RemoteLedger, StreamTransport,
    Transport,
};
pub use host::{Conn, HostEnv, HostLimits, LedgerHost, Reply};
pub use wire::{
    transcript, Fault, LedgerInfo, LedgerSummary, Malformed, Message, Refusal, Request, Response,
    LINK_VERSION, MAX_FRAME,
};
