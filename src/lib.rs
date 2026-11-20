//! # dns_net
//!
//! A DNS client for Rust: a strict, sans-IO message codec, and a caching
//! stub resolver on net-io's reactor driver that never blocks a server worker.
//!
//! ## Look up addresses
//!
//! ```no_run
//! # #[cfg(feature = "resolver")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use dns_net::{PublicOnly, Resolver, ResolverConfig};
//!
//! let resolver = Resolver::new(ResolverConfig::system()?)?;
//! // Refuses loopback, private, link-local and other non-public addresses,
//! // which is what a proxy or a webhook sender needs.
//! let addrs = resolver.lookup_ip_with("api.example.com", &PublicOnly::new())?;
//! # let _ = addrs;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "resolver"))]
//! # fn main() {}
//! ```
//!
//! ## Decode a message
//!
//! ```
//! use dns_net::{Message, Name, Question, RecordType};
//!
//! let query = Message::query(7, Question::new(Name::parse("example.com")?, RecordType::MX));
//! let bytes = query.encode()?;
//! assert_eq!(Message::decode(&bytes)?, query);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Features
//!
//! - `resolver` (default): the resolver, its cache, the address policies and
//!   the system configuration readers. Adds net-io and mod-rand. Without it
//!   the crate is the codec alone, with no dependencies.
//!
//! The design and its decisions are in `dev/PLAN.md` in the
//! [repository](https://github.com/jamesgober/dns-net).

#![doc(html_root_url = "https://docs.rs/dns-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

mod error;
mod exchange;
mod message;
mod name;
mod rdata;
mod types;

#[cfg(feature = "resolver")]
mod cache;
#[cfg(feature = "resolver")]
mod config;
#[cfg(feature = "resolver")]
mod policy;
#[cfg(feature = "resolver")]
mod random;
#[cfg(feature = "resolver")]
mod resolver;

pub use error::{DecodeError, EncodeError, NameError};
pub use exchange::{Answer, Exchange, MAX_CHAIN, Mismatch, Outcome, Status};
pub use message::{
    DEFAULT_PAYLOAD, Edns, EdnsOption, Header, MAX_MESSAGE, MAX_RECORDS, Message, Question, Record,
};
pub use name::{Labels, MAX_LABEL, MAX_NAME, MAX_POINTERS, Name};
pub use rdata::RData;
pub use types::{Class, Opcode, Rcode, RecordType, UnknownType};

#[cfg(feature = "resolver")]
#[cfg_attr(docsrs, doc(cfg(feature = "resolver")))]
pub use cache::CacheStats;
#[cfg(feature = "resolver")]
#[cfg_attr(docsrs, doc(cfg(feature = "resolver")))]
pub use config::{ConfigError, ResolverConfig, Upstream};
#[cfg(feature = "resolver")]
#[cfg_attr(docsrs, doc(cfg(feature = "resolver")))]
pub use policy::{AddressPolicy, AllowAll, PublicOnly, is_public};
#[cfg(feature = "resolver")]
#[cfg_attr(docsrs, doc(cfg(feature = "resolver")))]
pub use resolver::{Error, IpOrder, Lookup, Resolver, ResolverStats, Ticket};

/// Entry points for the fuzz targets (`fuzz/`), compiled only under
/// cargo-fuzz (`--cfg fuzzing`). Not part of the public API.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod __fuzz {
    /// The resolv.conf reader.
    #[cfg(feature = "resolver")]
    pub fn resolv_conf(text: &str) {
        let _ = crate::config::parse_resolv_conf(text);
    }

    /// The reader of `reg query` output.
    #[cfg(feature = "resolver")]
    pub fn registry(text: &str) {
        let _ = crate::config::parse_registry(text);
    }
}

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
