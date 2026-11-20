//! The splitter of length-prefixed replies on a TLS connection: no panic,
//! every message at least a header long, nothing left but an incomplete one.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dns_net::__fuzz::tls_frames(data);
});
