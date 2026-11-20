//! The readers of resolv.conf and of `reg query` output: no panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    dns_net::__fuzz::resolv_conf(&text);
    dns_net::__fuzz::registry(&text);
});
