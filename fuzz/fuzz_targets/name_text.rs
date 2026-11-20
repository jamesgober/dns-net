//! Names in text form: no panic, and an accepted name prints as text that
//! parses back to the same bytes.
#![no_main]

use dns_net::{MAX_NAME, Name};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(name) = Name::parse(text) {
        assert!(name.wire_len() <= MAX_NAME);
        let again = Name::parse(&name.to_string()).expect("printed names parse");
        assert!(name.eq_exact(&again), "{text:?}");
        assert_eq!(Name::from_wire(name.wire()).expect("wire form decodes"), name);
    }
    if let Ok(host) = Name::parse_hostname(text) {
        assert!(host.labels().all(|l| l
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')));
    }
});
