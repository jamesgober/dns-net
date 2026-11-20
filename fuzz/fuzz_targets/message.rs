//! The message decoder: no panic on any input, and whatever it accepts
//! encodes and decodes back to the same message.
#![no_main]

use dns_net::{EncodeError, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = Message::decode(data) else {
        return;
    };
    match msg.encode() {
        Ok(bytes) => {
            let back = Message::decode(&bytes).expect("an encoded message decodes");
            assert_eq!(back, msg);
        }
        // The input may have compressed more than the encoder does.
        Err(EncodeError::TooLong) => {}
        Err(e) => panic!("a decoded message failed to encode: {e}"),
    }
});
