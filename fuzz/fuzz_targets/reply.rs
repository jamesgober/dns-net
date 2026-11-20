//! A reply to a fixed query: no panic, an accepted reply repeats the
//! question exactly, and an answer only holds records owned by the end of
//! its chain.
#![no_main]

use dns_net::{Exchange, Name, Outcome, Question, RData, RecordType};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let question = Question::new(Name::parse("www.example.com").unwrap(), RecordType::A);
    let ex = Exchange::new(&question, 0x1234, &[0x5A, 0x3C], Some(1232)).unwrap();
    // Let the input start with the right id often enough to get past it.
    let mut reply = vec![0x12, 0x34];
    reply.extend_from_slice(data);
    let Ok(msg) = ex.check(&reply) else {
        return;
    };
    if let Some(q) = &msg.question {
        assert!(q.name.eq_exact(&ex.question().name));
    }
    if let Outcome::Answer(answer) = Outcome::read(&question, &msg) {
        let end = answer.canonical_name(&question.name).clone();
        assert!(answer.records.iter().all(|r| r.name == end));
        assert!(answer.chain.iter().all(|r| matches!(r.data, RData::Cname(_))));
        assert!(answer.chain.len() <= dns_net::MAX_CHAIN);
    }
});
