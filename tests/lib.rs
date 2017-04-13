extern crate mf_multihash;
extern crate ring;

use mf_multihash::Registry;
use mf_multihash::hashes::{SHA1, SHA2256, SHA2512};
use ring::test;

#[test]
fn registry_by_code() {
    let reg = Registry::default();
    assert_eq!(Some(SHA1), reg.by_code(0x11));
}

#[test]
fn hashing() {
    test::from_file("./tests/hashing.txt", |_, t| {
        let algo = t.consume_string("algo");
        let len = t.consume_usize("len");
        let input = t.consume_bytes("input");
        let output = t.consume_bytes("output");

        let algo = match algo.as_ref() {
            "SHA2256" => SHA2256,
            "SHA2512" => SHA2512,
            _ => unreachable!(),
        };
        let mh = if len == 0 {
            algo.hash(input.as_ref())
        } else {
            algo.hash_with_len(input.as_ref(), len)
        };
        let reg = Registry::default();
        let mut out = Vec::new();
        reg.serialize(&mh, &mut out);
        assert_eq!(output, out);

        Ok(())
    });
}
