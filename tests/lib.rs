extern crate multihash;
extern crate ring;

use multihash::{HashAlgo, Multihash};
use ring::test;

/// Helper function to convert a hex-encoded byte array back into a bytearray
fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut c = 0;
    let mut v = Vec::new();
    while c < s.len() {
        v.push(u8::from_str_radix(&s[c..c + 2], 16).unwrap());
        c += 2;
    }
    v
}

#[test]
fn hashing() {
    test::from_file("./tests/hashing.txt", |_, t| {
        let algo = t.consume_string("algo");
        let len = t.consume_usize("len");
        let input = t.consume_bytes("input");
        let output = t.consume_bytes("output");

        let algo = HashAlgo::from_name(algo).unwrap();
        let mut config = algo.config();
        if len != 0 {
            config = config.set_len(len);
        }
        let mh = config.hash(&input);
        let mut out = Vec::new();
        mh.to_bytes(&mut out).unwrap();
        assert_eq!(output, out);

        Ok(())
    });
}

#[test]
fn multihash_deserialize() {
    let buf =
        hex_to_bytes("1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af0000");
    let (hash, slice) = Multihash::from_bytes(buf.as_slice()).unwrap();
    assert_eq!(hash.algo(), Some(HashAlgo::SHA2256));
    assert_eq!(
        hash.hash(),
        hex_to_bytes("936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af").as_slice()
    );
    assert_eq!(slice, hex_to_bytes("0000").as_slice());
}
