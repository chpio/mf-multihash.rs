extern crate multihash;

use multihash::Multihash;

/// Helper function to convert a hex-encoded byte array back into a bytearray
fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut c = 0;
    let mut v = Vec::new();
    while c < s.len() {
        v.push(u8::from_str_radix(&s[c..c+2], 16).unwrap());
        c += 2;
    }
    v
}

#[test]
fn multihash_encode() {
    assert_eq!(
        Multihash::sha2_256("helloworld".as_bytes()).to_bytes(),
        hex_to_bytes("1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af").as_slice()
    );
    assert_eq!(
        Multihash::sha2_256("beep boop".as_bytes()).to_bytes(),
        hex_to_bytes("122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c").as_slice()
    );
    assert_eq!(
        Multihash::sha2_512("hello world".as_bytes()).to_bytes(),
        hex_to_bytes("1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f").as_slice()
    );
}

#[test]
fn multihash_decode() {
    let hash = Multihash::sha2_256("helloworld".as_bytes());
    assert!(match hash {
        Multihash::SHA2256(_) => true,
        _ => false,
    })
}

#[test]
fn hash_types() {
    let hash = Multihash::sha2_256(&[]);
    
    assert_eq!(hash.size(), 32);
    assert_eq!(hash.name(), "SHA2-256");
}
