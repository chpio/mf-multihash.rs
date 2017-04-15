use inner::InnerAlgo;
use Algo;

macro_rules! gen_hashing {
    (ring, $algo:ident, $input:expr, $output:ident) => {
        let result = ::ring::digest::digest(&::ring::digest::$algo, $input);
        let $output = result.as_ref();
    };

    (tiny, $algo:ident, $input:expr, $output:ident) => {
        let result = ::tiny_keccak::$algo($input);
        let $output = result.as_ref();
    };
}

macro_rules! impl_hashes {
    ($($name:ident, $max_len:expr, $hasher_type:ident, $hasher_algo:ident;)*) => {
        mod algos {
            use $crate::Multihash;
            use $crate::inner::InnerAlgo;
            use std::any::TypeId;

            $(
                #[allow(non_camel_case_types)]
                #[derive(Debug)]
                pub struct $name;
                impl InnerAlgo for $name {
                    fn algo_ty(&self) -> TypeId {
                        TypeId::of::<Self>()
                    }

                    fn hash_with_len(&self, input: &[u8], len: usize) -> Multihash {
                        gen_hashing!($hasher_type, $hasher_algo, input, output);
                        self.deserialize(&output[..len])
                    }

                    fn deserialize(&self, input: &[u8]) -> Multihash {
                        super::hashes::$name::new(input)
                    }

                    fn max_len(&self) -> usize {
                        $max_len
                    }
                }
            )*
        }

        $(
            #[allow(non_upper_case_globals)]
            pub static $name: Algo = Algo(&algos::$name as &InnerAlgo);
        )*

        mod hashes {
            use $crate::{Algo, Multihash};
            use $crate::inner::InnerMultihash;
            use arrayvec::ArrayVec;

            $(
                #[allow(non_camel_case_types)]
                #[derive(Debug, Clone)]
                pub struct $name(ArrayVec<[u8; $max_len]>);

                impl $name {
                    pub fn new(input: &[u8]) -> Multihash {
                        let mut buf = ArrayVec::new();
                        buf.extend(input.into_iter().cloned());
                        $name(buf).into()
                    }
                }

                impl InnerMultihash for $name {
                    fn algo(&self) -> Algo {
                        super::$name
                    }
                }

                impl AsRef<[u8]> for $name {
                    fn as_ref(&self) -> &[u8] {
                        self.0.as_ref()
                    }
                }
            )*
        }
    };
}


impl_hashes! {
    SHA1, 20, ring, SHA1;

    SHA2_256, 32, ring, SHA256;
    SHA2_384, 48, ring, SHA384;
    SHA2_512, 64, ring, SHA512;

    SHA3_224, 28, tiny, sha3_224;
    SHA3_256, 32, tiny, sha3_256;
    SHA3_384, 48, tiny, sha3_384;
    SHA3_512, 64, tiny, sha3_512;

    SHAKE_128, 16, tiny, shake128;
    SHAKE_256, 32, tiny, shake256;

    Keccak_224, 28, tiny, keccak224;
    Keccak_256, 32, tiny, keccak256;
    Keccak_384, 48, tiny, keccak384;
    Keccak_512, 64, tiny, keccak512;
}
