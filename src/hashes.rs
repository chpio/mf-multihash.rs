use inner::InnerAlgo;
use Algo;

macro_rules! gen_hashing {
    (ring, $algo:ident, $input:expr, $output:ident) => {
        let result = digest::digest(&digest::$algo, $input);
        let $output = result.as_ref();
    };
}

macro_rules! impl_hashes {
    ($($name:ident, $max_len:expr, $hasher_type:ident, $hasher_algo:ident;)*) => {
        pub mod algos {
            use $crate::Multihash;
            use $crate::inner::InnerAlgo;
            use ring::digest;
            use std::any::TypeId;

            $(
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
            pub static $name: Algo = Algo(&algos::$name as &InnerAlgo);
        )*

        pub mod hashes {
            use $crate::{Algo, Multihash};
            use $crate::inner::InnerMultihash;
            use arrayvec::ArrayVec;

            $(
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
    SHA2256, 32, ring, SHA256;
    SHA2512, 64, ring, SHA512;
}
