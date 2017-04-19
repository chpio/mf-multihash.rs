macro_rules! digest_struct {
    (ring) => {
        ::ring::digest::Context
    };
    (tiny) => {
        ::tiny_keccak::Keccak
    };
}

macro_rules! digest_new {
    (ring, $algo:ident) => {
        ::ring::digest::Context::new(&::ring::digest::$algo)
    };
    (tiny, $algo:ident) => {
        ::tiny_keccak::Keccak::$algo()
    };
}

macro_rules! digest_finish {
    (ring, $input: expr, $max_len: expr, $name: ident) => {{
        let result = $input.finish();
        super::hashes::$name::from_slice(result.as_ref())
    }};
    (tiny, $input: expr, $max_len: expr, $name: ident) => {{
        let mut buf = [0u8; $max_len];
        $input.finalize(&mut buf);
        super::hashes::$name::from_array(buf)
    }};
}

macro_rules! impl_hashes {
    ($($name:ident, $max_len:expr, $hasher_type:ident, $hasher_algo:ident;)*) => {
        mod algos {
            use $crate::Algo;

            $(
                #[allow(non_camel_case_types)]
                #[derive(Debug, Clone, PartialEq, Eq)]
                pub struct $name;
                impl Algo for $name {
                    type Hash = super::hashes::$name;
                    type Digest = super::digests::$name;

                    fn digest(&self) -> super::digests::$name {
                        super::digests::$name::new()
                    }

                    fn deserialize(&self, input: &[u8]) -> super::hashes::$name {
                        super::hashes::$name::from_slice(input)
                    }

                    fn max_len() -> usize {
                        $max_len
                    }
                }
            )*
        }

        mod digests {
            use $crate::Digest;

            $(
                #[allow(non_camel_case_types)]
                #[derive(Clone)]
                pub struct $name {
                    inner: digest_struct!($hasher_type),
                }

                impl $name {
                    pub fn new() -> $name {
                        $name { inner: digest_new!($hasher_type, $hasher_algo) }
                    }
                }

                impl Digest for $name {
                    type Algo = super::algos::$name;

                    fn algo(&self) -> super::algos::$name {
                        super::$name
                    }

                    fn update(&mut self, input: &[u8]) {
                        self.inner.update(input);
                    }

                    fn finish(self) -> super::hashes::$name {
                        digest_finish!($hasher_type, self.inner, $max_len, $name)
                    }
                }
            )*
        }

        $(
            #[allow(non_upper_case_globals)]
            pub const $name: algos::$name = algos::$name;
        )*

        mod hashes {
            use $crate::Multihash;
            use arrayvec::ArrayVec;

            $(
                #[allow(non_camel_case_types)]
                #[derive(Debug, Clone, PartialEq, Eq)]
                pub struct $name(ArrayVec<[u8; $max_len]>);

                impl $name {
                    pub fn from_slice(input: &[u8]) -> $name {
                        let mut buf = ArrayVec::new();
                        buf.extend(input.into_iter().cloned());
                        $name(buf)
                    }

                    pub fn from_array(input: [u8; $max_len]) -> $name {
                        $name(ArrayVec::from(input))
                    }
                }

                impl Multihash for $name {
                    type Algo = super::algos::$name;

                    fn algo(&self) -> super::algos::$name {
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

    SHA3_224, 28, tiny, new_sha3_224;
    SHA3_256, 32, tiny, new_sha3_256;
    SHA3_384, 48, tiny, new_sha3_384;
    SHA3_512, 64, tiny, new_sha3_512;

    SHAKE_128, 16, tiny, new_shake128;
    SHAKE_256, 32, tiny, new_shake256;

    Keccak_224, 28, tiny, new_keccak224;
    Keccak_256, 32, tiny, new_keccak256;
    Keccak_384, 48, tiny, new_keccak384;
    Keccak_512, 64, tiny, new_keccak512;
}
