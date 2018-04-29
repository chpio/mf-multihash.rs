extern crate arrayvec;
extern crate ring;
extern crate tiny_keccak;
extern crate varint;
#[macro_use]
extern crate error_chain;

mod errors {
    error_chain! {
        errors {
            InvalidHashLength(algo: Option<::HashAlgo>) {
                description("Invalid hash length")
                display(
                    "Invalid hash length for `{}`",
                    algo
                        .map(|a| format!("{:?}", a))
                        .unwrap_or("Unknown".to_string())
                )
            }
        }
    }
}

use arrayvec::ArrayVec;
use errors::*;
use ring::digest;
use std::borrow::Borrow;
use tiny_keccak::Keccak;

macro_rules! gen_hashing {
    (ring, $algo:ident, $input:expr, $output:expr, $len:expr) => {
        let result = digest::digest(&digest::$algo, $input);
        $output.copy_from_slice(&result.as_ref()[..$len]);
    };
    (tiny, $algo:ident, $input:expr, $output:expr, $len:expr) => {
        Keccak::$algo($input, $output);
    };
    (u, $algo:ident, $input:expr, $output:expr, $len:expr) => {
        unimplemented!();
    };
}

macro_rules! impl_multihash {
    ($($name:ident, $name_hr:expr, $code:expr, $len:expr, $hash_lib:ident: $hash_algo:ident;)*) => {
        #[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
        pub enum HashAlgo {
            $(
                $name,
            )*
            #[doc(hidden)]
            __Nonexhaustive,
        }

        impl HashAlgo {
            pub fn from_name<S: Borrow<str>>(name: S) -> Option<HashAlgo> {
                match name.borrow() {
                    $(
                        $name_hr => Some(HashAlgo::$name),
                    )*
                    _ => None,
                }
            }

            pub fn config(&self) -> HashConfig {
                HashConfig::new(*self)
            }

            /// ```rust
            /// use multihash::{Multihash, HashAlgo};
            /// let mh: Multihash = HashAlgo::SHA2256.hash("my hash".as_bytes());
            /// ```
            pub fn hash(&self, input: &[u8]) -> Multihash {
                self.config().hash(input)
            }

            /// Returns the len of the hash data
            pub fn max_len(&self) -> usize {
                match self {
                    $(
                        &HashAlgo::$name => $len,
                    )*
                    &HashAlgo::__Nonexhaustive => unreachable!(),
                }
            }

            /// Returns the human readable name of the hash algorithm
            pub fn name(&self) -> &'static str {
                match self {
                    $(
                        &HashAlgo::$name => $name_hr,
                    )*
                    &HashAlgo::__Nonexhaustive => unreachable!(),
                }
            }

            pub fn code(&self) -> u64 {
                match self {
                    $(
                        &HashAlgo::$name => $code,
                    )*
                    &HashAlgo::__Nonexhaustive => unreachable!(),
                }
            }
        }

        #[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
        pub struct HashConfig {
            algo: HashAlgo,
            len: usize,
        }

        impl HashConfig {
            pub fn new(algo: HashAlgo) -> HashConfig {
                HashConfig {
                    algo: algo,
                    len: algo.max_len(),
                }
            }

            pub fn algo(&self) -> HashAlgo {
                self.algo
            }

            pub fn len(&self) -> usize {
                self.len
            }

            pub fn set_len(&self, len: usize) -> HashConfig {
                assert!(len <= self.algo.max_len(), "Max algo length exceeded");
                HashConfig {
                    len: len,
                    ..*self
                }
            }

            pub fn hash(&self, input: &[u8]) -> Multihash {
                match self.algo {
                    $(
                        HashAlgo::$name => {
                            let mut output = ArrayVec::from([0u8; $len]);
                            let _ = output.drain(self.len..);
                            gen_hashing!($hash_lib, $hash_algo, input, output.as_mut(), self.len);
                            #[allow(unreachable_code)]
                            Multihash(MultihashInner::$name(output))
                        },
                    )*
                    HashAlgo::__Nonexhaustive => unreachable!(),
                }
            }
        }

        #[derive(PartialEq, Eq, Hash, Clone, Debug)]
        enum MultihashInner {
            $(
                $name(ArrayVec<[u8; $len]>),
            )*
            Unknown(u64, Vec<u8>),
        }

        /// Represents a valid multihash, by associating the hash algorithm with the data
        #[derive(PartialEq, Eq, Hash, Clone, Debug)]
        pub struct Multihash (MultihashInner);

        impl Multihash {
            /// Converts the Multihash into bytes
            pub fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
                match self.0 {
                    $(
                        MultihashInner::$name(ref hash) => {
                            let len = hash.len();
                            output.reserve_exact(
                                varint::size_u($code) + varint::size_u(len as u64) + len
                            );
                            varint::write_u($code, output)
                                .chain_err(|| "writing multihash code")?;
                            varint::write_u(len as u64, output)
                                .chain_err(|| "writing multihash length")?;
                            output.extend_from_slice(hash);
                        },
                    )*
                    MultihashInner::Unknown(code, ref hash) => {
                        let len = hash.len();
                        output.reserve_exact(varint::size_u(code) + varint::size_u(len as u64) + len);
                        varint::write_u(code, output)
                            .chain_err(|| "writing multihash code")?;
                        varint::write_u(len as u64, output)
                            .chain_err(|| "writing multihash length")?;
                        output.extend_from_slice(hash);
                    },
                }
                Ok(())
            }

            /// Converts bytes into a Multihash
            pub fn from_bytes(input: &[u8]) -> Result<(Multihash, &[u8])> {
                let (code, input) = varint::read_u(input)
                    .chain_err(|| "reading multihash code")?;
                let (len, input) = varint::read_u(input)
                    .chain_err(|| "reading multihash length")?;
                match code {
                    $(
                        $code => {
                            if $len < len || input.len() < len as usize {
                                return Err(ErrorKind::InvalidHashLength(Some(HashAlgo::$name)).into());
                            }
                            let len = len as usize;
                            let mut buf = ArrayVec::new();
                            buf.extend(input[..len].into_iter().cloned());
                            Ok((Multihash(MultihashInner::$name(ArrayVec::from(buf))), &input[len..]))
                        },
                    )*
                    _ => {
                        if 128 < len || input.len() < len as usize  {
                            return Err(ErrorKind::InvalidHashLength(None).into());
                        }
                        let len = len as usize;
                        let mut buf = Vec::with_capacity(len);
                        buf.extend(input[..len].into_iter().cloned());
                        Ok((Multihash(MultihashInner::Unknown(code, buf)), &input[len..]))
                    },
                }
            }

            /// Returns a slice containing the hash data
            pub fn hash(&self) -> &[u8] {
                match self.0 {
                    $(
                        MultihashInner::$name(ref hash) => hash,
                    )*
                    MultihashInner::Unknown(_, ref hash) => hash,
                }
            }

            /// Returns the len of the hash data
            pub fn len(&self) -> usize {
                match self.0 {
                    $(
                        MultihashInner::$name(ref hash) => hash.len(),
                    )*
                    MultihashInner::Unknown(_, ref hash) => hash.len(),
                }
            }

            /// Returns the human readable name of the hash algorithm
            pub fn name(&self) -> &'static str {
                match self.0 {
                    $(
                        MultihashInner::$name(_) => $name_hr,
                    )*
                    MultihashInner::Unknown(..) => "Unknown",
                }
            }

            pub fn code(&self) -> u64 {
                match self.0 {
                    $(
                        MultihashInner::$name(_) => $code,
                    )*
                    MultihashInner::Unknown(code, _) => code,
                }
            }


            pub fn algo(&self) -> Option<HashAlgo> {
                match self.0 {
                    $(
                        MultihashInner::$name(_) => Some(HashAlgo::$name),
                    )*
                    MultihashInner::Unknown(..) => None,
                }
            }

            pub fn config(&self) -> Option<HashConfig> {
                self.algo().map(|a| a.config().set_len(self.len()))
            }
        }
    }
}

impl_multihash! {
    SHA1, "SHA1", 0x11, 20, ring: SHA1;

    SHA2256, "SHA2-256", 0x12, 32, ring: SHA256;
    SHA2512, "SHA2-512", 0x13, 64, ring: SHA512;

    SHA3224, "SHA3-224", 0x17, 28, tiny: sha3_224;
    SHA3256, "SHA3-256", 0x16, 32, tiny: sha3_256;
    SHA3384, "SHA3-384", 0x15, 48, tiny: sha3_384;
    SHA3512, "SHA3-512", 0x14, 64, tiny: sha3_512;

    SHAKE128, "SHAKE-128", 0x18, 16, tiny: shake128;
    SHAKE256, "SHAKE-256", 0x19, 32, tiny: shake256;

    BLAKE2B, "BLAKE2B", 0x40, 64, u: u;
    BLAKE2S, "BLAKE2S", 0x41, 32, u: u;
}
