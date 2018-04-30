//! > Multihash is a protocol for differentiating outputs from various well-established
//! > cryptographic hash functions, addressing size + encoding considerations.
//! >
//! > It is useful to write applications that future-proof their use of hashes, and allow
//! > multiple hash functions to coexist.
//!
//! <https://github.com/multiformats/multihash>
//!
//! ## Supported Hash Types
//! * `SHA1`
//! * `SHA2`
//!   * `SHA2 256`
//!   * `SHA2 512`
//! * `SHA3`
//!   * `SHA3 224`
//!   * `SHA3 256`
//!   * `SHA3 384`
//!   * `SHA3 512`
//! * `SHAKE`
//!   * `SHAKE 128`
//!   * `SHAKE 256`
//! * `BLAKE`
//!   * `BLAKE2B`
//!   * `BLAKE2S`

extern crate arrayvec;
extern crate integer_encoding;
extern crate ring;
extern crate tiny_keccak;

use arrayvec::ArrayVec;
use integer_encoding::VarInt;
use ring::digest;
use std::borrow::Borrow;
use std::{error, fmt};
use tiny_keccak::Keccak;

#[derive(Debug)]
pub enum Error {
    InvalidHashLength,
    #[doc(hidden)]
    __Nonexhaustive,
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::InvalidHashLength => "InvalidHashLength",
            &Error::__Nonexhaustive => unreachable!(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", error::Error::description(self))
    }
}

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
        pub enum Algo {
            $(
                $name,
            )*
            #[doc(hidden)]
            __Nonexhaustive,
        }

        impl Algo {
            pub fn from_name<S: Borrow<str>>(name: S) -> Option<Algo> {
                match name.borrow() {
                    $(
                        $name_hr => Some(Algo::$name),
                    )*
                    _ => None,
                }
            }

            pub fn config(&self) -> Config {
                Config::new(*self)
            }

            /// ```rust
            /// use mf_multihash::{Multihash, Algo};
            /// let mh: Multihash = Algo::SHA2256.hash("my hash".as_bytes());
            /// ```
            pub fn hash(&self, input: &[u8]) -> Multihash {
                self.config().hash(input)
            }

            /// Returns the len of the hash data
            pub fn max_len(&self) -> usize {
                match self {
                    $(
                        &Algo::$name => $len,
                    )*
                    &Algo::__Nonexhaustive => unreachable!(),
                }
            }

            /// Returns the human readable name of the hash algorithm
            pub fn name(&self) -> &'static str {
                match self {
                    $(
                        &Algo::$name => $name_hr,
                    )*
                    &Algo::__Nonexhaustive => unreachable!(),
                }
            }

            pub fn code(&self) -> u64 {
                match self {
                    $(
                        &Algo::$name => $code,
                    )*
                    &Algo::__Nonexhaustive => unreachable!(),
                }
            }
        }

        #[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
        pub struct Config {
            algo: Algo,
            len: usize,
        }

        impl Config {
            pub fn new(algo: Algo) -> Config {
                Config {
                    algo: algo,
                    len: algo.max_len(),
                }
            }

            pub fn algo(&self) -> Algo {
                self.algo
            }

            pub fn len(&self) -> usize {
                self.len
            }

            pub fn set_len(&self, len: usize) -> Config {
                assert!(len <= self.algo.max_len(), "Max algo length exceeded");
                Config {
                    len: len,
                    ..*self
                }
            }

            pub fn hash(&self, input: &[u8]) -> Multihash {
                match self.algo {
                    $(
                        Algo::$name => {
                            let mut output = ArrayVec::from([0u8; $len]);
                            let _ = output.drain(self.len..);
                            gen_hashing!($hash_lib, $hash_algo, input, output.as_mut(), self.len);
                            #[allow(unreachable_code)]
                            Multihash(MultihashInner::$name(output))
                        },
                    )*
                    Algo::__Nonexhaustive => unreachable!(),
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
            pub fn to_bytes(&self, output: &mut Vec<u8>) {
                let (code, hash) = match self.0 {
                    $(
                        MultihashInner::$name(ref hash) => {
                            ($code, hash.as_ref())
                        },
                    )*
                    MultihashInner::Unknown(code, ref hash) => {
                        (code, hash.as_ref())
                    },
                };
                let len = hash.len();
                let len_vcode = code.required_space();
                let len_vlen = len.required_space();
                let len_v = len_vcode + len_vlen;
                output.reserve_exact(len_v + len);
                for _ in 0..len_v {
                    output.push(0);
                }
                code.encode_var(&mut output[0..len_vcode]);
                len.encode_var(&mut output[len_vcode..len_v]);
                output.extend_from_slice(hash);
            }

            /// Converts bytes into a Multihash
            pub fn from_bytes(input: &[u8]) -> Result<(Multihash, &[u8]), Error> {
                let (code, len_vcode) = u64::decode_var(input);
                let (len, len_vlen) = usize::decode_var(&input[len_vcode..]);
                let len_v = len_vlen + len_vcode;
                let input = &input[len_v..];
                match code {
                    $(
                        $code => {
                            if $len < len || input.len() < len {
                                return Err(Error::InvalidHashLength);
                            }
                            let len = len as usize;
                            let mut buf = ArrayVec::new();
                            buf.extend(input[..len].into_iter().cloned());
                            Ok((Multihash(MultihashInner::$name(ArrayVec::from(buf))), &input[len..]))
                        },
                    )*
                    _ => {
                        if 128 < len || input.len() < len  {
                            return Err(Error::InvalidHashLength);
                        }
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


            pub fn algo(&self) -> Option<Algo> {
                match self.0 {
                    $(
                        MultihashInner::$name(_) => Some(Algo::$name),
                    )*
                    MultihashInner::Unknown(..) => None,
                }
            }

            pub fn config(&self) -> Option<Config> {
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
