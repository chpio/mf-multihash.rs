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
use std::borrow::Borrow;
use std::{error, fmt};

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

macro_rules! gen_digest_data {
    (ring, $algo:ident) => {
        ::ring::digest::Context
    };
    (tiny, $algo:ident) => {
        ::tiny_keccak::Keccak
    };
    (u, $algo:ident) => {
        ()
    };
}

macro_rules! gen_digest_new {
    (ring, $algo:ident) => {
        ::ring::digest::Context::new(&::ring::digest::$algo)
    };
    (tiny, $algo:ident) => {
        ::tiny_keccak::Keccak::$algo();
    };
    (u, $algo:ident) => {
        unimplemented!();
    };
}

macro_rules! gen_digest_update {
    (ring, $algo:ident, $digester:expr, $input:expr) => {
        $digester.update($input);
    };
    (tiny, $algo:ident, $digester:expr, $input:expr) => {
        $digester.update($input);
    };
    (u, $algo:ident, $digester:expr, $input:expr) => {
        unimplemented!();
    };
}

macro_rules! gen_digest_finish {
    (ring, $algo:ident, $digester:expr, $max_len:expr, $len:expr) => {{
        let result = $digester.finish();
        let mut buf: ArrayVec<[u8; $max_len]> = ArrayVec::new();
        buf.extend(result.as_ref()[..$len].iter().cloned());
        buf
    }};
    (tiny, $algo:ident, $digester:expr, $max_len:expr, $len:expr) => {{
        let mut buf: ArrayVec<[u8; $max_len]> = ArrayVec::from([0; $max_len]);
        $digester.finalize(&mut buf);
        buf.drain($len..);
        buf
    }};
    (u, $algo:ident, $digester:expr, $max_len:expr, $len:expr) => {
        unimplemented!();
    };
}

macro_rules! impl_multihash {
    ($($name:ident, $name_hr:expr, $code:expr, $len:expr, $hash_lib:ident: $hash_algo:ident;)*) => {
        enum DigestInner {
            $(
                $name(usize, gen_digest_data!($hash_lib, $hash_algo)),
            )*
        }

        pub struct Digest(DigestInner);

        impl Digest {
            pub fn algo(&self) -> Algo {
                match self.0 {
                    $(
                        DigestInner::$name(..) => Algo::$name,
                    )*
                }
            }

            pub fn config(&self) -> Config {
                match self.0 {
                    $(
                        DigestInner::$name(len, ..) => {
                            Config {
                                algo: Algo::$name,
                                len: len
                            }
                        }
                    )*
                }
            }

            pub fn update(&mut self, input: &[u8]) {
                #[allow(unused_variables)]
                match self.0 {
                    $(
                        DigestInner::$name(_, ref mut digester) => {
                            gen_digest_update!($hash_lib, $hash_algo, digester, input);
                        }
                    )*
                }
            }

            pub fn finish(self) -> Multihash {
                #[allow(unreachable_code, unused_variables)]
                match self.0 {
                    $(
                        DigestInner::$name(len, digester) => {
                            let buf =
                                gen_digest_finish!($hash_lib, $hash_algo, digester, $len, len);
                            Multihash(MultihashInner::$name(buf))
                        }
                    )*
                }
            }
        }

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

            pub fn from_code(code: u64) -> Option<Algo> {
                match code {
                    $(
                        $code => Some(Algo::$name),
                    )*
                    _ => None,
                }
            }

            pub fn config(&self) -> Config {
                Config {
                    algo: *self,
                    len: self.max_len(),
                }
            }

            pub fn digest(&self) -> Digest {
                self.config().digest()
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
            pub fn algo(&self) -> Algo {
                self.algo
            }

            pub fn len(&self) -> usize {
                self.len
            }

            pub fn set_len(&self, len: usize) -> Config {
                assert!(len <= self.algo.max_len(), "Max algo length exceeded");
                Config {
                    algo: self.algo,
                    len: len,
                }
            }

            pub fn digest(&self) -> Digest {
                #[allow(unreachable_code, unused_variables)]
                match self.algo {
                    $(
                        Algo::$name => {
                            let digester = gen_digest_new!($hash_lib, $hash_algo);
                            Digest(DigestInner::$name(self.len, digester))
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
                match self.0 {
                    $(
                        MultihashInner::$name(ref hash) => Some(Config {
                            algo: Algo::$name,
                            len: hash.len(),
                        }),
                    )*
                    MultihashInner::Unknown(..) => None,
                }
            }
        }
    }
}

impl_multihash! {
    SHA1, "SHA1", 0x11, 20, ring: SHA1;

    SHA2256, "SHA2-256", 0x12, 32, ring: SHA256;
    SHA2512, "SHA2-512", 0x13, 64, ring: SHA512;

    SHA3224, "SHA3-224", 0x17, 28, tiny: new_sha3_224;
    SHA3256, "SHA3-256", 0x16, 32, tiny: new_sha3_256;
    SHA3384, "SHA3-384", 0x15, 48, tiny: new_sha3_384;
    SHA3512, "SHA3-512", 0x14, 64, tiny: new_sha3_512;

    SHAKE128, "SHAKE-128", 0x18, 16, tiny: new_shake128;
    SHAKE256, "SHAKE-256", 0x19, 32, tiny: new_shake256;

    BLAKE2B, "BLAKE2B", 0x40, 64, u: u;
    BLAKE2S, "BLAKE2S", 0x41, 32, u: u;
}
