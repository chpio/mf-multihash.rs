// For explanation of lint checks, run `rustc -W help`
// This is adapted from
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, //missing_docs,
non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, unused_extern_crates, unused_import_braces,
unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
missing_debug_implementations)]

/// ! # multihash
/// !
/// ! Implementation of [multihash](https://github.com/jbenet/multihash)
/// ! in Rust.
/// Representation of a Multiaddr.

extern crate ring;
extern crate tiny_keccak;
extern crate arrayvec;
extern crate varint;

use std::io;
use arrayvec::ArrayVec;
use ring::digest;
use tiny_keccak::Keccak;
use std::borrow::Borrow;

macro_rules! gen_hashing {
    (ring, $algo:ident, $input:expr, $output:expr, $len:expr) => {
        let result = digest::digest(&digest::$algo, $input);
        $output.copy_from_slice(&result.as_ref()[..$len]);
    };
    (tiny, $algo:ident, $input:expr, $output:expr, $len:expr) => {
        Keccak::$algo($input, $output);
    };
}

macro_rules! impl_multihash {
    ($($name:ident, $name_hr:expr, $name_lc:ident, $code:expr, $len:expr, $hash_lib:ident: $hash_algo:ident;)*) => {
        #[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
        pub enum HashAlgo {
            $(
                $name,
            )*
        }

        impl HashAlgo {
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
                }
            }

            /// Returns the human readable name of the hash algorithm
            pub fn name(&self) -> &'static str {
                match self {
                    $(
                        &HashAlgo::$name => $name_hr,
                    )*
                }
            }

            pub fn code(&self) -> u64 {
                match self {
                    $(
                        &HashAlgo::$name => $code,
                    )*
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
                            Multihash::$name(output)
                        },
                    )*
                }
            }
        }

        /// Represents a valid multihash, by associating the hash algorithm with the data
        #[derive(PartialEq, Eq, Hash, Clone, Debug)]
        pub enum Multihash {
            $(
                $name(ArrayVec<[u8; $len]>),
            )*
            Unknown(u64, Vec<u8>),
        }

        impl Multihash {
            /// Converts the Multihash into bytes
            pub fn to_bytes(&self, output: &mut Vec<u8>) -> io::Result<()> {
                match self {
                    $(
                        &Multihash::$name(ref hash) => {
                            let len = hash.len();
                            output.reserve_exact(
                                varint::size_u($code) + varint::size_u(len as u64) + len
                            );
                            varint::write_u($code, output)?;
                            varint::write_u(len as u64, output)?;
                            output.extend_from_slice(hash);
                        },
                    )*
                    &Multihash::Unknown(code, ref hash) => {
                        let len = hash.len();
                        output.reserve_exact(varint::size_u(code) + varint::size_u(len as u64) + len);
                        varint::write_u(code, output)?;
                        varint::write_u(len as u64, output)?;
                        output.extend_from_slice(hash);
                    },
                }
                Ok(())
            }

            /// Converts bytes into a Multihash
            pub fn from_bytes(input: &[u8]) -> io::Result<(Multihash, &[u8])> {
                let (code, input) = varint::read_u(input)?;
                let (len, input) = varint::read_u(input)?;
                match code {
                    $(
                        $code => {
                            if $len < len || input.len() < len as usize {
                                return Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "Invalid input length"
                                ));
                            }
                            let len = len as usize;
                            let mut buf = ArrayVec::new();
                            buf.extend(input[..len].into_iter().cloned());
                            Ok((Multihash::$name(ArrayVec::from(buf)), &input[len..]))
                        },
                    )*
                    _ => {
                        if 128 < len || input.len() < len as usize  {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "Input length exceeded for unknown algorithm"
                            ));
                        }
                        let len = len as usize;
                        let mut buf = Vec::with_capacity(len);
                        buf.extend(input[..len].into_iter().cloned());
                        Ok((Multihash::Unknown(code, buf), &input[len..]))
                    },
                }
            }

            /// Returns a slice containing the hash data
            pub fn hash(&self) -> &[u8] {
                match self {
                    $(
                        &Multihash::$name(ref hash) => hash,
                    )*
                    &Multihash::Unknown(_, ref hash) => hash,
                }
            }

            /// Returns the len of the hash data
            pub fn len(&self) -> usize {
                match self {
                    $(
                        &Multihash::$name(ref hash) => hash.len(),
                    )*
                    &Multihash::Unknown(_, ref hash) => hash.len(),
                }
            }

            /// Returns the human readable name of the hash algorithm
            pub fn name(&self) -> &'static str {
                match self {
                    $(
                        &Multihash::$name(_) => $name_hr,
                    )*
                    &Multihash::Unknown(..) => "Unknown",
                }
            }

            pub fn code(&self) -> u64 {
                match self {
                    $(
                        &Multihash::$name(_) => $code,
                    )*
                    &Multihash::Unknown(code, _) => code,
                }
            }


            pub fn algo(&self) -> Option<HashAlgo> {
                match self {
                    $(
                        &Multihash::$name(_) => Some(HashAlgo::$name),
                    )*
                    &Multihash::Unknown(..) => None,
                }
            }

            pub fn config(&self) -> Option<HashConfig> {
                self.algo().map(|a| a.config().set_len(self.len()))
            }
        }
    }
}

impl_multihash! {
    SHA1, "SHA1", sha1, 0x11, 20, ring: SHA1;

    SHA2256, "SHA2-256", sha2_256, 0x12, 32, ring: SHA256;
    SHA2512, "SHA2-512", sha2_512, 0x13, 64, ring: SHA512;

    SHA3224, "SHA3-224", sha3_224, 0x17, 28, tiny: sha3_224;
    SHA3256, "SHA3-256", sha3_256, 0x16, 32, tiny: sha3_256;
    SHA3384, "SHA3-384", sha3_384, 0x15, 48, tiny: sha3_384;
    SHA3512, "SHA3-512", sha3_512, 0x14, 64, tiny: sha3_512;

    SHAKE128, "SHAKE-128", shake_128, 0x18, 16, tiny: shake128;
    SHAKE256, "SHAKE-256", shake_256, 0x19, 32, tiny: shake256;

    // BLAKE2B, "BLAKE2B", blake2b, 0x40, 64, Blake2b::new(64);
    // BLAKE2S, "BLAKE2S", blake2s, 0x41, 32, Blake2s::new(32);
}
