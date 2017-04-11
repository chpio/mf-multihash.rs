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

extern crate crypto;
extern crate arrayvec;
extern crate varint;

use std::io;
use arrayvec::ArrayVec;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use crypto::sha2::{Sha256, Sha512};
use crypto::sha3::Sha3;
use crypto::blake2b::Blake2b;
use crypto::blake2s::Blake2s;

macro_rules! impl_multihash {
    ($($name:ident, $name_hr:expr, $name_lc:ident, $code:expr, $size:expr, $hasher:expr;)*) => {
        /// Represents a valid multihash, by associating the hash algorithm with the data
        #[derive(PartialEq, Eq, Clone, Debug)]
        pub enum Multihash {
            $(
                $name(ArrayVec<[u8; $size]>),
            )*
            Unknown(u64, Vec<u8>),
        }

        impl Multihash {
            /// Converts the Multihash into bytes
            pub fn to_bytes(&self, output: &mut Vec<u8>) -> io::Result<()> {
                match self {
                    $(
                        &Multihash::$name(ref hash) => {
                            output.reserve_exact(
                                varint::size_u($code) + varint::size_u($size) + $size
                            );
                            varint::write_u($code, output)?;
                            varint::write_u($size, output)?;
                            output.extend_from_slice(hash);
                        },
                    )*
                    &Multihash::Unknown(code, ref hash) => {
                        let size = hash.len();
                         // TODO:  make "size as u64" more overflow proof
                        output.reserve_exact(varint::size_u(code) + varint::size_u(size as u64) + size);
                        varint::write_u(code, output)?;
                        varint::write_u(size as u64, output)?;
                        output.extend_from_slice(hash);
                    },
                }
                Ok(())
            }

            /// Converts bytes into a Multihash
            pub fn from_bytes(input: &[u8]) -> io::Result<(Multihash, &[u8])> {
                let (code, input) = varint::read_u(input)?;
                let (size, input) = varint::read_u(input)?;
                match code {
                    $(
                        $code => {
                            if size != $size || input.len() < $size {
                                return Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "Invalid input length"
                                ));
                            }
                            let mut buf: [u8; $size] = [0; $size];
                            buf.copy_from_slice(&input[..$size]);
                            Ok((Multihash::$name(ArrayVec::from(buf)), &input[$size..]))
                        },
                    )*
                    _ => {
                        if size > 128 {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "Input length exceeded for unknown algorithm"
                            ));
                        }
                        let size = size as usize; // TODO: make overflow proof
                        let mut buf = Vec::with_capacity(size);
                        buf.copy_from_slice(&input[..size]);
                        Ok((Multihash::Unknown(code, buf), &input[size..]))
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

            /// Returns the size of the hash data
            pub fn size(&self) -> usize {
                match self {
                    $(
                        &Multihash::$name(_) => $size,
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

            $(
                /// Hashes the input by the designated algorithm. Returns a
                /// Multihash containing the hashed data.
                pub fn $name_lc(input: &[u8]) -> Multihash {
                    let mut buf: [u8; $size] = [0; $size];
                    let mut hasher = $hasher;
                    hasher.input(input);
                    hasher.result(&mut buf);
                    Multihash::$name(ArrayVec::from(buf))
                }
            )*
        }
    }
}

impl_multihash! {
    SHA1, "SHA1", sha1, 0x11, 20, Sha1::new();

    SHA2256, "SHA2-256", sha2_256, 0x12, 32, Sha256::new();
    SHA2512, "SHA2-512", sha2_512, 0x13, 64, Sha512::new();

    SHA3224, "SHA3-224", sha3_224, 0x17, 28, Sha3::sha3_224();
    SHA3256, "SHA3-256", sha3_256, 0x16, 32, Sha3::sha3_256();
    SHA3384, "SHA3-384", sha3_384, 0x15, 48, Sha3::sha3_384();
    SHA3512, "SHA3-512", sha3_512, 0x14, 64, Sha3::sha3_512();

    SHAKE128, "SHAKE-128", shake_128, 0x18, 16, Sha3::shake_128();
    SHAKE256, "SHAKE-256", shake_256, 0x19, 32, Sha3::shake_256();

    BLAKE2B, "BLAKE2B", blake2b, 0x40, 64, Blake2b::new(64);
    BLAKE2S, "BLAKE2S", blake2s, 0x41, 32, Blake2s::new(32);
}
