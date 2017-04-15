/// ! Implementation of [multihash](https://github.com/multiformats/multihash) in Rust.

extern crate arrayvec;
extern crate ring;

pub mod algos;

use std::collections::{HashMap, hash_map};
use std::convert::From;
use std::hash::{Hash, Hasher};

pub mod inner {
    use {Multihash, Algo};
    use std::fmt::Debug;
    use std::any::TypeId;

    pub trait InnerMultihash: AsRef<[u8]> + Debug + Send + Sync {
        fn algo(&self) -> Algo;
    }

    pub trait InnerAlgo: Debug + Send + Sync {
        fn algo_ty(&self) -> TypeId;
        fn hash(&self, input: &[u8]) -> Multihash {
            self.hash_with_len(input, self.max_len())
        }
        fn hash_with_len(&self, input: &[u8], len: usize) -> Multihash;
        fn deserialize(&self, input: &[u8]) -> Multihash;
        fn max_len(&self) -> usize;
    }
}
use inner::*;


#[derive(Debug, Clone)]
pub struct Registry {
    by_code: HashMap<u64, Algo>,
    by_algo: HashMap<Algo, u64>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry {
            by_code: HashMap::new(),
            by_algo: HashMap::new(),
        }
    }

    pub fn register(&mut self, code: u64, algo: Algo) {
        self.by_code.insert(code, algo);
        self.by_algo.insert(algo, code);
    }

    pub fn unregister(&mut self, code: u64) {
        if let Some(algo) = self.by_code.remove(&code) {
            self.by_algo.remove(&algo);
        }
    }

    pub fn iter<'a>(&'a self) -> hash_map::Iter<'a, u64, Algo> {
        self.by_code.iter()
    }

    pub fn iter_mut<'a>(&'a mut self) -> hash_map::IterMut<'a, u64, Algo> {
        self.by_code.iter_mut()
    }

    pub fn by_code(&self, code: u64) -> Option<Algo> {
        self.by_code.get(&code).map(|a| *a)
    }

    pub fn by_algo(&self, algo: Algo) -> Option<u64> {
        self.by_algo.get(&algo).map(|c| *c)
    }

    pub fn serialize(&self, input: &Multihash, output: &mut Vec<u8>) {
        let code = self.by_algo(input.algo()).unwrap();
        let slice = input.as_ref();
        output.push(code as u8);
        output.push(slice.len() as u8);
        output.extend_from_slice(slice);
    }

    pub fn deserialize<'a>(&self, input: &'a [u8]) -> (Multihash, &'a [u8]) {
        let code = input[0] as u64;
        let len = input[1] as usize;
        let algo = self.by_code(code).unwrap();
        let mh = algo.0.deserialize(&input[2..len]);
        (mh, &input[..len + 2])
    }
}

impl Default for Registry {
    fn default() -> Registry {
        let mut reg = Registry::new();
        reg.register(0x11, algos::SHA1);
        reg.register(0x12, algos::SHA2256);
        reg.register(0x13, algos::SHA2512);
        reg
    }
}


#[derive(Debug, Clone, Copy)]
pub struct Algo(pub &'static InnerAlgo);

impl Algo {
    pub fn hash(&self, input: &[u8]) -> Multihash {
        self.0.hash(input)
    }

    pub fn hash_with_len(&self, input: &[u8], len: usize) -> Multihash {
        self.0.hash_with_len(input, len)
    }

    pub fn max_len(&self) -> usize {
        self.0.max_len()
    }
}

impl Hash for Algo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.algo_ty().hash(state);
    }
}

impl PartialEq<Algo> for Algo {
    fn eq(&self, other: &Algo) -> bool {
        self.0.algo_ty() == other.0.algo_ty()
    }
}

impl Eq for Algo {}


#[derive(Debug)]
pub struct Multihash(Box<InnerMultihash>);

impl Multihash {
    pub fn algo(&self) -> Algo {
        self.0.algo()
    }
}

impl AsRef<[u8]> for Multihash {
    fn as_ref(&self) -> &[u8] {
        (*self.0).as_ref()
    }
}

impl Hash for Multihash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algo().0.algo_ty().hash(state);
        state.write(self.as_ref());
    }
}

impl PartialEq<Multihash> for Multihash {
    fn eq(&self, other: &Multihash) -> bool {
        self.algo() == other.algo() && self.as_ref() == other.as_ref()
    }
}

impl Eq for Multihash {}

impl Clone for Multihash {
    fn clone(&self) -> Multihash {
        self.algo().0.deserialize(self.as_ref())
    }
}

impl<H: InnerMultihash + 'static> From<H> for Multihash {
    fn from(hash: H) -> Multihash {
        Multihash(Box::new(hash) as Box<InnerMultihash>)
    }
}
