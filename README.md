# rust-multihash

[![](https://img.shields.io/badge/made%20by-Protocol%20Labs-blue.svg?style=flat-square)](http://ipn.io)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](http://github.com/multiformats/multiformats)
[![](https://img.shields.io/badge/freenode-%23ipfs-blue.svg?style=flat-square)](http://webchat.freenode.net/?channels=%23ipfs)
[![Build Status](https://img.shields.io/travis/multiformats/rust-multihash/master.svg?style=flat-square)](https://travis-ci.org/multiformats/rust-multihash)
[![Coverage Status](https://coveralls.io/repos/multiformats/rust-multihash/badge.svg?style=flat-square&branch=master)](https://coveralls.io/r/multiformats/rust-multihash?branch=master)
[![](https://img.shields.io/badge/rust-docs-blue.svg?style=flat-square)](http://multiformats.github.io/rust-multihash/multihash/struct.Multihash.html)
[![crates.io](http://meritbadge.herokuapp.com/multihash?style=flat-square)](https://crates.io/crates/multihash)

> [multihash](https://github.com/multiformats/multihash) implementation in Rust.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Supported Hash Types](#supported-hash-types)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

```
TODO
```

## Usage

First add this to your `Cargo.toml`

```toml
[dependencies]
multihash = "*"
```

## Supported Hash Types

* `SHA1`
* `SHA2`
  * `SHA2 256`
  * `SHA2 512`
* `SHA3`
  * `SHA3 224`
  * `SHA3 256`
  * `SHA3 384`
  * `SHA3 512`
* `SHAKE`
  * `SHAKE 128`
  * `SHAKE 256`
* `BLAKE`
  * `BLAKE2B`
  * `BLAKE2S`

## Maintainers

Captain: [@dignifiedquire](https://github.com/dignifiedquire).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/multiformats/rust-multihash/issues).

Check out our [contributing document](https://github.com/multiformats/multiformats/blob/master/contributing.md) for more information on how we work, and about contributing in general. Please be aware that all interactions related to multiformats are subject to the IPFS [Code of Conduct](https://github.com/ipfs/community/blob/master/code-of-conduct.md).

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.


## License

[MIT](LICENSE)
