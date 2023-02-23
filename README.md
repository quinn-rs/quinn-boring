[![codecov](https://codecov.io/gh/quinn-rs/quinn/branch/main/graph/badge.svg)](https://codecov.io/gh/quinn-rs/quinn-boring)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

A crypto provider for [quinn](https://github.com/quinn-rs/quinn) based on [BoringSSL](https://github.com/google/boringssl).

## Getting Started

The [examples](examples) directory provides example client and server applications, which can be run as follows: 

```sh
$ cargo run --example server ./
$ cargo run --example client https://localhost:4433/Cargo.toml
```

This launches an HTTP 0.9 server on the loopback address serving the current
working directory, with the client fetching `./Cargo.toml`. By default, the
server generates a self-signed certificate and stores it to disk, where the
client will automatically find and trust it.

## Testing

This repository relies on the [quinn_proto integration tests](https://github.com/quinn-rs/quinn/tree/main/quinn-proto/src/tests),
which can be made to run with the BoringSSL provider.

## FIPS

The BoringSSL provider is based on the Cloudflare [Boring library](https://github.com/cloudflare/boring), which
supports building against a FIPS-validated version of BoringSSL.

## Authors

* [Nathan Mittler](https://github.com/nmittler) - *Project owner*
