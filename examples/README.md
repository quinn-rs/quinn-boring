## HTTP/0.9 File Serving Example

The examples in this directory were copied from [quinn](https://github.com/quinn-rs/quinn/tree/main/quinn/examples)
and modified to use BoringSSL.

The `server` and `client` examples demonstrate fetching files using a HTTP-like toy protocol.

1. Server (`server.rs`)

The server listens for any client requesting a file.
If the file path is valid and allowed, it returns the contents.

Open up a terminal and execute:

```text
$ cargo run --example server ./
```

2. Client (`client.rs`)

The client requests a file and prints it to the console.
If the file is on the server, it will receive the response.

In a new terminal execute:

```test
$ cargo run --example client https://localhost:4433/Cargo.toml
```

where `Cargo.toml` is any file in the directory passed to the server.

**Result:**

The output will be the contents of this README.

**Troubleshooting:**

If the client times out with no activity on the server, try forcing the server to run on IPv4 by
running it with `cargo run --example server -- ./ --listen 127.0.0.1:4433`. The server listens on
IPv6 by default, `localhost` tends to resolve to IPv4, and support for accepting IPv4 packets on
IPv6 sockets varies between platforms.

If the client prints `failed to process request: failed reading file`, the request was processed
successfully but the path segment of the URL did not correspond to a file in the directory being
served.
